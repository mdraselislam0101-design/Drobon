import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, test } from 'vitest';
import type { Finding, ScaResult, SourceFinding } from '@drobon/shared';
import { createMemoryProjectStore } from '../src/projects/store.js';
import { buildSecurityReport, renderSecurityReportMarkdown } from '../src/reports/build.js';
import { createJsonFileScanStore, createMemoryScanStore, type ScanStore } from '../src/scans/store.js';
import { prepareFindingNote } from '../src/scans/findingWorkflow.js';
import { remediationGuidanceForFinding, scaInventoryGuidance } from '../src/scans/remediationGuidance.js';
import { cleanupTempStoreDir, makeTempStoreDir } from './helpers.js';

const OWNER_ID = 'usr_workflow_test_owner';
const SECRET_FIXTURE = 'SYNTHETIC_SECRET_DO_NOT_LEAK_7e2e09f5a1';

function makeFinding(scanId: string, fingerprint = 'a'.repeat(64), title = 'Synthetic rule finding'): SourceFinding {
  return {
    id: `fnd_${fingerprint.slice(0, 24)}`,
    scanId,
    scanner: 'SAST',
    ruleId: 'DG-SAST-001',
    severity: 'HIGH',
    title,
    description: 'Fixture evidence; no real target or vulnerability claim.',
    file: 'src/app.js',
    line: 3,
    column: 1,
    evidence: 'exec("git " + dynamicText);',
    remediation: 'Review dynamic input handling in application context.',
    fingerprint,
  };
}

async function completeScan(scans: ScanStore, projectId: string, finding?: Finding) {
  const created = await scans.createScanWithQuota({ ownerId: OWNER_ID, projectId, scanType: 'SAST', consume: async () => ({ ok: true }) });
  if (created.outcome !== 'created') throw new Error('Scan fixture creation failed.');
  const running = await scans.claimNextQueued();
  if (running === undefined) throw new Error('Scan fixture claim failed.');
  const item = finding === undefined ? undefined : { ...finding, scanId: running.id };
  const completed = await scans.completeScan(running.id, { findingsTotal: item === undefined ? 0 : 1 }, item === undefined ? [] : [item]);
  if (completed === undefined) throw new Error('Scan fixture completion failed.');
  return { scan: completed, finding: completed.findings?.[0] };
}

async function fixtureProject() {
  const projects = createMemoryProjectStore();
  const project = await projects.create({ ownerId: OWNER_ID, name: 'Workflow test project', description: '' });
  return { projects, project };
}

describe('finding workflow store, notes, guidance and reports', () => {
  test('guidance is closed-rule-specific, secret-safe, and preserves unavailable SCA intelligence as NOT ASSESSED', () => {
    const secretFinding: Finding = {
      ...makeFinding('scan_00000000-0000-4000-8000-000000000001', 'e'.repeat(64)),
      scanner: 'SECRETS', ruleId: 'DG-SEC-001', evidence: SECRET_FIXTURE,
    };
    const secretGuidance = remediationGuidanceForFinding(secretFinding);
    expect(secretGuidance.status).toBe('LIMITED');
    expect(JSON.stringify(secretGuidance)).not.toContain(SECRET_FIXTURE);
    expect(secretGuidance.actions.join(' ')).toContain('Drobon does not perform or attest');

    const dastFinding: Finding = {
      id: `fnd_${'f'.repeat(24)}`,
      scanId: 'scan_00000000-0000-4000-8000-000000000002',
      scanner: 'DAST', ruleId: 'DG-DAST-001', severity: 'HIGH', title: 'Insecure transport observation',
      description: 'Passive fixture observed an HTTP response.', evidence: 'HTTP response observed',
      remediation: 'Use HTTPS for application traffic.', fingerprint: 'f'.repeat(64),
      projectId: 'prj_00000000-0000-4000-8000-000000000001',
      targetUrl: 'http://fixture.example.test/', endpoint: 'http://fixture.example.test/', method: 'GET',
      responseStatus: 200, responseTimeMs: 1, observedAt: '2026-09-28T10:00:00.000Z', observedHeaders: [],
    };
    const dastGuidance = remediationGuidanceForFinding(dastFinding);
    expect(dastGuidance.status).toBe('LIMITED');
    expect(dastGuidance.verification).toContain('passive DAST scan');

    const sca: ScaResult = {
      summary: {
        assessmentState: 'NOT_ASSESSED', datasetStatus: 'NO_DATA_LOADED', providerId: 'none',
        dependenciesTotal: 0, directDependencies: 0, transitiveDependencies: 0, unclassifiedDependencies: 0,
        advisoriesTotal: 0, manifestsAnalyzed: 0, manifestsPartial: 0, manifestsUnsupported: 0, manifestsInvalid: 0,
        transitiveGraph: 'UNAVAILABLE', truncated: false,
      },
      dependencies: [], manifests: [], advisories: [],
      sbom: {
        bomFormat: 'CycloneDX', specVersion: '1.5', serialNumber: 'urn:uuid:00000000-0000-4000-8000-000000000000',
        version: 1, metadata: { tools: { components: [] } }, components: [], dependencies: [],
      },
    };
    const scaGuidance = scaInventoryGuidance(sca);
    expect(scaGuidance.status).toBe('NOT_ASSESSED');
    expect(scaGuidance.message).toContain('no package is declared safe or vulnerable');
    expect(scaGuidance.verification).toContain('out of band');
  });

  test('transitions are audited, notes are normalized/redacted, report snapshots update, and scans reopen by fingerprint only', async () => {
    const { project } = await fixtureProject();
    const scans = createMemoryScanStore();
    const fingerprint = 'a'.repeat(64);
    const first = await completeScan(scans, project.id, makeFinding('scan_placeholder', fingerprint));
    const originalFinding = first.finding;
    if (originalFinding === undefined) throw new Error('Expected first scanner finding.');

    const initial = await scans.getFindingWorkflow(project.id, fingerprint);
    expect(initial?.state).toBe('OPEN');
    expect(initial?.verificationState).toBe('OBSERVED');
    expect(initial?.historyTotal).toBe(1);
    expect(remediationGuidanceForFinding(originalFinding).status).toBe('RULE_SPECIFIC');

    // A legacy/custom completed record with a nonzero summary but no
    // persisted finding details is not verification evidence either way.
    const incompleteCreated = await scans.createScanWithQuota({ ownerId: OWNER_ID, projectId: project.id, scanType: 'SAST', consume: async () => ({ ok: true }) });
    if (incompleteCreated.outcome !== 'created') throw new Error('Incomplete-evidence scan creation failed.');
    const incompleteRunning = await scans.claimNextQueued();
    if (incompleteRunning === undefined) throw new Error('Incomplete-evidence scan claim failed.');
    expect(await scans.completeScan(incompleteRunning.id, { findingsTotal: 2 })).toBeDefined();
    const unchanged = await scans.getFindingWorkflow(project.id, fingerprint);
    expect(unchanged?.lastVerificationScanId).toBe(first.scan.id);
    expect(unchanged?.verificationState).toBe('OBSERVED');

    expect((await scans.transitionFindingLifecycle(project.id, fingerprint, 'ACKNOWLEDGED', OWNER_ID, '2026-09-28T10:00:00.000Z')).outcome).toBe('updated');
    expect((await scans.transitionFindingLifecycle(project.id, fingerprint, 'OPEN', OWNER_ID, '2026-09-28T10:01:00.000Z')).outcome).toBe('invalid-transition');
    expect((await scans.transitionFindingLifecycle(project.id, fingerprint, 'IN_PROGRESS', OWNER_ID, '2026-09-28T10:02:00.000Z')).outcome).toBe('updated');
    expect((await scans.transitionFindingLifecycle(project.id, fingerprint, 'RESOLVED', OWNER_ID, '2026-09-28T10:03:00.000Z')).outcome).toBe('updated');

    const rejectedHtml = prepareFindingNote('<script>alert(1)</script>');
    expect(rejectedHtml).toEqual({ ok: false, reason: 'HTML_NOT_ALLOWED' });
    const preparedSecret = prepareFindingNote(`Credential noted: ${SECRET_FIXTURE}`);
    expect(preparedSecret.ok).toBe(true);
    if (!preparedSecret.ok) throw new Error('Expected safe secret redaction.');
    expect(preparedSecret.redacted).toBe(true);
    expect(preparedSecret.text).not.toContain(SECRET_FIXTURE);
    expect((await scans.addFindingRemediationNote(project.id, fingerprint, preparedSecret, OWNER_ID, '2026-09-28T10:04:00.000Z')).outcome).toBe('updated');
    const preparedMarkdown = prepareFindingNote('Review complete:\n# injected-section');
    expect(preparedMarkdown.ok).toBe(true);
    if (!preparedMarkdown.ok) throw new Error('Expected normalized plain text.');
    expect((await scans.addFindingRemediationNote(project.id, fingerprint, preparedMarkdown, OWNER_ID, '2026-09-28T10:05:00.000Z')).outcome).toBe('updated');

    const savedWorkflow = await scans.getFindingWorkflow(project.id, fingerprint);
    expect(savedWorkflow?.state).toBe('RESOLVED');
    expect(savedWorkflow?.notes).toHaveLength(2);
    expect(JSON.stringify(savedWorkflow)).not.toContain(SECRET_FIXTURE);
    expect(await scans.findByProjectAndId(project.id, first.scan.id)).toMatchObject({ findings: [originalFinding] });

    const firstReport = buildSecurityReport(project, first.scan, '2026-09-28T10:10:00.000Z', savedWorkflow === undefined ? [] : [savedWorkflow]);
    expect(firstReport.findingWorkflows?.[0]?.state).toBe('RESOLVED');
    expect(await scans.createReport(firstReport)).toMatchObject({ outcome: 'created' });
    expect(JSON.stringify(firstReport)).not.toContain(SECRET_FIXTURE);
    const markdown = renderSecurityReportMarkdown(firstReport);
    expect(markdown).toContain('not proof of technical remediation');
    expect(markdown).toContain('credential-shaped text omitted');
    expect(markdown).not.toContain(SECRET_FIXTURE);
    expect(markdown).not.toContain('\n# injected-section');
    expect(markdown).toContain('\\# injected\\-section');

    const extraNote = prepareFindingNote('Reviewed owner-controlled source context.');
    if (!extraNote.ok) throw new Error('Expected safe note.');
    await scans.addFindingRemediationNote(project.id, fingerprint, extraNote, OWNER_ID, '2026-09-28T10:06:00.000Z');
    const staleReport = buildSecurityReport(project, first.scan, '2026-09-28T10:10:30.000Z', savedWorkflow === undefined ? [] : [savedWorkflow]);
    expect(await scans.createReport(staleReport)).toMatchObject({ outcome: 'workflow-changed' });
    const changedWorkflow = await scans.getFindingWorkflow(project.id, fingerprint);
    if (changedWorkflow === undefined) throw new Error('Expected persisted workflow.');
    const updatedReport = buildSecurityReport(project, first.scan, '2026-09-28T10:11:00.000Z', [changedWorkflow]);
    expect(updatedReport.contentDigest).not.toBe(firstReport.contentDigest);
    expect(await scans.createReport(updatedReport)).toMatchObject({ outcome: 'updated' });

    const second = await completeScan(scans, project.id, makeFinding('scan_placeholder', fingerprint, 'Changed scanner title'));
    expect(second.finding?.fingerprint).toBe(fingerprint);
    const reopened = await scans.getFindingWorkflow(project.id, fingerprint);
    expect(reopened?.state).toBe('REOPENED');
    expect(reopened?.verificationState).toBe('OBSERVED');
    expect(reopened?.lastVerificationScanId).toBe(second.scan.id);
    expect((await scans.getFindingHistory(project.id, fingerprint, 1, 2))?.events[0]?.action).toBe('FINDING_REOBSERVED');
    expect(await scans.findByProjectAndId(project.id, first.scan.id)).toMatchObject({ findings: [originalFinding] });

    const absent = await completeScan(scans, project.id);
    expect(absent.scan.findings).toBeUndefined();
    const notObserved = await scans.getFindingWorkflow(project.id, fingerprint);
    expect(notObserved?.state).toBe('REOPENED');
    expect(notObserved?.verificationState).toBe('NOT_OBSERVED_IN_LATEST_SCAN');
    expect(notObserved?.lastVerificationScanId).toBe(absent.scan.id);
    expect(notObserved?.lastObservedScanId).toBe(second.scan.id);

    // Titles may change while the deterministic scanner fingerprint does
    // not; a distinct fingerprint with the same title is a separate record.
    const unrelated = await completeScan(scans, project.id, makeFinding('scan_placeholder', 'b'.repeat(64), 'Changed scanner title'));
    expect(unrelated.finding?.title).toBe('Changed scanner title');
    expect((await scans.getFindingWorkflow(project.id, 'b'.repeat(64)))?.id).not.toBe(reopened?.id);
  });

  test('note-count cap is enforced without partial audit or note writes', async () => {
    const { project } = await fixtureProject();
    const scans = createMemoryScanStore();
    const fingerprint = '9'.repeat(64);
    const completed = await completeScan(scans, project.id, makeFinding('scan_placeholder', fingerprint));
    const note = prepareFindingNote('bounded owner note');
    if (!note.ok) throw new Error('Expected safe note.');
    for (let index = 0; index < 20; index += 1) {
      expect((await scans.addFindingRemediationNote(project.id, fingerprint, note, OWNER_ID, `2026-09-28T12:${String(index).padStart(2, '0')}:00.000Z`)).outcome).toBe('updated');
    }
    expect((await scans.addFindingRemediationNote(project.id, fingerprint, note, OWNER_ID, '2026-09-28T13:00:00.000Z')).outcome).toBe('notes-limit');
    const workflow = await scans.getFindingWorkflow(project.id, fingerprint);
    expect(workflow?.notes).toHaveLength(20);
    expect(workflow?.historyTotal).toBe(21);
    expect(await scans.findByProjectAndId(project.id, completed.scan.id)).toMatchObject({ findings: [completed.finding] });
  });

  test('workflow, audit history, and report snapshots survive a JSON-store restart', async () => {
    const dir = makeTempStoreDir('finding-workflow-restart');
    try {
      const { project } = await fixtureProject();
      const file = join(dir, 'scans.json');
      let scans = createJsonFileScanStore(file);
      const completed = await completeScan(scans, project.id, makeFinding('scan_placeholder', 'c'.repeat(64)));
      const finding = completed.finding;
      if (finding === undefined) throw new Error('Expected finding.');
      await scans.transitionFindingLifecycle(project.id, finding.fingerprint, 'ACKNOWLEDGED', OWNER_ID, '2026-09-28T11:00:00.000Z');
      const note = prepareFindingNote('Owner reviewed the source in context.');
      if (!note.ok) throw new Error('Expected safe note.');
      await scans.addFindingRemediationNote(project.id, finding.fingerprint, note, OWNER_ID, '2026-09-28T11:01:00.000Z');
      const workflow = await scans.getFindingWorkflow(project.id, finding.fingerprint);
      if (workflow === undefined) throw new Error('Expected workflow.');
      const report = buildSecurityReport(project, completed.scan, '2026-09-28T11:02:00.000Z', [workflow]);
      await scans.createReport(report);

      scans = createJsonFileScanStore(file);
      expect(await scans.getFindingWorkflow(project.id, finding.fingerprint)).toEqual(workflow);
      expect((await scans.getFindingHistory(project.id, finding.fingerprint, 1, 20))?.total).toBe(workflow.historyTotal);
      expect(await scans.findReportByProjectAndScan(project.id, completed.scan.id)).toEqual(report);
      expect(readFileSync(file, 'utf8')).not.toContain(SECRET_FIXTURE);
    } finally {
      cleanupTempStoreDir(dir);
    }
  });

  test('migrates legacy Pump 12 findings deterministically and rejects corrupted workflow history', async () => {
    const dir = makeTempStoreDir('finding-workflow-migration');
    try {
      const { project } = await fixtureProject();
      const file = join(dir, 'scans.json');
      let scans = createJsonFileScanStore(file);
      const completed = await completeScan(scans, project.id, makeFinding('scan_placeholder', 'd'.repeat(64)));
      const finding = completed.finding;
      if (finding === undefined) throw new Error('Expected finding.');
      const oldDocument = JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>;
      delete oldDocument['findingWorkflows'];
      writeFileSync(file, JSON.stringify(oldDocument));

      scans = createJsonFileScanStore(file);
      const migrated = await scans.getFindingWorkflow(project.id, finding.fingerprint);
      expect(migrated?.state).toBe('OPEN');
      expect(migrated?.firstObservedScanId).toBe(completed.scan.id);
      scans = createJsonFileScanStore(file);
      expect(await scans.getFindingWorkflow(project.id, finding.fingerprint)).toEqual(migrated);

      const corrupt = JSON.parse(readFileSync(file, 'utf8')) as { findingWorkflows?: Array<{ history?: Array<Record<string, unknown>> }> };
      expect(corrupt.findingWorkflows).toBeUndefined();
      // A migrated document remains byte-for-byte untouched until the next
      // ordinary store mutation; explicitly write a bad workflow from a
      // generated document to exercise strict startup validation instead.
      const writing = createJsonFileScanStore(file);
      const workflow = await writing.getFindingWorkflow(project.id, finding.fingerprint);
      if (workflow === undefined) throw new Error('Expected migrated workflow.');
      const materialized = JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>;
      // Persist one harmless supported mutation so workflows are materialized.
      await writing.transitionFindingLifecycle(project.id, finding.fingerprint, 'ACKNOWLEDGED', OWNER_ID, '2026-09-28T12:00:00.000Z');
      const durable = JSON.parse(readFileSync(file, 'utf8')) as { findingWorkflows: Array<{ history: Array<Record<string, unknown>> }> };
      durable.findingWorkflows[0]!.history[0]!.newState = 'RESOLVED';
      writeFileSync(file, JSON.stringify(durable));
      expect(() => createJsonFileScanStore(file)).toThrow(/invalid finding workflow/);
      expect(materialized['findingWorkflows']).toBeUndefined();
    } finally {
      cleanupTempStoreDir(dir);
    }
  });
  test('FALSE_POSITIVE is a terminal triage state and reobservation reopens it (Phase 22)', async () => {
    const { project } = await fixtureProject();
    const scans = createMemoryScanStore();
    const fingerprint = 'b'.repeat(64);
    const first = await completeScan(scans, project.id, makeFinding('scan_placeholder', fingerprint));
    if (first.finding === undefined) throw new Error('Expected first scanner finding.');

    expect((await scans.transitionFindingLifecycle(project.id, fingerprint, 'FALSE_POSITIVE', OWNER_ID, '2026-09-28T11:00:00.000Z')).outcome).toBe('updated');
    const marked = await scans.getFindingWorkflow(project.id, fingerprint);
    expect(marked?.state).toBe('FALSE_POSITIVE');
    const markedHistory = (await scans.getFindingHistory(project.id, fingerprint, 1, 50))!;
    expect(markedHistory.events.some((event) => event.action === 'STATE_CHANGED' && event.previousState === 'OPEN' && event.newState === 'FALSE_POSITIVE')).toBe(true);

    // Terminal: no user transition out of FALSE_POSITIVE.
    for (const next of ['OPEN', 'ACKNOWLEDGED', 'IN_PROGRESS', 'RESOLVED', 'FALSE_POSITIVE'] as const) {
      expect((await scans.transitionFindingLifecycle(project.id, fingerprint, next, OWNER_ID, '2026-09-28T11:01:00.000Z')).outcome).toBe('invalid-transition');
    }

    // A FALSE_POSITIVE finding is dispositioned: it is not "unresolved" and does
    // not inflate severity counts, while remaining visible in its lifecycle bucket.
    const summary = await scans.adminSummary(Date.parse('2026-09-28T11:02:00.000Z'));
    expect(summary.unresolvedFindings).toBe(0);
    expect(summary.findingsByLifecycleState.FALSE_POSITIVE).toBe(1);
    expect(summary.findingsBySeverity.HIGH).toBe(0);

    // Reobservation in a later same-scanner scan reopens it automatically.
    const second = await completeScan(scans, project.id, makeFinding('scan_placeholder', fingerprint));
    if (second.finding === undefined) throw new Error('Expected reobserved finding.');
    const reopened = await scans.getFindingWorkflow(project.id, fingerprint);
    expect(reopened?.state).toBe('REOPENED');
    const reopenHistory = (await scans.getFindingHistory(project.id, fingerprint, 1, 50))!;
    expect(reopenHistory.events.some((event) => event.action === 'FINDING_REOBSERVED' && event.previousState === 'FALSE_POSITIVE' && event.newState === 'REOPENED')).toBe(true);

    // Report snapshots carry the reopened state, not the stale FALSE_POSITIVE.
    const report = buildSecurityReport(project, second.scan, '2026-09-28T11:05:00.000Z', reopened === undefined ? [] : [reopened]);
    expect(report.findingWorkflows?.[0]?.state).toBe('REOPENED');
  });

  test('a FALSE_POSITIVE→REOPENED history reloads from the JSON store after a restart (Phase 22 regression)', async () => {
    const dir = makeTempStoreDir('finding-workflow-fp-restart');
    try {
      const { project } = await fixtureProject();
      const file = join(dir, 'scans.json');
      let scans = createJsonFileScanStore(file);
      const first = await completeScan(scans, project.id, makeFinding('scan_placeholder', 'd'.repeat(64)));
      const finding = first.finding;
      if (finding === undefined) throw new Error('Expected finding.');
      expect((await scans.transitionFindingLifecycle(project.id, finding.fingerprint, 'FALSE_POSITIVE', OWNER_ID, '2026-09-28T11:00:00.000Z')).outcome).toBe('updated');
      const second = await completeScan(scans, project.id, makeFinding('scan_placeholder', finding.fingerprint));
      if (second.finding === undefined) throw new Error('Expected reobserved finding.');
      const beforeRestart = await scans.getFindingWorkflow(project.id, finding.fingerprint);
      expect(beforeRestart?.state).toBe('REOPENED');

      // Reload from disk: the persisted FALSE_POSITIVE→REOPENED history must replay cleanly.
      scans = createJsonFileScanStore(file);
      const afterRestart = await scans.getFindingWorkflow(project.id, finding.fingerprint);
      expect(afterRestart).toEqual(beforeRestart);
      expect((await scans.getFindingHistory(project.id, finding.fingerprint, 1, 50))?.events.some((event) => event.action === 'FINDING_REOBSERVED' && event.previousState === 'FALSE_POSITIVE' && event.newState === 'REOPENED')).toBe(true);
    } finally {
      cleanupTempStoreDir(dir);
    }
  });

});
