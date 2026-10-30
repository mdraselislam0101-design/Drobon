import { afterEach, describe, expect, test } from 'vitest';
import { createHash } from 'node:crypto';
import { isSacAssessment, isSecurityReport, isSocPosture, isSocPostureResponse } from '@drobon/shared';
import { createMemoryProjectStore } from '../src/projects/store.js';
import { createMemoryScanStore } from '../src/scans/store.js';
import { buildSecurityReport, canonicalJson, renderSecurityReportMarkdown, renderSecurityReportSarif, verifySecurityReportIntegrity } from '../src/reports/build.js';
import { buildSocPosture, type SocInput } from '../src/soc/engine.js';
import { readJson, sessionCookieFrom, startTestServer, type TestServer } from './helpers.js';

const PROJECT = 'prj_00000000-0000-4000-8000-000000000001';
const SCAN = 'scan_00000000-0000-4000-8000-000000000001';
const FINDING = `fnd_${'a'.repeat(24)}`;
const NOW = '2026-10-28T12:00:00.000Z';
const servers: TestServer[] = [];
afterEach(async () => { await Promise.all(servers.splice(0).map((server) => server.stop())); });

function socInput(): SocInput {
  return {
    projectId: PROJECT,
    generatedAt: NOW,
    dataset: 'NOT_CONFIGURED',
    advisory: 'STALE',
    scansOmitted: 0,
    scans: [{
      id: SCAN,
      scanType: 'SAST',
      status: 'COMPLETED',
      createdAt: '2026-10-28T11:00:00.000Z',
      completedAt: '2026-10-28T11:30:00.000Z',
      partial: true,
      truncated: false,
      findings: [{ id: FINDING, ruleId: 'DG-SAST-001', severity: 'HIGH', workflowState: 'RESOLVED' }],
    }],
  };
}

describe('SOC-style saved-scan triage', () => {
  test('reports real scan conditions, missing coverage and source status without claiming an attack', () => {
    const input = socInput();
    const result = buildSocPosture(input);
    expect(isSocPosture(result)).toBe(true);
    expect(isSocPostureResponse({ posture: result })).toBe(true);
    expect(result.scansReviewed).toBe(1);
    expect(result.scannerCoverage.find((entry) => entry.scanner === 'SAST')?.lastCompletedAt).toBe('2026-10-28T11:30:00.000Z');
    expect(result.scannerCoverage.find((entry) => entry.scanner === 'DAST')?.lastCompletedAt).toBeNull();
    expect(result.alerts.map((alert) => alert.ruleId)).toEqual(expect.arrayContaining([
      'HIGH_SEVERITY_FINDING', 'SCAN_PARTIAL', 'MISSING_RECENT_SCANS', 'DATASET_UNAVAILABLE', 'ADVISORY_STALE',
    ]));
    // A user-marked RESOLVED finding is not proof of a fix, and still appears.
    expect(result.alerts.find((alert) => alert.ruleId === 'HIGH_SEVERITY_FINDING')?.detail).toContain('RESOLVED');
    expect(result.limitations.join(' ')).toContain('not confirmed attacks');
    expect(result).toEqual(buildSocPosture(input));
  });

  test('alerts on actual high-severity SCA advisory matches and explicitly flags NOT_ASSESSED', () => {
    const base = socInput();
    const sca = { id: SCAN, scanType: 'SCA' as const, status: 'COMPLETED' as const,
      createdAt: '2026-10-28T11:00:00.000Z', completedAt: '2026-10-28T11:30:00.000Z', partial: false, truncated: false, findings: [],
      sca: { assessmentState: 'ASSESSED' as const, advisories: [
        { id: 'ADV-TEST-1', dependencyId: 'dep-one', name: 'fixture-one', severity: 'HIGH' as const },
        { id: 'ADV-TEST-1', dependencyId: 'dep-two', name: 'fixture-two', severity: 'CRITICAL' as const },
        { id: 'ADV-TEST-2', dependencyId: 'dep-three', name: 'fixture-three', severity: 'LOW' as const },
      ] },
    };
    const assessed = buildSocPosture({ ...base, scans: [sca] });
    expect(isSocPosture(assessed)).toBe(true);
    const alerts = assessed.alerts.filter((alert) => alert.ruleId === 'HIGH_SEVERITY_ADVISORY');
    expect(alerts).toHaveLength(2);
    expect(new Set(alerts.map((alert) => alert.id)).size).toBe(2);
    expect(alerts[0]?.severity).toBe('CRITICAL');
    expect(alerts.map((alert) => alert.detail).join(' ')).toContain('fixture-one');
    expect(JSON.stringify(alerts)).not.toContain('dependencyId');
    const unassessed = buildSocPosture({ ...base, scans: [{ ...sca, sca: { assessmentState: 'NOT_ASSESSED', advisories: [] } }] });
    expect(unassessed.alerts.find((alert) => alert.ruleId === 'SCA_NOT_ASSESSED')?.detail).toContain('does not mean dependencies are safe');
    expect(isSocPosture(unassessed)).toBe(true);
  });

  test('bounds review and alerts and makes omissions visible', () => {
    const base = socInput();
    const template = base.scans[0];
    if (template === undefined) throw new Error('fixture missing');
    const many = Array.from({ length: 125 }, (_, index) => ({
      ...template,
      id: `scan_00000000-0000-4000-8000-${index.toString(16).padStart(12, '0')}`,
    }));
    const result = buildSocPosture({ ...base, scans: many });
    expect(result.scansReviewed).toBe(100);
    expect(result.scansOmitted).toBe(25);
    expect(result.alerts.length).toBeLessThanOrEqual(100);
    expect(result.truncated).toBe(true);
    expect(isSocPosture(result)).toBe(true);
  });

  test('a future-dated scan is not counted as recent coverage', () => {
    const base = socInput();
    const item = base.scans[0];
    if (item === undefined) throw new Error('fixture missing');
    const result = buildSocPosture({ ...base, scans: [{ ...item, completedAt: '2027-01-01T00:00:00.000Z' }] });
    const missing = result.alerts.find((alert) => alert.ruleId === 'MISSING_RECENT_SCANS');
    expect(missing?.detail).toContain('SAST');
  });
});

async function completedReport(partial = false) {
  const projects = createMemoryProjectStore();
  const project = await projects.create({ ownerId: 'usr_owner', name: 'Owner report', description: '' });
  const scans = createMemoryScanStore();
  const created = await scans.createScanWithQuota({ ownerId: 'usr_owner', projectId: project.id, scanType: 'SAST', consume: async () => ({ ok: true }) });
  if (created.outcome !== 'created') throw new Error('scan fixture failed');
  const running = await scans.claimNextQueued();
  if (running === undefined) throw new Error('scan fixture failed');
  const completed = await scans.completeScan(running.id, {
    findingsTotal: 0,
    filesScanned: 1,
    ...(partial ? { partial: true, partialReason: 'Some inputs were not processed.' } : {}),
  }, []);
  if (completed === undefined) throw new Error('scan fixture failed');
  return { project, completed, scans };
}

describe('SAC bounded report coverage ledger', () => {
  test('zero findings never means secure and missing metrics stay unknown', async () => {
    const { project, completed } = await completedReport();
    const report = buildSecurityReport(project, completed, NOW);
    expect(report.sac).toBeDefined();
    expect(isSacAssessment(report.sac)).toBe(true);
    expect(isSecurityReport(report)).toBe(true);
    expect(verifySecurityReportIntegrity(report)).toBe(true);
    expect(report.sac?.verdict).toBe('NO_FINDINGS_RECORDED');
    expect(report.sac?.verdictStatement).toContain('does not establish');
    expect(report.sac?.residualRisk.status).toBe('UNKNOWN');
    expect(report.sac?.compliance.status).toBe('NOT_ASSESSED');
    expect(report.sac?.metrics.filesScanned).toBe(1);
    expect(report.sac?.metrics.filesSkipped).toBeNull();
    expect(report.sac?.ruleProvenance).toBe('NOT_RECORDED_AT_SCAN');
    expect(report.sac?.scannerCoverage.find((entry) => entry.scanner === 'DAST')?.status).toBe('NOT_RUN');
    expect(renderSecurityReportMarkdown(report)).toContain('Coverage and residual risk');
    const sarif = JSON.parse(renderSecurityReportSarif(report)) as { runs: Array<{ properties: Record<string, unknown> }> };
    expect(sarif.runs[0]?.properties['drobon/residualRisk']).toBe('UNKNOWN');
    // Generating the same snapshot later does not change its content identity.
    expect(buildSecurityReport(project, completed, '2026-10-29T12:00:00.000Z').contentDigest).toBe(report.contentDigest);
  });

  test('records real finding counts without treating them as a complete vulnerability inventory', async () => {
    const projects = createMemoryProjectStore();
    const project = await projects.create({ ownerId: 'usr_owner', name: 'Observed finding', description: '' });
    const scans = createMemoryScanStore();
    const created = await scans.createScanWithQuota({ ownerId: 'usr_owner', projectId: project.id, scanType: 'SAST', consume: async () => ({ ok: true }) });
    if (created.outcome !== 'created') throw new Error('scan fixture failed');
    const running = await scans.claimNextQueued();
    if (running === undefined) throw new Error('scan fixture failed');
    const finding = {
      id: FINDING, scanId: running.id, scanner: 'SAST' as const, ruleId: 'DG-SAST-001', severity: 'HIGH' as const,
      title: 'Fixture finding', description: 'Review the observed flow.', remediation: 'Review the source.',
      evidence: 'fixture only', file: 'src/app.js', line: 1, column: 1, fingerprint: 'b'.repeat(64),
    };
    const completed = await scans.completeScan(running.id, { findingsTotal: 1 }, [finding]);
    if (completed === undefined) throw new Error('scan fixture failed');
    const report = buildSecurityReport(project, completed, NOW);
    expect(report.sac?.verdict).toBe('FINDINGS_PRESENT');
    expect(report.sac?.findings.total).toBe(1);
    expect(report.sac?.findings.bySeverity.HIGH).toBe(1);
    expect(report.sac?.verdictStatement).toContain('Other vulnerabilities may remain');
    expect(isSecurityReport(report)).toBe(true);
  });

  test('partial scans are labelled PARTIAL and report contents are integrity protected', async () => {
    const { project, completed, scans } = await completedReport(true);
    const report = buildSecurityReport(project, completed, NOW);
    expect(report.sac?.scannerCoverage.find((entry) => entry.scanner === 'SAST')?.status).toBe('PARTIAL');
    expect(report.sac?.metrics.partialReason).toBe('Some inputs were not processed.');
    expect((await scans.createReport(report)).outcome).toBe('created');
    if (report.sac === undefined) throw new Error('SAC fixture missing');
    const changed = { ...report, sac: { ...report.sac, verdictStatement: 'Altered verdict.' } };
    expect(isSecurityReport(changed)).toBe(true);
    expect(verifySecurityReportIntegrity(changed)).toBe(false);
    expect(isSecurityReport({ ...report, sac: { ...report.sac, findings: { ...report.sac.findings, total: 1 } } })).toBe(false);
    const misleading = report.sac.scannerCoverage.map((entry) => entry.scanner === 'SAST' ? { ...entry, status: 'RAN' as const } : entry);
    expect(isSecurityReport({ ...report, sac: { ...report.sac, scannerCoverage: misleading } })).toBe(false);
  });

  test('preserves the recorded DAST mode in the report rather than calling an active result passive', async () => {
    const projects = createMemoryProjectStore();
    const project = await projects.create({ ownerId: 'usr_owner', name: 'DAST report', description: '' });
    const scans = createMemoryScanStore();
    const target = 'https://app.example.org/';
    const created = await scans.createScanWithQuota({
      ownerId: 'usr_owner', projectId: project.id, scanType: 'DAST', targetUrl: target,
      dastMode: 'ACTIVE_SAFE', dastActiveConsent: true, consume: async () => ({ ok: true }),
    });
    if (created.outcome !== 'created') throw new Error('scan fixture failed');
    const running = await scans.claimNextQueued();
    if (running === undefined) throw new Error('scan fixture failed');
    const completed = await scans.completeScan(running.id, { findingsTotal: 0, requestsMade: 1, redirectsFollowed: 0 }, [], undefined, {
      targetUrl: target, mode: 'ACTIVE_SAFE', requestCount: 1, redirectsFollowed: 0, partial: false,
      observations: [{ endpoint: target, method: 'GET', status: 200, observedAt: NOW, responseTimeMs: 1, bodyBytes: 0, bodyTruncated: false, headers: [] }],
    });
    if (completed === undefined) throw new Error('scan fixture failed');
    const report = buildSecurityReport(project, completed, NOW);
    expect(report.scan.dastMode).toBe('ACTIVE_SAFE');
    expect(renderSecurityReportMarkdown(report)).toContain('DAST observations (ACTIVE_SAFE)');
    expect(verifySecurityReportIntegrity(report)).toBe(true);
    expect((await scans.createReport(report)).outcome).toBe('created');
  });

  test('legacy reports without a ledger remain valid and are not mislabelled', async () => {
    const { project, completed } = await completedReport();
    const report = buildSecurityReport(project, completed, NOW);
    const { sac: _sac, reportId: _id, contentDigest: _content, integrityDigest: _integrity, generatedAt, ...remaining } = report;
    const contentDigest = createHash('sha256').update(canonicalJson(remaining), 'utf8').digest('hex');
    const unsigned = { reportId: `rpt_${contentDigest.slice(0, 24)}`, generatedAt, ...remaining, contentDigest };
    const legacy = { ...unsigned, integrityDigest: createHash('sha256').update(canonicalJson(unsigned), 'utf8').digest('hex') };
    expect(verifySecurityReportIntegrity(legacy)).toBe(true);
    expect(renderSecurityReportMarkdown(legacy)).toContain('no saved coverage ledger');
  });
});

describe('SOC route ownership and real scan integration', () => {
  test('anonymous and foreign access are refused; an owner sees saved scan data only', async () => {
    const server = await startTestServer();
    servers.push(server);
    const register = async (email: string): Promise<string> => {
      const response = await fetch(`${server.baseUrl}/api/v1/auth/register`, {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email, password: 'soc-route-fake-test-password' }), // fake test fixture
      });
      expect(response.status).toBe(201);
      const session = sessionCookieFrom(response);
      const me = await fetch(`${server.baseUrl}/api/v1/me`, { headers: { cookie: session } });
      const device = me.headers.getSetCookie().find((value) => value.startsWith('drobon_device='));
      return device === undefined ? session : `${session}; ${device.split(';')[0]}`;
    };
    const owner = await register('soc-owner@example.test');
    const other = await register('soc-other@example.test');
    const projectResponse = await fetch(`${server.baseUrl}/api/v1/projects`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: owner },
      body: JSON.stringify({ name: 'Operations test project' }),
    });
    const project = (await readJson(projectResponse)) as { data: { project: { id: string } } };
    const projectId = project.data.project.id;
    const path = `${server.baseUrl}/api/v1/projects/${projectId}/soc`;
    expect((await fetch(path)).status).toBe(401);
    expect((await fetch(path, { headers: { cookie: other } })).status).toBe(403);
    expect((await fetch(`${path}?extra=1`, { headers: { cookie: owner } })).status).toBe(422);
    const emptyResponse = await fetch(path, { headers: { cookie: owner } });
    expect(emptyResponse.status).toBe(200);
    const empty = (await readJson(emptyResponse)) as { data: unknown };
    expect(isSocPostureResponse(empty.data)).toBe(true);

    const source = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/sources`, {
      method: 'PUT', headers: { 'content-type': 'application/json', cookie: owner },
      body: JSON.stringify({ files: [{ path: 'src/app.js', content: 'exec("ls " + req.body.cmd);\n' }] }),
    });
    expect(source.status).toBe(200);
    const requested = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: owner }, body: JSON.stringify({ scanType: 'SAST' }),
    });
    expect(requested.status).toBe(201);
    await server.scanProcessor.drain();
    const result = (await readJson(await fetch(path, { headers: { cookie: owner } }))) as { data: { posture: { scansReviewed: number; alerts: Array<{ ruleId: string }> } } };
    expect(result.data.posture.scansReviewed).toBe(1);
    expect(result.data.posture.alerts.some((alert) => alert.ruleId === 'HIGH_SEVERITY_FINDING')).toBe(true);
    const sca = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: owner }, body: JSON.stringify({ scanType: 'SCA' }),
    });
    expect(sca.status).toBe(201);
    await server.scanProcessor.drain();
    const afterSca = (await readJson(await fetch(path, { headers: { cookie: owner } }))) as { data: { posture: { alerts: Array<{ ruleId: string }> } } };
    expect(afterSca.data.posture.alerts.some((alert) => alert.ruleId === 'SCA_NOT_ASSESSED')).toBe(true);
  });
});
