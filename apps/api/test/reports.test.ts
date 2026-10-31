import { describe, expect, test } from 'vitest';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { isSecurityReport, type Finding } from '@drobon/shared';
import { createMemoryProjectStore } from '../src/projects/store.js';
import { buildSecurityReport, canonicalJson, renderSecurityReportMarkdown, verifySecurityReportIntegrity } from '../src/reports/build.js';
import { createJsonFileScanStore, createMemoryScanStore } from '../src/scans/store.js';
import { cleanupTempStoreDir, makeTempStoreDir } from './helpers.js';

async function completedSast() {
  const projects = createMemoryProjectStore();
  const project = await projects.create({ ownerId: 'usr_report_owner', name: 'Assessment <unsafe> &lt;script&gt;', description: '' });
  const scans = createMemoryScanStore();
  const created = await scans.createScanWithQuota({
    ownerId: 'usr_report_owner', projectId: project.id, scanType: 'SAST',
    consume: async () => ({ ok: true }),
  });
  if (created.outcome !== 'created') throw new Error('scan creation failed');
  const running = await scans.claimNextQueued();
  if (running === undefined) throw new Error('scan claim failed');
  const completed = await scans.completeScan(running.id, { findingsTotal: 0 }, []);
  if (completed === undefined) throw new Error('scan completion failed');
  return { project, scan: completed, scans };
}

describe('persisted security assessment reports', () => {
  test('builds deterministic content identity, real integrity digest, and inert human-readable text', async () => {
    const { project, scan } = await completedSast();
    const report = buildSecurityReport(project, scan, '2026-09-28T10:00:00.000Z');
    const sameContentLater = buildSecurityReport(project, scan, '2026-09-28T11:00:00.000Z');
    const sameStateSameTime = buildSecurityReport(project, scan, '2026-09-28T10:00:00.000Z');
    expect(canonicalJson(sameStateSameTime)).toBe(canonicalJson(report));
    expect(isSecurityReport(report)).toBe(true);
    expect(verifySecurityReportIntegrity(report)).toBe(true);
    expect(report.reportId).toBe(sameContentLater.reportId);
    expect(report.contentDigest).toBe(sameContentLater.contentDigest);
    expect(report.integrityDigest).not.toBe(sameContentLater.integrityDigest);
    expect(report.scannerCoverage.find((entry) => entry.scanner === 'SAST')?.status).toBe('RAN');
    expect(report.scannerCoverage.filter((entry) => entry.status === 'RAN')).toHaveLength(1);
    expect(report.dependencyIntelligence).toEqual({ status: 'NOT_ASSESSED', reason: 'Dependency analysis was not run in this scan.' });
    const markdown = renderSecurityReportMarkdown(report);
    expect(markdown).toContain('Dependency vulnerability intelligence: NOT ASSESSED');
    expect(markdown).not.toContain('<unsafe>');
    expect(markdown).not.toContain('<script>');
    expect(markdown).toContain('&lt;unsafe&gt;');
    expect(markdown).toContain('&amp;lt;script&amp;gt;');
    expect(canonicalJson({ z: 1, a: { y: 2, x: 3 } })).toBe('{"a":{"x":3,"y":2},"z":1}');
  });

  test('refuses to generate reports when persisted finding details disagree with the scan summary', async () => {
    const projects = createMemoryProjectStore();
    const project = await projects.create({ ownerId: 'usr_report_owner', name: 'Incomplete details', description: '' });
    const scans = createMemoryScanStore();
    const created = await scans.createScanWithQuota({ ownerId: 'usr_report_owner', projectId: project.id, scanType: 'SAST', consume: async () => ({ ok: true }) });
    if (created.outcome !== 'created') throw new Error('scan creation failed');
    const running = await scans.claimNextQueued();
    if (running === undefined) throw new Error('scan claim failed');
    const incomplete = await scans.completeScan(running.id, { findingsTotal: 1 });
    if (incomplete === undefined) throw new Error('summary-only scan completion failed');
    expect(incomplete.findings).toBeUndefined();
    expect(await scans.getFindingWorkflowsForFindings(project.id, [])).toEqual([]);
    expect(() => buildSecurityReport(project, incomplete, '2026-09-28T10:00:00.000Z')).toThrow(/do not agree/);
  });

  test('atomically stores one report per scan and retrieves the original after restart', async () => {
    const dir = makeTempStoreDir('report-restart');
    try {
      const file = join(dir, 'scans.json');
      const projectStore = createMemoryProjectStore();
      const project = await projectStore.create({ ownerId: 'usr_report_owner', name: 'Persisted project', description: '' });
      let scans = createJsonFileScanStore(file);
      const created = await scans.createScanWithQuota({
        ownerId: 'usr_report_owner', projectId: project.id, scanType: 'SAST',
        consume: async () => ({ ok: true }),
      });
      if (created.outcome !== 'created') throw new Error('scan creation failed');
      const running = await scans.claimNextQueued();
      if (running === undefined) throw new Error('scan claim failed');
      const completed = await scans.completeScan(running.id, { findingsTotal: 0 }, []);
      if (completed === undefined) throw new Error('scan completion failed');
      const generated = buildSecurityReport(project, completed, '2026-09-28T10:00:00.000Z');
      expect(await scans.createReport(generated)).toEqual({ outcome: 'created', report: generated });
      const replay = await scans.createReport(buildSecurityReport(project, completed, '2026-09-28T12:00:00.000Z'));
      expect(replay).toEqual({ outcome: 'existing', report: generated });

      scans = createJsonFileScanStore(file);
      expect(await scans.findReportByProjectAndScan(project.id, completed.id)).toEqual(generated);
      expect(await scans.findReportByProjectAndScan('prj_00000000-0000-4000-8000-000000000099', completed.id)).toBeUndefined();
    } finally {
      cleanupTempStoreDir(dir);
    }
  });

  test('hydrates legacy source finding project context from its scan and rejects a transplanted project id', async () => {
    const dir = makeTempStoreDir('finding-project-context');
    try {
      const file = join(dir, 'scans.json');
      const projectId = 'prj_00000000-0000-4000-8000-000000000055';
      let scans = createJsonFileScanStore(file);
      const created = await scans.createScanWithQuota({ ownerId: 'usr_report_owner', projectId, scanType: 'SAST', consume: async () => ({ ok: true }) });
      if (created.outcome !== 'created') throw new Error('scan creation failed');
      const running = await scans.claimNextQueued();
      if (running === undefined) throw new Error('scan claim failed');
      const finding: Finding = {
        id: `fnd_${'5'.repeat(24)}`, scanId: running.id, scanner: 'SAST', ruleId: 'DG-SAST-001',
        severity: 'HIGH', title: 'Synthetic legacy finding', description: 'Fixture only.',
        evidence: '<redacted>', remediation: 'Use a safe implementation.', file: 'src/app.ts',
        line: 1, column: 1, fingerprint: '6'.repeat(64),
      };
      const completed = await scans.completeScan(running.id, { findingsTotal: 1 }, [finding]);
      if (completed === undefined) throw new Error('scan completion failed');
      const oldDocument = JSON.parse(readFileSync(file, 'utf8')) as { scans: Array<{ findings?: Array<Record<string, unknown>> }> };
      delete oldDocument.scans[0]?.findings?.[0]?.projectId;
      writeFileSync(file, JSON.stringify(oldDocument));

      scans = createJsonFileScanStore(file);
      const hydrated = await scans.findByProjectAndId(projectId, completed.id);
      expect(hydrated?.findings?.[0]?.projectId).toBe(projectId);

      const transplanted = JSON.parse(readFileSync(file, 'utf8')) as { scans: Array<{ findings?: Array<Record<string, unknown>> }> };
      transplanted.scans[0]!.findings![0]!.projectId = 'prj_00000000-0000-4000-8000-000000000056';
      writeFileSync(file, JSON.stringify(transplanted));
      expect(() => createJsonFileScanStore(file)).toThrow(/invalid record/);
    } finally {
      cleanupTempStoreDir(dir);
    }
  });

  test('fail-fast on a report digest mismatch in persisted state', async () => {
    const dir = makeTempStoreDir('report-corrupt');
    try {
      const file = join(dir, 'scans.json');
      const projectStore = createMemoryProjectStore();
      const project = await projectStore.create({ ownerId: 'usr_report_owner', name: 'Corruption test', description: '' });
      const scans = createJsonFileScanStore(file);
      const created = await scans.createScanWithQuota({ ownerId: 'usr_report_owner', projectId: project.id, scanType: 'SAST', consume: async () => ({ ok: true }) });
      if (created.outcome !== 'created') throw new Error('scan creation failed');
      const running = await scans.claimNextQueued();
      if (running === undefined) throw new Error('scan claim failed');
      const completed = await scans.completeScan(running.id, { findingsTotal: 0 }, []);
      if (completed === undefined) throw new Error('scan completion failed');
      const report = buildSecurityReport(project, completed, '2026-09-28T10:00:00.000Z');
      await scans.createReport(report);
      const document = JSON.parse(readFileSync(file, 'utf8')) as { reports: Array<Record<string, unknown>> };
      document.reports[0]!.integrityDigest = '0'.repeat(64);
      writeFileSync(file, JSON.stringify(document));
      expect(() => createJsonFileScanStore(file)).toThrow(/invalid report/);
    } finally {
      cleanupTempStoreDir(dir);
    }
  });
});
