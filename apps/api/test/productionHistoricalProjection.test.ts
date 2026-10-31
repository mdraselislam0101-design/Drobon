import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, test } from 'vitest';
import { FINDING_TEXT_MAX_LENGTH, FINDING_TITLE_MAX_LENGTH, isFinding, type Finding, type SecurityReport } from '@drobon/shared';
import { createMemoryProjectStore } from '../src/projects/store.js';
import { buildSecurityReport, canonicalJson, verifySecurityReportIntegrity } from '../src/reports/build.js';
import { createJsonFileScanStore } from '../src/scans/store.js';
import { safeFindingEvidence } from '../src/scans/findingIdentity.js';
import { readJson, sessionCookieFrom, startTestServer, type TestServer } from './helpers.js';

const syntheticKey = ['AK', 'IA', 'Q7W8E9R0T1Y2U3I4'].join('');
const syntheticPassword = 'DISPOSABLE-HISTORICAL-FIXTURE-7321';
const stamp = '2026-10-31T00:00:00.000Z';
const digest = (value: string) => createHash('sha256').update(value, 'utf8').digest('hex');

/** Forge a valid historical snapshot in an isolated synthetic fixture file.
 * This does not modify a real deployment store and verifies the old digest. */
function signedLegacyReport(report: SecurityReport, finding: Finding): SecurityReport {
  const { reportId: _id, generatedAt, contentDigest: _content, integrityDigest: _integrity, ...material } = report;
  void _id; void _content; void _integrity;
  const changed = { ...material, findings: [finding] };
  const contentDigest = digest(canonicalJson(changed));
  const unsigned = { reportId: `rpt_${contentDigest.slice(0, 24)}`, generatedAt, ...changed, contentDigest };
  const legacy = { ...unsigned, integrityDigest: digest(canonicalJson(unsigned)) };
  expect(verifySecurityReportIntegrity(legacy)).toBe(true);
  return legacy;
}

describe('historical finding text projection', () => {
  test('recognized metadata replacements stay bounded, contract-valid, and idempotent for SAST, SCA and DAST', () => {
    const common = { id: `fnd_${'a'.repeat(24)}`, scanId: 'scan_00000000-0000-4000-8000-000000000001',
      projectId: 'prj_00000000-0000-4000-8000-000000000001', severity: 'HIGH' as const,
      title: `${'x'.repeat(FINDING_TITLE_MAX_LENGTH - syntheticKey.length - 1)} ${syntheticKey}`,
      description: `password="${syntheticPassword}"${'x'.repeat(FINDING_TEXT_MAX_LENGTH - syntheticPassword.length - 11)}`, // synthetic test value
      remediation: 'Review manually.', evidence: `password="${syntheticPassword}"`, fingerprint: 'a'.repeat(64) }; // synthetic test value
    const findings: Finding[] = [
      { ...common, scanner: 'SAST', ruleId: 'DG-SAST-001', file: 'src/demo.js', line: 1, column: 1 },
      { ...common, scanner: 'SCA', ruleId: 'DPK-SCA-0001', file: 'package.json', line: 1, column: 1 },
      { ...common, scanner: 'DAST', ruleId: 'DPK-DAST-002', targetUrl: 'https://fixture.example.org/',
        endpoint: 'https://fixture.example.org/', method: 'GET', responseStatus: 200, responseTimeMs: 1, observedAt: stamp, observedHeaders: [] },
    ];
    for (const finding of findings) {
      expect(isFinding(finding)).toBe(true);
      const projected = safeFindingEvidence(finding);
      expect(isFinding(projected)).toBe(true);
      expect(safeFindingEvidence(projected)).toEqual(projected);
      expect(projected.remediation).toBe(finding.remediation);
      for (const marker of [syntheticKey, syntheticPassword]) expect(JSON.stringify(projected).includes(marker)).toBe(false);
    }
  });

  test('redacts recognized secrets in synthetic legacy metadata on scan, report, exports and assistant without rewriting history', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'drobon-legacy-projection-'));
    const path = join(dir, 'scans.json');
    const projects = createMemoryProjectStore();
    let first: TestServer | undefined;
    let second: TestServer | undefined;
    try {
      const scans = createJsonFileScanStore(path);
      first = await startTestServer({ scanStore: scans, projectStore: projects });
      const password = 'fixture account password'; // synthetic test account
      const register = await fetch(`${first.baseUrl}/api/v1/auth/register`, { method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email: 'historical-projection@example.test', password }) });
      expect(register.status).toBe(201);
      const owner = (await readJson(register) as { data: { user: { id: string } } }).data.user.id;
      const project = await projects.create({ ownerId: owner, name: 'Synthetic history', description: '' });
      const created = await scans.createScanWithQuota({ ownerId: owner, projectId: project.id, scanType: 'SAST', consume: async () => ({ ok: true }) });
      expect(created.outcome).toBe('created');
      const running = await scans.claimNextQueued();
      if (running === undefined) throw new Error('missing scan');
      const safe: Finding = { id: `fnd_${'a'.repeat(24)}`, scanId: running.id, scanner: 'SAST', projectId: project.id,
        ruleId: 'DG-SAST-001', severity: 'HIGH', title: 'Synthetic title', description: 'Synthetic description.',
        remediation: 'Review this synthetic finding.', evidence: 'synthetic evidence', file: 'src/demo.js', line: 1, column: 1, fingerprint: 'a'.repeat(64) };
      const completed = await scans.completeScan(running.id, { findingsTotal: 1 }, [safe]);
      if (completed === undefined) throw new Error('missing completed scan');
      const report = buildSecurityReport(project, completed, stamp);
      expect((await scans.createReport(report)).outcome).toBe('created');
      await first.stop();
      const old: Finding = { ...safe, title: `Synthetic ${syntheticKey}`, description: `password="${syntheticPassword}"`, // synthetic test value
        remediation: `Rotate ${syntheticKey} and investigate.`, evidence: `const oldValue = "${syntheticPassword}";` };
      const legacyReport = signedLegacyReport(report, old);
      const document = JSON.parse(readFileSync(path, 'utf8')) as { scans: Array<{ findings: Finding[] }>; reports: SecurityReport[] };
      document.scans[0]!.findings = [old];
      document.reports = [legacyReport];
      writeFileSync(path, JSON.stringify(document), { mode: 0o600 });
      const before = digest(readFileSync(path, 'utf8'));
      const reopened = createJsonFileScanStore(path);
      second = await startTestServer({ users: first.users, scanStore: reopened, projectStore: projects });
      const login = await fetch(`${second.baseUrl}/api/v1/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email: 'historical-projection@example.test', password }) });
      expect(login.status).toBe(200);
      const cookie = sessionCookieFrom(login);
      const url = `${second.baseUrl}/api/v1/projects/${project.id}/scans/${running.id}`;
      const scanResponse = await fetch(url, { headers: { cookie } });
      expect(scanResponse.status).toBe(200);
      const scanText = await scanResponse.text();
      for (const marker of [syntheticKey, syntheticPassword]) expect(scanText.includes(marker)).toBe(false);
      const reportResponse = await fetch(`${url}/report`, { headers: { cookie } });
      expect(reportResponse.status).toBe(200);
      const visible = (await readJson(reportResponse) as { data: { report: SecurityReport } }).data.report;
      expect(verifySecurityReportIntegrity(visible)).toBe(true);
      expect(visible.reportId).not.toBe(legacyReport.reportId);
      for (const marker of [syntheticKey, syntheticPassword]) expect(JSON.stringify(visible).includes(marker)).toBe(false);
      for (const format of ['json', 'markdown', 'sarif']) {
        const response = await fetch(`${url}/report/download?format=${format}`, { headers: { cookie } });
        expect(response.status).toBe(200);
        const text = await response.text();
        for (const marker of [syntheticKey, syntheticPassword]) expect(text.includes(marker)).toBe(false);
      }
      const assistant = await fetch(`${second.baseUrl}/api/v1/projects/${project.id}/assistant/ask`, { method: 'POST',
        headers: { 'content-type': 'application/json', cookie }, body: JSON.stringify({ question: 'Explain this finding', scanId: running.id, findingId: safe.id }) });
      expect(assistant.status).toBe(200);
      const answer = await assistant.text();
      for (const marker of [syntheticKey, syntheticPassword]) expect(answer.includes(marker)).toBe(false);
      expect(digest(readFileSync(path, 'utf8'))).toBe(before);
      for (const marker of [syntheticKey, syntheticPassword]) expect(second.logs.join('\n').includes(marker)).toBe(false);
    } finally {
      await second?.stop();
      // This removes only the disposable synthetic test directory.
      rmSync(dir, { recursive: true, force: true });
    }
  }, 30_000);
});
