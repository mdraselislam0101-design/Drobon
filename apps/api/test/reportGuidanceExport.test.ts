import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, test, vi } from 'vitest';
import type { SecurityReport } from '@drobon/shared';
import { createDatasetService } from '../src/external/service.js';
import { REPORT_GUIDANCE_NOTICE, renderSecurityReportMarkdown, renderSecurityReportSarif, verifySecurityReportIntegrity, type ReportGuidanceEntry } from '../src/reports/build.js';
import { renderSecurityReportPdf } from '../src/reports/pdf.js';
import { pdfText } from './pdfTextFixture.js';
import { cleanupTempStoreDir, makeTempStoreDir, readJson, sessionCookieFrom, startTestServer, type TestServer } from './helpers.js';

const servers: TestServer[] = [];
afterEach(async () => { await Promise.all(servers.splice(0).map((server) => server.stop())); });

async function register(server: TestServer, email: string): Promise<string> {
  const response = await fetch(`${server.baseUrl}/api/v1/auth/register`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: 'synthetic-guidance-fixture-passphrase' }), // test-only synthetic fixture
  });
  expect(response.status).toBe(201);
  return sessionCookieFrom(response);
}

describe('opt-in report guidance exports', () => {
  test('resolves per finding across all formats without changing the saved report or fixture Dataset', async () => {
    const dir = makeTempStoreDir('guidance-export');
    try {
      const secret = 'q7syntheticSecret9'; // test-only synthetic fixture
      const records = [{
        ruleId: 'DG-SAST-001',
        whyItMatters: `Command fixture: token="${secret}"`,
        actions: ['Use a shell-free argument list. <script>fixture</script>'],
        verification: 'Rerun the authorized test.',
        standardId: 'CWE-78',
      }];
      const beforeDataset = JSON.stringify(records);
      const remediation = vi.fn(async () => records);
      const datasetService = { ...createDatasetService({ providerId: 'none' }), remediation };
      const server = await startTestServer({ scanStoreDir: dir, datasetService });
      servers.push(server);
      const owner = await register(server, 'guidance-owner@example.test');
      const other = await register(server, 'guidance-other@example.test');
      const headers = { cookie: owner };
      const create = await fetch(`${server.baseUrl}/api/v1/projects`, {
        method: 'POST', headers: { ...headers, 'content-type': 'application/json' }, body: JSON.stringify({ name: 'Guidance fixture' }),
      });
      expect(create.status).toBe(201);
      const projectId = ((await readJson(create)) as { data: { project: { id: string } } }).data.project.id;
      const projectUrl = `${server.baseUrl}/api/v1/projects/${projectId}`;
      const upload = await fetch(`${projectUrl}/sources`, {
        method: 'PUT', headers: { ...headers, 'content-type': 'application/json' },
        body: JSON.stringify({ files: [{ path: 'src/fixture.js', content: 'exec("run " + user);\ndb.query("select " + user);' }] }),
      });
      expect(upload.status).toBe(200);
      const created = await fetch(`${projectUrl}/scans`, {
        method: 'POST', headers: { ...headers, 'content-type': 'application/json' }, body: JSON.stringify({ scanType: 'SAST' }),
      });
      expect(created.status).toBe(201);
      const scanId = ((await readJson(created)) as { data: { scan: { id: string } } }).data.scan.id;
      await server.scanProcessor.drain();
      const reportUrl = `${projectUrl}/scans/${scanId}/report`;
      const generated = await fetch(reportUrl, { method: 'POST', headers: { ...headers, 'content-type': 'application/json' }, body: '{}' });
      expect(generated.status).toBe(201);
      const stored = ((await readJson(generated)) as { data: { report: SecurityReport } }).data.report;
      expect(stored.findings.some((finding) => finding.ruleId === 'DG-SAST-001')).toBe(true);
      expect(stored.findings.some((finding) => finding.ruleId === 'DG-SAST-003')).toBe(true);
      expect(verifySecurityReportIntegrity(stored)).toBe(true);
      const storedBytes = readFileSync(join(dir, 'scans.json'), 'utf8');
      const downloadUrl = `${reportUrl}/download`;
      const normal = await fetch(`${downloadUrl}?format=json`, { headers });
      expect(normal.status).toBe(200);
      expect(await normal.json()).toEqual(stored);
      expect(remediation).not.toHaveBeenCalled();

      const bundled = await fetch(`${downloadUrl}?format=json&guidance=1`, { headers });
      expect(bundled.status).toBe(200);
      expect(bundled.headers.get('content-disposition')).toContain('-guidance.json');
      expect(bundled.headers.get('cache-control')).toBe('private, no-store');
      const bundle = await bundled.json() as { bundleVersion: string; report: SecurityReport; guidance: ReportGuidanceEntry[]; notice: string };
      expect(bundle.bundleVersion).toBe('1.0');
      expect(bundle.report).toEqual(stored);
      expect(verifySecurityReportIntegrity(bundle.report)).toBe(true);
      expect(bundle.notice).toBe(REPORT_GUIDANCE_NOTICE);
      const byFinding = new Map(bundle.guidance.map((entry) => [entry.findingId, entry.guidance]));
      for (const finding of stored.findings) {
        const advice = byFinding.get(finding.id);
        expect(advice?.ruleId).toBe(finding.ruleId);
        expect(advice?.status).toBe(finding.ruleId === 'DG-SAST-001' ? 'RULE_SPECIFIC' : 'UNAVAILABLE');
        expect(finding.remediation.length).toBeGreaterThan(0);
      }
      expect(JSON.stringify(bundle.guidance)).not.toContain(secret);
      expect(JSON.stringify(bundle.guidance)).toContain('[credential omitted]');
      expect(bundle.guidance.find((entry) => entry.guidance.ruleId === 'DG-SAST-001')?.guidance.standardId).toBe('CWE-78');

      const markdownResponse = await fetch(`${downloadUrl}?format=markdown&guidance=1`, { headers });
      expect(markdownResponse.status).toBe(200);
      const markdown = await markdownResponse.text();
      expect(markdown).toContain('Dataset guidance (RULE_SPECIFIC)');
      expect(markdown).toContain('Dataset guidance (UNAVAILABLE)');
      expect(markdown).toContain('&lt;script&gt;fixture&lt;/script&gt;');
      expect(markdown).not.toContain(secret);
      expect(markdown).toContain('not covered by the saved report digest');

      const sarifResponse = await fetch(`${downloadUrl}?format=sarif&guidance=1`, { headers });
      expect(sarifResponse.status).toBe(200);
      const sarif = await sarifResponse.json() as { runs: Array<{ properties: Record<string, unknown>; results: Array<{ ruleId: string; properties: Record<string, unknown> }> }> };
      expect(sarif.runs[0]?.properties['drobon/guidanceNotice']).toBe(REPORT_GUIDANCE_NOTICE);
      for (const result of sarif.runs[0]?.results ?? []) {
        const guidance = result.properties['drobon/remediationGuidance'] as ReportGuidanceEntry['guidance'];
        expect(guidance.ruleId).toBe(result.ruleId);
        expect(guidance.status).toBe(result.ruleId === 'DG-SAST-001' ? 'RULE_SPECIFIC' : 'UNAVAILABLE');
      }
      expect(JSON.stringify(sarif)).not.toContain(secret);

      const pdfResponse = await fetch(`${downloadUrl}?format=pdf&guidance=1`, { headers });
      expect(pdfResponse.status).toBe(200);
      const pdf = pdfText(Buffer.from(await pdfResponse.arrayBuffer()));
      expect(pdf).toContain('Dataset guidance: RULE_SPECIFIC');
      expect(pdf).toContain('Dataset guidance: UNAVAILABLE');
      expect(pdf).toContain('not covered by the saved report digest');
      expect(pdf).not.toContain(secret);
      const portfolioUrl = `${projectUrl}/reports/portfolio/download`;
      const portfolioResponse = await fetch(`${portfolioUrl}?guidance=1`, { headers });
      expect(portfolioResponse.status).toBe(200);
      expect(portfolioResponse.headers.get('content-disposition')).toContain('-guidance.pdf');
      const portfolio = pdfText(Buffer.from(await portfolioResponse.arrayBuffer()));
      expect(portfolio).toContain('Dataset guidance: RULE_SPECIFIC');
      expect(portfolio).toContain('not covered by the saved report digest');
      expect(portfolio).not.toContain(secret);

      expect((await fetch(`${downloadUrl}?format=json&guidance=1`, { headers: { cookie: other } })).status).toBe(403);
      expect((await fetch(`${downloadUrl}?format=json&guidance=1`)).status).toBe(401);
      expect((await fetch(`${portfolioUrl}?guidance=1`, { headers: { cookie: other } })).status).toBe(403);
      expect((await fetch(`${downloadUrl}?format=json&guidance=1&guidance=1`, { headers })).status).toBe(400);
      expect((await fetch(`${downloadUrl}?format=json&guidance=0`, { headers })).status).toBe(422);
      expect((await fetch(`${downloadUrl}?format=json&unknown=1`, { headers })).status).toBe(400);
      expect((await fetch(`${portfolioUrl}?guidance=1&guidance=1`, { headers })).status).toBe(400);
      expect((await fetch(`${portfolioUrl}?guidance=2`, { headers })).status).toBe(422);
      expect(readFileSync(join(dir, 'scans.json'), 'utf8')).toBe(storedBytes);
      expect(JSON.stringify(records)).toBe(beforeDataset);
      expect(remediation).toHaveBeenCalledTimes(1);

      const wrongRule = bundle.guidance.map((entry, index) => index === 0 ? { ...entry, guidance: { ...entry.guidance, ruleId: 'DG-SAST-999' } } : entry);
      expect(() => renderSecurityReportMarkdown(stored, wrongRule)).toThrow(/match/i);
      expect(() => renderSecurityReportSarif(stored, bundle.guidance.slice(1))).toThrow(/incomplete/i);
      await expect(renderSecurityReportPdf(stored, wrongRule)).rejects.toThrow(/match/i);
    } finally {
      await Promise.all(servers.splice(0).map((server) => server.stop()));
      cleanupTempStoreDir(dir);
    }
  });
});
