import { afterEach, describe, expect, test } from 'vitest';
import { inflateSync } from 'node:zlib';
import { createHash } from 'node:crypto';
import type { Finding } from '@drobon/shared';
import { createMemorySourceStore } from '../src/scans/sources.js';
import { createScaEngine } from '../src/scans/sca/engine.js';
import { createMemoryProjectStore } from '../src/projects/store.js';
import { createMemoryScanStore } from '../src/scans/store.js';
import { buildSecurityReport, verifySecurityReportIntegrity } from '../src/reports/build.js';
import { PDF_MAX_BYTES, renderPortfolioPdf, renderSecurityReportPdf } from '../src/reports/pdf.js';
import { selectLatestAttempt } from '../src/reports/portfolio.js';
import type { ScanRecord } from '../src/scans/store.js';
import { readJson, sessionCookieFrom, startTestServer, type TestServer } from './helpers.js';

const servers: TestServer[] = [];
afterEach(async () => { await Promise.all(servers.splice(0).map((server) => server.stop())); });

/** Minimal test-only decoder for this renderer's subset-font TJ streams. */
function pdfText(pdf: Buffer): string {
  const binary = pdf.toString('latin1');
  const streams: string[] = [];
  for (const match of binary.matchAll(/\bstream\r?\n/g)) {
    const start = (match.index ?? 0) + match[0].length;
    const end = binary.indexOf('endstream', start);
    if (end < 0) continue;
    try { streams.push(inflateSync(pdf.subarray(start, end)).toString('utf8')); } catch { /* other streams are not zlib */ }
  }
  const cmap = streams.find((stream) => stream.includes('beginbfrange'));
  if (cmap === undefined) throw new Error('Font mapping missing');
  const chars = new Map<number, string>();
  for (const block of cmap.matchAll(/<([0-9a-f]{4})>\s*<[0-9a-f]{4}>\s*\[([^\]]*)\]/gi)) {
    let id = parseInt(block[1] ?? '', 16);
    for (const entry of (block[2] ?? '').matchAll(/<([0-9a-f\s]*)>/gi)) {
      const hex = (entry[1] ?? '').replace(/\s/g, '');
      let decoded = '';
      for (let index = 0; index < hex.length; index += 4) decoded += String.fromCharCode(parseInt(hex.slice(index, index + 4), 16));
      chars.set(id++, decoded);
    }
  }
  let out = '';
  for (const stream of streams.filter((item) => item.includes(' TJ'))) {
    for (const operation of stream.matchAll(/\[([^\]]+)\]\s*TJ/g)) {
      for (const token of (operation[1] ?? '').matchAll(/<([0-9a-f]+)>/gi)) {
        const hex = token[1] ?? '';
        for (let index = 0; index < hex.length; index += 4) out += chars.get(parseInt(hex.slice(index, index + 4), 16)) ?? '?';
      }
    }
  }
  return out;
}

async function fixtureReport() {
  const project = await createMemoryProjectStore().create({ ownerId: 'usr_pdf_fixture', name: 'বাংলা প্রকল্প', description: '' });
  const scans = createMemoryScanStore();
  await scans.createScanWithQuota({ ownerId: project.ownerId, projectId: project.id, scanType: 'SAST', consume: async () => ({ ok: true }) });
  const running = await scans.claimNextQueued();
  if (running === undefined) throw new Error('fixture scan was not claimed');
  const completed = await scans.completeScan(running.id, { findingsTotal: 0 }, []);
  if (completed === undefined) throw new Error('fixture scan did not complete');
  return { project, report: buildSecurityReport(project, completed, '2026-10-29T00:00:00.000Z') };
}

async function register(server: TestServer, email: string): Promise<string> {
  const response = await fetch(`${server.baseUrl}/api/v1/auth/register`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: 'pdf-test-fixture-passphrase' }),
  });
  expect(response.status).toBe(201);
  return sessionCookieFrom(response);
}

async function project(server: TestServer, cookie: string): Promise<string> {
  const response = await fetch(`${server.baseUrl}/api/v1/projects`, {
    method: 'POST', headers: { 'content-type': 'application/json', cookie }, body: JSON.stringify({ name: 'PDF test project' }),
  });
  expect(response.status).toBe(201);
  return ((await readJson(response)) as { data: { project: { id: string } } }).data.project.id;
}

describe('bounded PDF exports', () => {
  test('selects the latest attempt, not a stale success, and refuses to guess on timestamp ties', () => {
    const old = { id: 'old', scanType: 'SAST', status: 'COMPLETED', createdAt: '2026-01-01T00:00:00.000Z' } as ScanRecord;
    const failed = { ...old, id: 'failed', status: 'FAILED' as const, createdAt: '2026-01-02T00:00:00.000Z' };
    expect(selectLatestAttempt([old, failed], 'SAST')).toEqual({ kind: 'SELECTED', scan: failed });
    const queued = { ...failed, id: 'queued', status: 'QUEUED' as const };
    expect(selectLatestAttempt([old, failed, queued], 'SAST')).toEqual({ kind: 'ORDER_UNCERTAIN', requestedAt: queued.createdAt });
    expect(selectLatestAttempt([old], 'SCA')).toEqual({ kind: 'NONE' });
  });

  test('renders a valid bounded single report with Bengali text and rejects modified report content', async () => {
    const { report } = await fixtureReport();
    const pdf = await renderSecurityReportPdf(report);
    expect(pdf.subarray(0, 5).toString()).toBe('%PDF-');
    expect(pdf.subarray(-32).toString()).toContain('%%EOF');
    expect(pdf.length).toBeGreaterThan(1000);
    expect(pdf.length).toBeLessThanOrEqual(PDF_MAX_BYTES);
    expect(pdfText(pdf)).toContain('Dependency intelligence: NOT_ASSESSED');
    // Regression: a shaped Bengali conjunct can create an empty glyph mapping.
    // An empty < > entry corrupts extraction of the whole font in PDF readers.
    const binary = pdf.toString('latin1');
    const maps: string[] = [];
    for (const match of binary.matchAll(/\bstream\r?\n/g)) {
      const start = (match.index ?? 0) + match[0].length;
      const end = binary.indexOf('endstream', start);
      if (end < 0) continue;
      try {
        const decoded = inflateSync(pdf.subarray(start, end)).toString('utf8');
        if (decoded.includes('beginbfrange')) maps.push(decoded);
      } catch { /* other streams need not be zlib-compressed */ }
    }
    expect(maps).toHaveLength(1);
    expect(maps[0]).not.toContain('<>');
    expect(maps[0]).toContain('<200b>');
    await expect(renderSecurityReportPdf({ ...report, contentDigest: '0'.repeat(64) })).rejects.toThrow(/integrity/i);
  });

  test('shows NOT_ASSESSED and real matched SCA advisories rather than treating zero findings as safe', async () => {
    const project = await createMemoryProjectStore().create({ ownerId: 'usr_pdf_sca', name: 'SCA test', description: '' });
    const sources = createMemorySourceStore();
    await sources.replace({ ownerId: project.ownerId, projectId: project.id, files: [{ path: 'package.json', content: JSON.stringify({ dependencies: { 'fixture-pkg': '1.0.0' } }) }] });
    for (const withAdvisory of [false, true]) {
      const scans = createMemoryScanStore();
      await scans.createScanWithQuota({ ownerId: project.ownerId, projectId: project.id, scanType: 'SCA', consume: async () => ({ ok: true }) });
      const running = await scans.claimNextQueued();
      if (running === undefined) throw new Error('scan missing');
      const provider = withAdvisory ? {
        id: 'fixture',
        assess: async (coordinates: readonly { dependencyId: string }[]) => ({ datasetStatus: 'DATASET_AVAILABLE' as const, providerId: 'fixture', advisories: [{ id: 'ADV-TEST-900', dependencyId: coordinates[0]?.dependencyId ?? '', severity: 'HIGH' as const, summary: 'Synthetic advisory details' }] }),
      } : undefined;
      const engine = createScaEngine({ sources, ...(provider === undefined ? {} : { provider }) });
      const outcome = await engine.execute(running, { signal: AbortSignal.timeout(10_000) });
      if (outcome.kind !== 'completed') throw new Error('SCA fixture failed');
      const completed = await scans.completeScan(running.id, outcome.resultSummary, outcome.findings, outcome.sca);
      if (completed === undefined) throw new Error('SCA completion failed');
      const report = buildSecurityReport(project, completed, '2026-10-29T00:00:00.000Z');
      const rendered = pdfText(await renderSecurityReportPdf(report));
      if (withAdvisory) {
        expect(rendered).toContain('ADV-TEST-900');
        expect(rendered).toContain('Synthetic advisory details');
      } else {
        expect(rendered).toContain('Dependency intelligence: NOT_ASSESSED');
        expect(rendered).toContain('not a safety verdict');
      }
    }
  });

  test('prioritises critical finding details before the PDF cap without changing the report or location/workflow links', async () => {
    const project = await createMemoryProjectStore().create({ ownerId: 'usr_pdf_many', name: 'Many findings', description: '' });
    const scans = createMemoryScanStore();
    await scans.createScanWithQuota({ ownerId: project.ownerId, projectId: project.id, scanType: 'SAST', consume: async () => ({ ok: true }) });
    const running = await scans.claimNextQueued();
    if (running === undefined) throw new Error('scan missing');
    const findings: Finding[] = Array.from({ length: 61 }, (_, index) => {
      const fingerprint = createHash('sha256').update(`fixture-${index}`).digest('hex');
      return { id: `fnd_${fingerprint.slice(0, 24)}`, fingerprint, scanId: running.id, projectId: project.id,
        scanner: 'SAST' as const, ruleId: 'DPK-SAST-900', severity: index === 60 ? 'CRITICAL' as const : 'HIGH' as const, title: `Fixture finding ${index}`,
        description: 'Synthetic test finding.', evidence: 'Redacted.', remediation: 'Review.', file: index === 60 ? 'src/critical.js' : 'src/app.js', line: index + 1, column: 1,
        ...(index === 60 ? { astFlow: { mode: 'PROJECT' as const, category: 'command' as const, attribution: 'CATEGORY_REPORTER' as const,
          source: { file: 'src/input.js', line: 2, column: 1 }, via: [{ file: 'src/relay.js', line: 3, column: 2 }] } } : {}) };
    });
    const completed = await scans.completeScan(running.id, { findingsTotal: findings.length }, findings);
    if (completed === undefined) throw new Error('fixture completion failed');
    const critical = findings[60];
    if (critical === undefined) throw new Error('critical fixture missing');
    expect((await scans.transitionFindingLifecycle(project.id, critical.fingerprint, 'ACKNOWLEDGED', project.ownerId, '2026-10-29T00:00:00.000Z')).outcome).toBe('updated');
    const workflows = await Promise.all(findings.map((finding) => scans.getFindingWorkflow(project.id, finding.fingerprint)));
    if (workflows.some((workflow) => workflow === undefined)) throw new Error('workflow fixture missing');
    const report = buildSecurityReport(project, completed, '2026-10-29T00:00:00.000Z', workflows.filter((item) => item !== undefined));
    const original = JSON.stringify(report);
    const text = pdfText(await renderSecurityReportPdf(report));
    expect(text).toContain('1 finding details omitted from this bounded PDF');
    expect(text).toContain('Fixture finding 60');
    expect(text).not.toContain('Fixture finding 59 (');
    expect(text.indexOf('Fixture finding 60')).toBeLessThan(text.indexOf('Fixture finding 0'));
    expect(text).toContain('src/critical.js:61:1');
    expect(text).toContain('Possible source: src/input.js:2:1');
    expect(text).toContain('Possible flow step: src/relay.js:3:2');
    expect(text).toContain('Workflow: ACKNOWLEDGED');
    expect(JSON.stringify(report)).toBe(original);
    expect(verifySecurityReportIntegrity(report)).toBe(true);
  });

  test('prioritises a later critical SCA advisory before the PDF detail cap', async () => {
    const project = await createMemoryProjectStore().create({ ownerId: 'usr_pdf_advisories', name: 'Many advisories', description: '' });
    const sources = createMemorySourceStore();
    await sources.replace({ ownerId: project.ownerId, projectId: project.id, files: [{ path: 'requirements.txt', content: 'fixture==1.0.0\n' }] });
    const scans = createMemoryScanStore();
    await scans.createScanWithQuota({ ownerId: project.ownerId, projectId: project.id, scanType: 'SCA', consume: async () => ({ ok: true }) });
    const running = await scans.claimNextQueued();
    if (running === undefined) throw new Error('scan missing');
    const provider = { id: 'fixture', assess: async (coordinates: readonly { dependencyId: string }[]) => ({
      datasetStatus: 'DATASET_AVAILABLE' as const, providerId: 'fixture', advisories: [
        ...Array.from({ length: 30 }, (_, index) => ({ id: `SYNTHETIC-LOW-${index}`, severity: 'LOW' as const, summary: 'Low fixture.', dependencyId: coordinates[0]?.dependencyId ?? '' })),
        { id: 'SYNTHETIC-CRITICAL', severity: 'CRITICAL' as const, summary: 'Critical fixture.', dependencyId: coordinates[0]?.dependencyId ?? '' },
      ],
    }) };
    const outcome = await createScaEngine({ sources, provider }).execute(running, { signal: AbortSignal.timeout(10_000) });
    if (outcome.kind !== 'completed') throw new Error('fixture SCA failed');
    const completed = await scans.completeScan(running.id, outcome.resultSummary, outcome.findings, outcome.sca);
    if (completed === undefined) throw new Error('fixture completion failed');
    const report = buildSecurityReport(project, completed, '2026-10-29T00:00:00.000Z');
    const original = JSON.stringify(report);
    const output = pdfText(await renderSecurityReportPdf(report));
    expect(output).toContain('SYNTHETIC-CRITICAL');
    expect(output).toContain('SYNTHETIC-LOW-18');
    expect(output).not.toContain('SYNTHETIC-LOW-19');
    expect(output).toContain('11 advisory details omitted');
    expect(output).toContain('not proof that the same version is installed');
    expect(JSON.stringify(report)).toBe(original);
    expect(verifySecurityReportIntegrity(report)).toBe(true);
  });

  test('portfolio validates all four scanner slots and never accepts a report from a different project', async () => {
    const { project: target, report } = await fixtureReport();
    const input = { project: { id: target.id, name: target.name }, generatedAt: report.generatedAt, entries: [
      { scanner: 'SAST' as const, status: 'COMPLETED' as const, report },
      { scanner: 'SCA' as const, status: 'FAILED' as const, requestedAt: report.generatedAt },
      { scanner: 'SECRETS' as const, status: 'NOT_RUN' as const },
      { scanner: 'DAST' as const, status: 'NOT_RUN' as const },
    ] };
    const pdf = await renderPortfolioPdf(input);
    expect(pdf.subarray(0, 5).toString()).toBe('%PDF-');
    const output = pdfText(pdf);
    expect(output).toContain('SAST: COMPLETED');
    expect(output).toContain('SCA: FAILED');
    expect(output).toContain('SECRETS: NOT_RUN');
    const unsupported = pdfText(await renderPortfolioPdf({ ...input, project: { ...input.project, name: 'Project 世界' } }));
    expect(unsupported).toContain('Project: Project ??');
    expect(unsupported).toContain('Characters not supported by the bundled font are shown as ?');
    await expect(renderPortfolioPdf({ ...input, project: { id: 'prj_other', name: 'Other' } })).rejects.toThrow(/scope/i);
    await expect(renderPortfolioPdf({ ...input, entries: input.entries.slice(0, 3) })).rejects.toThrow(/scope/i);
  });

  test('real HTTP downloads require project ownership and preserve existing report/quota boundaries', async () => {
    const server = await startTestServer();
    servers.push(server);
    const owner = await register(server, 'pdf-owner@example.test');
    const stranger = await register(server, 'pdf-stranger@example.test');
    const id = await project(server, owner);
    const portfolioUrl = `${server.baseUrl}/api/v1/projects/${id}/reports/portfolio/download`;
    expect((await fetch(portfolioUrl)).status).toBe(401);
    expect((await fetch(portfolioUrl, { headers: { cookie: stranger } })).status).toBe(403);
    expect((await fetch(`${portfolioUrl}?extra=1`, { headers: { cookie: owner } })).status).toBe(400);
    const empty = await fetch(portfolioUrl, { headers: { cookie: owner } });
    expect(empty.status).toBe(200);
    expect(empty.headers.get('content-type')).toBe('application/pdf');
    expect(empty.headers.get('cache-control')).toBe('private, no-store');
    expect(empty.headers.get('content-disposition')).toBe(`attachment; filename="drobon-project-${id}.pdf"`);
    expect(Buffer.from(await empty.arrayBuffer()).subarray(0, 5).toString()).toBe('%PDF-');

    const upload = await fetch(`${server.baseUrl}/api/v1/projects/${id}/sources`, {
      method: 'PUT', headers: { 'content-type': 'application/json', cookie: owner },
      body: JSON.stringify({ files: [{ path: 'src/app.js', content: 'const x = 1;' }] }),
    });
    expect(upload.status).toBe(200);
    const created = await fetch(`${server.baseUrl}/api/v1/projects/${id}/scans`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: owner }, body: JSON.stringify({ scanType: 'SAST' }),
    });
    expect(created.status).toBe(201);
    const scanId = ((await readJson(created)) as { data: { scan: { id: string } } }).data.scan.id;
    await server.scanProcessor.drain();
    const reportResponse = await fetch(`${server.baseUrl}/api/v1/projects/${id}/scans/${scanId}/report`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: owner }, body: '{}',
    });
    expect(reportResponse.status).toBe(201);
    const downloadUrl = `${server.baseUrl}/api/v1/projects/${id}/scans/${scanId}/report/download?format=pdf`;
    expect((await fetch(downloadUrl, { headers: { cookie: stranger } })).status).toBe(403);
    const result = await fetch(downloadUrl, { headers: { cookie: owner } });
    expect(result.status).toBe(200);
    expect(result.headers.get('content-type')).toBe('application/pdf');
    expect(result.headers.get('content-disposition')).toMatch(/^attachment; filename="drobon-rpt_[0-9a-f]{24}\.pdf"$/);
    expect(Buffer.from(await result.arrayBuffer()).subarray(0, 5).toString()).toBe('%PDF-');
    const combined = await fetch(portfolioUrl, { headers: { cookie: owner } });
    expect(combined.status).toBe(200);
    expect(Buffer.from(await combined.arrayBuffer()).subarray(0, 5).toString()).toBe('%PDF-');
    const usage = await fetch(`${server.baseUrl}/api/v1/usage`, { headers: { cookie: owner } });
    expect(((await readJson(usage)) as { data: { used: number } }).data.used).toBe(1);
  });
});
