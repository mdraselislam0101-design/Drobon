import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, test } from 'vitest';
import { isDastResult, isFinding, isScan, isScanDetailResponse, isScanResultSummary, isSecurityReport } from '@drobon/shared';
import { createMemoryProjectStore } from '../src/projects/store.js';
import { convertDastPackToRule, convertSecretsPackToRule } from '../src/external/packProvider.js';
import { buildSecurityReport, renderSecurityReportMarkdown, renderSecurityReportSarif, verifySecurityReportIntegrity } from '../src/reports/build.js';
import { createActiveDastEngine } from '../src/scans/dast/activeEngine.js';
import { createDastEngine } from '../src/scans/dast/engine.js';
import type { DastProbeResponse, DastTransport } from '../src/scans/dast/http.js';
import { createDastTargetPolicy } from '../src/scans/dast/target.js';
import { createScaEngine } from '../src/scans/sca/engine.js';
import { createSecretsEngine } from '../src/scans/secrets/engine.js';
import type { SourceSnapshotRecord } from '../src/scans/sources.js';
import { createJsonFileScanStore, toScanDetailResponse, toScanResponse, type ScanRecord } from '../src/scans/store.js';
import { analyzeScaManifestAst } from '../src/scans/supplementAst.js';
import { StructuredAstSession } from '../src/scans/sast/structuredAstSession.js';
import { TEST_SECRETS_RULES } from './fixtures/testData.js';
import { readJson, sessionCookieFrom, startTestServer } from './helpers.js';

const OWNER = 'usr_00000000-0000-4000-8000-000000000001';
const PROJECT = 'prj_00000000-0000-4000-8000-000000000002';
const SCAN = 'scan_00000000-0000-4000-8000-000000000003';
const TARGET = 'https://app.example.org/';
const AT = '2026-10-28T10:00:00.000Z';
const signal = new AbortController().signal;
const TEST_SECRET = 'AKIAP10QZ9WM7XK2BR4J'; // synthetic fixture, never a real credential
const MARKER = join(tmpdir(), 'drobon-ast-supplement-never-execute-marker');
const reporter = {
  id: 'DG-DAST-900', category: 'content-injection', severity: 'HIGH' as const,
  title: 'Fixture category reporter', description: 'This exact check is not matched.', remediation: 'Review.',
  check: { type: 'response-body-matches', valuePattern: 'NEVER-MATCH-FIXTURE' },
};
const record = (scanType: ScanRecord['scanType']): ScanRecord => ({
  id: SCAN, ownerId: OWNER, projectId: PROJECT, scanType, status: 'RUNNING',
  createdAt: AT, updatedAt: AT, startedAt: AT,
  ...(scanType === 'DAST' ? { dastTargetUrl: TARGET } : {}),
});
function source(files: Array<{ path: string; content: string }>): SourceSnapshotRecord {
  return { ownerId: OWNER, projectId: PROJECT, files: files.map((file) => ({ ...file, bytes: Buffer.byteLength(file.content) })), createdAt: AT, updatedAt: AT };
}
function transport(body: string, contentType = 'text/html', bodyTruncated = false): { service: DastTransport; calls: string[] } {
  const calls: string[] = [];
  return { calls, service: { probe: async (target) => {
    calls.push(target.url);
    return { status: 200, body, bodyTruncated, elapsedMs: 5, headers: { 'content-type': contentType } } satisfies DastProbeResponse;
  } } };
}
const policy = () => createDastTargetPolicy({ resolve: async () => ['93.184.216.34'] });
const body = `<script>const input = location.hash; document.write(input);</script><script src="https://other.example/script.js"></script>`;
const dirs: string[] = [];
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); rmSync(MARKER, { force: true }); });

describe('bounded DAST response AST', () => {
  test('valid external DAST metadata is normalized to the persisted finding contract', async () => {
    const rule = convertDastPackToRule({ schemaVersion: 'drobon.pack.dast/v1', id: 'DPK-DAST-900', severity: 'HIGH',
      title: `Title ${'x'.repeat(200)}`, description: `Description ${'x'.repeat(500)}`, remediation: `Fix ${'x'.repeat(700)}`,
      category: 'content-injection', cwe: 'invalid', check: { type: 'response-body-matches', valuePattern: 'fixture-body' } });
    expect(rule).toBeDefined();
    if (rule === undefined) throw new Error('conversion failed');
    expect(rule.title).toHaveLength(80);
    expect(rule.description).toHaveLength(400);
    expect(rule.remediation).toHaveLength(400);
    expect(rule.remediation.endsWith('…')).toBe(true);
    expect(rule.cwe).toBeUndefined();
    const fixture = transport('fixture-body');
    const outcome = await createDastEngine({ targetPolicy: policy(), transport: fixture.service, packRules: [rule], now: () => Date.parse(AT) }).execute(record('DAST'), { signal });
    if (outcome.kind !== 'completed') throw new Error('scan failed');
    expect(outcome.findings).toHaveLength(1);
    expect(outcome.findings?.every(isFinding)).toBe(true);
  });

  test('passive inspection adds category-attributed metadata without another request or body disclosure', async () => {
    const fixture = transport(body);
    const outcome = await createDastEngine({ targetPolicy: policy(), transport: fixture.service, packRules: [reporter], now: () => Date.parse(AT) }).execute(record('DAST'), { signal });
    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed') throw new Error('scan failed');
    expect(fixture.calls).toEqual([TARGET]);
    expect(outcome.resultSummary.astSupplement).toMatchObject({ mode: 'DAST_RESPONSE_SCRIPTS', status: 'PARTIAL', parsed: 1, incomplete: 0, skipped: 1, signals: 1, reporterRuleId: reporter.id });
    const candidate = outcome.findings?.find((item) => item.astContext?.kind === 'DAST_RESPONSE_FLOW');
    expect(candidate).toMatchObject({ scanner: 'DAST', ruleId: reporter.id, severity: 'HIGH', astContext: { category: 'html', attribution: 'CATEGORY_REPORTER', script: 1 } });
    expect(candidate?.description).toContain('check may not match');
    expect(isFinding(candidate)).toBe(true);
    expect(isScanResultSummary(outcome.resultSummary)).toBe(true);
    expect(JSON.stringify(outcome)).not.toContain(body);
    expect(JSON.stringify(outcome)).not.toContain('document.write');
    expect(JSON.stringify(outcome)).not.toContain('other.example');
  });

  test('direct JavaScript is parsed; missing reporter, malformed scripts and truncated bodies remain partial', async () => {
    const cases = [
      { data: 'const x=location.hash; document.write(x);', type: 'application/javascript', rules: [], truncated: false, expected: { parsed: 1, incomplete: 0 } },
      { data: '<script>const = ;</script>', type: 'text/html', rules: [reporter], truncated: false, expected: { parsed: 0, incomplete: 1 } },
      { data: '<script>const x=location.hash; document.write(x);</script>', type: 'text/html', rules: [reporter], truncated: true, expected: { parsed: 1, skipped: 1 } },
    ];
    for (const fixture of cases) {
      const source = transport(fixture.data, fixture.type, fixture.truncated);
      const outcome = await createDastEngine({ targetPolicy: policy(), transport: source.service, packRules: fixture.rules, now: () => Date.parse(AT) }).execute(record('DAST'), { signal });
      expect(outcome.kind).toBe('completed');
      if (outcome.kind !== 'completed') throw new Error('scan failed');
      expect(outcome.resultSummary.astSupplement).toMatchObject({ mode: 'DAST_RESPONSE_SCRIPTS', status: 'PARTIAL', ...fixture.expected });
      expect(source.calls).toHaveLength(1);
      if (fixture.rules.length === 0) expect(outcome.findings ?? []).toHaveLength(0);
    }
  });

  test('split UTF-8 at the body cap stays bounded and partial in passive and active modes', async () => {
    const body = `${'a'.repeat(31)}😀`;
    const passiveTransport = transport(body);
    const passive = await createDastEngine({ targetPolicy: policy(), transport: passiveTransport.service, packRules: [reporter], maxResponseBytes: 32, now: () => Date.parse(AT) }).execute(record('DAST'), { signal });
    const activeTransport = transport(body);
    const active = await createActiveDastEngine({ targetPolicy: policy(), transport: activeTransport.service, packRules: [reporter], maxResponseBytes: 32, throttleMs: 0, now: () => Date.parse(AT) }).execute({ ...record('DAST'), dastMode: 'ACTIVE_SAFE', dastActiveConsent: true }, { signal });
    for (const result of [passive, active]) {
      if (result.kind !== 'completed') throw new Error('scan failed');
      expect(result.dast?.observations[0]).toMatchObject({ bodyBytes: 31, bodyTruncated: true });
      expect(result.resultSummary.astSupplement).toMatchObject({ status: 'PARTIAL', skipped: 1 });
    }
  });

  test('caps inline scripts, reports ignored external files and never executes target code', async () => {
    const source = `<script>require('node:fs').writeFileSync('${MARKER}','bad')</script>` + '<script>const x=1</script>'.repeat(10) + '<script src="/external.js"></script>';
    const fixture = transport(source);
    const outcome = await createDastEngine({ targetPolicy: policy(), transport: fixture.service, packRules: [reporter], now: () => Date.parse(AT) }).execute(record('DAST'), { signal });
    if (outcome.kind !== 'completed') throw new Error('scan failed');
    expect(outcome.resultSummary.astSupplement).toMatchObject({ status: 'PARTIAL', parsed: 8, skipped: 4 });
    expect(fixture.calls).toEqual([TARGET]);
    expect(existsSync(MARKER)).toBe(false);
  });

  test('only the first completed baseline response is parsed after a passive redirect', async () => {
    const calls: string[] = [];
    const service: DastTransport = { probe: async (target) => {
      calls.push(target.url);
      return calls.length === 1
        ? { status: 302, headers: { location: '/next' }, body: '', bodyTruncated: false, elapsedMs: 1 }
        : { status: 200, headers: { 'content-type': 'application/javascript' }, body: 'const x=location.hash; document.write(x);', bodyTruncated: false, elapsedMs: 2 };
    } };
    const outcome = await createDastEngine({ targetPolicy: policy(), transport: service, packRules: [reporter], now: () => Date.parse(AT) }).execute(record('DAST'), { signal });
    if (outcome.kind !== 'completed') throw new Error('scan failed');
    expect(calls).toEqual([TARGET, `${TARGET}next`]);
    expect(outcome.resultSummary.astSupplement).toMatchObject({ status: 'RAN', parsed: 1, signals: 1 });
    expect(outcome.findings?.find((f) => f.astContext?.kind === 'DAST_RESPONSE_FLOW')?.endpoint).toBe(`${TARGET}next`);
  });

  test('active redirect stops at the baseline limit without inventing a followed redirect or parsing a crawl response', async () => {
    const calls: string[] = [];
    const service: DastTransport = { probe: async (target) => {
      calls.push(target.url);
      return calls.length === 1
        ? { status: 302, headers: { location: '/next', 'content-type': 'text/html' }, body: '<a href="/page">page</a>', bodyTruncated: false, elapsedMs: 20_000 }
        : { status: 200, headers: { 'content-type': 'text/html' }, body: '<script>document.write(location.hash)</script>', bodyTruncated: false, elapsedMs: 20_000 };
    } };
    const outcome = await createActiveDastEngine({ targetPolicy: policy(), transport: service, packRules: [reporter], now: () => Date.parse(AT), throttleMs: 0 }).execute({ ...record('DAST'), dastMode: 'ACTIVE_SAFE', dastActiveConsent: true }, { signal });
    if (outcome.kind !== 'completed') throw new Error('scan failed');
    expect(calls).not.toContain(`${TARGET}next`);
    expect(outcome.dast?.redirectsFollowed).toBe(0);
    expect(outcome.resultSummary.astSupplement).toMatchObject({ status: 'NOT_APPLICABLE', parsed: 0, signals: 0 });
    expect(isDastResult(outcome.dast)).toBe(true);
    expect(outcome.dast?.observations.every((item) => item.responseTimeMs === 15_000)).toBe(true);
  });

  test('active mode can send a bounded path marker probe on an allowed same-host link', async () => {
    const fixture = transport('<a href="/page">Page</a>');
    const engine = createActiveDastEngine({ targetPolicy: policy(), transport: fixture.service, packRules: [reporter], throttleMs: 0, now: () => Date.parse(AT) });
    const outcome = await engine.execute({ ...record('DAST'), dastMode: 'ACTIVE_SAFE', dastActiveConsent: true }, { signal });
    if (outcome.kind !== 'completed') throw new Error('scan failed');
    expect(fixture.calls).toHaveLength(3);
    expect(fixture.calls[0]).toBe(TARGET);
    expect(fixture.calls[1]).toBe(`${TARGET}page`);
    expect(fixture.calls[2]).toContain('drobon-xss-1337');
    expect(fixture.calls.every((url) => !url.includes('?'))).toBe(true);
    expect(isDastResult(outcome.dast)).toBe(true);
  });

  test('active mode marks blocked query links and parameter probes partial without sending them', async () => {
    const fixture = transport('<a href="/search?q=example">Search</a>');
    const engine = createActiveDastEngine({ targetPolicy: policy(), transport: fixture.service, packRules: [reporter], throttleMs: 0, now: () => Date.parse(AT) });
    const outcome = await engine.execute({ ...record('DAST'), dastMode: 'ACTIVE_SAFE', dastActiveConsent: true }, { signal });
    if (outcome.kind !== 'completed') throw new Error('scan failed');
    expect(fixture.calls).toEqual([TARGET]);
    expect(outcome.dast).toMatchObject({ mode: 'ACTIVE_SAFE', requestCount: 1, partial: true, partialReason: expect.stringContaining('Query-bearing') });
    expect(outcome.resultSummary.partial).toBe(true);
    expect(outcome.resultSummary.astSupplement?.status).toBe('NOT_APPLICABLE');
    expect(JSON.stringify(outcome)).not.toContain('q=example');
  });

  test('active mode still requires consent and parses only its observed baseline without extra AST requests', async () => {
    const fixture = transport('<script>const x=location.hash; document.write(x)</script>');
    const engine = createActiveDastEngine({ targetPolicy: policy(), transport: fixture.service, packRules: [reporter], now: () => Date.parse(AT), throttleMs: 0 });
    const rejected = await engine.execute({ ...record('DAST'), dastMode: 'ACTIVE_SAFE' }, { signal });
    expect(rejected.kind).toBe('failed');
    expect(fixture.calls).toHaveLength(0);
    const accepted = await engine.execute({ ...record('DAST'), dastMode: 'ACTIVE_SAFE', dastActiveConsent: true }, { signal });
    expect(accepted.kind).toBe('completed');
    if (accepted.kind !== 'completed') throw new Error('scan failed');
    expect(accepted.dast?.mode).toBe('ACTIVE_SAFE');
    expect(accepted.resultSummary.astSupplement).toMatchObject({ status: 'RAN', parsed: 1, signals: 1 });
    expect(fixture.calls).toEqual([TARGET]);
  });
});

describe('Secrets and SCA AST supplements', () => {
  test('external Secrets metadata is bounded while the matched value remains redacted', async () => {
    const rule = convertSecretsPackToRule({ schemaVersion: 'drobon.pack.secrets/v1', id: 'DPK-SEC-900', severity: 'HIGH', confidence: 'HIGH',
      title: `Title ${'x'.repeat(200)}`, description: `Description ${'x'.repeat(500)}`, remediation: `Fix ${'x'.repeat(700)}`,
      cwe: 'invalid', patterns: [{ source: 'AKIA[A-Z0-9]{16}' }] });
    if (rule === undefined) throw new Error('conversion failed');
    expect([rule.title.length, rule.description.length, rule.remediation.length]).toEqual([80, 400, 400]);
    expect(rule.cwe).toBeUndefined();
    const files = source([{ path: 'src/a.js', content: `const key = "${TEST_SECRET}";` }]);
    const result = await createSecretsEngine({ sources: { findByProject: async () => files }, rules: [rule] }).execute(record('SECRETS'), { signal });
    if (result.kind !== 'completed') throw new Error('scan failed');
    expect(result.findings).toHaveLength(1);
    expect(result.findings?.every(isFinding)).toBe(true);
    expect(result.findings?.[0]?.astContext?.kind).toBe('SECRETS_STRING_LITERAL');
    expect(JSON.stringify(result)).not.toContain(TEST_SECRET);
  });

  test('adds only literal context to existing redacted findings, including normalized tabs/CRLF', async () => {
    const files = source([
      { path: 'src/a.ts', content: `\tconst key = "${TEST_SECRET}";\r\n// ${TEST_SECRET}\r\nconst note = "a value";` },
      { path: 'src/b.py', content: `key = "${TEST_SECRET}"` },
    ]);
    const engine = createSecretsEngine({ sources: { findByProject: async () => files }, rules: TEST_SECRETS_RULES });
    const outcome = await engine.execute(record('SECRETS'), { signal });
    if (outcome.kind !== 'completed') throw new Error('scan failed');
    expect(outcome.findings).toHaveLength(3);
    expect(outcome.findings?.find((f) => f.file === 'src/a.ts' && f.line === 1)?.astContext).toEqual({ kind: 'SECRETS_STRING_LITERAL' });
    expect(outcome.findings?.find((f) => f.file === 'src/a.ts' && f.line === 2)?.astContext).toBeUndefined();
    expect(outcome.findings?.find((f) => f.file === 'src/b.py')?.astContext).toBeUndefined();
    expect(outcome.resultSummary.astSupplement).toMatchObject({ mode: 'SECRETS_LITERAL_CONTEXT', status: 'PARTIAL', parsed: 1, skipped: 1, signals: 1 });
    expect(outcome.findings?.every(isFinding)).toBe(true);
    expect(JSON.stringify(outcome)).not.toContain(TEST_SECRET);
  });

  test('classifies multiline and interpolated template literal segments without returning their contents', async () => {
    const content = `const first = \`line one\n${TEST_SECRET}\nend\`;\nconst second = \`prefix ${TEST_SECRET} ${'${1 + 1}'} suffix\`;`;
    const files = source([{ path: 'templates.js', content }]);
    const outcome = await createSecretsEngine({ sources: { findByProject: async () => files }, rules: TEST_SECRETS_RULES }).execute(record('SECRETS'), { signal });
    if (outcome.kind !== 'completed') throw new Error('scan failed');
    expect(outcome.findings).toHaveLength(2);
    expect(outcome.findings?.every((f) => f.astContext?.kind === 'SECRETS_STRING_LITERAL')).toBe(true);
    expect(outcome.resultSummary.astSupplement).toMatchObject({ status: 'RAN', parsed: 1, signals: 2 });
    expect(JSON.stringify(outcome)).not.toContain(TEST_SECRET);
  });

  test('missing rules and parse errors never become complete literal coverage', async () => {
    const files = source([{ path: 'src/a.js', content: 'const a = "safe";' }, { path: 'src/b.ts', content: 'const = ;' }]);
    const withoutRules = await createSecretsEngine({ sources: { findByProject: async () => files }, rules: [] }).execute(record('SECRETS'), { signal });
    if (withoutRules.kind !== 'completed') throw new Error('scan failed');
    expect(withoutRules.resultSummary).toMatchObject({ partial: true, filesScanned: 0, filesSkipped: 2 });
    expect(withoutRules.resultSummary.astSupplement).toMatchObject({ status: 'NOT_APPLICABLE', parsed: 0, incomplete: 0, signals: 0 });
    expect(withoutRules.findings ?? []).toHaveLength(0);

    // With rules available, both files are reached; an invalid source must
    // still make the optional literal-context analysis partial.
    const withRules = await createSecretsEngine({ sources: { findByProject: async () => files }, rules: TEST_SECRETS_RULES }).execute(record('SECRETS'), { signal });
    if (withRules.kind !== 'completed') throw new Error('scan failed');
    expect(withRules.resultSummary.astSupplement).toMatchObject({ status: 'PARTIAL', parsed: 1, incomplete: 1, signals: 0 });
    expect(withRules.findings ?? []).toHaveLength(0);
  });

  test('SCA counts syntactic package.json declarations without turning them into vulnerability verdicts', async () => {
    const files = source([
      { path: 'package.json', content: '{"dependencies":{"alpha":"1","beta":"2"},"devDependencies":{"gamma":"3"}}' },
      { path: 'requirements.txt', content: 'demo==1.0\n' },
    ]);
    const result = await createScaEngine({ sources: { findByProject: async () => files } }).execute(record('SCA'), { signal });
    if (result.kind !== 'completed') throw new Error('scan failed');
    expect(result.resultSummary.astSupplement).toMatchObject({ mode: 'SCA_JSON_MANIFEST', status: 'PARTIAL', parsed: 1, skipped: 1, signals: 3 });
    expect(result.sca?.summary.assessmentState).toBe('NOT_ASSESSED');
    expect(JSON.stringify(result.resultSummary.astSupplement)).not.toContain('alpha');
    expect(result.findings ?? []).toHaveLength(0);
  });

  test('malformed JSON, file caps and cancellation remain incomplete', async () => {
    const malformed = await analyzeScaManifestAst([{ path: 'package.json', content: '{ bad' }], signal, () => 10_000);
    expect(malformed).toMatchObject({ status: 'PARTIAL', parsed: 0, incomplete: 1, signals: 0 });
    const many = Array.from({ length: 34 }, (_, i) => ({ path: `p${i}/package.json`, content: '{}' }));
    const bounded = await analyzeScaManifestAst(many, signal, () => 10_000);
    expect(bounded).toMatchObject({ status: 'PARTIAL', parsed: 32, skipped: 2 });
    const abort = new AbortController(); abort.abort();
    const canceled = await analyzeScaManifestAst(many, abort.signal, () => 10_000);
    expect(canceled).toMatchObject({ status: 'PARTIAL', parsed: 0, skipped: 34 });
    const session = new StructuredAstSession();
    try { expect((await session.analyzeSupplement({ kind: 'SCA', content: '{}' }, abort.signal, 5_000)).status).toBe('ABORTED'); }
    finally { await session.close(); }
  });
});

describe('authenticated AST supplement workflow', () => {
  test('owner HTTP scans, reports and SOC preserve supplement metadata and secret redaction', async () => {
    const server = await startTestServer();
    try {
      const register = await fetch(`${server.baseUrl}/api/v1/auth/register`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: 'supplement-owner@example.test', password: 'fixture-password-not-real' }) });
      expect(register.status).toBe(201);
      const session = sessionCookieFrom(register);
      const me = await fetch(`${server.baseUrl}/api/v1/me`, { headers: { cookie: session } });
      const device = me.headers.getSetCookie().find((item) => item.startsWith('drobon_device='));
      const cookie = device === undefined ? session : `${session}; ${device.split(';')[0]}`;
      const headers = { 'content-type': 'application/json', cookie };
      const projectResponse = await fetch(`${server.baseUrl}/api/v1/projects`, { method: 'POST', headers, body: JSON.stringify({ name: 'AST supplement HTTP' }) });
      expect(projectResponse.status).toBe(201);
      const project = await readJson(projectResponse) as { data: { project: { id: string } } };
      const base = `${server.baseUrl}/api/v1/projects/${project.data.project.id}`;
      const upload = await fetch(`${base}/sources`, { method: 'PUT', headers, body: JSON.stringify({ files: [
        { path: 'src/a.js', content: `const key = "${TEST_SECRET}";` },
        { path: 'package.json', content: '{"dependencies":{"fixture":"1.0"}}' },
      ] }) });
      expect(upload.status).toBe(200);
      const request = async (scanType: 'SECRETS' | 'SCA') => {
        const response = await fetch(`${base}/scans`, { method: 'POST', headers, body: JSON.stringify({ scanType }) });
        expect(response.status).toBe(201);
        const data = await readJson(response) as { data: { scan: { id: string } } };
        await server.scanProcessor.drain();
        const url = `${base}/scans/${data.data.scan.id}`;
        const detail = await readJson(await fetch(url, { headers: { cookie } })) as { data: { scan: { status: string; resultSummary: { astSupplement: { mode: string; status: string; signals: number } }; findings: Array<{ astContext?: { kind: string } }> } } };
        expect(detail.data.scan.status).toBe('COMPLETED');
        return { url, detail };
      };
      const secrets = await request('SECRETS');
      expect(secrets.detail.data.scan.resultSummary.astSupplement).toMatchObject({ mode: 'SECRETS_LITERAL_CONTEXT', status: 'PARTIAL', signals: 1 });
      expect(secrets.detail.data.scan.findings[0]?.astContext?.kind).toBe('SECRETS_STRING_LITERAL');
      const generated = await fetch(`${secrets.url}/report`, { method: 'POST', headers, body: '{}' });
      expect(generated.status).toBe(201);
      const report = await readJson(generated) as { data: { report: { sac: { scannerCoverage: Array<{ scanner: string; status: string }> }; scan: { resultSummary: { astSupplement: unknown } } } } };
      expect(report.data.report.sac.scannerCoverage.find((entry) => entry.scanner === 'SECRETS')?.status).toBe('PARTIAL');
      expect(report.data.report.scan.resultSummary.astSupplement).toEqual(secrets.detail.data.scan.resultSummary.astSupplement);
      const soc = await readJson(await fetch(`${base}/soc`, { headers: { cookie } })) as { data: { posture: { alerts: Array<{ ruleId: string }> } } };
      expect(soc.data.posture.alerts.some((item) => item.ruleId === 'SCAN_PARTIAL')).toBe(true);
      const sca = await request('SCA');
      expect(sca.detail.data.scan.resultSummary.astSupplement).toMatchObject({ mode: 'SCA_JSON_MANIFEST', signals: 1 });
      expect(JSON.stringify(secrets.detail) + JSON.stringify(report) + JSON.stringify(sca.detail) + server.logs.join(' ')).not.toContain(TEST_SECRET);
      const foreign = await fetch(`${server.baseUrl}/api/v1/auth/register`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: 'other-owner@example.test', password: 'fixture-password-not-real' }) });
      const foreignSession = sessionCookieFrom(foreign);
      const foreignMe = await fetch(`${server.baseUrl}/api/v1/me`, { headers: { cookie: foreignSession } });
      const foreignDevice = foreignMe.headers.getSetCookie().find((item) => item.startsWith('drobon_device='));
      const foreignCookie = foreignDevice === undefined ? foreignSession : `${foreignSession}; ${foreignDevice.split(';')[0]}`;
      expect((await fetch(secrets.url, { headers: { cookie: foreignCookie } })).status).toBe(403);
    } finally { await server.stop(); }
  }, 20_000);
});

describe('supplement persistence, reports and guards', () => {
  test('DAST observation attribution persists and exports without the response body', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'drobon-ast-dast-')); dirs.push(dir);
    const storePath = join(dir, 'scans.json');
    const scans = createJsonFileScanStore(storePath);
    const project = await createMemoryProjectStore().create({ ownerId: OWNER, name: 'DAST AST report', description: '' });
    const created = await scans.createScanWithQuota({ ownerId: OWNER, projectId: project.id, scanType: 'DAST', targetUrl: TARGET, consume: async () => ({ ok: true }) });
    if (created.outcome !== 'created') throw new Error('create failed');
    const running = await scans.claimNextQueued(); if (running === undefined) throw new Error('claim failed');
    const fixture = transport(body);
    const outcome = await createDastEngine({ targetPolicy: policy(), transport: fixture.service, packRules: [reporter], now: () => Date.parse(AT) }).execute(running, { signal });
    if (outcome.kind !== 'completed') throw new Error('scan failed');
    const completed = await scans.completeScan(running.id, outcome.resultSummary, outcome.findings, undefined, outcome.dast);
    if (completed === undefined) throw new Error('complete failed');
    expect(isScanDetailResponse({ scan: toScanDetailResponse(completed) })).toBe(true);
    const reloaded = await createJsonFileScanStore(storePath).findByProjectAndId(project.id, running.id);
    expect(reloaded?.findings?.[0]?.astContext?.kind).toBe('DAST_RESPONSE_FLOW');
    const report = buildSecurityReport(project, completed, AT);
    expect(isSecurityReport(report)).toBe(true);
    expect(report.sac?.scannerCoverage.find((entry) => entry.scanner === 'DAST')?.status).toBe('PARTIAL');
    const markdown = renderSecurityReportMarkdown(report);
    expect(markdown).toContain('AST response script');
    expect(markdown).toContain('category-selected rule');
    const sarif = JSON.parse(renderSecurityReportSarif(report)) as { runs: Array<{ properties: Record<string, unknown>; results: Array<{ properties?: Record<string, unknown> }> }> };
    expect(sarif.runs[0]?.results[0]?.properties?.['drobon/astContext']).toEqual(completed.findings?.[0]?.astContext);
    expect(readFileSync(storePath, 'utf8') + JSON.stringify(report) + markdown + JSON.stringify(sarif)).not.toContain(body);
    expect(JSON.stringify(report)).not.toContain('document.write');
  });

  test('redacted context survives durable reload, SAC, Markdown and SARIF', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'drobon-ast-supplement-')); dirs.push(dir);
    const storePath = join(dir, 'scans.json');
    const scans = createJsonFileScanStore(storePath);
    const project = await createMemoryProjectStore().create({ ownerId: OWNER, name: 'AST report', description: '' });
    const created = await scans.createScanWithQuota({ ownerId: OWNER, projectId: project.id, scanType: 'SECRETS', consume: async () => ({ ok: true }) });
    if (created.outcome !== 'created') throw new Error('create failed');
    const running = await scans.claimNextQueued(); if (running === undefined) throw new Error('claim failed');
    const files = { ...source([{ path: 'a.js', content: `const key = "${TEST_SECRET}";` }, { path: 'b.py', content: 'print(1)' }]), projectId: project.id };
    const outcome = await createSecretsEngine({ sources: { findByProject: async () => files }, rules: TEST_SECRETS_RULES }).execute(running, { signal });
    if (outcome.kind !== 'completed') throw new Error('scan failed');
    const completed = await scans.completeScan(running.id, outcome.resultSummary, outcome.findings);
    if (completed === undefined) throw new Error('complete failed');
    const restored = await createJsonFileScanStore(storePath).findByProjectAndId(project.id, running.id);
    expect(restored?.resultSummary?.astSupplement).toEqual(outcome.resultSummary.astSupplement);
    expect(restored?.findings?.[0]?.astContext).toEqual({ kind: 'SECRETS_STRING_LITERAL' });
    expect(isScan(toScanResponse(completed))).toBe(true);
    const report = buildSecurityReport(project, completed, AT);
    expect(isSecurityReport(report)).toBe(true);
    expect(verifySecurityReportIntegrity(report)).toBe(true);
    expect(report.sac?.scannerCoverage.find((entry) => entry.scanner === 'SECRETS')?.status).toBe('PARTIAL');
    expect(report.sac?.residualRisk.status).toBe('UNKNOWN');
    expect(report.sac?.compliance.status).toBe('NOT_ASSESSED');
    expect(report.sac?.limitations.join(' ')).toContain('does not verify credentials');
    const markdown = renderSecurityReportMarkdown(report);
    expect(markdown).toContain('Scanner-specific AST supplement');
    expect(markdown).toContain('AST context: matched value overlaps');
    const sarif = JSON.parse(renderSecurityReportSarif(report)) as { runs: Array<{ properties: Record<string, unknown>; results: Array<{ properties?: Record<string, unknown> }> }> };
    expect(sarif.runs[0]?.properties['drobon/astSupplement']).toEqual(outcome.resultSummary.astSupplement);
    expect(sarif.runs[0]?.results[0]?.properties?.['drobon/astContext']).toEqual({ kind: 'SECRETS_STRING_LITERAL' });
    expect(readFileSync(storePath, 'utf8') + JSON.stringify(report) + markdown + JSON.stringify(sarif)).not.toContain(TEST_SECRET);
  });
});
