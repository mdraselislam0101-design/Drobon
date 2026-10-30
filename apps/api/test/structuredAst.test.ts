import { describe, expect, test } from 'vitest';
import { isFinding, isScanResultSummary, isSecurityReport } from '@drobon/shared';
import { createMemoryProjectStore } from '../src/projects/store.js';
import { buildSecurityReport, renderSecurityReportMarkdown, renderSecurityReportSarif, verifySecurityReportIntegrity } from '../src/reports/build.js';
import { createSastEngine } from '../src/scans/sast/engine.js';
import { analyzeAstFile } from '../src/scans/sast/astAnalyzer.js';
import { astProfileFor } from '../src/scans/sast/astProfiles.js';
import { analyzeStructuredAst } from '../src/scans/sast/structuredAst.mjs';
import { StructuredAstSession, STRUCTURED_AST_MAX_BYTES, STRUCTURED_AST_MAX_WORKERS } from '../src/scans/sast/structuredAstSession.js';
import { createMemoryScanStore, type ScanRecord } from '../src/scans/store.js';
import type { SourceSnapshotRecord } from '../src/scans/sources.js';
import type { SastRule } from '../src/scans/sast/rules.js';
import { readJson, sessionCookieFrom, startTestServer } from './helpers.js';

const OWNER = 'usr_00000000-0000-4000-8000-000000000001';
const PROJECT = 'prj_00000000-0000-4000-8000-000000000002';
const SCAN = 'scan_00000000-0000-4000-8000-000000000003';
const SIGNAL = new AbortController().signal;
const REPORTERS = { command: 'DG-SAST-001', sql: 'DG-SAST-003', html: 'DG-SAST-004', code: 'DG-SAST-002' };
const RULE: SastRule = {
  id: 'DG-SAST-001', title: 'Test command flow', description: 'A test-only command flow candidate.',
  severity: 'HIGH', category: 'command-injection', remediation: 'Review the source and sink.',
  limitation: 'A test-only heuristic.', patterns: [/never-matches-this-fixture/],
  languages: ['javascript', 'typescript', 'jsx', 'tsx'],
};
const record: ScanRecord = {
  id: SCAN, ownerId: OWNER, projectId: PROJECT, scanType: 'SAST', status: 'RUNNING',
  createdAt: '2026-10-28T10:00:00.000Z', updatedAt: '2026-10-28T10:00:00.000Z', startedAt: '2026-10-28T10:00:00.000Z',
};

function snapshot(files: Array<{ path: string; content: string }>, projectId = PROJECT): SourceSnapshotRecord {
  return {
    projectId, ownerId: OWNER,
    files: files.map((file) => ({ ...file, bytes: Buffer.byteLength(file.content, 'utf8') })),
    createdAt: '2026-10-28T09:00:00.000Z', updatedAt: '2026-10-28T09:00:00.000Z',
  };
}

function structured(family: string, content: string) {
  const profile = astProfileFor(family);
  if (profile === undefined) throw new Error('missing test profile');
  return analyzeStructuredAst({ family, content, profile, reporters: REPORTERS }) as {
    status: string; candidates: Array<{ ruleId: string; kind: string; lineIndex: number; column: number }>;
  };
}

async function execute(files: Array<{ path: string; content: string }>, rules: readonly SastRule[] = [RULE]) {
  const engine = createSastEngine({ sources: { findByProject: async () => snapshot(files) }, rules });
  return await engine.execute(record, { signal: SIGNAL });
}

describe('bounded JS/TS structured syntax analysis', () => {
  test.each(['javascript', 'typescript', 'jsx', 'tsx'])('%s parses destructuring and static bracket calls missed by the shallow pass', (family) => {
    const content = 'const {body: {cmd: command}} = req;\nchild_process["exec"](command);\n';
    expect(analyzeAstFile({ family, content, reporters: REPORTERS }).candidates).toEqual([]);
    const result = structured(family, content);
    expect(result.status).toBe('OK');
    expect(result.candidates).toEqual([{ ruleId: 'DG-SAST-001', kind: 'command', lineIndex: 1, column: 1 }]);
  });

  test('handles JSX raw HTML, SQL interpolation and the narrow parameterized-query exception', () => {
    const jsx = structured('tsx', 'const html = req.body.html;\nconst el = <div dangerouslySetInnerHTML={{__html: html}} />;');
    expect(jsx.candidates).toEqual([{ ruleId: 'DG-SAST-004', kind: 'html', lineIndex: 1, column: 17 }]);
    const unsafeSql = structured('typescript', 'const {x} = req.body;\ndb.query(`SELECT ${x}`);');
    expect(unsafeSql.candidates[0]?.kind).toBe('sql');
    const parameterized = structured('typescript', 'const {x} = req.body;\ndb.query("SELECT ?", [x]);');
    expect(parameterized.candidates).toEqual([]);
    const unsafeConcat = structured('typescript', 'const {x} = req.body;\ndb.query("SELECT ?" + x, []);');
    expect(unsafeConcat.candidates[0]?.kind).toBe('sql');
  });

  test('does not treat comments, strings or a different function scope as structured flow', () => {
    expect(structured('javascript', '// exec(req.body.x)\nconst t = "exec(req.body.x)";').candidates).toEqual([]);
    expect(structured('javascript', 'function a(){ const local = req.body.x; }\nfunction b(){ child_process.exec(local); }').candidates).toEqual([]);
    expect(structured('javascript', 'const x = req.body.x;\nchild_process.exec(encodeURIComponent(x));').candidates[0]?.kind).toBe('command');
  });

  test('invalid syntax and hard limits are incomplete; target code is never executed', () => {
    expect(structured('javascript', 'const = ;').status).toBe('SYNTAX_ERROR');
    expect(structured('javascript', 'while (true) {}').status).toBe('OK');
    const deep = `const x = ${'('.repeat(100)}req.body.x${')'.repeat(100)};`;
    expect(structured('javascript', deep).status).toBe('LIMIT');
    const many = Array.from({ length: 8 }, () => 'child_process.exec(req.body.x);').join('\n');
    const limited = structured('javascript', many);
    expect(limited.status).toBe('LIMIT');
    expect(limited.candidates).toHaveLength(3);
  });

  test('pathologically nested untrusted source does not crash the API process', async () => {
    const profile = astProfileFor('javascript');
    if (profile === undefined) throw new Error('missing test profile');
    const session = new StructuredAstSession();
    try {
      const content = `const x = ${'('.repeat(15_000)}1${')'.repeat(15_000)};`;
      const result = await session.analyze({ family: 'javascript', content, profile, reporters: REPORTERS }, SIGNAL, 3_000);
      expect(['ERROR', 'LIMIT', 'TIMEOUT']).toContain(result.status);
      expect(result.candidates).toEqual([]);
    } finally { await session.close(); }
  });

  test('concurrent parser workers are capped and excess work is explicitly unavailable', async () => {
    const profile = astProfileFor('javascript');
    if (profile === undefined) throw new Error('missing test profile');
    const input = { family: 'javascript', content: 'const x = 1;', profile, reporters: REPORTERS };
    const sessions = Array.from({ length: STRUCTURED_AST_MAX_WORKERS + 1 }, () => new StructuredAstSession());
    try {
      const jobs = sessions.slice(0, STRUCTURED_AST_MAX_WORKERS).map((session) => session.analyze(input, SIGNAL, 3_000));
      const overflow = sessions[STRUCTURED_AST_MAX_WORKERS];
      if (overflow === undefined) throw new Error('missing overflow session');
      expect((await overflow.analyze(input, SIGNAL, 3_000)).status).toBe('UNAVAILABLE');
      await Promise.all(jobs);
    } finally { await Promise.all(sessions.map((session) => session.close())); }
  });

  test('a worker can be cancelled and an expired worker is not reused', async () => {
    const profile = astProfileFor('javascript');
    if (profile === undefined) throw new Error('missing test profile');
    const input = { family: 'javascript', content: 'while (true) {}', profile, reporters: REPORTERS };
    const stopped = new StructuredAstSession();
    const controller = new AbortController();
    try {
      const work = stopped.analyze(input, controller.signal, 3_000);
      controller.abort();
      expect((await work).status).toBe('ABORTED');
      expect((await stopped.analyze(input, SIGNAL, 3_000)).status).toBe('UNAVAILABLE');
    } finally { await stopped.close(); }
    const expired = new StructuredAstSession();
    try {
      expect((await expired.analyze(input, SIGNAL, 1)).status).toBe('TIMEOUT');
      expect((await expired.analyze(input, SIGNAL, 3_000)).status).toBe('UNAVAILABLE');
    } finally { await expired.close(); }
  });
});

describe('existing SAST, SOC/SAC and report integration', () => {
  test('adds a real parser-only finding without copying a source literal to evidence', async () => {
    const source = 'const {cmd: command} = req["body"];\nchild_process["exec"](command, "fixture-private-value");\n';
    const first = await execute([{ path: 'src/index.js', content: source }]);
    const second = await execute([{ path: 'src/index.js', content: source }]);
    expect(first).toEqual(second);
    if (first.kind !== 'completed') throw new Error('expected completion');
    expect(first.resultSummary.astParser).toEqual({ parsedFiles: 1, incompleteFiles: 0, filesWithoutRules: 0, findings: 1 });
    expect(first.resultSummary.astFlowsFound).toBe(1);
    expect(first.findings).toHaveLength(1);
    expect(first.findings?.[0]?.line).toBe(2);
    expect(first.findings?.[0]?.evidence).toContain('AST command flow candidate');
    expect(first.findings?.[0]?.evidence).not.toContain('fixture-private-value');
    expect(isFinding(first.findings?.[0])).toBe(true);
    expect(isScanResultSummary(first.resultSummary)).toBe(true);
  });

  test('does not collapse equal rule/line findings in different files', async () => {
    const content = 'const cmd = req.body.cmd;\nchild_process.exec(cmd);\n';
    const outcome = await execute([{ path: 'a.js', content }, { path: 'b.js', content }]);
    if (outcome.kind !== 'completed') throw new Error('expected completion');
    expect(outcome.findings?.map((finding) => 'file' in finding ? finding.file : '')).toEqual(['a.js', 'b.js']);
    expect(outcome.resultSummary.astFlowsFound).toBe(2);
  });

  test('files not reached after the finding cap are counted as skipped, not scanned', async () => {
    const engine = createSastEngine({
      sources: { findByProject: async () => snapshot([{ path: 'a.js', content: 'exec(req.body.x);' }, { path: 'b.js', content: 'exec(req.body.y);' }]) },
      rules: [{ ...RULE, patterns: [/exec/] }], limits: { maxFindings: 1 },
    });
    const outcome = await engine.execute(record, { signal: SIGNAL });
    if (outcome.kind !== 'completed') throw new Error('expected completion');
    expect(outcome.resultSummary.filesScanned).toBe(1);
    expect(outcome.resultSummary.filesSkipped).toBe(1);
    expect(outcome.resultSummary.truncated).toBe(true);
    expect(isScanResultSummary(outcome.resultSummary)).toBe(true);
  });

  test('missing rules and malformed or oversized files produce explicit PARTIAL coverage', async () => {
    const noRules = await execute([{ path: 'a.js', content: 'const {cmd} = req.body; child_process.exec(cmd);' }], []);
    if (noRules.kind !== 'completed') throw new Error('expected completion');
    expect(noRules.resultSummary.partial).toBe(true);
    expect(noRules.resultSummary.partialReason).toContain('No SAST rules');
    expect(noRules.resultSummary.astParser?.filesWithoutRules).toBe(1);
    expect(noRules.findings).toBeUndefined();
    const unrelated = await execute([{ path: 'a.js', content: 'const ok = true;' }], [{ ...RULE, category: 'weak-cryptography' }]);
    if (unrelated.kind !== 'completed') throw new Error('expected completion');
    expect(unrelated.resultSummary.astParser?.filesWithoutRules).toBe(1);
    expect(unrelated.resultSummary.partialReason).toContain('no applicable AST flow rules');
    const invalid = await execute([{ path: 'b.ts', content: 'const = ;' }]);
    if (invalid.kind !== 'completed') throw new Error('expected completion');
    expect(invalid.resultSummary.astParser?.incompleteFiles).toBe(1);
    expect(invalid.resultSummary.partial).toBe(true);
    const large = await execute([{ path: 'large.js', content: `/*${'x'.repeat(STRUCTURED_AST_MAX_BYTES)}*/` }]);
    if (large.kind !== 'completed') throw new Error('expected completion');
    expect(large.resultSummary.astParser?.incompleteFiles).toBe(1);
    expect(large.resultSummary.partial).toBe(true);
  });

  test('the parser cannot erase an earlier lexical finding on syntax error', async () => {
    const lexicalRule: SastRule = { ...RULE, patterns: [/exec/] };
    const outcome = await execute([{ path: 'invalid.js', content: 'child_process.exec(req.body.x);\nconst = ;' }], [lexicalRule]);
    if (outcome.kind !== 'completed') throw new Error('expected completion');
    expect(outcome.findings?.some((finding) => finding.line === 1)).toBe(true);
    expect(outcome.resultSummary.astParser?.incompleteFiles).toBe(1);
    expect(outcome.resultSummary.partial).toBe(true);
  });

  test('the existing authenticated HTTP workflow exposes real AST findings and report coverage', async () => {
    const server = await startTestServer();
    try {
      const registration = await fetch(`${server.baseUrl}/api/v1/auth/register`, {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email: 'ast-owner@example.test', password: 'ast-fixture-password-not-real' }),
      });
      expect(registration.status).toBe(201);
      const session = sessionCookieFrom(registration);
      const me = await fetch(`${server.baseUrl}/api/v1/me`, { headers: { cookie: session } });
      const device = me.headers.getSetCookie().find((item) => item.startsWith('drobon_device='));
      const cookie = device === undefined ? session : `${session}; ${device.split(';')[0]}`;
      const headers = { 'content-type': 'application/json', cookie };
      const projectResponse = await fetch(`${server.baseUrl}/api/v1/projects`, {
        method: 'POST', headers, body: JSON.stringify({ name: 'AST HTTP test' }),
      });
      const project = (await readJson(projectResponse)) as { data: { project: { id: string } } };
      const base = `${server.baseUrl}/api/v1/projects/${project.data.project.id}`;
      const upload = await fetch(`${base}/sources`, {
        method: 'PUT', headers, body: JSON.stringify({ files: [{ path: 'src/handler.js', content: 'const {cmd} = req["body"];\nchild_process["exec"](cmd);' }] }),
      });
      expect(upload.status).toBe(200);
      const requested = await fetch(`${base}/scans`, { method: 'POST', headers, body: JSON.stringify({ scanType: 'SAST' }) });
      expect(requested.status).toBe(201);
      const created = (await readJson(requested)) as { data: { scan: { id: string } } };
      await server.scanProcessor.drain();
      const scanUrl = `${base}/scans/${created.data.scan.id}`;
      const detailResponse = await fetch(scanUrl, { headers: { cookie } });
      expect(detailResponse.status).toBe(200);
      const detail = (await readJson(detailResponse)) as { data: { scan: { status: string; resultSummary: { astParser: { findings: number } }; findings: unknown[] } } };
      expect(detail.data.scan.status).toBe('COMPLETED');
      expect(detail.data.scan.resultSummary.astParser.findings).toBe(1);
      expect(detail.data.scan.findings).toHaveLength(1);
      const reportResponse = await fetch(`${scanUrl}/report`, { method: 'POST', headers, body: '{}' });
      expect(reportResponse.status).toBe(201);
      const report = (await readJson(reportResponse)) as { data: { report: { scan: { resultSummary: { astParser: { findings: number } } }; sac: { residualRisk: { status: string } } } } };
      expect(report.data.report.scan.resultSummary.astParser.findings).toBe(1);
      expect(report.data.report.sac.residualRisk.status).toBe('UNKNOWN');

      // A malformed later file keeps the legacy scan but becomes an honest
      // partial result in both the SOC overview and the SAC report.
      expect((await fetch(`${base}/sources`, {
        method: 'PUT', headers, body: JSON.stringify({ files: [{ path: 'src/broken.js', content: 'const = ;' }] }),
      })).status).toBe(200);
      const incompleteResponse = await fetch(`${base}/scans`, { method: 'POST', headers, body: JSON.stringify({ scanType: 'SAST' }) });
      const incomplete = (await readJson(incompleteResponse)) as { data: { scan: { id: string } } };
      expect(incompleteResponse.status).toBe(201);
      await server.scanProcessor.drain();
      const soc = (await readJson(await fetch(`${base}/soc`, { headers: { cookie } }))) as { data: { posture: { alerts: Array<{ ruleId: string }> } } };
      expect(soc.data.posture.alerts.some((alert) => alert.ruleId === 'SCAN_PARTIAL')).toBe(true);
      const partialReportResponse = await fetch(`${base}/scans/${incomplete.data.scan.id}/report`, { method: 'POST', headers, body: '{}' });
      const partialReport = (await readJson(partialReportResponse)) as { data: { report: { sac: { scannerCoverage: Array<{ scanner: string; status: string }> } } } };
      expect(partialReport.data.report.sac.scannerCoverage.find((entry) => entry.scanner === 'SAST')?.status).toBe('PARTIAL');
    } finally { await server.stop(); }
  });

  test('saved reports, Markdown and SARIF preserve parser coverage and bounded conclusions', async () => {
    const projects = createMemoryProjectStore();
    const project = await projects.create({ ownerId: OWNER, name: 'AST test', description: '' });
    const scans = createMemoryScanStore();
    const created = await scans.createScanWithQuota({ ownerId: OWNER, projectId: project.id, scanType: 'SAST', consume: async () => ({ ok: true }) });
    if (created.outcome !== 'created') throw new Error('scan creation failed');
    const running = await scans.claimNextQueued();
    if (running === undefined) throw new Error('scan claim failed');
    const source = snapshot([{ path: 'a.js', content: 'const {cmd} = req.body;\nchild_process["exec"](cmd);' }], project.id);
    const engine = createSastEngine({ sources: { findByProject: async () => source }, rules: [RULE] });
    const outcome = await engine.execute(running, { signal: SIGNAL });
    if (outcome.kind !== 'completed') throw new Error('scan failed');
    const completed = await scans.completeScan(running.id, outcome.resultSummary, outcome.findings);
    if (completed === undefined) throw new Error('persistence failed');
    const report = buildSecurityReport(project, completed, '2026-10-28T12:00:00.000Z');
    expect(isSecurityReport(report)).toBe(true);
    expect(verifySecurityReportIntegrity(report)).toBe(true);
    expect(report.sac?.residualRisk.status).toBe('UNKNOWN');
    expect(report.sac?.compliance.status).toBe('NOT_ASSESSED');
    expect(report.sac?.ruleProvenance).toBe('SAST_EFFECTIVE_RULES_RECORDED');
    expect(report.scan.resultSummary?.astParser?.findings).toBe(1);
    const markdown = renderSecurityReportMarkdown(report);
    expect(markdown).toContain('AST syntax-parser coverage');
    expect(markdown).toContain('Effective rules');
    expect(markdown).toContain('category-selected reporter');
    const sarif = JSON.parse(renderSecurityReportSarif(report)) as { runs: Array<{ properties: Record<string, unknown>; results: Array<{ properties?: Record<string, unknown> }> }> };
    expect(sarif.runs[0]?.properties['drobon/astParser']).toEqual(report.scan.resultSummary?.astParser);
    expect(sarif.runs[0]?.properties['drobon/astCoverage']).toEqual(report.scan.resultSummary?.astCoverage);
    expect(sarif.runs[0]?.results[0]?.properties?.['drobon/astFlow']).toEqual(report.findings[0]?.astFlow);
    const altered = structuredClone(report);
    if (altered.scan.resultSummary?.astCoverage === undefined) throw new Error('provenance missing');
    altered.scan.resultSummary.astCoverage.rules.sha256 = '0'.repeat(64);
    expect(verifySecurityReportIntegrity(altered)).toBe(false);
  });
});
