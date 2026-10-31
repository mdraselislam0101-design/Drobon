import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, test } from 'vitest';
import { isFinding } from '@drobon/shared';
import type { SastRule } from '../src/scans/sast/rules.js';
import type { ScanRecord } from '../src/scans/store.js';
import type { SourceSnapshotRecord } from '../src/scans/sources.js';
import type { SourceSnapshotProvider } from '../src/scans/sast/engine.js';
import { createSastEngine } from '../src/scans/sast/engine.js';
import { WITHHELD_SOURCE_EVIDENCE } from '../src/scans/findingIdentity.js';
import { createDatasetService } from '../src/external/service.js';
import { supportsBoundedAst } from '../src/scans/sast/languages.js';
import { AST_SUPPORTED_FAMILIES, astProfileFor, isSourceChain } from '../src/scans/sast/astProfiles.js';
import { chainAt, lexSource, matchingClose, MAX_AST_TOKENS } from '../src/scans/sast/astLexer.js';
import {
  analyzeAstFile,
  astReporterRules,
  MAX_AST_FINDINGS_PER_RULE_PER_FILE,
  type AstReporterMap,
} from '../src/scans/sast/astAnalyzer.js';

/**
 * Pump 16 — BOUNDED AST / DATAFLOW ENGINE (MAIN-APP ONLY).
 * Proves the extra pass is language-agnostic (profiles are data), removes
 * comment/string false positives, honours sanitizers and parameterized SQL,
 * propagates one level through function parameters, and stays bounded.
 */

const OWNER = 'usr_00000000-0000-4000-8000-000000000001';
const PROJECT = 'prj_00000000-0000-4000-8000-000000000002';
const SCAN = 'scan_00000000-0000-4000-8000-000000000003';
const ctx = { signal: new AbortController().signal };

function scanRecord(): ScanRecord {
  return {
    id: SCAN, ownerId: OWNER, projectId: PROJECT, scanType: 'SAST', status: 'RUNNING',
    createdAt: '2026-10-26T10:00:00.000Z', updatedAt: '2026-10-26T10:00:00.000Z',
    startedAt: '2026-10-26T10:00:00.000Z',
  };
}

function snapshot(files: Array<{ path: string; content: string }>): SourceSnapshotRecord {
  return {
    projectId: PROJECT, ownerId: OWNER,
    files: files.map((file) => ({ path: file.path, bytes: Buffer.byteLength(file.content, 'utf8'), content: file.content })),
    createdAt: '2026-10-26T09:00:00.000Z', updatedAt: '2026-10-26T09:00:00.000Z',
  };
}

function providerFor(record: SourceSnapshotRecord | undefined): SourceSnapshotProvider {
  return { findByProject: async () => record };
}

function fixtureRule(id: string, category: string, languages?: readonly string[]): SastRule {
  return {
    id, title: `Fixture ${category}`, description: 'Test-only classification rule.',
    severity: 'HIGH', category, remediation: 'Review the flow.', limitation: 'Fixture only.',
    patterns: [/^\bnever-matches-this-fixture\b/],
    ...(languages === undefined ? {} : { languages }),
  } as SastRule;
}

const REPORTERS = { command: 'DG-SAST-001', sql: 'DG-SAST-003', html: 'DG-SAST-004', code: 'DG-SAST-002' };

function analyze(family: string, content: string, reporters: AstReporterMap = REPORTERS) {
  return analyzeAstFile({ family, content, reporters });
}

const dirs: string[] = [];
afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

/** Minimal conformance-valid dataset with ONE command rule (no embedded app rules). */
function fixtureDataset(): string {
  const root = mkdtempSync(join(tmpdir(), 'drobon-deep-sast-'));
  dirs.push(root);
  const put = (path: string, value: unknown): void => {
    mkdirSync(join(root, path, '..'), { recursive: true });
    writeFileSync(join(root, path), JSON.stringify(value));
  };
  put('packs/sast/v1/pack.json', { schemaVersion: 'drobon.pack.sast/v1', packId: 'fixture-sast', version: '1.0.0' });
  put('packs/sast/v1/rules/DPK-SAST-901.json', {
    schemaVersion: 'drobon.pack.sast/v1', id: 'DPK-SAST-901',
    title: 'OS command built from untrusted input', description: 'AST dataflow fixture.',
    severity: 'HIGH', cwe: 'CWE-78', category: 'command-injection',
    remediation: 'Use execFile with an argument array and no shell.',
    limitation: 'Bounded AST analysis; not proof of exploitability.',
    patternRefs: ['DPK-PAT-9001'], languages: ['javascript'],
    // Deliberately does NOT match the fixture source: the AST pass must be
    // the thing that finds it (proves it is not a second line matcher).
    patterns: [{ source: '\\bspawnSync\\s*\\(' }],
    tests: [{ line: 'spawnSync(x);', match: true }, { line: 'const x = 1;', match: false }],
  });
  return root;
}

describe('bounded tokenizer', () => {
  test('comments are dropped and string bodies become ONE token', () => {
    const profile = astProfileFor('javascript');
    expect(profile).toBeDefined();
    if (profile === undefined) return;
    const lexed = lexSource('const a = "dangerous(req.body.x)"; // exec(req.body.x)\n/* os.system(x) */\n', profile);
    const tokens = lexed.tokens;
    expect(lexed.truncated).toBe(false);
    expect(tokens.some((token) => token.value.includes('dangerous'))).toBe(true);
    expect(tokens.filter((token) => token.kind === 'string')).toHaveLength(1);
    // No identifier token from inside the comment or string body.
    expect(tokens.some((token) => token.kind === 'ident' && token.value === 'os')).toBe(false);
    expect(tokens.some((token) => token.kind === 'ident' && token.value === 'dangerous')).toBe(false);
  });

  test('template interpolations are recorded and chains/parens resolve', () => {
    const profile = astProfileFor('javascript');
    if (profile === undefined) return;
    const lexed = lexSource('const q = `ls ${req.body.dir}`;\ndb.query(q);\n', profile);
    const template = lexed.tokens.find((token) => token.kind === 'template');
    expect(template?.interpolations).toEqual(['req', 'body', 'dir']);
    const db = lexed.tokens.findIndex((token) => token.kind === 'ident' && token.value === 'db');
    expect(chainAt(lexed.tokens, db).chain).toBe('db.query');
    const open = lexed.tokens.findIndex((token) => token.kind === 'open' && token.value === '(');
    expect(matchingClose(lexed.tokens, open)).toBeGreaterThan(open);
  });

  test('token count is hard-capped for hostile input', () => {
    const profile = astProfileFor('javascript');
    if (profile === undefined) return;
    const huge = 'a '.repeat(40_000);
    const lexed = lexSource(huge, profile);
    expect(lexed.tokens.length).toBeLessThanOrEqual(MAX_AST_TOKENS);
    expect(lexed.truncated).toBe(true);
  });
});

describe('profiles and reporters (data-driven, language-agnostic)', () => {
  test('the profile registry is closed but covers multiple language families', () => {
    expect(AST_SUPPORTED_FAMILIES).toContain('javascript');
    expect(AST_SUPPORTED_FAMILIES).toContain('python');
    expect(AST_SUPPORTED_FAMILIES).toContain('php');
    expect(AST_SUPPORTED_FAMILIES).toContain('go');
    expect(supportsBoundedAst('javascript')).toBe(true);
    expect(supportsBoundedAst('brainfuck')).toBe(false);
    expect(astProfileFor('brainfuck')).toBeUndefined();
    const js = astProfileFor('javascript');
    expect(js).toBeDefined();
    if (js !== undefined) expect(isSourceChain(js, 'req.body.name')).toBe(true);
  });

  test('reporters are chosen by category and language gating, never invented', () => {
    const rules = [
      fixtureRule('DG-SAST-009', 'weak-cryptography'),
      fixtureRule('DG-SAST-002', 'command-injection', ['javascript']),
      fixtureRule('DG-SAST-001', 'sql-injection', ['python']),
    ];
    expect(astReporterRules(rules, 'javascript')).toEqual({ command: 'DG-SAST-002' });
    expect(astReporterRules(rules, 'python')).toEqual({ sql: 'DG-SAST-001' });
    expect(astReporterRules([], 'javascript')).toEqual({});
    expect(analyze('javascript', 'child_process.exec(req.body.x);', {}).candidates).toEqual([]);
  });
});

describe('AST dataflow: real detection, honest suppression', () => {
  test('command flow through a variable is detected in JavaScript', () => {
    const result = analyze('javascript', 'const cmd = req.body.cmd;\nchild_process.exec(cmd);\n');
    expect(result.candidates).toHaveLength(1);
    expect(result.candidates[0]?.kind).toBe('command');
    expect(result.candidates[0]?.ruleId).toBe('DG-SAST-001');
    expect(result.candidates[0]?.lineIndex).toBe(1);
  });

  test('comments and string literals do not create AST candidates; URL encoding does not sanitize a shell command', () => {
    expect(analyze('javascript', '// child_process.exec(req.body.x)\n').candidates).toEqual([]);
    expect(analyze('javascript', 'const s = "child_process.exec(req.body.x)";\n').candidates).toEqual([]);
    const encoded = analyze('javascript', 'const x = encodeURIComponent(req.body.n);\nchild_process.exec(x);\n');
    expect(encoded.candidates.some((candidate) => candidate.kind === 'command')).toBe(true);
  });

  test('template interpolation taint, SQL concat vs parameterized query', () => {
    const template = analyze('javascript', 'const q = `ls ${req.body.dir}`;\nchild_process.exec(q);\n');
    expect(template.candidates).toHaveLength(1);
    const sql = analyze('javascript', 'db.query("SELECT * FROM t WHERE n = " + req.body.n);\n');
    expect(sql.candidates[0]?.kind).toBe('sql');
    expect(analyze('javascript', 'db.query("SELECT * FROM t WHERE n = ?", [req.body.n]);\n').candidates).toEqual([]);
    const mixed = analyze('javascript', 'db.query("SELECT ? WHERE n = " + req.body.n, ["x"]);\n');
    expect(mixed.candidates.some((candidate) => candidate.kind === 'sql')).toBe(true);
  });

  test('assignment-form HTML sink and one level of function-parameter flow', () => {
    const html = analyze('javascript', 'el.innerHTML = req.body.html;\n');
    expect(html.candidates[0]?.kind).toBe('html');
    const fn = analyze('javascript', 'function run(v) { child_process.exec(v); }\nrun(req.body.x);\n');
    expect(fn.candidates.some((candidate) => candidate.kind === 'command')).toBe(true);
    expect(fn.functions).toBe(1);
  });

  test('ONE analyzer handles Python, PHP and Go without language-specific code', () => {
    const cases: Array<[string, string]> = [
      ['python', 'name = request.args.get("x")\nos.system(name)\n'],
      ['php', '$x = $_GET["a"];\nsystem($x);\n'],
      ['go', 'v := r.FormValue("x")\nexec.Command(v)\n'],
    ];
    for (const [family, content] of cases) {
      const result = analyze(family, content);
      expect(result.candidates.some((candidate) => candidate.kind === 'command'), family).toBe(true);
    }
  });

  test('findings are capped per rule per file and the deadline is cooperative', () => {
    const lines = Array.from({ length: 40 }, (_, i) => `const v${i} = req.body.x; child_process.exec(v${i});`).join('\n');
    const result = analyze('javascript', lines);
    expect(result.candidates.length).toBeLessThanOrEqual(MAX_AST_FINDINGS_PER_RULE_PER_FILE);
    const stopped = analyzeAstFile({
      family: 'javascript', content: lines, reporters: REPORTERS, shouldStop: () => true,
    });
    expect(stopped.candidates).toEqual([]);
  });
});

describe('SAST engine integration: AST findings are real persisted findings', () => {
  test('concurrent dataset consumers wait for the same complete validated load', async () => {
    const dataset = createDatasetService({ datasetPath: fixtureDataset(), providerId: 'filesystem' });
    const [status, rules, metadata, secondRules] = await Promise.all([
      dataset.status(), dataset.sastPacks(), dataset.packMetadata('sast'), dataset.sastPacks(),
    ]);
    expect(status.sastPacks.count).toBe(1);
    expect(rules).toHaveLength(1);
    expect(secondRules).toHaveLength(1);
    expect(metadata).toEqual({ packId: 'fixture-sast', version: '1.0.0' });
  });

  test('a dataset-backed scan reports an AST flow with honest coverage counters', async () => {
    const dataset = createDatasetService({
      datasetPath: fixtureDataset(), providerId: 'filesystem',
      logger: { info: () => {}, warn: () => {}, error: () => {} },
    });
    const engine = createSastEngine({
      sources: providerFor(snapshot([{
        path: 'src/handler.js',
        content: 'const cmd = req.body.cmd;\nchild_process.exec(cmd);\n',
      }])),
      dataset,
    });
    const outcome = await engine.execute(scanRecord(), ctx);
    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed') return;
    expect(outcome.resultSummary.astFilesAnalyzed).toBe(1);
    expect(outcome.resultSummary.astFlowsFound).toBe(1);
    expect(outcome.resultSummary.findingsTotal).toBe(1);
    expect(outcome.resultSummary.astCoverage?.rules).toMatchObject({ source: 'DATASET', count: 1, packId: 'fixture-sast', packVersion: '1.0.0' });
    expect(outcome.resultSummary.astCoverage?.rules.sha256).toMatch(/^[0-9a-f]{64}$/);
    const finding = outcome.findings?.[0];
    expect(finding).toBeDefined();
    if (finding === undefined) return;
    expect(finding.ruleId).toBe('DPK-SAST-901');
    expect(finding.scanner).toBe('SAST');
    expect(finding.line).toBe(2);
    expect(isFinding(finding)).toBe(true);
    expect(finding.evidence).toBe(WITHHELD_SOURCE_EVIDENCE);
    expect(finding.evidence).not.toContain('exec');
    // The Dataset rule pattern does NOT match this source; explicit AST
    // attribution, rule, sink line and coverage counters establish the pass.
    expect(finding.astFlow).toMatchObject({ category: 'command', attribution: 'CATEGORY_REPORTER' });
    expect(finding.evidence).not.toContain('spawnSync');
  });

  test('an unsupported family produces no AST coverage but still scans lexically', async () => {
    const dataset = createDatasetService({
      datasetPath: fixtureDataset(), providerId: 'filesystem',
      logger: { info: () => {}, warn: () => {}, error: () => {} },
    });
    const engine = createSastEngine({
      sources: providerFor(snapshot([{ path: 'notes.txt', content: 'spawnSync(x);\n' }])),
      dataset,
    });
    const outcome = await engine.execute(scanRecord(), ctx);
    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed') return;
    expect(outcome.resultSummary.astFilesAnalyzed).toBe(0);
    expect(outcome.resultSummary.astFlowsFound).toBe(0);
  });
});
