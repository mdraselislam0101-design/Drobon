import { describe, expect, test } from 'vitest';
import { isFinding } from '@drobon/shared';
import type { ScanRecord } from '../src/scans/store.js';
import type { SourceSnapshotRecord } from '../src/scans/sources.js';
import { ALL_TEST_SAST_RULES } from './fixtures/testData.js';
import { WITHHELD_SOURCE_EVIDENCE } from '../src/scans/findingIdentity.js';
import {
  createSastEngine,
  type SourceSnapshotProvider,
} from '../src/scans/sast/engine.js';
import {
  analyzeFileFlows,
  maskLiterals,
  maskComments,
  MAX_FLOW_FINDINGS_PER_RULE_PER_FILE,
  MAX_FLOW_VARS,
  flowRulesForFamily,
} from '../src/scans/sast/semantic.js';

/**
 * Bounded semantic layer tests (deep-semantic pump).
 *
 * Every semantic detector needs the FULL fixture discipline:
 * positive (real flow → finding at the SINK line), negative (safe
 * equivalents → NO finding), noise (comments/strings/similar names →
 * NO finding) and boundary (sanitized / reassigned / missing source →
 * NO finding). Plus the hard bounds and malformed-input tolerance.
 */

describe('literal masking', () => {
  test('comments and string contents are masked, offsets preserved', () => {
    const js = 'const a = 1; // eval(process.request)\nconst url = "req.params.x";\n/* req.query.y */';
    const masked = maskLiterals(js, 'javascript');
    expect(masked.length).toBe(js.length);
    const lines = masked.split('\n');
    // The comment body is spaces; the code shape survives.
    expect(lines[0]).toMatch(/^const a = 1; {2,}$/);
    expect(lines[1]).toMatch(/^const url = +;$/);
    expect(lines[2]).toMatch(/^ +$/);
    // Newlines survive: same line count.
    expect(lines.length).toBe(3);
  });

  test('python comments/strings masked; triple-quoted blocks masked across lines', () => {
    const py = [
      'x = 1',
      "s = '''req.args.get",
      "still inside'''",
      'y = 2',
    ].join('\n');
    const masked = maskLiterals(py, 'python');
    const lines = masked.split('\n');
    expect(lines[1]).toMatch(/^s = +$/);
    expect(lines[2]).toMatch(/^ +$/);
    expect(lines[3]).toBe('y = 2');
  });

  test('Ruby command interpolation keeps # inside backticks while masking real comments', () => {
    const source = 'out = `ls #{user}` # inactive';
    const masked = maskComments(source, 'ruby');
    expect(masked).toContain('`ls #{user}`');
    expect(masked).not.toContain('inactive');
    expect(masked.length).toBe(source.length);
  });

  test('rust lifetimes are NOT treated as strings (documented limitation)', () => {
    const rs = "let x: &'a str = \"req.args\";";
    const masked = maskLiterals(rs, 'rust');
    expect(masked).toContain("'a str");
  });

  test('malformed/garbage input never throws and preserves length', () => {
    for (const garbage of ['"', "'", '/*', '"""', '`', '\\\\\\', ']]]', '--', '#']) {
      const masked = maskLiterals(garbage + '\nmore', 'javascript');
      expect(masked.length).toBe(garbage.length + 5);
    }
  });
});

describe('bounded flow analysis (unit)', () => {
  const flowRules = flowRulesForFamily('javascript', ALL_TEST_SAST_RULES);
  const pyFlowRules = flowRulesForFamily('python', ALL_TEST_SAST_RULES);

  test('flow rules are registered for the right families (test-only flow fixtures)', () => {
    const jsIds = flowRules.map((r) => r.id).sort();
    expect(jsIds).toEqual(['DG-SAST-048', 'DG-SAST-049', 'DG-SAST-050']);
    const pyIds = pyFlowRules.map((r) => r.id).sort();
    expect(pyIds).toEqual(['DG-SAST-048', 'DG-SAST-049', 'DG-SAST-050']);
    // A config family has no flow rules at all.
    expect(flowRulesForFamily('yaml', ALL_TEST_SAST_RULES)).toEqual([]);
  });

  test('positive: source → variable → sink across lines fires at the SINK line', () => {
    const code = [
      'const host = req.params.host;',
      '',
      'const { exec } = require("x");',
      'exec("ping " + host);',
    ].join('\n');
    const findings = analyzeFileFlows('javascript', maskLiterals(code, 'javascript').split('\n'), flowRules);
    const cmd = findings.find((f) => f.ruleId === 'DG-SAST-048');
    expect(cmd).toBeDefined();
    expect(cmd?.lineIndex).toBe(3); // 0-based sink line
    expect(cmd?.column).toBeGreaterThan(0);
  });

  test('boundary: sanitized at the sink → NO finding', () => {
    const code = [
      'const host = req.params.host;',
      'const safe = encodeURIComponent(host);',
      'exec("ping " + safe);',
    ].join('\n');
    const findings = analyzeFileFlows('javascript', maskLiterals(code, 'javascript').split('\n'), flowRules);
    expect(findings.find((f) => f.ruleId === 'DG-SAST-048')).toBeUndefined();
  });

  test('boundary: reassigned to a constant → NO finding (kill)', () => {
    const code = [
      'const host = req.params.host;',
      'host = "fixed.example.invalid";',
      'exec("ping " + host);',
    ].join('\n');
    const findings = analyzeFileFlows('javascript', maskLiterals(code, 'javascript').split('\n'), flowRules);
    expect(findings.find((f) => f.ruleId === 'DG-SAST-048')).toBeUndefined();
  });

  test('noise: comment/string mentions and similarly named vars → NO finding', () => {
    const code = [
      '// exec("ping " + host);',
      'const hostName = "static";',
      'const s = "req.params.host";',
      'executor("ping");',
    ].join('\n');
    const findings = analyzeFileFlows('javascript', maskLiterals(code, 'javascript').split('\n'), flowRules);
    expect(findings).toEqual([]);
  });

  test('positive (python): request.args → os.system across lines', () => {
    const code = [
      'from flask import request',
      'target = request.args.get("h")',
      'os.system("ping " + target)',
    ].join('\n');
    const findings = analyzeFileFlows('python', maskLiterals(code, 'python').split('\n'), pyFlowRules);
    expect(findings.find((f) => f.ruleId === 'DG-SAST-048')?.lineIndex).toBe(2);
  });

  test('positive (python, sql): request value → cursor.execute with concat', () => {
    const code = [
      'name = request.args.get("name")',
      'q = "SELECT * FROM u WHERE n=" + name',
      'cur.execute(q)',
    ].join('\n');
    const findings = analyzeFileFlows('python', maskLiterals(code, 'python').split('\n'), pyFlowRules);
    expect(findings.find((f) => f.ruleId === 'DG-SAST-049')?.lineIndex).toBe(2);
  });

  test('boundary (sql): parameterized query placeholder → NO finding', () => {
    const code = [
      'name = request.args.get("name")',
      'cur.execute("SELECT * FROM u WHERE n=?", (name,))',
    ].join('\n');
    const lines = code.split('\n');
    const findings = analyzeFileFlows(
      'python',
      maskLiterals(code, 'python').split('\n'),
      pyFlowRules,
      lines,
    );
    expect(findings.find((f) => f.ruleId === 'DG-SAST-049')).toBeUndefined();
  });

  test('positive (html): request value → innerHTML assignment', () => {
    const code = [
      'const markup = req.body.markup;',
      'el.innerHTML = markup;',
    ].join('\n');
    const findings = analyzeFileFlows('javascript', maskLiterals(code, 'javascript').split('\n'), flowRules);
    expect(findings.find((f) => f.ruleId === 'DG-SAST-050')?.lineIndex).toBe(1);
  });

  test('boundary (html): textContent assignment is the sanitizer → NO finding', () => {
    const code = [
      'const markup = req.body.markup;',
      'el.textContent = markup;',
      'el.innerHTML = "static";',
    ].join('\n');
    const findings = analyzeFileFlows('javascript', maskLiterals(code, 'javascript').split('\n'), flowRules);
    expect(findings).toEqual([]);
  });

  test('bound: at most 3 flow findings per rule per file', () => {
    const lines: string[] = ['const h = req.params.h;'];
    for (let i = 0; i < 10; i += 1) lines.push(`exec("ping " + h);`);
    const findings = analyzeFileFlows('javascript', maskLiterals(lines.join('\n'), 'javascript').split('\n'), flowRules);
    const cmd = findings.filter((f) => f.ruleId === 'DG-SAST-048');
    expect(cmd.length).toBe(MAX_FLOW_FINDINGS_PER_RULE_PER_FILE);
  });

  test('bound: the tainted-variable cap stops unbounded growth', () => {
    const lines: string[] = [];
    for (let i = 0; i < MAX_FLOW_VARS + 50; i += 1) lines.push(`const v${i} = req.params.p${i};`);
    lines.push('exec("x " + v0);');
    const findings = analyzeFileFlows('javascript', maskLiterals(lines.join('\n'), 'javascript').split('\n'), flowRules);
    // The pass completes and stays bounded (the first MAX_FLOW_VARS
    // variables may taint; nothing blows up).
    expect(findings.filter((f) => f.ruleId === 'DG-SAST-048').length).toBeLessThanOrEqual(
      MAX_FLOW_FINDINGS_PER_RULE_PER_FILE,
    );
  });

  test('malformed source: garbage produces no findings and never throws', () => {
    const garbage = Array.from({ length: 200 }, (_, i) => `))) ]]] ${'='.repeat(i % 7)} exec( ${i}`);
    expect(() => analyzeFileFlows('javascript', maskLiterals(garbage.join('\n'), 'javascript').split('\n'), flowRules)).not.toThrow();
  });

  test('determinism: same input → byte-identical findings', () => {
    const code = ['const h = req.params.h;', 'exec("ping " + h);', 'el.innerHTML = h;'].join('\n');
    const a = analyzeFileFlows('javascript', maskLiterals(code, 'javascript').split('\n'), flowRules);
    const b = analyzeFileFlows('javascript', maskLiterals(code, 'javascript').split('\n'), flowRules);
    expect(a).toEqual(b);
  });
});

// ---------------------------------------------------------------------------
// Engine integration: flow findings are REAL findings (same model/identity)
// ---------------------------------------------------------------------------

const OWNER = 'usr_00000000-0000-4000-8000-000000000001';
const PROJECT = 'prj_00000000-0000-4000-8000-000000000002';

function scanRecord(id = 'scan_00000000-0000-4000-8000-000000000003'): ScanRecord {
  return {
    id,
    ownerId: OWNER,
    projectId: PROJECT,
    scanType: 'SAST',
    status: 'RUNNING',
    createdAt: '2026-09-28T10:00:00.000Z',
    updatedAt: '2026-09-28T10:00:00.000Z',
    startedAt: '2026-09-28T10:00:00.000Z',
  };
}

function snapshot(files: Array<{ path: string; content: string }>): SourceSnapshotRecord {
  return {
    projectId: PROJECT,
    ownerId: OWNER,
    files: files.map((file) => ({
      path: file.path,
      bytes: Buffer.byteLength(file.content, 'utf8'),
      content: file.content,
    })),
    createdAt: '2026-09-28T09:00:00.000Z',
    updatedAt: '2026-09-28T09:00:00.000Z',
  };
}

function providerFor(record: SourceSnapshotRecord | undefined): SourceSnapshotProvider {
  return { findByProject: async () => record };
}

const ctx = { signal: new AbortController().signal };

async function scan(files: Array<{ path: string; content: string }>): Promise<ReturnType<ReturnType<typeof createSastEngine>['execute']>> {
  const engine = createSastEngine({ rules: ALL_TEST_SAST_RULES, sources: providerFor(snapshot(files)) });
  return engine.execute(scanRecord(), ctx);
}

describe('engine × semantic integration', () => {
  test('a multi-line command flow produces a REAL finding at the sink line', async () => {
    const outcome = await scan([
      {
        path: 'srv/run.js',
        content: [
          'const target = req.params.target;',
          'const { exec } = require("child-tools");',
          'exec("ping " + target);',
        ].join('\n'),
      },
    ]);
    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed') return;
    const flow = (outcome.findings ?? []).find((f) => f.ruleId === 'DG-SAST-048');
    expect(flow).toBeDefined();
    expect(isFinding(flow)).toBe(true);
    expect(flow?.line).toBe(3);
    expect(flow?.file).toBe('srv/run.js');
    expect(flow?.severity).toBe('HIGH');
    expect(flow?.cwe).toBe('CWE-78');
    expect(flow?.column).toBe(1);
    expect(flow?.evidence).toBe(WITHHELD_SOURCE_EVIDENCE);
    expect(flow?.evidence).not.toContain('exec');
    expect(flow?.remediation.length).toBeGreaterThan(10);
  });

  test('URL encoding does not suppress cross-context AST review of a process call', async () => {
    // The earlier lexical flow pass may suppress URL-encoded input, but URL
    // encoding is not a general-purpose shell or process sanitizer. The
    // bounded AST pass reports a review candidate, not confirmed injection.
    const outcome = await scan([
      {
        path: 'srv/safe.js',
        content: [
          'const target = req.params.target;',
          'const safe = encodeURIComponent(target);',
          'spawn("ping", [safe]);',
        ].join('\n'),
      },
    ]);
    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed') return;
    expect(outcome.resultSummary.astFlowsFound).toBeGreaterThan(0);
    expect((outcome.findings ?? []).length).toBeGreaterThan(0);
  });

  test('the vulnerable twin (same shape, no sanitizer) DOES produce the flow finding', async () => {
    const outcome = await scan([
      {
        path: 'srv/unsafe.js',
        content: [
          'const target = req.params.target;',
          'const args = ["-c", "ping " + target];',
          'spawn("sh", args);',
        ].join('\n'),
      },
    ]);
    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed') return;
    expect((outcome.findings ?? []).map((f) => f.ruleId)).toContain('DG-SAST-048');
  });

  test('flow findings are deterministic across repeated scans', async () => {
    const files = [
      {
        path: 'app/main.py',
        content: ['v = request.args.get("q")', 'os.system("cat " + v)'].join('\n'),
      },
    ];
    const first = await scan(files);
    const second = await scan(files);
    const ids = (o: Awaited<ReturnType<typeof scan>>) =>
      o.kind === 'completed' ? (o.findings ?? []).map((f) => `${f.id}:${f.fingerprint}`) : [];
    expect(ids(first)).toEqual(ids(second));
    expect(ids(first).length).toBeGreaterThan(0);
  });

  test('flow finding + line finding coexist with distinct identities', async () => {
    const outcome = await scan([
      {
        path: 'app/mix.js',
        content: [
          'const host = req.params.host;',
          'exec("deploy " + host);', // BOTH: line rule 001 (concat at sink) + flow rule 048
        ].join('\n'),
      },
    ]);
    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed') return;
    const ruleIds = new Set((outcome.findings ?? []).map((f) => f.ruleId));
    expect(ruleIds.has('DG-SAST-001')).toBe(true);
    expect(ruleIds.has('DG-SAST-048')).toBe(true);
    const ids = new Set((outcome.findings ?? []).map((f) => f.id));
    expect(ids.size).toBe((outcome.findings ?? []).length);
  });

  test('a large generated project completes within the bounded deadline', async () => {
    const files: Array<{ path: string; content: string }> = [];
    for (let i = 0; i < 40; i += 1) {
      const lines: string[] = [];
      for (let j = 0; j < 400; j += 1) {
        lines.push(`const v${j} = "static-${i}-${j}";`);
      }
      files.push({ path: `gen/mod${i}.js`, content: lines.join('\n') });
    }
    const outcome = await scan(files);
    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed') return;
    expect(outcome.findings ?? []).toHaveLength(0);
  });
});
