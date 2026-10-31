import { describe, expect, test } from 'vitest';
import { isFinding, isScanResultSummary } from '@drobon/shared';
import { astProfileFor } from '../src/scans/sast/astProfiles.js';
import { astReporterRules } from '../src/scans/sast/astAnalyzer.js';
import { analyzePolyglotAst } from '../src/scans/sast/polyglotAst.mjs';
import { analyzeProjectAst } from '../src/scans/sast/projectAst.mjs';
import { analyzeStructuredAst } from '../src/scans/sast/structuredAst.mjs';
import { createSastEngine } from '../src/scans/sast/engine.js';
import { effectiveSastRuleDigest } from '../src/scans/sast/astCoverage.js';
import { convertSastPackToRule } from '../src/external/packProvider.js';
import { StructuredAstSession, STRUCTURED_AST_MAX_WORKERS, STRUCTURED_AST_MAX_WAITERS } from '../src/scans/sast/structuredAstSession.js';
import type { SastRule } from '../src/scans/sast/rules.js';
import type { ScanRecord } from '../src/scans/store.js';
import type { SourceSnapshotRecord } from '../src/scans/sources.js';

const REPORTERS = { command: 'DG-SAST-001', code: 'DG-SAST-002', sql: 'DG-SAST-003', html: 'DG-SAST-004' };
const OWNER = 'usr_00000000-0000-4000-8000-000000000001';
const PROJECT = 'prj_00000000-0000-4000-8000-000000000002';
const SCAN = 'scan_00000000-0000-4000-8000-000000000003';
const AT = '2026-10-28T10:00:00.000Z';
const SIGNAL = new AbortController().signal;
const RULE: SastRule = {
  id: 'DG-SAST-001', title: 'Specific test command rule', description: 'This specific rule pattern did not match.',
  severity: 'HIGH', cwe: 'CWE-78', category: 'command-injection', remediation: 'Specific rule remediation.',
  limitation: 'Fixture only.', patterns: [/never-match-fixture/], languages: ['javascript', 'typescript'],
};
const record: ScanRecord = { id: SCAN, ownerId: OWNER, projectId: PROJECT, scanType: 'SAST', status: 'RUNNING', createdAt: AT, updatedAt: AT, startedAt: AT };

function profile(family: string) {
  const value = astProfileFor(family);
  if (value === undefined) throw new Error('Missing fixture profile.');
  return value;
}
function file(path: string, content: string) {
  return { path, content, bytes: Buffer.byteLength(content, 'utf8') };
}
function snapshot(files: ReturnType<typeof file>[]): SourceSnapshotRecord {
  return { ownerId: OWNER, projectId: PROJECT, files, createdAt: AT, updatedAt: AT };
}
async function scan(files: ReturnType<typeof file>[], rules: readonly SastRule[] = [RULE]) {
  return await createSastEngine({ sources: { findByProject: async () => snapshot(files) }, rules }).execute(record, { signal: SIGNAL });
}
function projectFile(path: string, content: string) {
  return { path, content, family: 'javascript', profile: profile('javascript'), reporters: REPORTERS };
}

// Labeled examples are deliberately small synthetic fixtures. These are not a
// representative production benchmark and cannot measure real-world recall.
const corpus: Array<{ name: string; family: string; vulnerable: boolean; content: string }> = [
  { name: 'JS destructured command', family: 'javascript', vulnerable: true, content: 'const {cmd} = req.body;\nchild_process["exec"](cmd);' },
  { name: 'JS interpolated SQL', family: 'javascript', vulnerable: true, content: 'const {name} = req.body;\ndb.query(`SELECT * FROM u WHERE n = ${name}`);' },
  { name: 'JSX raw HTML', family: 'jsx', vulnerable: true, content: 'const {html} = req.body;\nconst v=<div dangerouslySetInnerHTML={{__html: html}}/>;' },
  { name: 'JS comment and string', family: 'javascript', vulnerable: false, content: '// child_process.exec(req.body.cmd)\nconst x="exec(req.body.cmd)";' },
  { name: 'JS SQL parameter array', family: 'javascript', vulnerable: false, content: 'const {name}=req.body;\ndb.query("SELECT * FROM u WHERE name = ?", [name]);' },
  { name: 'JS separate scopes', family: 'javascript', vulnerable: false, content: 'function a(){const x=req.body.cmd;}\nfunction b(){child_process.exec(x);}' },
  { name: 'Python Flask command', family: 'python', vulnerable: true, content: 'from flask import request\nimport os\ncmd=request.args.get("cmd")\nos.system(cmd)' },
  { name: 'Python interpolated SQL', family: 'python', vulnerable: true, content: 'from flask import request\nname=request.args.get("name")\ncursor.execute(f"SELECT * FROM users WHERE n={name}")' },
  { name: 'Python input command', family: 'python', vulnerable: true, content: 'import os\nos.system(input())' },
  { name: 'Python comment and string', family: 'python', vulnerable: false, content: '# os.system(request.args)\ns = "os.system(request.args)"' },
  { name: 'Python SQL parameters', family: 'python', vulnerable: false, content: 'name=request.args.get("name")\ncursor.execute("SELECT * FROM users WHERE n=?", [name])' },
  { name: 'Python separate scopes', family: 'python', vulnerable: false, content: 'def a():\n  x=request.args.get("x")\ndef b():\n  os.system(x)' },
  { name: 'PHP command', family: 'php', vulnerable: true, content: '<?php\n$cmd = $_GET["cmd"];\nshell_exec($cmd);' },
  { name: 'PHP SQL concatenation', family: 'php', vulnerable: true, content: '<?php\n$name = $_POST["name"];\n$db->query("SELECT * FROM users WHERE n=" . $name);' },
  { name: 'PHP raw echo', family: 'php', vulnerable: true, content: '<?php\n$input = $_GET["x"];\necho $input;' },
  { name: 'PHP comment and string', family: 'php', vulnerable: false, content: '<?php\n// shell_exec($_GET["cmd"]);\n$note="shell_exec($_GET)";' },
  { name: 'PHP constant command', family: 'php', vulnerable: false, content: '<?php\nshell_exec("uptime");' },
  { name: 'PHP separate scopes', family: 'php', vulnerable: false, content: '<?php\nfunction a(){ $x=$_GET["x"]; }\nfunction b(){ shell_exec($x); }' },
  { name: 'Java request command', family: 'java', vulnerable: true, content: 'class H { void h(HttpServletRequest request) { String cmd=request.getParameter("c"); Runtime.getRuntime().exec(cmd); }}' },
  { name: 'Java SQL concatenation', family: 'java', vulnerable: true, content: 'class H { void h(HttpServletRequest request) { String name=request.getParameter("n"); db.executeQuery("SELECT " + name); }}' },
  { name: 'Java raw output', family: 'java', vulnerable: true, content: 'class H { void h(HttpServletRequest request) { String html=request.getParameter("n"); out.print(html); }}' },
  { name: 'Java constant string', family: 'java', vulnerable: false, content: 'class H { void h() { String note="Runtime.exec(request.getParameter)"; }}' },
  { name: 'Java constant command', family: 'java', vulnerable: false, content: 'class H { void h() { Runtime.getRuntime().exec("uptime"); }}' },
  { name: 'Java separate scopes', family: 'java', vulnerable: false, content: 'class H { void a(HttpServletRequest request){ String x=request.getParameter("x"); } void b(){ Runtime.getRuntime().exec(x); }}' },
];

describe('labeled, synthetic syntax-tree corpus', () => {
  test.each(corpus)('$name', ({ family, vulnerable, content }) => {
    const input = { family, content, profile: profile(family), reporters: REPORTERS };
    const result = ['javascript', 'typescript', 'jsx', 'tsx'].includes(family)
      ? analyzeStructuredAst(input) : analyzePolyglotAst(input);
    expect(result.status).toBe('OK');
    expect(result.candidates.length > 0).toBe(vulnerable);
  });

  test('fixture composition is visible: 12 positives and 12 negatives', () => {
    expect(corpus.filter((item) => item.vulnerable)).toHaveLength(12);
    expect(corpus.filter((item) => !item.vulnerable)).toHaveLength(12);
  });

  test.each([
    ['python', 'value = ('],
    ['php', '<?php $value = ;'],
    ['java', 'class X { void f( { }'],
  ])('%s syntax failures are never reported as complete', (family, content) => {
    const result = analyzePolyglotAst({ family, content, profile: profile(family), reporters: REPORTERS });
    expect(result.status).toBe('SYNTAX_ERROR');
    expect(result.candidates).toEqual([]);
  });

  test('the Python grammar pass does not pretend to perform interprocedural analysis', () => {
    const content = 'def run(cmd):\n  os.system(cmd)\nrun(request.args["cmd"])';
    const result = analyzePolyglotAst({ family: 'python', content, profile: profile('python'), reporters: REPORTERS });
    expect(result.status).toBe('OK');
    expect(result.candidates).toEqual([]);
  });
});

describe('published training-app excerpts and adapted controls', () => {
  // PyGoat (MIT, copyright 2020 pygoat), excerpted from command/sql labs at
  // github.com/adeyosemanputra/pygoat commit 46fef968f3f44d1191363baf936aaa3335dc5c6d.
  // NodeGoat (Apache-2.0), excerpted from app/routes/contributions.js at
  // github.com/OWASP/NodeGoat commit c5cb68a7084e4ae7dcc60e6a98768720a81841e8.
  // Licenses are preserved in test/fixtures/ast/licenses. These are deliberately
  // vulnerable training apps, NOT representative production measurements.
  const examples = [
    { name: 'PyGoat command lab', family: 'python', vulnerable: true, content: `from flask import request\nimport subprocess\ndef lab1():\n    domain = request.form.get("domain", "")\n    command = f"dig {domain}"\n    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)\n` },
    { name: 'PyGoat SQL test lab', family: 'python', vulnerable: true, content: `from flask import request\ndef lab():\n    username = request.form.get("username", "")\n    password = request.form.get("password", "")\n    sql_query = (f"SELECT * FROM users WHERE username='{username}' AND password='{password}'")\n    result = c.execute(sql_query).fetchone()\n` },
    { name: 'NodeGoat eval route', family: 'javascript', vulnerable: true, content: `this.handleContributionsUpdate = (req, res, next) => {\n    const preTax = eval(req.body.preTax);\n    const afterTax = eval(req.body.afterTax);\n    const roth = eval(req.body.roth);\n};` },
    { name: 'adapted SQL parameters', family: 'python', vulnerable: false, content: `from flask import request\ndef lab():\n    username = request.form.get("username", "")\n    c.execute("SELECT * FROM users WHERE username=?", [username])\n` },
    { name: 'NodeGoat commented parseInt alternative', family: 'javascript', vulnerable: false, content: `this.handleContributionsUpdate = (req, res, next) => {\n    const preTax = parseInt(req.body.preTax);\n    const afterTax = parseInt(req.body.afterTax);\n    const roth = parseInt(req.body.roth);\n};` },
    // No shell-string interpolation; the heuristic still flags untrusted argv.
    // Argument-level risks depend on the called program, so this is a review
    // candidate even though it is a false positive for this shell-injection label.
    { name: 'adapted shell-false argument array', family: 'python', vulnerable: false, content: `from flask import request\nimport subprocess\ndef lab1():\n    domain = request.form.get("domain", "")\n    subprocess.run(["dig", domain], shell=False)\n` },
  ];
  test('records the small sample confusion matrix, including a known over-report', () => {
    let tp = 0; let fp = 0; let tn = 0; let fn = 0;
    for (const item of examples) {
      const input = { family: item.family, content: item.content, profile: profile(item.family), reporters: REPORTERS };
      const result = item.family === 'python' ? analyzePolyglotAst(input) : analyzeStructuredAst(input);
      expect(result.status, item.name).toBe('OK');
      const found = result.candidates.length > 0;
      if (item.vulnerable && found) tp += 1;
      else if (item.vulnerable) fn += 1;
      else if (found) fp += 1;
      else tn += 1;
    }
    expect({ tp, fp, tn, fn }).toEqual({ tp: 3, fp: 1, tn: 2, fn: 0 });
  });
});

describe('bounded project flow and scan-time facts', () => {
  test('resolves multiple named relative imports and records source, calls and sink', async () => {
    const files = [
      file('src/handler.js', 'import {middle} from "./middle";\nexport function handle(req){middle(req.body.cmd);}'),
      file('src/middle.js', 'import {run} from "./runner";\nexport function middle(x){run(x);}'),
      file('src/runner.js', 'export function run(y){child_process.exec(y);}'),
    ];
    const result = await scan(files);
    if (result.kind !== 'completed') throw new Error('Scan did not complete.');
    expect(isScanResultSummary(result.resultSummary)).toBe(true);
    expect(result.resultSummary.partial).toBe(true); // only command category has a reporter
    expect(result.resultSummary.astCoverage?.projectFlow).toEqual({ status: 'RAN', examinedFiles: 3, unresolvedImports: 0, findings: 1 });
    expect(result.resultSummary.astCoverage?.families).toEqual([{ family: 'javascript', reporters: { command: RULE.id } }]);
    expect(result.resultSummary.astCoverage?.rules).toMatchObject({ source: 'EXPLICIT', count: 1, sha256: effectiveSastRuleDigest([RULE]) });
    expect(result.resultSummary.astCoverage?.parsers.python).toMatch(/^\d/);
    expect(result.findings).toHaveLength(1);
    const finding = result.findings?.[0];
    if (finding === undefined || finding.scanner === 'DAST') throw new Error('Missing source finding.');
    expect(isFinding(finding)).toBe(true);
    expect(finding.file).toBe('src/runner.js');
    expect(finding.astFlow).toMatchObject({ mode: 'PROJECT', category: 'command', attribution: 'CATEGORY_REPORTER', source: { file: 'src/handler.js', line: 2 } });
    expect(finding.astFlow?.via?.map((step) => step.file)).toEqual(['src/handler.js', 'src/middle.js']);
    expect(finding.title).toContain('AST heuristic');
    expect(finding.title).not.toBe(RULE.title);
    expect(finding.description).toContain('not by its exact pattern');
    expect(finding.description).toContain('argument-vector');
    expect(finding.description).toContain('does not prove shell execution');
    expect(finding.cwe).toBeUndefined();
  });

  test('missing virtual imports and missing categories are visible, without resolving host files', async () => {
    const result = await scan([file('src/a.js', 'import {run} from "../not-uploaded";\nrun(req.body.x);')]);
    if (result.kind !== 'completed') throw new Error('Scan did not complete.');
    expect(result.resultSummary.astCoverage?.projectFlow).toMatchObject({ status: 'INCOMPLETE', unresolvedImports: 1 });
    expect(result.resultSummary.partial).toBe(true);
    expect(result.resultSummary.partialReason).toContain('Project flow');
    expect(isScanResultSummary(result.resultSummary)).toBe(true);
  });

  test('files exceeding the project file cap make project analysis incomplete', () => {
    const files = Array.from({ length: 65 }, (_, index) => projectFile(`f${index}.js`, 'const value = 1;'));
    const result = analyzeProjectAst({ files });
    expect(result.status).toBe('LIMIT');
    expect(result.examinedFiles).toBe(64);
    expect(result.candidates).toEqual([]);
  });

  test('constant arguments do not produce a project flow; SQL parameter arrays remain suppressed', () => {
    const files = [projectFile('x.js', 'function run(x){child_process.exec(x);}\nrun("uptime");\nconst x=req.body.name; db.query("SELECT ?", [x]);')];
    expect(analyzeProjectAst({ files }).candidates).toEqual([]);
  });

  test('normalizes dataset metadata and evidence to persisted finding bounds', async () => {
    const raw = {
      schemaVersion: 'drobon.pack.sast/v1', id: 'DPK-SAST-043', title: `${'Long title '.repeat(15)}😀`,
      description: `${'Description '.repeat(45)}\n`, severity: 'HIGH', cwe: 'CWE-invalid',
      category: 'command-injection', remediation: '', limitation: 'Fixture only',
      languages: ['javascript'], patterns: [{ source: 'exec\\(' }],
    };
    const rule = convertSastPackToRule(raw);
    expect(rule).toBeDefined();
    expect(rule?.title.length).toBeLessThanOrEqual(80);
    expect(rule?.title.endsWith('…')).toBe(true);
    expect(rule?.description.length).toBeLessThanOrEqual(400);
    expect(rule?.description.endsWith('…')).toBe(true);
    expect(rule?.cwe).toBeUndefined();
    expect(rule?.remediation).toContain('not provided');
    expect(convertSastPackToRule({ ...raw, id: 'DPK-SAST-1' })).toBeUndefined();
    expect(convertSastPackToRule({ ...raw, patterns: [null] })).toBeUndefined();
    expect(convertSastPackToRule({ ...raw, patterns: [{ source: 'exec', flags: 'g' }] })).toBeUndefined();
    expect(convertSastPackToRule({ ...raw, severity: 'EXTREME' })).toBeUndefined();
    const result = await scan([file('src/main.js', 'exec(\rreq.body.cmd);\n')], [rule!]);
    expect(result.kind).toBe('completed');
    if (result.kind !== 'completed') throw new Error('Expected a completed scan.');
    expect(result.findings?.length).toBeGreaterThan(0);
    expect(result.findings?.every(isFinding)).toBe(true);
    expect(result.findings?.[0]?.evidence).not.toContain('\r');
    expect(result.resultSummary.astCoverage?.rules.sha256).toBe(effectiveSastRuleDigest([rule!]));
  });

  test('rule classification is exact, deterministic and language-gated', () => {
    expect(astReporterRules([{ ...RULE, category: 'nosql-injection' }], 'javascript')).toEqual({});
    expect(astReporterRules([{ ...RULE, category: 'unrelated-command-logging' }], 'javascript')).toEqual({});
    expect(astReporterRules([RULE], 'python')).toEqual({});
    expect(astReporterRules([{ ...RULE, id: 'DG-SAST-009' }, RULE], 'javascript')).toEqual({ command: RULE.id });
    expect(effectiveSastRuleDigest([RULE])).not.toBe(effectiveSastRuleDigest([{ ...RULE, patterns: [/different/] }]));
    expect(effectiveSastRuleDigest([RULE, { ...RULE, id: 'DG-SAST-002' }])).toBe(effectiveSastRuleDigest([{ ...RULE, id: 'DG-SAST-002' }, RULE]));
  });
});

describe('bounded worker scheduling', () => {
  test('a waiting scan gets a released worker rather than immediately failing', async () => {
    const input = { family: 'javascript', content: 'const value=1;', profile: profile('javascript'), reporters: REPORTERS };
    const sessions = Array.from({ length: STRUCTURED_AST_MAX_WORKERS + 1 }, () => new StructuredAstSession());
    try {
      const initial = sessions.slice(0, STRUCTURED_AST_MAX_WORKERS).map((session) => session.analyze(input, SIGNAL, 5_000));
      await Promise.all(initial);
      const waiting = sessions[STRUCTURED_AST_MAX_WORKERS];
      const released = sessions[0];
      if (!waiting || !released) throw new Error('Session fixture missing.');
      const queued = waiting.analyze(input, SIGNAL, 5_000);
      await released.close();
      expect((await queued).status).toBe('OK');
    } finally { await Promise.all(sessions.map((session) => session.close())); }
  });

  test('queue cancellation and excess capacity remain bounded', async () => {
    const input = { family: 'javascript', content: 'const value=1;', profile: profile('javascript'), reporters: REPORTERS };
    const sessions = Array.from({ length: STRUCTURED_AST_MAX_WORKERS + STRUCTURED_AST_MAX_WAITERS + 1 }, () => new StructuredAstSession());
    try {
      await Promise.all(sessions.slice(0, STRUCTURED_AST_MAX_WORKERS).map((session) => session.analyze(input, SIGNAL, 5_000)));
      const controller = new AbortController();
      const queued = sessions.slice(STRUCTURED_AST_MAX_WORKERS, STRUCTURED_AST_MAX_WORKERS + STRUCTURED_AST_MAX_WAITERS)
        .map((session) => session.analyze(input, controller.signal, 5_000));
      const overflow = sessions[sessions.length - 1];
      if (!overflow) throw new Error('Session fixture missing.');
      expect((await overflow.analyze(input, SIGNAL, 5_000)).status).toBe('UNAVAILABLE');
      controller.abort();
      expect((await Promise.all(queued)).every((result) => result.status === 'ABORTED')).toBe(true);
    } finally { await Promise.all(sessions.map((session) => session.close())); }
  });
});
