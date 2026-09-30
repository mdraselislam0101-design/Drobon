import { describe, expect, test } from 'vitest';
import type { ScanRecord } from '../src/scans/store.js';
import type { SourceSnapshotRecord } from '../src/scans/sources.js';
import { createSastEngine, type SourceSnapshotProvider } from '../src/scans/sast/engine.js';
import {
  SAST_LANGUAGE_CATALOG,
  sastMaturityCounts,
  detectLanguageFamily,
  detectFrameworks,
  isAnalyzedMaturity,
} from '../src/scans/sast/languages.js';
import { SAST_RULES, sastRuleById } from '../src/scans/sast/rules.js';
import type { Finding } from '@drobon/shared';

/**
 * UNIVERSAL SAST (v2) — the 40+ language/configuration expansion:
 *
 * - catalog integrity (honest maturity model, stable rule gating);
 * - detection (extension, filename, shebang, documented content
 *   tie-breaks);
 * - ONE positive synthetic fixture per rule across every implemented
 *   language family, scanned in a single POLYGLOT snapshot;
 * - negative/safety shapes (conservative rules, malformed/unknown
 *   sources fail honestly, no guessing);
 * - framework detection over manifests;
 * - fingerprint stability for the new families.
 */

const OWNER = 'usr_00000000-0000-4000-8000-000000000011';
const PROJECT = 'prj_00000000-0000-4000-8000-000000000012';

function scanRecord(id = 'scan_00000000-0000-4000-8000-000000000013'): ScanRecord {
  return {
    id,
    ownerId: OWNER,
    projectId: PROJECT,
    scanType: 'SAST',
    status: 'RUNNING',
    createdAt: '2026-09-30T10:00:00.000Z',
    updatedAt: '2026-09-30T10:00:00.000Z',
    startedAt: '2026-09-30T10:00:00.000Z',
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
    createdAt: '2026-09-30T09:00:00.000Z',
    updatedAt: '2026-09-30T09:00:00.000Z',
  };
}

function providerFor(record: SourceSnapshotRecord | undefined): SourceSnapshotProvider {
  return { findByProject: async () => record };
}

const ctx = { signal: new AbortController().signal };

async function scan(files: Array<{ path: string; content: string }>) {
  const engine = createSastEngine({ sources: providerFor(snapshot(files)) });
  const outcome = await engine.execute(scanRecord(), ctx);
  if (outcome.kind !== 'completed') throw new Error(`expected completion, got ${outcome.kind}`);
  return outcome;
}

describe('SAST v2 catalog integrity', () => {
  test('the catalog is honest: 40+ families, FULL reached by none, counts derived', () => {
    const counts = sastMaturityCounts();
    expect(counts.total).toBeGreaterThanOrEqual(40);
    expect(counts.full).toBe(0); // no parser/AST/dataflow engine exists — FULL is never faked
    expect(counts.partial).toBeGreaterThanOrEqual(25);
    expect(counts.configAnalysis).toBeGreaterThanOrEqual(7);
    expect(counts.unsupported).toBeGreaterThanOrEqual(5);
    // Derived counts agree with a direct iteration (no hand-written numbers).
    let direct = 0;
    for (const family of SAST_LANGUAGE_CATALOG) {
      direct += 1;
      expect(['FULL', 'PARTIAL', 'SYNTAX_ONLY', 'CONFIG_ANALYSIS', 'UNSUPPORTED']).toContain(family.maturity);
      expect(family.platforms.length).toBeGreaterThan(0);
      expect(family.note.length).toBeGreaterThan(10);
    }
    expect(direct).toBe(counts.total);
  });

  test('every PARTIAL family has a dedicated rule; every CONFIG family has at least the universal analysis', () => {
    for (const family of SAST_LANGUAGE_CATALOG) {
      if (family.maturity === 'PARTIAL') {
        const covered = SAST_RULES.some((rule) => rule.languages?.includes(family.id));
        expect(covered, `PARTIAL family ${family.id} must have a dedicated rule`).toBe(true);
      }
      if (family.maturity === 'CONFIG_ANALYSIS') {
        const covered = SAST_RULES.some(
          (rule) => rule.languages === undefined || rule.languages.includes(family.id),
        );
        expect(covered, `CONFIG_ANALYSIS family ${family.id} must be analyzable`).toBe(true);
      }
    }
  });

  test('every rule is well-formed and only references catalogued families', () => {
    const familyIds = new Set(SAST_LANGUAGE_CATALOG.map((family) => family.id));
    const ids = new Set<string>();
    for (const rule of SAST_RULES) {
      expect(ids.has(rule.id)).toBe(false); // ids are unique — never reused
      ids.add(rule.id);
      expect(rule.id).toMatch(/^DG-SAST-\d{3}$/);
      for (const family of rule.languages ?? []) {
        expect(familyIds.has(family), `rule ${rule.id} references unknown family ${family}`).toBe(true);
      }
      for (const pattern of rule.patterns) {
        expect(pattern.global).toBe(false); // no stateful flags
        expect(pattern.sticky).toBe(false);
      }
      expect(sastRuleById(rule.id)).toBe(rule);
    }
    expect(SAST_RULES.length).toBeGreaterThanOrEqual(46);
  });

  test('the legacy v1 six rules remain present and JS/TS-scoped', () => {
    for (const id of ['DG-SAST-001', 'DG-SAST-002', 'DG-SAST-003', 'DG-SAST-004', 'DG-SAST-006']) {
      const rule = sastRuleById(id);
      expect(rule).toBeDefined();
      expect(rule?.languages).toEqual(['javascript', 'typescript', 'jsx', 'tsx']);
    }
    expect(sastRuleById('DG-SAST-005')?.languages).toBeUndefined(); // universal credential heuristic
  });
});

describe('SAST v2 language detection', () => {
  test('extensions, filenames and shebangs resolve deterministically', () => {
    expect(detectLanguageFamily('src/app.ts')?.family).toBe('typescript');
    expect(detectLanguageFamily('src/app.JS')?.family).toBe('javascript'); // case-insensitive
    expect(detectLanguageFamily('lib/main.dart')?.family).toBe('dart');
    expect(detectLanguageFamily('Dockerfile')?.family).toBe('dockerfile');
    expect(detectLanguageFamily('deploy.Dockerfile')?.family).toBe('dockerfile');
    expect(detectLanguageFamily('app/src/main/AndroidManifest.xml')?.family).toBe('android-manifest');
    expect(detectLanguageFamily('Gemfile')?.family).toBe('ruby');
    expect(detectLanguageFamily('schema.sql')?.family).toBe('sql');
    expect(detectLanguageFamily('infra/main.tf')?.family).toBe('terraform');
    expect(detectLanguageFamily('run-tool', '#!/usr/bin/env python3\nimport os\n')?.family).toBe('python');
    expect(detectLanguageFamily('run-tool', '#!/bin/bash\nset -eu\n')?.family).toBe('bash');
    expect(detectLanguageFamily('Makefile')).toBeUndefined(); // unknown → honest refusal
    expect(detectLanguageFamily('notes.md')).toBeUndefined();
  });

  test('content tie-breaks: .m (Objective-C vs MATLAB) and YAML vs GitHub Actions', () => {
    expect(
      detectLanguageFamily('Native.m', '#import <Foundation/Foundation.h>\nNSLog(@"hi");\n')?.family,
    ).toBe('objc');
    expect(detectLanguageFamily('plot.m', '% plot the data\nfunction y = f(x)\n')?.family).toBe('matlab');
    expect(detectLanguageFamily('Native.m', 'int main(void) { return 0; }\n')?.family).toBe('objc'); // default reading
    const workflow = 'name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n';
    expect(detectLanguageFamily('ci/build.yml', workflow)?.family).toBe('github-actions');
    expect(detectLanguageFamily('ci/build.yml', 'services:\n  db:\n    image: pg\n    privileged: true\n')?.family).toBe('yaml');
  });
});

/**
 * ONE positive synthetic fixture per rule (v2): every implemented
 * language family, in a single POLYGLOT snapshot. All samples are
 * clearly synthetic (never executed, no real exploit material).
 */
const POLYGLOT: Array<{ path: string; content: string; ruleId: string }> = [
  { path: 'py/app.py', ruleId: 'DG-SAST-007', content: 'result = eval(f"total_{user_input}")\n' },
  { path: 'py/cmd.py', ruleId: 'DG-SAST-008', content: 'os.system(f"ping {host}")\nos.popen("ls " + d)\n' },
  { path: 'py/load.py', ruleId: 'DG-SAST-009', content: 'data = pickle.loads(blob)\nconf = yaml.load(raw)\n' },
  { path: 'py/hash.py', ruleId: 'DG-SAST-010', content: 'digest = hashlib.md5(data)\n' },
  { path: 'py/orm.py', ruleId: 'DG-SAST-011', content: 'rows = User.objects.raw(f"SELECT * FROM auth_user WHERE id = {uid}")\n' },
  { path: 'py/web.py', ruleId: 'DG-SAST-012', content: 'app.run(debug=True)\n' },
  { path: 'java/Tool.java', ruleId: 'DG-SAST-013', content: 'Process p = Runtime.getRuntime().exec("sh -c " + cmd);\n' },
  { path: 'java/Repo.java', ruleId: 'DG-SAST-014', content: 'ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE name=" + name);\n' },
  { path: 'java/Digest.java', ruleId: 'DG-SAST-015', content: 'MessageDigest md = MessageDigest.getInstance("MD5");\n' },
  { path: 'kotlin/Store.kt', ruleId: 'DG-SAST-016', content: 'val fos = openFileOutput("cfg.xml", Context.MODE_WORLD_READABLE)\n' },
  { path: 'kotlin/Bridge.kt', ruleId: 'DG-SAST-017', content: 'webView.settings.setJavaScriptEnabled(true)\n' },
  { path: 'native/buffer.c', ruleId: 'DG-SAST-018', content: 'strcpy(buffer, input);\n' },
  { path: 'cs/Launch.cs', ruleId: 'DG-SAST-019', content: 'Process.Start("cmd.exe", "/c " + arg);\n' },
  { path: 'cs/Query.cs', ruleId: 'DG-SAST-020', content: 'var command = new SqlCommand("SELECT * FROM Users WHERE Id=" + id, conn);\n' },
  { path: 'cs/Hash.cs', ruleId: 'DG-SAST-021', content: 'var hasher = MD5.Create();\n' },
  { path: 'vb/Shell.vb', ruleId: 'DG-SAST-022', content: 'Shell("notepad.exe " & filePath)\n' },
  { path: 'php/exec.php', ruleId: 'DG-SAST-023', content: '$out = shell_exec("ping " . $host);\n$raw = `dig $host`;\n' },
  { path: 'php/query.php', ruleId: 'DG-SAST-024', content: '$res = mysqli_query($conn, "SELECT * FROM u WHERE i=" . $id);\n' },
  { path: 'go/runner.go', ruleId: 'DG-SAST-025', content: 'exec.Command("sh", "-c", fmt.Sprintf("ping %s", host))\n' },
  { path: 'go/hash.go', ruleId: 'DG-SAST-026', content: 'h := md5.New()\n' },
  { path: 'ruby/task.rb', ruleId: 'DG-SAST-027', content: 'system("ping #{host}")\noutput = `ping #{host}`\n' },
  { path: 'rust/runner.rs', ruleId: 'DG-SAST-028', content: 'Command::new(format!("ping {}", host));\n' },
  { path: 'swift/Crypto.swift', ruleId: 'DG-SAST-029', content: 'CCCrypt(kCCAlgorithmDES, key, data)\nlet weak = Insecure.md5(data)\n' },
  { path: 'dart/runner.dart', ruleId: 'DG-SAST-030', content: 'await Process.run("ping " + host);\n' },
  { path: 'lua/runner.lua', ruleId: 'DG-SAST-031', content: 'os.execute("ping " .. host)\n' },
  { path: 'perl/task.pl', ruleId: 'DG-SAST-032', content: 'system("ping $host");\n' },
  { path: 'contracts/Vault.sol', ruleId: 'DG-SAST-033', content: 'target.delegatecall(payload);\n' },
  { path: 'scripts/deploy.sh', ruleId: 'DG-SAST-034', content: 'eval "curl $URL"\n' },
  { path: 'scripts/run.ps1', ruleId: 'DG-SAST-035', content: 'Invoke-Expression "ping $target"\n' },
  { path: 'apex/Query.cls', ruleId: 'DG-SAST-036', content: "Database.query('SELECT Id FROM Account' + whereClause);\n" },
  { path: 'lib/eval.ex', ruleId: 'DG-SAST-037', content: 'Code.eval_string(user_input)\n' },
  { path: 'src/ops.erl', ruleId: 'DG-SAST-037', content: 'os:cmd("ping " ++ Host)\n' },
  { path: 'analysis/plot.R', ruleId: 'DG-SAST-038', content: 'system(paste("ping", host))\n' },
  { path: 'scripts/run.jl', ruleId: 'DG-SAST-039', content: 'run(`ping $host`)\n' },
  { path: 'db/schema.sql', ruleId: 'DG-SAST-040', content: 'EXEC(@sql);\n' },
  { path: 'config/entities.xml', ruleId: 'DG-SAST-041', content: '<!ENTITY xxe SYSTEM "http://internal.synthetic.test/secret">\n' },
  { path: 'k8s/deploy.yaml', ruleId: 'DG-SAST-042', content: 'spec:\n  containers:\n    - securityContext:\n        privileged: true\n' },
  { path: 'ci/build.yml', ruleId: 'DG-SAST-043', content: 'name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\npermissions: write-all\n' },
  { path: 'Dockerfile', ruleId: 'DG-SAST-044', content: 'FROM alpine:3\nRUN curl https://cdn.synthetic.test/install.sh | sh\n' },
  { path: 'infra/main.tf', ruleId: 'DG-SAST-045', content: 'ingress {\n  cidr_blocks = ["0.0.0.0/0"]\n}\n' },
  { path: 'electron/main.js', ruleId: 'DG-SAST-046', content: 'new BrowserWindow({ webPreferences: { nodeIntegration: true } });\n' },
  { path: 'app/src/main/AndroidManifest.xml', ruleId: 'DG-SAST-047', content: '<activity android:name=".Main" android:exported="true">\n' },
];

describe('SAST v2 polyglot rule matrix', () => {
  test('one scan detects every implemented rule family across the polyglot snapshot', async () => {
    const outcome = await scan(POLYGLOT.map((file) => ({ path: file.path, content: file.content })));
    const findings = outcome.findings ?? [];
    const byRule = new Map<string, Finding[]>();
    for (const finding of findings) {
      byRule.set(finding.ruleId, [...(byRule.get(finding.ruleId) ?? []), finding]);
    }
    for (const file of POLYGLOT) {
      const hits = byRule.get(file.ruleId);
      expect(hits, `${file.ruleId} must fire on ${file.path}`).toBeDefined();
      expect(hits?.some((finding) => finding.file === file.path), `${file.ruleId} evidence on ${file.path}`).toBe(true);
    }
    // Every finding flows through the EXISTING finding model: rule id,
    // evidence, fingerprint, remediation — one lifecycle for all languages.
    for (const finding of findings) {
      expect(finding.scanner).toBe('SAST');
      expect(finding.fingerprint).toMatch(/^[0-9a-f]{64}$/);
      expect(finding.remediation.length).toBeGreaterThan(10);
      expect(finding.evidence.length).toBeGreaterThan(0);
      expect(finding.line).toBeGreaterThanOrEqual(1);
    }
    // Distinct languages produced findings in this one scan.
    const files = new Set(findings.map((finding) => finding.file));
    expect(files.size).toBeGreaterThanOrEqual(35);
  });

  test('polyglot summary is honest: analyzed files counted, unsupported skipped', async () => {
    const outcome = await scan([
      ...POLYGLOT.slice(0, 10).map((file) => ({ path: file.path, content: file.content })),
      { path: 'legacy/main.hs', content: 'main = putStrLn "hi"\n' },
      { path: 'legacy/core.asm', content: 'mov ax, 1\n' },
      { path: 'assets/style.css', content: 'body { color: red; }\n' },
      { path: 'README.md', content: '# docs\n' },
    ]);
    expect(outcome.resultSummary.filesScanned).toBe(10);
    expect(outcome.resultSummary.filesSkipped).toBe(4);
    expect(outcome.resultSummary.truncated).toBe(false);
  });

  test('findings from new languages carry the same severity contract as v1', async () => {
    const outcome = await scan(POLYGLOT.map((file) => ({ path: file.path, content: file.content })));
    const findings = outcome.findings ?? [];
    expect(sastRuleById('DG-SAST-007')?.severity).toBe('HIGH');
    expect(sastRuleById('DG-SAST-018')?.severity).toBe('MEDIUM');
    expect(sastRuleById('DG-SAST-010')?.severity).toBe('LOW');
    expect(sastRuleById('DG-SAST-043')?.severity).toBe('MEDIUM');
    const pyEval = findings.find((finding) => finding.ruleId === 'DG-SAST-007');
    expect(pyEval?.severity).toBe('HIGH');
    const mem = findings.find((finding) => finding.ruleId === 'DG-SAST-018');
    expect(mem?.severity).toBe('MEDIUM');
  });
});

describe('SAST v2 gating and conservative shapes', () => {
  test('family-scoped rules never fire on other languages (JS eval rule vs python backticks)', async () => {
    const outcome = await scan([
      // JS-shaped backtick interpolation inside a python file: the JS
      // rule is gated away, and no python rule matches this shape.
      { path: 'odd/py_style.py', content: 'x = eval(`val ${v}`)\n' },
      { path: 'ok/cmd.kt', content: 'eval(f"script {x}")\n' }, // python rule must NOT run on kotlin
    ]);
    expect(outcome.findings ?? []).toEqual([]);
  });

  test('conservative: safe forms do not fire', async () => {
    const outcome = await scan([
      { path: 'safe/app.py', content: 'value = eval("1 + 1")\nos.system("systemstatus")\nconf = yaml.load(raw, Loader=yaml.SafeLoader)\n' },
      { path: 'safe/app.js', content: 'const q = db.query("SELECT * FROM users WHERE id = ?", [id]);\n' },
      { path: 'safe/manifest.xml', content: '<activity android:name=".Hidden" android:exported="false">\n' },
    ]);
    expect(outcome.findings ?? []).toEqual([]);
  });

  test('malformed, unicode, minified and shebang-only sources behave honestly', async () => {
    const outcome = await scan([
      { path: 'broken/garbage.py', content: '))) ]]] }}}} @@@ ~~~\n' },
      { path: 'broken/binary.v', content: 'module m; endmodule\n' }, // unsupported family → skipped
      { path: 'uni/unicode.py', content: '× = 1\n结果 = eval(f"計算{用户}")\n' },
      { path: 'web/min.js', content: 'eval("a"+b);document.write("<i>"+x);\n' },
      { path: 'scripts/tool', content: '#!/usr/bin/env python3\nimport os\nos.system(f"ping {h}")\n' },
    ]);
    const findings = outcome.findings ?? [];
    const ruleIds = findings.map((finding) => finding.ruleId).sort();
    // unicode eval → 007; minified JS → 002 + 004; shebang script → 008; garbage/binary → nothing.
    expect(ruleIds).toContain('DG-SAST-007');
    expect(ruleIds).toContain('DG-SAST-002');
    expect(ruleIds).toContain('DG-SAST-004');
    expect(ruleIds).toContain('DG-SAST-008');
    expect(outcome.resultSummary.filesScanned).toBe(4); // garbage.py + unicode.py + min.js + shebang tool
    expect(outcome.resultSummary.filesSkipped).toBe(1); // binary.v (UNSUPPORTED)
  });

  test('empty snapshots complete honestly with zero findings', async () => {
    const outcome = await scan([]);
    expect(outcome.resultSummary.findingsTotal).toBe(0);
    expect(outcome.resultSummary.filesScanned).toBe(0);
    expect(outcome.resultSummary.filesSkipped).toBe(0);
  });
});

describe('SAST v2 fingerprint stability', () => {
  test('unchanged python source reproduces identical fingerprints; shifts do not collide', async () => {
    const vulnerable = [{ path: 'py/app.py', content: 'result = eval(f"total_{user_input}")\n' }];
    const first = await scan(vulnerable);
    const second = await scan(vulnerable);
    const firstFp = (first.findings ?? [])[0]?.fingerprint;
    const secondFp = (second.findings ?? [])[0]?.fingerprint;
    expect(firstFp).toBe(secondFp);
    const shifted = await scan([{ path: 'py/app.py', content: '\n\nresult = eval(f"total_{user_input}")\n' }]);
    expect((shifted.findings ?? [])[0]?.fingerprint).not.toBe(firstFp);
  });
});

describe('SAST v2 framework detection', () => {
  test('manifests yield deterministic framework labels', () => {
    const frameworks = detectFrameworks([
      {
        path: 'package.json',
        content: '{"dependencies":{"react":"18","react-dom":"18","express":"4"},"devDependencies":{"electron":"28"}}',
      },
      { path: 'requirements.txt', content: 'django==4.2\nflask==3.0\n' },
      { path: 'go.mod', content: 'module x\nrequire github.com/gin-gonic/gin v1.9\n' },
      { path: 'Gemfile', content: "source 'https://rubygems.org'\ngem 'rails', '~> 7.0'\n" },
      { path: 'pom.xml', content: '<dependency><artifactId>spring-boot-starter-web</artifactId></dependency>\n' },
      { path: 'android/app/build.gradle', content: 'plugins { id "com.android.application" }\ndependencies { implementation "androidx.core:core-ktx:1.10" }\n' },
      { path: 'src/App/App.csproj', content: '<Project Sdk="Microsoft.NET.Sdk.Web"></Project>\n' },
      { path: 'pubspec.yaml', content: 'dependencies:\n  flutter:\n    sdk: flutter\n' },
    ]);
    expect(frameworks).toEqual(
      [
        'Android', 'ASP.NET Core', 'Django', 'Electron', 'Express', 'Flask', 'Flutter', 'Gin', 'Rails', 'React', 'Spring Boot',
      ].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)),
    );
  });

  test('no manifests → no invented frameworks', () => {
    expect(detectFrameworks([{ path: 'src/app.ts', content: 'export const ok = true;\n' }])).toEqual([]);
    expect(detectFrameworks([])).toEqual([]);
  });
});

describe('SAST v2 detection maturity gates analysis', () => {
  test('only PARTIAL and CONFIG_ANALYSIS families are analyzed', () => {
    expect(isAnalyzedMaturity('PARTIAL')).toBe(true);
    expect(isAnalyzedMaturity('CONFIG_ANALYSIS')).toBe(true);
    expect(isAnalyzedMaturity('SYNTAX_ONLY')).toBe(false);
    expect(isAnalyzedMaturity('UNSUPPORTED')).toBe(false);
    expect(isAnalyzedMaturity('FULL')).toBe(true); // forward-compatible definition
  });
});
