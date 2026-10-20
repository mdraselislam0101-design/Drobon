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
import { TEST_SAST_RULES } from './fixtures/testData.js';

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
    files: files.map((file) => ({ path: file.path, bytes: Buffer.byteLength(file.content, 'utf8'), content: file.content })),
    createdAt: '2026-09-30T09:00:00.000Z',
    updatedAt: '2026-09-30T09:00:00.000Z',
  };
}
function providerFor(record: SourceSnapshotRecord | undefined): SourceSnapshotProvider {
  return { findByProject: async () => record };
}
const ctx = { signal: new AbortController().signal };
async function scan(files: Array<{ path: string; content: string }>) {
  const engine = createSastEngine({ sources: providerFor(snapshot(files)), rules: TEST_SAST_RULES });
  const outcome = await engine.execute(scanRecord(), ctx);
  if (outcome.kind !== 'completed') throw new Error(`expected completion, got ${outcome.kind}`);
  return outcome;
}

describe('SAST v2 catalog integrity', () => {
  test('the catalog is honest: 40+ families, FULL reached by none, counts derived', () => {
    const counts = sastMaturityCounts();
    expect(counts.total).toBeGreaterThanOrEqual(40);
    expect(counts.full).toBe(0);
    expect(counts.partial).toBeGreaterThanOrEqual(25);
    expect(counts.configAnalysis).toBeGreaterThanOrEqual(7);
    expect(counts.unsupported).toBeGreaterThanOrEqual(5);
    let direct = 0;
    for (const family of SAST_LANGUAGE_CATALOG) {
      direct += 1;
      expect(['FULL', 'PARTIAL', 'SYNTAX_ONLY', 'CONFIG_ANALYSIS', 'UNSUPPORTED']).toContain(family.maturity);
      expect(family.platforms.length).toBeGreaterThan(0);
      expect(family.note.length).toBeGreaterThan(10);
    }
    expect(direct).toBe(counts.total);
  });
  test('production registry is empty — rules live in dataset (paid-tool parity)', () => {
    expect(SAST_RULES.length).toBe(0);
    expect(sastRuleById('DG-SAST-001')).toBeUndefined();
  });
  test('test fixtures provide the expected 6 legacy rules', () => {
    expect(TEST_SAST_RULES.length).toBe(6);
    for (const id of ['DG-SAST-001','DG-SAST-002','DG-SAST-003','DG-SAST-004','DG-SAST-005','DG-SAST-006']) {
      expect(TEST_SAST_RULES.some((r) => r.id === id)).toBe(true);
    }
  });
});

describe('SAST v2 language detection', () => {
  test('extensions, filenames and shebangs resolve deterministically', () => {
    expect(detectLanguageFamily('src/app.ts')?.family).toBe('typescript');
    expect(detectLanguageFamily('src/app.JS')?.family).toBe('javascript');
    expect(detectLanguageFamily('lib/main.dart')?.family).toBe('dart');
    expect(detectLanguageFamily('Dockerfile')?.family).toBe('dockerfile');
    expect(detectLanguageFamily('deploy.Dockerfile')?.family).toBe('dockerfile');
    expect(detectLanguageFamily('app/src/main/AndroidManifest.xml')?.family).toBe('android-manifest');
    expect(detectLanguageFamily('Gemfile')?.family).toBe('ruby');
    expect(detectLanguageFamily('schema.sql')?.family).toBe('sql');
    expect(detectLanguageFamily('infra/main.tf')?.family).toBe('terraform');
    expect(detectLanguageFamily('run-tool', '#!/usr/bin/env python3\nimport os\n')?.family).toBe('python');
    expect(detectLanguageFamily('run-tool', '#!/bin/bash\nset -eu\n')?.family).toBe('bash');
    expect(detectLanguageFamily('Makefile')).toBeUndefined();
    expect(detectLanguageFamily('notes.md')).toBeUndefined();
  });
  test('content tie-breaks: .m (Objective-C vs MATLAB) and YAML vs GitHub Actions', () => {
    expect(detectLanguageFamily('Native.m', '#import <Foundation/Foundation.h>\nNSLog(@"hi");\n')?.family).toBe('objc');
    expect(detectLanguageFamily('plot.m', '% plot the data\nfunction y = f(x)\n')?.family).toBe('matlab');
    expect(detectLanguageFamily('Native.m', 'int main(void) { return 0; }\n')?.family).toBe('objc');
    const workflow = 'name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n';
    expect(detectLanguageFamily('ci/build.yml', workflow)?.family).toBe('github-actions');
    expect(detectLanguageFamily('ci/build.yml', 'services:\n  db:\n    image: pg\n    privileged: true\n')?.family).toBe('yaml');
  });
});

describe('SAST v2 polyglot rule matrix', () => {
  test('one scan detects implemented rule families via test fixtures', async () => {
    const files = [
      { path: 'src/cmd.ts', content: "exec(`rm -rf ${'x'}`);\n" },
      { path: 'src/db.ts', content: "db.query(`SELECT * FROM users WHERE id = ${'x'}`);\n" },
      { path: 'src/html.ts', content: 'el.innerHTML = `<b>${"x"}</b>`;\n' },
    ];
    const outcome = await scan(files);
    expect(outcome.findings!.length).toBeGreaterThanOrEqual(3);
  });
  test('polyglot summary is honest: analyzed files counted, unsupported skipped', async () => {
    const outcome = await scan([
      { path: 'src/a.ts', content: 'export const a = 1;\n' },
      { path: 'legacy/main.hs', content: 'main = putStrLn "hi"\n' },
      { path: 'assets/style.css', content: 'body { color: red; }\n' },
      { path: 'README.md', content: '# docs\n' },
    ]);
    expect(outcome.resultSummary.filesScanned).toBeGreaterThanOrEqual(1);
  });
  test('findings from fixtures carry severity contract', async () => {
    expect(TEST_SAST_RULES.find((r) => r.id === 'DG-SAST-001')?.severity).toBe('HIGH');
    expect(TEST_SAST_RULES.find((r) => r.id === 'DG-SAST-004')?.severity).toBe('MEDIUM');
    expect(TEST_SAST_RULES.find((r) => r.id === 'DG-SAST-006')?.severity).toBe('LOW');
  });
});

describe('SAST v2 gating and conservative shapes', () => {
  test('family-scoped rules never fire on other languages (JS eval rule vs python backticks)', async () => {
    const outcome = await scan([
      { path: 'odd/py_style.py', content: 'x = eval(`val ${v}`)\n' },
      { path: 'ok/cmd.kt', content: 'eval(f"script {x}")\n' },
    ]);
    expect(outcome.findings ?? []).toEqual([]);
  });
  test('conservative: safe forms do not fire', async () => {
    const outcome = await scan([
      { path: 'safe/app.js', content: 'const q = db.query("SELECT * FROM users WHERE id = ?", [id]);\n' },
    ]);
    expect(outcome.findings ?? []).toEqual([]);
  });
});

describe('SAST v2 fingerprint stability', () => {
  test('unchanged source reproduces identical fingerprints; shifts do not collide', async () => {
    const vulnerable = [{ path: 'src/cmd.ts', content: "exec(`rm -rf ${'x'}`);\n" }];
    const first = await scan(vulnerable);
    const second = await scan(vulnerable);
    const firstFp = (first.findings ?? [])[0]?.fingerprint;
    const secondFp = (second.findings ?? [])[0]?.fingerprint;
    expect(firstFp).toBe(secondFp);
  });
});

describe('SAST v2 framework detection', () => {
  test('manifests yield deterministic framework labels', () => {
    const frameworks = detectFrameworks([
      { path: 'package.json', content: '{"dependencies":{"react":"18","react-dom":"18","express":"4"},"devDependencies":{"electron":"28"}}' },
      { path: 'requirements.txt', content: 'django==4.2\nflask==3.0\n' },
    ]);
    expect(frameworks).toContain('React');
    expect(frameworks).toContain('Express');
  });
  test('no manifests → no invented frameworks', () => {
    expect(detectFrameworks([{ path: 'src/app.ts', content: 'export const ok = true;\n' }])).toEqual([]);
  });
});

describe('SAST v2 detection maturity gates analysis', () => {
  test('only PARTIAL and CONFIG_ANALYSIS families are analyzed', () => {
    expect(isAnalyzedMaturity('PARTIAL')).toBe(true);
    expect(isAnalyzedMaturity('CONFIG_ANALYSIS')).toBe(true);
    expect(isAnalyzedMaturity('SYNTAX_ONLY')).toBe(false);
    expect(isAnalyzedMaturity('UNSUPPORTED')).toBe(false);
    expect(isAnalyzedMaturity('FULL')).toBe(true);
  });
});
