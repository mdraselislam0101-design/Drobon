import { describe, expect, test } from 'vitest';
import { isFinding, isScanResultSummary, type Finding } from '@drobon/shared';
import type { ScanRecord } from '../src/scans/store.js';
import type { SourceSnapshotRecord } from '../src/scans/sources.js';
import { TEST_SAST_RULES } from './fixtures/testData.js';
import {
  createSastEngine,
  DEFAULT_SAST_LIMITS,
  SAST_IGNORED_DIR_SEGMENTS,
  type SastLimits,
  type SourceSnapshotProvider,
} from '../src/scans/sast/engine.js';
import { SAST_LANGUAGE_CATALOG, sastMaturityCounts, detectLanguageFamily } from '../src/scans/sast/languages.js';

/**
 * SAST engine unit tests (Pump 8) — the engine's security boundaries
 * and its determinism, exercised directly (the HTTP contract is
 * covered by sastApi.test.ts).
 */

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

const VULNERABLE = [
  {
    path: 'src/cmd.ts',
    content: "import { exec } from 'x';\nexport function run(dir) {\n  exec(`rm -rf ${dir}`);\n}\n",
  },
  {
    path: 'src/db.ts',
    content: "db.query(`SELECT * FROM users WHERE id = ${id}`);\n",
  },
  {
    path: 'src/html.ts',
    content: 'el.innerHTML = `<b>${name}</b>`;\n',
  },
  {
    path: 'src/eval.ts',
    content: "eval(`(${expr})`);\n",
  },
  {
    path: 'src/secret.ts',
    content: "const apiKey = 'sk_live_abcdef123456';\n", // fake fixture
  },
  {
    path: 'src/hash.ts',
    content: "createHash('md5');\n",
  },
];

describe('SAST engine: happy paths', () => {
  test('a SAFE snapshot completes with zero findings and honest counts', async () => {
    const engine = createSastEngine({ rules: TEST_SAST_RULES,
      sources: providerFor(snapshot([{ path: 'src/safe.ts', content: 'export const ok = true;\n' }])),
    });
    const outcome = await engine.execute(scanRecord(), ctx);
    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed') return;
    expect(outcome.resultSummary.findingsTotal).toBe(0);
    expect(outcome.resultSummary.filesScanned).toBe(1);
    expect(outcome.resultSummary.filesSkipped).toBe(0);
    expect(outcome.resultSummary.truncated).toBe(false);
    expect(outcome.findings).toBeUndefined();
    expect(isScanResultSummary(outcome.resultSummary)).toBe(true);
  });

  test('a VULNERABLE snapshot produces the six real findings with full detail', async () => {
    const engine = createSastEngine({ rules: TEST_SAST_RULES, sources: providerFor(snapshot(VULNERABLE)) });
    const outcome = await engine.execute(scanRecord(), ctx);
    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed') return;
    const findings = outcome.findings ?? [];
    expect(findings).toHaveLength(6);
    expect(outcome.resultSummary.findingsTotal).toBe(6);
    expect(outcome.resultSummary.findingsBySeverity).toEqual({
      CRITICAL: 0,
      HIGH: 3, // command injection, code injection, SQL injection
      MEDIUM: 2, // raw HTML, hardcoded credential
      LOW: 1, // weak hash
      INFO: 0,
    });
    for (const finding of findings) {
      expect(isFinding(finding)).toBe(true); // the shared guard accepts everything produced
      expect(finding.scanId).toBe('scan_00000000-0000-4000-8000-000000000003');
      expect(finding.line).toBeGreaterThanOrEqual(1);
      expect(finding.column).toBeGreaterThanOrEqual(1);
      expect(finding.evidence.length).toBeLessThanOrEqual(200);
    }
    const byRule = new Map(findings.map((finding) => [finding.ruleId, finding]));
    expect(byRule.get('DG-SAST-001')?.file).toBe('src/cmd.ts');
    expect(byRule.get('DG-SAST-001')?.line).toBe(3);
    expect(byRule.get('DG-SAST-001')?.evidence).toContain('exec(`rm -rf ${dir}`)');
    expect(byRule.get('DG-SAST-005')?.evidence).toContain('<redacted>');
    expect(byRule.get('DG-SAST-005')?.evidence).not.toContain('sk_live_abcdef123456');
  });

  test('repeated scans of unchanged source are byte-identical (stable ids + fingerprints)', async () => {
    const engine = createSastEngine({ rules: TEST_SAST_RULES, sources: providerFor(snapshot(VULNERABLE)) });
    const first = await engine.execute(scanRecord(), ctx);
    const second = await engine.execute(scanRecord(), ctx);
    expect(second).toEqual(first);
    if (first.kind !== 'completed' || second.kind !== 'completed') return;
    expect(second.findings).toEqual(first.findings);
  });

  test('unrelated findings never collapse into one fingerprint or id', async () => {
    const engine = createSastEngine({ rules: TEST_SAST_RULES, sources: providerFor(snapshot(VULNERABLE)) });
    const outcome = await engine.execute(scanRecord(), ctx);
    if (outcome.kind !== 'completed') throw new Error('expected completion');
    const findings = outcome.findings ?? [];
    const fingerprints = new Set(findings.map((finding) => finding.fingerprint));
    const ids = new Set(findings.map((finding) => finding.id));
    expect(fingerprints.size).toBe(findings.length);
    expect(ids.size).toBe(findings.length);
    // Moving the vulnerable line changes the fingerprint (line is part
    // of the identity).
    const shifted = snapshot([
      { path: 'src/cmd.ts', content: "import { exec } from 'x';\n\n\nexport function run(dir) {\n  exec(`rm -rf ${dir}`);\n}\n" },
    ]);
    const shiftedEngine = createSastEngine({ rules: TEST_SAST_RULES, sources: providerFor(shifted) });
    const shiftedOutcome = await shiftedEngine.execute(scanRecord(), ctx);
    if (shiftedOutcome.kind !== 'completed') throw new Error('expected completion');
    expect((shiftedOutcome.findings ?? [])[0]?.fingerprint).not.toBe(
      findings.find((finding) => finding.ruleId === 'DG-SAST-001')?.fingerprint,
    );
  });
});

describe('SAST engine: discovery', () => {
  test('SAST v2: python/csharp are analyzed; syntax-only and unknown files are skipped and counted', async () => {
    const engine = createSastEngine({ rules: TEST_SAST_RULES,
      sources: providerFor(
        snapshot([
          { path: 'src/app.ts', content: 'export const a = 1;\n' },
          { path: 'script.py', content: 'os.system(user_input)\n' },
          { path: 'Program.cs', content: 'Process.Start(user);\n' },
          { path: 'README.md', content: '# readme\n' },
          { path: 'style.css', content: 'body { color: red; }\n' },
        ]),
      ),
    });
    const outcome = await engine.execute(scanRecord(), ctx);
    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed') return;
    expect(outcome.resultSummary.filesScanned).toBe(3); // .ts + .py + .cs (pass-through calls, no rule shape)
    expect(outcome.resultSummary.filesSkipped).toBe(2); // README.md (unknown) + style.css (SYNTAX_ONLY)
    expect(outcome.resultSummary.findingsTotal).toBe(0); // conservative rules: pass-through shapes do NOT fire
  });

  test('dependency/build directories are ignored deterministically', async () => {
    const engine = createSastEngine({ rules: TEST_SAST_RULES,
      sources: providerFor(
        snapshot([
          { path: 'node_modules/pkg/index.js', content: 'exec(`x ${y}`);\n' },
          { path: 'dist/bundle.js', content: 'exec(`x ${y}`);\n' },
          { path: 'build/out.js', content: 'exec(`x ${y}`);\n' },
          { path: 'coverage/lcov.js', content: 'exec(`x ${y}`);\n' },
          { path: 'src/deep/node_modules/x.js', content: 'exec(`x ${y}`);\n' },
          { path: 'src/real.ts', content: 'export const ok = true;\n' },
        ]),
      ),
    });
    const outcome = await engine.execute(scanRecord(), ctx);
    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed') return;
    expect(outcome.resultSummary.filesScanned).toBe(1);
    expect(outcome.resultSummary.filesSkipped).toBe(5);
    expect(outcome.resultSummary.findingsTotal).toBe(0); // node_modules content is NOT user source
    expect(SAST_IGNORED_DIR_SEGMENTS).toContain('node_modules');
  });

  test('the v2 catalog covers the legacy JavaScript/TypeScript extensions and 40+ families', () => {
    const legacy = ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs'];
    for (const extension of legacy) {
      const family = SAST_LANGUAGE_CATALOG.find((entry) => entry.extensions?.includes(extension));
      expect(family, `legacy extension ${extension} must remain catalogued`).toBeDefined();
    }
    const counts = sastMaturityCounts();
    expect(counts.total).toBeGreaterThanOrEqual(40);
    expect(SAST_LANGUAGE_CATALOG.find((entry) => entry.id === 'python')?.maturity).toBe('PARTIAL');
    expect(detectLanguageFamily('main.rs')?.family).toBe('rust');
  });

  test('oversize files are skipped (per-file bound, defense in depth)', async () => {
    const engine = createSastEngine({ rules: TEST_SAST_RULES,
      sources: providerFor(
        snapshot([
          { path: 'src/huge.ts', content: 'x'.repeat(DEFAULT_SAST_LIMITS.maxFileBytes + 1) },
          { path: 'src/ok.ts', content: 'export const ok = true;\n' },
        ]),
      ),
    });
    const outcome = await engine.execute(scanRecord(), ctx);
    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed') return;
    expect(outcome.resultSummary.filesScanned).toBe(1);
    expect(outcome.resultSummary.filesSkipped).toBe(1);
  });

  test('over the file-count cap: fail closed with SAST_FILE_LIMIT_EXCEEDED', async () => {
    const files = Array.from({ length: 3 }, (_, index) => ({
      path: `src/f${index}.ts`,
      content: 'export const a = 1;\n',
    }));
    const engine = createSastEngine({ rules: TEST_SAST_RULES,
      sources: providerFor(snapshot(files)),
      limits: { maxFiles: 2 },
    });
    const outcome = await engine.execute(scanRecord(), ctx);
    expect(outcome).toEqual({
      kind: 'failed',
      failureCode: 'SAST_FILE_LIMIT_EXCEEDED',
      failureMessage: 'The source snapshot has more scannable files than the SAST limit (2).',
    });
  });

  test('over the total-bytes cap: fail closed with SAST_TARGET_TOO_LARGE', async () => {
    const engine = createSastEngine({ rules: TEST_SAST_RULES,
      sources: providerFor(snapshot([{ path: 'src/big.ts', content: 'x'.repeat(2000) }])),
      limits: { maxTotalBytes: 1000 },
    });
    const outcome = await engine.execute(scanRecord(), ctx);
    expect(outcome).toEqual({
      kind: 'failed',
      failureCode: 'SAST_TARGET_TOO_LARGE',
      failureMessage: 'The source snapshot exceeds the SAST scan size limit (1000 bytes).',
    });
  });
});

describe('SAST engine: failure modes (fail closed, no leaks)', () => {
  test('no snapshot: SAST_TARGET_NOT_FOUND with a safe, actionable message', async () => {
    const engine = createSastEngine({ rules: TEST_SAST_RULES, sources: providerFor(undefined) });
    const outcome = await engine.execute(scanRecord(), ctx);
    expect(outcome).toEqual({
      kind: 'failed',
      failureCode: 'SAST_TARGET_NOT_FOUND',
      failureMessage:
        'No source snapshot is attached to this project. Upload source files before requesting a SAST scan.',
    });
  });

  test('owner mismatch (inconsistent state): SAST_INPUT_INVALID, no details', async () => {
    const foreign = { ...snapshot([{ path: 'a.ts', content: 'x' }]), ownerId: 'usr_other' };
    const engine = createSastEngine({ rules: TEST_SAST_RULES, sources: providerFor(foreign) });
    const outcome = await engine.execute(scanRecord(), ctx);
    expect(outcome).toEqual({
      kind: 'failed',
      failureCode: 'SAST_INPUT_INVALID',
      failureMessage: 'The scan target is inconsistent with the scan owner.',
    });
  });

  test('a traversal-shaped path inside the snapshot: SAST_INPUT_INVALID (containment re-check)', async () => {
    // Bypassing the store's validation on purpose: the engine must
    // still refuse to resolve anything outside the virtual root.
    const poisoned = snapshot([{ path: 'ok.ts', content: 'x' }]);
    poisoned.files.push({ path: '../../etc/passwd', bytes: 4, content: 'root' });
    const engine = createSastEngine({ rules: TEST_SAST_RULES, sources: providerFor(poisoned) });
    const outcome = await engine.execute(scanRecord(), ctx);
    expect(outcome).toEqual({
      kind: 'failed',
      failureCode: 'SAST_INPUT_INVALID',
      failureMessage: 'The scan target failed validation.',
    });
  });

  test('processing deadline exceeded: SAST_SCAN_TIMEOUT (never COMPLETED)', async () => {
    // A fake clock that jumps past the deadline after startup.
    let time = 1_000_000;
    const engine = createSastEngine({ rules: TEST_SAST_RULES,
      sources: providerFor(snapshot(VULNERABLE)),
      limits: { deadlineMs: 1000 },
      now: () => {
        time += 5000; // Every check is past the deadline.
        return time;
      },
    });
    const outcome = await engine.execute(scanRecord(), ctx);
    expect(outcome).toEqual({
      kind: 'failed',
      failureCode: 'SAST_SCAN_TIMEOUT',
      failureMessage: 'The SAST engine exceeded its processing deadline.',
    });
  });

  test('an aborted signal is observed as a deterministic timeout failure', async () => {
    const controller = new AbortController();
    controller.abort();
    const engine = createSastEngine({ rules: TEST_SAST_RULES, sources: providerFor(snapshot(VULNERABLE)) });
    const outcome = await engine.execute(scanRecord(), { signal: controller.signal });
    expect(outcome.kind).toBe('failed');
    if (outcome.kind !== 'failed') return;
    expect(outcome.failureCode).toBe('SAST_SCAN_TIMEOUT');
  });

  test('the findings cap truncates honestly (truncated: true, bounded list)', async () => {
    // 200 vulnerable lines → the cap (3 here) stops analysis and flags.
    const lines = Array.from({ length: 200 }, () => 'exec(`x ${y}`);').join('\n');
    const engine = createSastEngine({ rules: TEST_SAST_RULES,
      sources: providerFor(snapshot([{ path: 'src/many.ts', content: lines }])),
      limits: { maxFindings: 3 },
    });
    const outcome = await engine.execute(scanRecord(), ctx);
    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed') return;
    expect(outcome.findings).toHaveLength(3);
    expect(outcome.resultSummary.findingsTotal).toBe(3);
    expect(outcome.resultSummary.truncated).toBe(true);
  });
});

describe('SAST engine: evidence discipline', () => {
  test('long lines produce bounded, match-centered evidence', async () => {
    const pad = 'x'.repeat(500);
    const line = `const a = "${pad}"; exec(\`rm \${dir}\`);`;
    const engine = createSastEngine({ rules: TEST_SAST_RULES,
      sources: providerFor(snapshot([{ path: 'src/long.ts', content: line }])),
    });
    const outcome = await engine.execute(scanRecord(), ctx);
    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed') return;
    const finding = (outcome.findings ?? [])[0];
    expect(finding).toBeDefined();
    expect(finding?.evidence.length).toBeLessThanOrEqual(200);
    expect(finding?.evidence).toContain('exec(`rm ${dir}`)'); // the match is visible
    expect(finding?.evidence.startsWith('…')).toBe(true); // windowed from a long line
    expect(finding !== undefined && isFinding(finding)).toBe(true); // guard accepts it
  });

  test('redaction applies inside windowed evidence too', async () => {
    const pad = 'y'.repeat(400);
    // The 'sk_live_…' literal below is a FAKE test fixture.
    const line = `const pad = "${pad}"; const apiKey = 'sk_live_abcdef123456';`; // fake
    const engine = createSastEngine({ rules: TEST_SAST_RULES,
      sources: providerFor(snapshot([{ path: 'src/secret.ts', content: line }])),
    });
    const outcome = await engine.execute(scanRecord(), ctx);
    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed') return;
    const finding: Finding | undefined = (outcome.findings ?? [])[0];
    expect(finding).toBeDefined();
    expect(finding?.evidence).not.toContain('sk_live_abcdef123456');
    expect(finding?.evidence).toContain('<redacted>');
  });

  test('CRLF and tabs in source never leak control characters into evidence', async () => {
    const content = 'const t = 1;\r\nexec(`x ${y}`);\r\nconst z\t= 2;\r\n';
    const engine = createSastEngine({ rules: TEST_SAST_RULES,
      sources: providerFor(snapshot([{ path: 'src/crlf.ts', content }])),
    });
    const outcome = await engine.execute(scanRecord(), ctx);
    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed') return;
    for (const finding of outcome.findings ?? []) {
      // eslint-disable-next-line no-control-regex -- the point of the test
      expect(finding.evidence).not.toMatch(/[\x00-\x1f\x7f]/);
      expect(isFinding(finding)).toBe(true);
    }
  });

  test('XSS payloads in evidence are plain text (never markup)', async () => {
    const content = 'el.innerHTML = `<img src=x onerror=alert(1)>${user}`;\n';
    const engine = createSastEngine({ rules: TEST_SAST_RULES,
      sources: providerFor(snapshot([{ path: 'src/xss.ts', content }])),
    });
    const outcome = await engine.execute(scanRecord(), ctx);
    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed') return;
    const finding = (outcome.findings ?? [])[0];
    expect(finding?.evidence).toContain('<img src=x onerror=alert(1)>');
    // eslint-disable-next-line no-control-regex -- the point of the test
    expect(finding?.evidence).not.toMatch(/[\x00-\x1f\x7f]/);
  });
});

describe('SAST engine: performance bounds', () => {
  test('a bounded large project scans quickly (limits enforced, not just documented)', async () => {
    const files = Array.from({ length: 100 }, (_, index) => ({
      path: `src/mod${String(index).padStart(3, '0')}.ts`,
      content: Array.from({ length: 100 }, (_, line) => `export const v${line} = ${line};`).join('\n') + '\n',
    }));
    const started = Date.now();
    const engine = createSastEngine({ rules: TEST_SAST_RULES, sources: providerFor(snapshot(files)) });
    const outcome = await engine.execute(scanRecord(), ctx);
    const elapsed = Date.now() - started;
    expect(outcome.kind).toBe('completed');
    expect(elapsed).toBeLessThan(5000); // 10k lines: well inside the deadline
    if (outcome.kind !== 'completed') return;
    expect(outcome.resultSummary.filesScanned).toBe(100);
    expect(outcome.resultSummary.findingsTotal).toBe(0);
  });

  test('DEFAULT_SAST_LIMITS are the documented values', () => {
    expect(DEFAULT_SAST_LIMITS).toEqual({
      maxFiles: 200,
      maxFileBytes: 262_144,
      maxTotalBytes: 1_048_576,
      maxFindings: 200,
      deadlineMs: 10_000,
    } satisfies SastLimits);
  });
});
