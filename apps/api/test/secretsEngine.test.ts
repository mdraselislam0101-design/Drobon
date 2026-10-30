import { describe, expect, test } from 'vitest';
import { isFinding, isScanResultSummary, type Finding } from '@drobon/shared';
import type { ScanRecord } from '../src/scans/store.js';
import type { SourceSnapshotRecord } from '../src/scans/sources.js';
import { TEST_SECRETS_RULES } from './fixtures/testData.js';
import {
  createSecretsEngine,
  DEFAULT_SECRETS_LIMITS,
  SECRETS_IGNORED_DIR_SEGMENTS,
  SECRETS_SUPPORTED_EXTENSIONS,
  type SourceSnapshotProvider,
} from '../src/scans/secrets/engine.js';

/**
 * SECRETS ENGINE unit tests (Pump 10) — the engine's redaction
 * contract, determinism, limits and failure modes, exercised directly.
 * The HTTP contract is covered by secretsApi.test.ts; the rule logic
 * by secretsRules.test.ts.
 *
 * ALL fixture values are SYNTHETIC (never real credentials) and built
 * to dodge the placeholder denylist so the POSITIVE paths fire.
 */

const OWNER = 'usr_00000000-0000-4000-8000-000000000001';
const PROJECT = 'prj_00000000-0000-4000-8000-000000000002';

const SYNTH = {
  awsKey: 'AKIAP10QZ9WM7XK2BR4J', // fake-test fixture
  awsKey2: 'AKIAQ10Z8XK2BR4JW9MD', // fake-test fixture
  githubToken: 'ghp_P10aBcDeFgHiJkLmNoPqRsTuVwXyZ123456A', // fake-test fixture
  bearer: 'P10AbCdEfGhIjKlMnOpQrStUvWx40', // fake-test fixture
  dbUrl: 'postgres://svc:P10-sUp3r-Pg@db.host:5432/app', // fake-test fixture
  apiKeyValue: 'P10ApiKeyZx9Qw8Er7Ty6Uio5Pl', // fake-test fixture
  passwordValue: 'P10-C0rr3ct-Horse-Stapl3-Batt3ry', // fake-test fixture
  shortPassword: 'P10-sUp3r', // fake-test fixture (9 chars → asterisk marker)
} as const;

/** PEM fixtures are CONCATENATED so no literal key-block header exists in this file. */
const PEM_HEADER = ['-----BEGIN RSA ', 'PRIVATE KEY-----'].join(''); // fake-test fixture

function scanRecord(id = 'scan_00000000-0000-4000-8000-000000000003'): ScanRecord {
  return {
    id,
    ownerId: OWNER,
    projectId: PROJECT,
    scanType: 'SECRETS',
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

function engineWith(record: SourceSnapshotRecord | undefined, limits?: Parameters<typeof createSecretsEngine>[0]['limits']) {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- legacy untyped boundary; new modules use unknown.
  return createSecretsEngine({ sources: providerFor(record), rules: TEST_SECRETS_RULES as any, ...(limits === undefined ? {} : { limits }) });
}

type Completed = Extract<Awaited<ReturnType<ReturnType<typeof createSecretsEngine>['execute']>>, { kind: 'completed' }>;

async function completedOutcome(
  engine: ReturnType<typeof createSecretsEngine>,
): Promise<Completed> {
  const outcome = await engine.execute(scanRecord(), ctx);
  expect(outcome.kind).toBe('completed');
  if (outcome.kind !== 'completed') {
    throw new Error('unreachable');
  }
  return outcome;
}

/** The master redaction assertion: NO raw fixture value in the whole outcome. */
function assertNoRawSecrets(outcome: unknown): void {
  const serialized = JSON.stringify(outcome);
  for (const [name, value] of Object.entries(SYNTH)) {
    if (name === 'dbUrl') {
      // The URL's non-secret parts (scheme/host) may appear as context;
      // the PASSWORD segment must not.
      expect(serialized, `raw db password leaked`).not.toContain('P10-sUp3r-Pg');
      continue;
    }
    expect(serialized, `raw ${name} leaked`).not.toContain(value);
  }
}

describe('secrets engine: a real multi-file scan', () => {
  test('detects every category with redaction, ordered by file/line, honest summary', async () => {
    const engine = engineWith(
      snapshot([
        {
          // `.pem` paths are BLOCKED at upload (SOURCE_BLOCKED_EXTENSIONS)
          // — the realistic case is a key pasted INTO code.
          path: 'src/keys.ts',
          content: 'export const key = `${' + PEM_HEADER + '}\\nbody\\n-----END RSA PRIVATE KEY-----`;' + '\n', // fake fixture
        },
        {
          path: 'src/zservice.ts',
          content: `export const aws = "${SYNTH.awsKey}";\nexport const gh = "${SYNTH.githubToken}";\n`,
        },
        {
          path: 'src/aservice.py',
          content: `PASSWORD = "${SYNTH.passwordValue}"\nAUTH = "Authorization: Bearer ${SYNTH.bearer}"\n`, // fake
        },
        {
          // `.env` is upload-blocked too — env-style values surface in
          // config files instead.
          path: 'config/prod.yaml',
          content: `api_key: ${SYNTH.apiKeyValue}\ndb_url: ${SYNTH.dbUrl}\n`,
        },
      ]),
    );
    const outcome = await completedOutcome(engine);
    const findings = outcome.findings ?? [];
    expect(findings.length).toBe(7);
    const sourceFindings = findings;

    // Deterministic order: path ASC, then line, then ruleId.
    const ordered = [...sourceFindings].sort((a, b) => {
      const fileA = a.scanner === 'DAST' ? a.endpoint : a.file ?? '';
      const fileB = b.scanner === 'DAST' ? b.endpoint : b.file ?? '';
      const lineA = a.scanner === 'DAST' ? 0 : a.line ?? 0;
      const lineB = b.scanner === 'DAST' ? 0 : b.line ?? 0;
      return fileA < fileB ? -1 : fileA > fileB ? 1 : lineA - lineB || (a.ruleId < b.ruleId ? -1 : 1);
    });
    expect(sourceFindings.map((f) => [f.file ?? '', f.line ?? 0, f.ruleId])).toEqual(
      ordered.map((f) => [f.file ?? '', f.line ?? 0, f.ruleId]),
    );
    expect(sourceFindings.map((f) => `${f.file ?? ''}:${f.line ?? 0}:${f.ruleId}`)).toEqual([
      'config/prod.yaml:1:DG-SEC-005',
      'config/prod.yaml:2:DG-SEC-004',
      'src/aservice.py:1:DG-SEC-006',
      'src/aservice.py:2:DG-SEC-003',
      'src/keys.ts:1:DG-SEC-001',
      'src/zservice.ts:1:DG-SEC-002',
      'src/zservice.ts:2:DG-SEC-002',
    ]);

    for (const finding of findings) {
      expect(isFinding(finding)).toBe(true);
      expect(finding.id).toMatch(/^fnd_[0-9a-f]{24}$/);
      expect(finding.fingerprint).toMatch(/^[0-9a-f]{64}$/);
      expect(finding.evidence.length).toBeLessThanOrEqual(200);
      expect(finding.confidence).toBeDefined();
      expect(finding.remediation).toBeTruthy();
      // NEVER a verification claim (DETECTED ≠ VERIFIED_LIVE).
      expect(finding.title.toLowerCase()).not.toContain('valid');
      expect(finding.title.toLowerCase()).not.toContain('active');
      expect(finding.remediation).not.toContain('revoked');
    }

    // Evidence shows context with the value blanked.
    const pem = findings.find((f) => f.ruleId === 'DG-SEC-001');
    expect(pem?.evidence).toBe(PEM_HEADER);
    const aws = findings.find((f) => f.ruleId === 'DG-SEC-002' && f.file === 'src/zservice.ts');
    expect(aws?.evidence).toBe(`export const aws = "<redacted>";`);
    const apiKey = findings.find((f) => f.ruleId === 'DG-SEC-005');
    expect(apiKey?.evidence).toBe(`api_key: <redacted>`);

    // Honest summary: 4 files scanned, 7 findings, no partial.
    expect(isScanResultSummary(outcome.resultSummary)).toBe(true);
    expect(outcome.resultSummary.filesScanned).toBe(4);
    expect(outcome.resultSummary.filesSkipped).toBe(0);
    expect(outcome.resultSummary.findingsTotal).toBe(7);
    expect(outcome.resultSummary.findingsBySeverity?.HIGH ?? -1).toBe(6);
    expect(outcome.resultSummary.findingsBySeverity?.MEDIUM ?? -1).toBe(1);
    expect(outcome.resultSummary.truncated).toBe(false);
    expect(outcome.resultSummary.partial).toBeUndefined();

    // THE MASTER REDACTION ASSERTION — no raw value anywhere.
    assertNoRawSecrets(outcome);
  });

  test('deterministic: same snapshot twice → identical ids, fingerprints, evidence', async () => {
    const files = [
      { path: 'a.ts', content: `const t = "${SYNTH.bearer}";\n` },
      { path: 'b.py', content: `password = '${SYNTH.passwordValue}'\n` }, // fake
    ];
    const first = await completedOutcome(engineWith(snapshot(files)));
    const second = await completedOutcome(engineWith(snapshot(files)));
    expect(second.findings).toEqual(first.findings);
    expect(second.resultSummary).toEqual(first.resultSummary);
    // Not a random UUID in sight — ids derive from the fingerprint.
    expect(first.findings?.every((f) => f.id === `fnd_${f.fingerprint.slice(0, 24)}`)).toBe(true);
  });

  test('fingerprint is location/evidence sensitive but never value-derived', async () => {
    // Same rule/file/line, DIFFERENT value → same redacted evidence →
    // SAME fingerprint (the raw secret is not fingerprint input).
    const a = await completedOutcome(
      engineWith(snapshot([{ path: 'a.ts', content: `const aws = "${SYNTH.awsKey}";\n` }])),
    );
    const b = await completedOutcome(
      engineWith(snapshot([{ path: 'a.ts', content: `const aws = "${SYNTH.awsKey2}";\n` }])),
    );
    expect(a.findings?.[0]?.fingerprint).toBe(b.findings?.[0]?.fingerprint);
    expect(a.findings?.[0]?.id).toBe(b.findings?.[0]?.id);

    // Different LINE → different fingerprint.
    const c = await completedOutcome(
      engineWith(snapshot([{ path: 'a.ts', content: `\nconst aws = "${SYNTH.awsKey}";\n` }])),
    );
    expect(c.findings?.[0]?.fingerprint).not.toBe(a.findings?.[0]?.fingerprint);

    // The active rule set (not the empty production registry) drives the
    // defensive re-scan. A short url password first redacts to asterisks,
    // but those asterisks still satisfy the URL-password pattern, so BOTH
    // the long and short shapes fail closed to the same bare marker — and
    // therefore produce the same fingerprint (identity follows redacted
    // evidence, never the raw value). A different LINE still changes it.
    const long = await completedOutcome(
      engineWith(snapshot([{ path: 'u.ts', content: `db = "${SYNTH.dbUrl}"\n` }])),
    );
    const short = await completedOutcome(
      engineWith(snapshot([{ path: 'u.ts', content: `db = "redis://default:${SYNTH.shortPassword}@c:1"\n` }])),
    );
    expect(long.findings?.[0]?.evidence).toBe('[DG-SEC-004] <redacted>');
    expect(short.findings?.[0]?.evidence).toBe('[DG-SEC-004] <redacted>');
    expect(long.findings?.[0]?.fingerprint).toBe(short.findings?.[0]?.fingerprint);
    expect(JSON.stringify(short)).not.toContain(SYNTH.shortPassword);
    // Evidence sensitivity is still real: a different visible marker
    // (another rule) yields a different identity on the same location.
    const pem = await completedOutcome(
      engineWith(snapshot([{ path: 'u.ts', content: ['-----BEGIN RSA ', 'PRIVATE KEY-----\n'].join('') }])),
    );
    expect(pem.findings?.[0]?.fingerprint).not.toBe(short.findings?.[0]?.fingerprint);
  });

  test('dedupe: one finding per (rule, file, line); different rules stay distinct', async () => {
    // Two identical values, ONE rule, one line → ONE finding, and the
    // identical neighbour forces the fail-closed evidence (the visible
    // copy would leak).
    const same = await completedOutcome(
      engineWith(snapshot([{ path: 'dup.ts', content: `a = "${SYNTH.awsKey}"; b = "${SYNTH.awsKey}";\n` }])),
    );
    expect(same.findings?.length).toBe(1);
    expect(same.findings?.[0]?.evidence).toBe('[DG-SEC-002] <redacted>');
    assertNoRawSecrets(same);

    // TWO different AWS keys on one line: only the first is blanked by
    // the span pass; the defensive re-scan catches the survivor →
    // fail closed. One finding, no leak.
    const pair = await completedOutcome(
      engineWith(snapshot([{ path: 'dup.ts', content: `a = "${SYNTH.awsKey}"; b = "${SYNTH.awsKey2}";\n` }])),
    );
    expect(pair.findings?.length).toBe(1);
    expect(pair.findings?.[0]?.evidence).toBe('[DG-SEC-002] <redacted>');
    expect(JSON.stringify(pair)).not.toContain(SYNTH.awsKey2);

    // SEC-005 + SEC-006 on the SAME line → two findings, both values
    // redacted in BOTH findings' evidence (neighbour redaction).
    const multi = await completedOutcome(
      engineWith(snapshot([{ path: 'multi.ts', content: `api_key = '${SYNTH.apiKeyValue}'; password = '${SYNTH.passwordValue}';\n` }])), // fake
    );
    expect(multi.findings?.map((f) => f.ruleId).sort()).toEqual(['DG-SEC-005', 'DG-SEC-006']);
    for (const finding of multi.findings ?? []) {
      expect(finding.evidence).toContain('<redacted>');
      expect(finding.evidence).not.toContain(SYNTH.apiKeyValue);
      expect(finding.evidence).not.toContain(SYNTH.passwordValue);
    }
  });
});

describe('secrets engine: scope — ignored dirs and unsupported formats', () => {
  test('node_modules/dist/etc and binaries are skipped, not interpreted, not reported', async () => {
    const outcome = await completedOutcome(
      engineWith(
        snapshot([
          { path: 'node_modules/pkg/index.js', content: `const k = "${SYNTH.awsKey}";\n` },
          { path: 'dist/bundle.js', content: `const k = "${SYNTH.awsKey}";\n` },
          { path: 'assets/logo.png', content: '\u0089PNG\r\n\x1a\n' },
          { path: 'src/real.ts', content: `const k = "${SYNTH.awsKey}";\n` },
        ]),
      ),
    );
    expect(outcome.findings?.length).toBe(1);
    expect(outcome.findings?.[0]?.file).toBe('src/real.ts');
    expect(outcome.resultSummary.filesScanned).toBe(1);
    expect(outcome.resultSummary.filesSkipped).toBe(3);
    expect(outcome.resultSummary.partial).toBeUndefined(); // Out of scope, not partial.
    // The registry stays a closed, documented list.
    expect(SECRETS_IGNORED_DIR_SEGMENTS).toContain('node_modules');
    expect(SECRETS_SUPPORTED_EXTENSIONS).toContain('.yaml');
    expect(SECRETS_SUPPORTED_EXTENSIONS).not.toContain('.png');
    // NOTE: `.pem`/`.key`/`.env` paths are upload-blocked wholesale
    // (SOURCE_BLOCKED_EXTENSIONS) — such a path in a store is corrupt
    // state, and the engine's re-validation fails the scan closed
    // (covered in the failure-mode suite below).
  });
});

describe('secrets engine: PARTIAL honesty (never "0 secrets")', () => {
  test('oversize files are skipped → partial:true with a bounded reason', async () => {
    const outcome = await completedOutcome(
      engineWith(
        snapshot([
          { path: 'src/ok.ts', content: `const k = "${SYNTH.awsKey}";\n` },
          { path: 'src/big.ts', content: `${'x'.repeat(200)}\n` },
        ]),
        { maxFileBytes: 100 },
      ),
    );
    // A secret WAS found AND content was skipped — both stated.
    expect(outcome.findings?.length).toBe(1);
    expect(outcome.resultSummary.filesScanned).toBe(1);
    expect(outcome.resultSummary.partial).toBe(true);
    expect(outcome.resultSummary.partialReason).toContain('exceeded the per-file size limit');
    expect(outcome.resultSummary.partialReason).toContain('1 file(s)');

    // Nothing inspected at all: 0 findings is "not assessed", NOT
    // "no secrets" — partial:true + reason carry that meaning.
    const none = await completedOutcome(
      engineWith(snapshot([{ path: 'src/big.ts', content: `${'x'.repeat(200)}\n` }]), {
        maxFileBytes: 100,
      }),
    );
    expect(none.findings).toBeUndefined();
    expect(none.resultSummary.findingsTotal).toBe(0);
    expect(none.resultSummary.partial).toBe(true);
    expect(none.resultSummary.partialReason).toContain('exceeded the per-file size limit');
    assertNoRawSecrets(none);
  });

  test('the findings cap truncates and flags partial — HTTP-reachable path', async () => {
    const outcome = await completedOutcome(
      engineWith(
        snapshot([
          { path: 'a.ts', content: `const a = "${SYNTH.awsKey}";\n` },
          { path: 'b.ts', content: `const b = "${SYNTH.awsKey}";\n` },
        ]),
        { maxFindings: 1 },
      ),
    );
    expect(outcome.findings?.length).toBe(1);
    expect(outcome.resultSummary.findingsTotal).toBe(1);
    expect(outcome.resultSummary.truncated).toBe(true);
    expect(outcome.resultSummary.partial).toBe(true);
    expect(outcome.resultSummary.partialReason).toContain('findings cap');
    assertNoRawSecrets(outcome);
  });
});

describe('secrets engine: adversarial redaction (the long-line edge)', () => {
  test('a >200-char line with the secret at the far end leaks no fragment', async () => {
    const line = `${'#'.repeat(300)}aws_key = "${SYNTH.awsKey}"${'.'.repeat(220)}`;
    const outcome = await completedOutcome(
      engineWith(snapshot([{ path: 'long.js', content: `${line}\n` }])),
    );
    const finding: Finding | undefined = outcome.findings?.[0];
    expect(finding?.ruleId).toBe('DG-SEC-002');
    expect(finding?.evidence.length).toBeLessThanOrEqual(200);
    expect(finding?.evidence.startsWith('…')).toBe(true);
    expect(finding?.evidence.endsWith('…')).toBe(true);
    expect(finding?.evidence).toContain('<redacted>');
    // No fragment of the value — not even half of it.
    expect(finding?.evidence).not.toContain(SYNTH.awsKey.slice(0, 10));
    expect(finding?.evidence).not.toContain(SYNTH.awsKey.slice(-10));
    assertNoRawSecrets(outcome);
  });

  test('a long line whose value is cut by the window edge still shows no fragment', async () => {
    // Value sits near the END of the line: the window must clip the
    // span, never expose the clipped remainder.
    const line = `${'#'.repeat(280)}token ${SYNTH.githubToken}${'.'.repeat(5)}`;
    const outcome = await completedOutcome(
      engineWith(snapshot([{ path: 'long.js', content: `${line}\n` }])),
    );
    const evidence = outcome.findings?.[0]?.evidence ?? '';
    expect(evidence).not.toContain(SYNTH.githubToken.slice(0, 10));
    expect(evidence).not.toContain(SYNTH.githubToken.slice(-10));
    assertNoRawSecrets(outcome);
  });

  test('tabs never shift the redaction span (coordinate consistency)', async () => {
    const outcome = await completedOutcome(
      engineWith(snapshot([{ path: 'tabs.js', content: `\t\taws_key = "${SYNTH.awsKey}"\n` }])),
    );
    const finding = outcome.findings?.[0];
    expect(finding?.ruleId).toBe('DG-SEC-002');
    expect(finding?.evidence).toBe('    aws_key = "<redacted>"');
    expect(finding?.evidence).not.toContain('\t');
    assertNoRawSecrets(outcome);
  });
});

describe('secrets engine: failure modes fail closed', () => {
  test('no snapshot → SECRETS_TARGET_NOT_FOUND', async () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- legacy untyped boundary; new modules use unknown.
    const engine = createSecretsEngine({ sources: providerFor(undefined), rules: TEST_SECRETS_RULES as any });
    const outcome = await engine.execute(scanRecord(), ctx);
    expect(outcome).toMatchObject({ kind: 'failed', failureCode: 'SECRETS_TARGET_NOT_FOUND' });
  });

  test('owner mismatch (defense in depth) → SECRETS_INPUT_INVALID', async () => {
    const record = snapshot([{ path: 'a.ts', content: 'x = 1;\n' }]);
    const foreign: SourceSnapshotRecord = { ...record, ownerId: 'usr_00000000-0000-4000-8000-000000000099' };
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- legacy untyped boundary; new modules use unknown.
    const engine = createSecretsEngine({ sources: providerFor(foreign), rules: TEST_SECRETS_RULES as any });
    const outcome = await engine.execute(scanRecord(), ctx);
    expect(outcome).toMatchObject({ kind: 'failed', failureCode: 'SECRETS_INPUT_INVALID' });
  });

  test('a corrupt path fails the whole scan → SECRETS_INPUT_INVALID (traversal defense)', async () => {
    const engine = engineWith(
      snapshot([
        { path: 'src/ok.ts', content: 'x = 1;\n' },
        { path: '../escape.js', content: `const k = "${SYNTH.awsKey}";\n` },
      ]),
    );
    const outcome = await engine.execute(scanRecord(), ctx);
    expect(outcome).toMatchObject({ kind: 'failed', failureCode: 'SECRETS_INPUT_INVALID' });
    // Nothing was reported on the way out.
    expect(JSON.stringify(outcome)).not.toContain(SYNTH.awsKey);
  });

  test('too many scannable files → SECRETS_FILE_LIMIT_EXCEEDED', async () => {
    const engine = engineWith(
      snapshot([
        { path: 'a.ts', content: 'x = 1;\n' },
        { path: 'b.ts', content: 'x = 1;\n' },
      ]),
      { maxFiles: 1 },
    );
    const outcome = await engine.execute(scanRecord(), ctx);
    expect(outcome).toMatchObject({ kind: 'failed', failureCode: 'SECRETS_FILE_LIMIT_EXCEEDED' });
  });

  test('snapshot over the total size cap → SECRETS_TARGET_TOO_LARGE', async () => {
    const engine = engineWith(snapshot([{ path: 'a.ts', content: 'x'.repeat(120) }]), {
      maxTotalBytes: 100,
    });
    const outcome = await engine.execute(scanRecord(), ctx);
    expect(outcome).toMatchObject({ kind: 'failed', failureCode: 'SECRETS_TARGET_TOO_LARGE' });
  });

  test('deadline exceeded → SECRETS_SCAN_TIMEOUT', async () => {
    const engine = engineWith(
      snapshot([{ path: 'a.ts', content: `const k = "${SYNTH.awsKey}";\n` }]),
      { deadlineMs: 0 },
    );
    const outcome = await engine.execute(scanRecord(), ctx);
    expect(outcome).toMatchObject({ kind: 'failed', failureCode: 'SECRETS_SCAN_TIMEOUT' });
    expect(JSON.stringify(outcome)).not.toContain(SYNTH.awsKey);
  });

  test('pre-aborted signal → SECRETS_SCAN_TIMEOUT (cooperative cancel)', async () => {
    const engine = engineWith(snapshot([{ path: 'a.ts', content: 'x = 1;\n' }]));
    const controller = new AbortController();
    controller.abort();
    const outcome = await engine.execute(scanRecord(), { signal: controller.signal });
    expect(outcome).toMatchObject({ kind: 'failed', failureCode: 'SECRETS_SCAN_TIMEOUT' });
  });
});

describe('secrets engine: it never executes snapshot content', () => {
  test('scanning side-effect-bearing source changes nothing', async () => {
    const marker = `pump10-marker-${Date.now()}`;
    const engine = engineWith(
      snapshot([
        {
          path: 'payload.js',
          // Would create a marker file IF anything executed it.
          content: `require('node:fs').writeFileSync('/tmp/${marker}', 'pwned');\nconst k = "${SYNTH.awsKey}";\n`,
        },
      ]),
    );
    const outcome = await completedOutcome(engine);
    expect(outcome.findings?.length).toBe(1);
    expect(process.env.DROBON_P10_EXECUTED).toBeUndefined();
    // The engine is pure text analysis — no marker file was created.
    const { existsSync } = await import('node:fs');
    expect(existsSync(`/tmp/${marker}`)).toBe(false);
    assertNoRawSecrets(outcome);
  });
});

describe('secrets engine: limits registry', () => {
  test('defaults are the documented production limits', () => {
    expect(DEFAULT_SECRETS_LIMITS).toEqual({
      maxFiles: 200,
      maxFileBytes: 262_144,
      maxTotalBytes: 1_048_576,
      maxFindings: 200,
      deadlineMs: 10_000,
    });
  });
});
