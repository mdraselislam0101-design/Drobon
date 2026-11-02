import { describe, expect, test } from 'vitest';
import { isScanResultSummary } from '@drobon/shared';
import type { ScanRecord } from '../src/scans/store.js';
import type { SourceSnapshotRecord } from '../src/scans/sources.js';
import { TEST_SECRETS_RULES } from './fixtures/testData.js';
import { createSecretsEngine, type SourceSnapshotProvider } from '../src/scans/secrets/engine.js';
import {
  isSecretsFindingBaselined,
  parseSecretsBaseline,
  SECRETS_BASELINE_PATH,
} from '../src/scans/secrets/baseline.js';

/**
 * P2-14 — the secrets baseline.
 *
 * The contract: a baseline suppresses ONLY what it names, every suppression is
 * disclosed, an unusable baseline suppresses nothing and says so, and no
 * baseline document can hide a different rule, a different file or a secret it
 * does not describe.
 */

const OWNER = 'usr_00000000-0000-4000-8000-000000000001';
const PROJECT = 'prj_00000000-0000-4000-8000-000000000002';
const SYNTH_KEY = 'AKIAP14QZ9WM7XK2BR4J'; // fake-test fixture
const SYNTH_PEM = ['-----BEGIN RSA ', 'PRIVATE KEY-----'].join(''); // fake-test fixture
const ctx = { signal: new AbortController().signal };

function scanRecord(): ScanRecord {
  return {
    id: 'scan_00000000-0000-4000-8000-000000000003',
    ownerId: OWNER,
    projectId: PROJECT,
    scanType: 'SECRETS',
    status: 'RUNNING',
    createdAt: '2026-11-02T10:00:00.000Z',
    updatedAt: '2026-11-02T10:00:00.000Z',
    startedAt: '2026-11-02T10:00:00.000Z',
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
    createdAt: '2026-11-02T09:00:00.000Z',
    updatedAt: '2026-11-02T09:00:00.000Z',
  };
}

function providerFor(record: SourceSnapshotRecord): SourceSnapshotProvider {
  return { findByProject: async () => record };
}

function engineFor(record: SourceSnapshotRecord) {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- test fixture rules
  return createSecretsEngine({ sources: providerFor(record), rules: TEST_SECRETS_RULES as any });
}

const SECRET_FILE = { path: 'src/config.js', content: `const key = "${SYNTH_KEY}";\nconst pem = "${SYNTH_PEM}";\n` };

describe('secrets baseline document (P2-14)', () => {
  test('a missing baseline is ABSENT, not an error', () => {
    expect(parseSecretsBaseline(undefined)).toEqual({ status: 'ABSENT', entries: [], invalid: 0 });
  });

  test('accepts rule+file and fingerprint entries, preserving order and reasons', () => {
    const parsed = parseSecretsBaseline(JSON.stringify({
      version: 1,
      entries: [
        { ruleId: 'DG-SEC-001', file: 'test/fixture.js', reason: 'synthetic fixture' },
        { fingerprint: 'a'.repeat(64) },
        { ruleId: 'DG-SEC-002', fingerprint: 'b'.repeat(64) },
      ],
    }));
    expect(parsed.status).toBe('ANALYZED');
    expect(parsed.invalid).toBe(0);
    expect(parsed.entries).toEqual([
      { ruleId: 'DG-SEC-001', file: 'test/fixture.js', reason: 'synthetic fixture' },
      { fingerprint: 'a'.repeat(64) },
      { ruleId: 'DG-SEC-002', fingerprint: 'b'.repeat(64) },
    ]);
  });

  test('rejects unusable documents instead of half-applying them', () => {
    for (const text of ['{oops', '[]', '{"version":2,"entries":[]}', '{"version":1}', '{"entries":[]}']) {
      const parsed = parseSecretsBaseline(text);
      expect(parsed.status).toBe('INVALID');
      expect(parsed.entries).toEqual([]);
    }
  });

  test('bounds the document and the entry count', () => {
    const oversized = `{"version":1,"entries":[],"pad":"${'x'.repeat(70 * 1024)}"}`;
    const tooBig = parseSecretsBaseline(oversized);
    expect(tooBig.status).toBe('INVALID');
    expect(tooBig.note).toContain('64 KiB');

    const tooMany = parseSecretsBaseline(JSON.stringify({
      version: 1,
      entries: Array.from({ length: 501 }, (_, index) => ({ ruleId: 'DG-SEC-001', file: `src/f${index}.js` })),
    }));
    expect(tooMany.status).toBe('INVALID');
    expect(tooMany.entries).toEqual([]);
  });

  test('counts every malformed entry and applies none of them', () => {
    const parsed = parseSecretsBaseline(JSON.stringify({
      version: 1,
      entries: [
        { ruleId: 'DG-SEC-001', file: 'src/ok.js' },
        'not-an-object',
        { reason: 'no target' },
        { ruleId: '../bad', file: 'src/x.js' },
        { ruleId: 'DG-SEC-001', file: '../etc/passwd' },
        { fingerprint: 'not-a-hash' },
        { ruleId: 'DG-SEC-001', file: 'src/y.js', reason: 'x'.repeat(201) },
      ],
    }));
    expect(parsed.status).toBe('ANALYZED');
    expect(parsed.entries).toEqual([{ ruleId: 'DG-SEC-001', file: 'src/ok.js' }]);
    expect(parsed.invalid).toBe(6);
    expect(parsed.note).toContain('6 baseline entries were invalid');
  });

  test('an entry only matches the fields it states', () => {
    const entries = [{ ruleId: 'DG-SEC-001', file: 'src/a.js' }];
    const base = { ruleId: 'DG-SEC-001', file: 'src/a.js', fingerprint: 'f'.repeat(64) };
    expect(isSecretsFindingBaselined(entries, base)).toBe(true);
    expect(isSecretsFindingBaselined(entries, { ...base, ruleId: 'DG-SEC-002' })).toBe(false);
    expect(isSecretsFindingBaselined(entries, { ...base, file: 'src/b.js' })).toBe(false);
    expect(isSecretsFindingBaselined([{ fingerprint: base.fingerprint }], base)).toBe(true);
    expect(isSecretsFindingBaselined([{ fingerprint: 'e'.repeat(64) }], base)).toBe(false);
    expect(isSecretsFindingBaselined([], base)).toBe(false);
  });
});

describe('secrets baseline in the engine (P2-14)', () => {
  test('without a baseline every finding is reported and the status is ABSENT', async () => {
    const outcome = await engineFor(snapshot([SECRET_FILE])).execute(scanRecord(), ctx);
    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed') return;
    expect(outcome.findings?.length).toBeGreaterThanOrEqual(2);
    expect(outcome.resultSummary.secretsBaseline).toEqual({ status: 'ABSENT', entries: 0, applied: 0, invalid: 0 });
    expect(isScanResultSummary(outcome.resultSummary)).toBe(true);
  });

  test('a rule+file entry suppresses only that rule in that file, and is disclosed', async () => {
    const outcome = await engineFor(snapshot([
      SECRET_FILE,
      {
        path: SECRETS_BASELINE_PATH,
        content: JSON.stringify({ version: 1, entries: [{ ruleId: 'DG-SEC-001', file: 'src/config.js', reason: 'synthetic fixture' }] }),
      },
    ])).execute(scanRecord(), ctx);
    if (outcome.kind !== 'completed') throw new Error('scan failed');
    expect(outcome.resultSummary.secretsBaseline).toEqual({ status: 'ANALYZED', entries: 1, applied: 1, invalid: 0 });
    // The PEM finding (DG-SEC-001) is suppressed; the service credential is not.
    expect(outcome.findings?.some((finding) => finding.ruleId === 'DG-SEC-001')).toBe(false);
    expect(outcome.findings?.some((finding) => finding.ruleId === 'DG-SEC-002')).toBe(true);
    expect(isScanResultSummary(outcome.resultSummary)).toBe(true);
    // Redaction survives suppression: no synthetic value in the payload.
    expect(JSON.stringify(outcome)).not.toContain(SYNTH_KEY);
  });

  test('a fingerprint entry suppresses exactly one finding', async () => {
    const first = await engineFor(snapshot([SECRET_FILE])).execute(scanRecord(), ctx);
    if (first.kind !== 'completed') throw new Error('scan failed');
    const target = first.findings?.find((finding) => finding.ruleId === 'DG-SEC-002');
    if (target === undefined) throw new Error('missing fixture finding');

    const outcome = await engineFor(snapshot([
      SECRET_FILE,
      { path: SECRETS_BASELINE_PATH, content: JSON.stringify({ version: 1, entries: [{ fingerprint: target.fingerprint }] }) },
    ])).execute(scanRecord(), ctx);
    if (outcome.kind !== 'completed') throw new Error('scan failed');
    expect(outcome.resultSummary.secretsBaseline).toMatchObject({ status: 'ANALYZED', entries: 1, applied: 1 });
    expect(outcome.findings?.some((finding) => finding.fingerprint === target.fingerprint)).toBe(false);
    // The unrelated rule is untouched.
    expect(outcome.findings?.some((finding) => finding.ruleId === 'DG-SEC-001')).toBe(true);
  });

  test('an invalid baseline suppresses nothing and marks the scan partial', async () => {
    const outcome = await engineFor(snapshot([
      SECRET_FILE,
      { path: SECRETS_BASELINE_PATH, content: '{"version":1,"entries":' },
    ])).execute(scanRecord(), ctx);
    if (outcome.kind !== 'completed') throw new Error('scan failed');
    expect(outcome.resultSummary.secretsBaseline).toEqual({ status: 'INVALID', entries: 0, applied: 0, invalid: 0 });
    expect(outcome.findings?.length).toBeGreaterThanOrEqual(2);
    expect(outcome.resultSummary.partial).toBe(true);
    expect(outcome.resultSummary.partialReason).toContain('baseline');
    expect(isScanResultSummary(outcome.resultSummary)).toBe(true);
  });

  test('a baseline cannot hide a rule it does not name, even when every entry is valid', async () => {
    const outcome = await engineFor(snapshot([
      SECRET_FILE,
      { path: SECRETS_BASELINE_PATH, content: JSON.stringify({ version: 1, entries: [{ ruleId: 'DG-SEC-999', file: 'src/config.js' }] }) },
    ])).execute(scanRecord(), ctx);
    if (outcome.kind !== 'completed') throw new Error('scan failed');
    expect(outcome.resultSummary.secretsBaseline).toEqual({ status: 'ANALYZED', entries: 1, applied: 0, invalid: 0 });
    expect(outcome.findings?.length).toBeGreaterThanOrEqual(2);
  });

  test('suppression is deterministic across identical scans', async () => {
    const record = snapshot([
      SECRET_FILE,
      { path: SECRETS_BASELINE_PATH, content: JSON.stringify({ version: 1, entries: [{ ruleId: 'DG-SEC-001', file: 'src/config.js' }] }) },
    ]);
    const first = await engineFor(record).execute(scanRecord(), ctx);
    const second = await engineFor(record).execute(scanRecord(), ctx);
    if (first.kind !== 'completed' || second.kind !== 'completed') throw new Error('scan failed');
    expect(second.resultSummary.secretsBaseline).toEqual(first.resultSummary.secretsBaseline);
    expect(second.findings?.map((finding) => finding.fingerprint)).toEqual(first.findings?.map((finding) => finding.fingerprint));
  });
});
