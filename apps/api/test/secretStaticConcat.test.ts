import { describe, expect, test } from 'vitest';
import { isFinding, isScanResultSummary } from '@drobon/shared';
import { createSecretsEngine } from '../src/scans/secrets/engine.js';
import { StructuredAstSession } from '../src/scans/sast/structuredAstSession.js';
import type { SourceSnapshotRecord } from '../src/scans/sources.js';
import type { ScanRecord } from '../src/scans/store.js';
import { TEST_SECRETS_RULES } from './fixtures/testData.js';

const OWNER = 'usr_00000000-0000-4000-8000-000000000001';
const PROJECT = 'prj_00000000-0000-4000-8000-000000000002';
const TIME = '2026-10-31T00:00:00.000Z';
const PREFIX = ['AK', 'IA'].join('');
const SUFFIX = 'X9V8U7T6S5R4Q3P2'; // invented shape; never a real credential
const record: ScanRecord = { id: 'scan_00000000-0000-4000-8000-000000000003', ownerId: OWNER, projectId: PROJECT,
  scanType: 'SECRETS', status: 'RUNNING', createdAt: TIME, updatedAt: TIME };

async function scan(files: Array<{ path: string; content: string }>, maxFindings?: number) {
  const snapshot: SourceSnapshotRecord = { ownerId: OWNER, projectId: PROJECT, createdAt: TIME, updatedAt: TIME,
    files: files.map((file) => ({ ...file, bytes: Buffer.byteLength(file.content) })) };
  const outcome = await createSecretsEngine({ sources: { findByProject: async () => snapshot }, rules: TEST_SECRETS_RULES,
    ...(maxFindings === undefined ? {} : { limits: { maxFindings } }) }).execute(record, { signal: new AbortController().signal });
  if (outcome.kind !== 'completed') throw new Error('Unexpected scan failure');
  expect(isScanResultSummary(outcome.resultSummary)).toBe(true);
  expect((outcome.findings ?? []).every(isFinding)).toBe(true);
  expect(JSON.stringify(outcome)).not.toContain(PREFIX + SUFFIX);
  expect(JSON.stringify(outcome)).not.toContain(SUFFIX);
  return outcome;
}

describe('bounded static literal-concatenation handling', () => {
  test('detects two and three literal pieces without evaluating source or exposing any pieces', async () => {
    const a = `const first = "${PREFIX}" + "${SUFFIX}";`;
    const b = `const second = ('${PREFIX.slice(0, 2)}' + '${PREFIX.slice(2)}') + '${SUFFIX}';`;
    const result = await scan([{ path: 'src/a.js', content: `// harmless\n${a}\n${b}\n` }]);
    const hits = (result.findings ?? []).filter((finding) => finding.ruleId === 'DG-SEC-002');
    expect(hits.map((finding) => finding.line)).toEqual([2, 3]);
    expect(hits.every((finding) => finding.evidence.includes('withheld'))).toBe(true);
    expect(result.resultSummary.astSupplement).toMatchObject({ status: 'RAN', parsed: 1 });
    expect(result.resultSummary.findingsTotal).toBe(hits.length);
  });

  test('preserves validation, deduplication, caps and deterministic file/line ordering', async () => {
    const files = [
      { path: 'z.js', content: `const key = "${PREFIX}" + "${SUFFIX}";` },
      { path: 'a.js', content: `const x = "${PREFIX}" + "${SUFFIX}"; const y = "${PREFIX}${SUFFIX}";` },
    ];
    const first = await scan(files);
    const second = await scan(files);
    const hits = (first.findings ?? []).filter((finding) => finding.ruleId === 'DG-SEC-002');
    expect(hits.map((finding) => finding.file)).toEqual(['a.js', 'z.js']);
    expect(hits.map((finding) => finding.fingerprint)).toEqual((second.findings ?? []).filter((f) => f.ruleId === 'DG-SEC-002').map((f) => f.fingerprint));
    const capped = await scan([{ path: 'a.js', content: `const x="${PREFIX}"+"${SUFFIX}";\nconst y="${PREFIX}"+"${SUFFIX}";` }], 1);
    expect(capped.findings).toHaveLength(1);
    expect(capped.resultSummary).toMatchObject({ truncated: true, partial: true });
    const placeholder = await scan([{ path: 'a.js', content: 'const api_key = "example-" + "placeholder-value-1234";' }]);
    expect(placeholder.findings ?? []).toHaveLength(0);
  });

  test('does not fold comments, dynamic expressions, templates, escaped literals or other languages', async () => {
    const inputs = [
      `// const key = "${PREFIX}" + "${SUFFIX}";\nconst note = "ok";`,
      `const key = "${PREFIX}" + process.env.REMAINDER + "${SUFFIX}";`,
      'const key = `AK${process.env.REMAINDER}IA`; ',
      `const key = "\\x41KIA" + "${SUFFIX}";`,
    ];
    for (const content of inputs) {
      const result = await scan([{ path: 'src/a.js', content }]);
      expect((result.findings ?? []).some((finding) => finding.ruleId === 'DG-SEC-002')).toBe(false);
    }
    const unsupported = await scan([{ path: 'src/a.py', content: `key = "${PREFIX}" + "${SUFFIX}"` }]);
    expect(unsupported.findings ?? []).toHaveLength(0);
    expect(unsupported.resultSummary.astSupplement?.status).toBe('PARTIAL');
  });

  test('work and line limits are explicit and preserve existing literal context', async () => {
    const many = `const direct="${PREFIX}${SUFFIX}";\n` + Array.from({ length: 70 }, (_, i) => `const v${i}="a"+"b";`).join('\n');
    const result = await scan([{ path: 'src/a.js', content: many }]);
    expect(result.resultSummary.astSupplement).toMatchObject({ status: 'PARTIAL', incomplete: 1, signals: 1 });
    expect(result.findings?.[0]?.astContext).toEqual({ kind: 'SECRETS_STRING_LITERAL' });
    const long = await scan([{ path: 'src/a.js', content: `const ${'v'.repeat(4_100)}="${PREFIX}"+"${SUFFIX}";` }]);
    expect(long.findings ?? []).toHaveLength(0);
    expect(long.resultSummary.astSupplement).toMatchObject({ status: 'PARTIAL', incomplete: 1 });
  });

  test('the isolated worker returns coordinates only, never literal contents', async () => {
    const session = new StructuredAstSession();
    try {
      const result = await session.analyzeSupplement({ kind: 'SECRETS', family: 'javascript',
        content: `const key = "${PREFIX}" + "${SUFFIX}";` }, new AbortController().signal, 5_000);
      expect(result.status).toBe('OK');
      expect(result.records.some((entry) => typeof entry === 'object' && entry !== null && 'type' in entry && entry.type === 'concat')).toBe(true);
      expect(JSON.stringify(result)).not.toContain(PREFIX);
      expect(JSON.stringify(result)).not.toContain(SUFFIX);
    } finally { await session.close(); }
  });
});
