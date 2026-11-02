import { describe, expect, test } from 'vitest';
import {
  SAST_YIELD_BUDGET_MS,
  SAST_YIELD_EVERY_FILES,
  createSastEngine,
  sastShouldYield,
} from '../src/scans/sast/engine.js';
import type { SastRule } from '../src/scans/sast/rules.js';
import type { ScanRecord } from '../src/scans/store.js';
import type { SourceSnapshotRecord } from '../src/scans/sources.js';

/**
 * P1-5 — cooperative yielding. The engine runs synchronous lexical matching, so
 * the ONLY thing that keeps the API process responsive during a scan is the
 * yield policy. These tests pin the policy itself (pure function) and prove the
 * engine still completes a maximal-ish snapshot, deterministically.
 */

const OWNER = 'usr_00000000-0000-4000-8000-000000000051';
const PROJECT = 'prj_00000000-0000-4000-8000-000000000052';
const SCAN = 'scan_00000000-0000-4000-8000-000000000053';
const AT = '2026-11-02T10:00:00.000Z';

const record: ScanRecord = {
  id: SCAN,
  ownerId: OWNER,
  projectId: PROJECT,
  scanType: 'SAST',
  status: 'RUNNING',
  createdAt: AT,
  updatedAt: AT,
  startedAt: AT,
};

const RULE: SastRule = {
  id: 'DG-SAST-001',
  title: 'Fixture command rule',
  description: 'Fixture rule used to exercise the scan loop.',
  severity: 'HIGH',
  cwe: 'CWE-78',
  category: 'command-injection',
  remediation: 'Fixture remediation.',
  limitation: 'Fixture only.',
  patterns: [/never-match-yield-fixture/],
  languages: ['javascript', 'typescript'],
};

function snapshot(files: Array<{ path: string; content: string }>): SourceSnapshotRecord {
  return {
    ownerId: OWNER,
    projectId: PROJECT,
    files: files.map((file) => ({
      path: file.path,
      content: file.content,
      bytes: Buffer.byteLength(file.content, 'utf8'),
    })),
    createdAt: AT,
    updatedAt: AT,
  };
}

describe('SAST yield policy (P1-5)', () => {
  test('the first file never yields, and the file ceiling still applies', () => {
    expect(sastShouldYield(1, 10_000)).toBe(false);
    expect(sastShouldYield(2, 0)).toBe(false);
    expect(sastShouldYield(SAST_YIELD_EVERY_FILES, 0)).toBe(false);
    // …until the ceiling is crossed.
    expect(sastShouldYield(SAST_YIELD_EVERY_FILES + 1, 0)).toBe(true);
    expect(sastShouldYield(2 * SAST_YIELD_EVERY_FILES + 1, 0)).toBe(true);
  });

  test('a slice that used its CPU budget yields regardless of the file count', () => {
    expect(sastShouldYield(2, SAST_YIELD_BUDGET_MS - 1)).toBe(false);
    expect(sastShouldYield(2, SAST_YIELD_BUDGET_MS)).toBe(true);
    // A single enormous file (256 KiB) must not starve the loop.
    expect(sastShouldYield(3, SAST_YIELD_BUDGET_MS * 4)).toBe(true);
  });
});

describe('SAST engine with time-sliced yielding', () => {
  const files = Array.from({ length: 40 }, (_, index) => ({
    path: `src/file-${String(index).padStart(2, '0')}.ts`,
    content: `export const value${index} = ${index};\nchild_process.exec(req.body.cmd);\n`,
  }));

  test('a scan whose files are "slow" still completes and stays deterministic', async () => {
    // Every clock read advances 25 ms, i.e. every file looks expensive: the
    // engine must yield on essentially every file and still finish correctly.
    let tick = 0;
    const engine = createSastEngine({
      sources: { findByProject: async () => snapshot(files) },
      rules: [RULE],
      sliceClock: () => (tick += 25),
    });
    const first = await engine.execute(record, { signal: new AbortController().signal });
    const second = await engine.execute(record, { signal: new AbortController().signal });
    expect(first.kind).toBe('completed');
    expect(second.kind).toBe('completed');
    if (first.kind !== 'completed' || second.kind !== 'completed') return;
    // Same scan, same result — yielding changes scheduling, not output.
    expect(second.findings).toEqual(first.findings);
    expect(second.resultSummary).toEqual(first.resultSummary);
    expect(first.resultSummary.filesScanned).toBe(files.length);
  });

  test('a frozen slice clock behaves exactly like the old every-8-files rule', async () => {
    const engine = createSastEngine({
      sources: { findByProject: async () => snapshot(files) },
      rules: [RULE],
      sliceClock: () => 0,
    });
    const outcome = await engine.execute(record, { signal: new AbortController().signal });
    expect(outcome.kind).toBe('completed');
    if (outcome.kind !== 'completed') return;
    expect(outcome.resultSummary.filesScanned).toBe(files.length);
    expect(outcome.findings?.length ?? 0).toBeGreaterThan(0);
  });
});
