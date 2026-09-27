import { describe, expect, test } from 'vitest';
import {
  IDEMPOTENCY_KEY_PATTERN,
  SCAN_FAILURE_CODES,
  SCAN_ID_PATTERN,
  SCAN_STATUSES,
  SCAN_TYPES,
  compareScansDesc,
  isScan,
  isScanFailureCode,
  isScanResponse,
  isScanStatus,
  isScanType,
  isScansResponse,
  type Scan,
} from '../src/scans.js';

/**
 * Scan-job contract tests (Pump 7) — the orchestration vocabulary and
 * the public response guards, including the state-machine invariants a
 * client must never be able to violate with a forged payload.
 */

function baseScan(overrides: Partial<Scan> = {}): Scan {
  return {
    id: 'scan_00000000-0000-4000-8000-000000000000',
    projectId: 'prj_00000000-0000-4000-8000-000000000000',
    scanType: 'SAST',
    status: 'QUEUED',
    createdAt: '2026-09-15T12:00:00.000Z',
    updatedAt: '2026-09-15T12:00:00.000Z',
    ...overrides,
  };
}

describe('scan vocabulary', () => {
  test('SCAN_TYPES is exactly the four supported job types', () => {
    expect([...SCAN_TYPES]).toEqual(['SAST', 'SCA', 'SECRETS', 'DAST']);
  });

  test('SCAN_STATUSES is the closed server-authoritative lifecycle', () => {
    expect([...SCAN_STATUSES]).toEqual(['QUEUED', 'RUNNING', 'COMPLETED', 'FAILED']);
  });

  test('SCAN_FAILURE_CODES is closed and carries no internals', () => {
    expect([...SCAN_FAILURE_CODES]).toEqual([
      'SCAN_ENGINE_NOT_IMPLEMENTED',
      'SCAN_INTERRUPTED',
      'SCAN_ENGINE_ERROR',
    ]);
  });

  test('type guards accept members and reject everything else', () => {
    for (const type of SCAN_TYPES) {
      expect(isScanType(type)).toBe(true);
    }
    for (const status of SCAN_STATUSES) {
      expect(isScanStatus(status)).toBe(true);
    }
    for (const code of SCAN_FAILURE_CODES) {
      expect(isScanFailureCode(code)).toBe(true);
    }
    expect(isScanType('sast')).toBe(false); // Case-sensitive.
    expect(isScanType('EVIL')).toBe(false); // No arbitrary types.
    expect(isScanType(42)).toBe(false);
    expect(isScanStatus('completed')).toBe(false);
    expect(isScanStatus(null)).toBe(false);
    expect(isScanFailureCode('STACK_TRACE_DUMP')).toBe(false);
    expect(isScanFailureCode(undefined)).toBe(false);
  });

  test('id pattern: scan_ + lowercase UUID v4 only', () => {
    expect(SCAN_ID_PATTERN.test('scan_920fdca8-63f9-491b-9858-cc5f3ac96860')).toBe(true);
    expect(SCAN_ID_PATTERN.test('prj_920fdca8-63f9-491b-9858-cc5f3ac96860')).toBe(false);
    expect(SCAN_ID_PATTERN.test('scan_920FDCA8-63F9-491B-9858-CC5F3AC96860')).toBe(false);
    expect(SCAN_ID_PATTERN.test('scan_1')).toBe(false);
    expect(SCAN_ID_PATTERN.test('scan_920fdca8-63f9-491b-9858-cc5f3ac9686')).toBe(false);
    expect(SCAN_ID_PATTERN.test('../../etc/passwd')).toBe(false);
  });

  test('idempotency key pattern: 8–64 URL-safe characters', () => {
    expect(IDEMPOTENCY_KEY_PATTERN.test('abc123XY_-')).toBe(true);
    expect(IDEMPOTENCY_KEY_PATTERN.test('920fdca8-63f9-491b-9858-cc5f3ac96860')).toBe(true);
    expect(IDEMPOTENCY_KEY_PATTERN.test('short')).toBe(false); // < 8.
    expect(IDEMPOTENCY_KEY_PATTERN.test('a'.repeat(65))).toBe(false); // > 64.
    expect(IDEMPOTENCY_KEY_PATTERN.test('has space')).toBe(false);
    expect(IDEMPOTENCY_KEY_PATTERN.test('has/slash')).toBe(false);
    expect(IDEMPOTENCY_KEY_PATTERN.test('')).toBe(false);
  });
});

describe('isScan guard', () => {
  test('accepts a valid QUEUED scan and every legal terminal shape', () => {
    expect(isScan(baseScan())).toBe(true);
    expect(
      isScan(
        baseScan({
          status: 'RUNNING',
          startedAt: '2026-09-15T12:00:01.000Z',
          updatedAt: '2026-09-15T12:00:01.000Z',
        }),
      ),
    ).toBe(true);
    expect(
      isScan(
        baseScan({
          status: 'COMPLETED',
          startedAt: '2026-09-15T12:00:01.000Z',
          completedAt: '2026-09-15T12:00:02.000Z',
          updatedAt: '2026-09-15T12:00:02.000Z',
          resultSummary: { findingsTotal: 0 },
        }),
      ),
    ).toBe(true);
    expect(
      isScan(
        baseScan({
          status: 'FAILED',
          startedAt: '2026-09-15T12:00:01.000Z',
          completedAt: '2026-09-15T12:00:02.000Z',
          updatedAt: '2026-09-15T12:00:02.000Z',
          failureCode: 'SCAN_ENGINE_NOT_IMPLEMENTED',
          failureMessage: 'The SAST scanner engine is not implemented yet.',
        }),
      ),
    ).toBe(true);
  });

  test('rejects non-objects, wrong shapes and unknown fields', () => {
    expect(isScan(null)).toBe(false);
    expect(isScan('scan')).toBe(false);
    expect(isScan([])).toBe(false);
    expect(isScan({})).toBe(false);
    // Unknown property (e.g. a smuggled owner/worker field).
    expect(isScan({ ...baseScan(), ownerId: 'usr_1' })).toBe(false);
    expect(isScan({ ...baseScan(), worker: 'node-7' })).toBe(false);
    expect(isScan({ ...baseScan(), extra: true })).toBe(false);
    // Bad id / type / status.
    expect(isScan(baseScan({ id: 'not-a-scan-id' }))).toBe(false);
    // Invalid literals: assert through the widened Partial<Scan> input
    // the guard actually receives at runtime (untrusted JSON).
    expect(isScan({ ...baseScan(), scanType: 'EVIL' })).toBe(false);
    expect(isScan({ ...baseScan(), status: 'CANCELLED' })).toBe(false);
    expect(isScan(baseScan({ projectId: '' }))).toBe(false);
  });

  test('enforces the state-machine invariants on forged payloads', () => {
    // A client must never conjure a completed/failed scan by itself.
    expect(isScan(baseScan({ status: 'RUNNING' }))).toBe(false); // No startedAt.
    expect(
      isScan(baseScan({ status: 'COMPLETED', completedAt: '2026-09-15T12:00:02.000Z' })),
    ).toBe(false); // No startedAt/result.
    expect(
      isScan(
        baseScan({
          status: 'COMPLETED',
          startedAt: '2026-09-15T12:00:01.000Z',
          completedAt: '2026-09-15T12:00:02.000Z',
        }),
      ),
    ).toBe(false); // COMPLETED requires a resultSummary.
    expect(
      isScan(
        baseScan({
          status: 'FAILED',
          startedAt: '2026-09-15T12:00:01.000Z',
          completedAt: '2026-09-15T12:00:02.000Z',
          failureMessage: 'boom',
        }),
      ),
    ).toBe(false); // FAILED requires a failureCode.
    // QUEUED carries no lifecycle fields at all.
    expect(isScan(baseScan({ startedAt: '2026-09-15T12:00:01.000Z' }))).toBe(false);
    expect(isScan(baseScan({ completedAt: '2026-09-15T12:00:02.000Z' }))).toBe(false);
    expect(isScan(baseScan({ failureCode: 'SCAN_ENGINE_ERROR' }))).toBe(false);
    expect(isScan(baseScan({ resultSummary: { findingsTotal: 3 } }))).toBe(false);
    // COMPLETED never carries failure fields; FAILED never a result.
    expect(
      isScan(
        baseScan({
          status: 'COMPLETED',
          startedAt: '2026-09-15T12:00:01.000Z',
          completedAt: '2026-09-15T12:00:02.000Z',
          resultSummary: { findingsTotal: 0 },
          failureCode: 'SCAN_ENGINE_ERROR',
        }),
      ),
    ).toBe(false);
    expect(
      isScan(
        baseScan({
          status: 'FAILED',
          startedAt: '2026-09-15T12:00:01.000Z',
          completedAt: '2026-09-15T12:00:02.000Z',
          failureCode: 'SCAN_INTERRUPTED',
          resultSummary: { findingsTotal: 0 },
        }),
      ),
    ).toBe(false);
    // resultSummary shape: non-negative integer counts only.
    expect(
      isScan(
        baseScan({
          status: 'COMPLETED',
          startedAt: '2026-09-15T12:00:01.000Z',
          completedAt: '2026-09-15T12:00:02.000Z',
          resultSummary: { findingsTotal: -1 },
        }),
      ),
    ).toBe(false);
    expect(
      isScan(
        baseScan({
          status: 'COMPLETED',
          startedAt: '2026-09-15T12:00:01.000Z',
          completedAt: '2026-09-15T12:00:02.000Z',
          resultSummary: { findingsTotal: 1.5 },
        }),
      ),
    ).toBe(false);
  });
});

describe('response guards', () => {
  test('isScansResponse accepts a list and rejects everything else', () => {
    expect(isScansResponse({ scans: [baseScan()] })).toBe(true);
    expect(isScansResponse({ scans: [] })).toBe(true);
    expect(isScansResponse({ scans: [baseScan(), { nope: true }] })).toBe(false);
    expect(isScansResponse({ scans: [baseScan()], meta: 'x' })).toBe(false);
    expect(isScansResponse({ items: [] })).toBe(false);
    expect(isScansResponse(null)).toBe(false);
  });

  test('isScanResponse accepts exactly { scan } and rejects everything else', () => {
    expect(isScanResponse({ scan: baseScan() })).toBe(true);
    expect(isScanResponse({ scan: baseScan(), extra: 1 })).toBe(false);
    expect(isScanResponse({ scan: null })).toBe(false);
    expect(isScanResponse(baseScan())).toBe(false);
    expect(isScanResponse(undefined)).toBe(false);
  });
});

describe('compareScansDesc ordering contract', () => {
  test('newest createdAt first; id ASC breaks ties deterministically', () => {
    const a = baseScan({ id: 'scan_00000000-0000-4000-8000-00000000000a' });
    const b = baseScan({
      id: 'scan_00000000-0000-4000-8000-00000000000b',
      createdAt: '2026-09-15T12:00:01.000Z',
    });
    const c = baseScan({
      id: 'scan_00000000-0000-4000-8000-00000000000c',
      createdAt: '2026-09-15T12:00:02.000Z',
    });
    expect([...[a, c, b].sort(compareScansDesc)].map((scan) => scan.id)).toEqual([
      c.id,
      b.id,
      a.id,
    ]);
    // Identical createdAt → id ASC.
    expect(compareScansDesc(a, { ...a, id: `z${a.id}` }) < 0).toBe(true);
  });
});
