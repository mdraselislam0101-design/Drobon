import { describe, expect, test } from 'vitest';
import {
  IDEMPOTENCY_KEY_PATTERN,
  MAX_FINDINGS_PER_SCAN,
  SCAN_FAILURE_CODES,
  SCAN_ID_PATTERN,
  SCAN_STATUSES,
  SCAN_TYPES,
  compareFindings,
  compareScansDesc,
  isFinding,
  isFindingSeverity,
  isScan,
  isScanDetailResponse,
  isScanFailureCode,
  isScanResponse,
  isScanResultSummary,
  isScanStatus,
  isScanType,
  isScansResponse,
  type Finding,
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
      'SAST_TARGET_NOT_FOUND',
      'SAST_TARGET_TOO_LARGE',
      'SAST_FILE_LIMIT_EXCEEDED',
      'SAST_SCAN_TIMEOUT',
      'SAST_INPUT_INVALID',
      'SAST_UNSUPPORTED_LANGUAGE',
      // Pump 9: the SCA engine's mirror set.
      'SCA_TARGET_NOT_FOUND',
      'SCA_TARGET_TOO_LARGE',
      'SCA_MANIFEST_LIMIT_EXCEEDED',
      'SCA_SCAN_TIMEOUT',
      'SCA_INPUT_INVALID',
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

describe('findings (Pump 8)', () => {
  const finding: Finding = {
    id: 'fnd_' + 'a'.repeat(24),
    scanId: 'scan_00000000-0000-4000-8000-000000000000',
    ruleId: 'DG-SAST-001',
    severity: 'HIGH',
    title: 'OS command built from dynamic input',
    description: 'A shell command is constructed with interpolated values.',
    cwe: 'CWE-78',
    file: 'src/run.ts',
    line: 12,
    column: 7,
    evidence: 'exec(`rm -rf ${dir}`)',
    remediation: 'Use execFile with an argument array.',
    fingerprint: 'b'.repeat(64),
  };

  test('isFinding accepts the exact closed shape', () => {
    expect(isFinding(finding)).toBe(true);
    expect(compareFindings(finding, { ...finding, severity: 'HIGH' as const })).toBe(0);
  });

  test('isFinding rejects unknown/injected fields (closed shape)', () => {
    expect(isFinding({ ...finding, ownerId: 'usr_1' })).toBe(false);
    expect(isFinding({ ...finding, cvss: 9.8 })).toBe(false); // NEVER fabricated scores.
    expect(isFinding({ ...finding, exploitability: 'high' })).toBe(false);
    expect(isFinding({ ...finding, status: 'OPEN' })).toBe(false);
  });

  test('isFinding enforces id/fingerprint/rule/CWE patterns', () => {
    expect(isFinding({ ...finding, id: 'fnd_short' })).toBe(false);
    expect(isFinding({ ...finding, id: 'scan_' + 'a'.repeat(24) })).toBe(false);
    expect(isFinding({ ...finding, fingerprint: 'z'.repeat(64) })).toBe(false);
    expect(isFinding({ ...finding, ruleId: 'SAST-001' })).toBe(false);
    expect(isFinding({ ...finding, ruleId: 'DG-SAST-9999' })).toBe(false);
    expect(isFinding({ ...finding, cwe: 'CWE-0' })).toBe(false);
    expect(isFinding({ ...finding, cwe: 'CWE-7x' })).toBe(false);
    expect(isFinding({ ...finding, cwe: 'CWE-78' })).toBe(true);
  });

  test('isFinding enforces severity vocabulary and rejects client input shapes', () => {
    for (const severity of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']) {
      expect(isFinding({ ...finding, severity })).toBe(true);
      expect(isFindingSeverity(severity)).toBe(true);
    }
    for (const severity of ['critical', 'EXTREME', 'NONE', '', 5, null, undefined]) {
      expect(isFinding({ ...finding, severity })).toBe(false);
      expect(isFindingSeverity(severity)).toBe(false);
    }
  });

  test('isFinding enforces line/column bounds and safe text', () => {
    expect(isFinding({ ...finding, line: 0 })).toBe(false);
    expect(isFinding({ ...finding, line: -1 })).toBe(false);
    expect(isFinding({ ...finding, line: 1.5 })).toBe(false);
    expect(isFinding({ ...finding, column: 0 })).toBe(false);
    expect(isFinding({ ...finding, column: 1.5 })).toBe(false);
    expect(isFinding({ ...finding, evidence: '' })).toBe(false);
    expect(isFinding({ ...finding, evidence: 'x'.repeat(201) })).toBe(false);
    expect(isFinding({ ...finding, evidence: 'a\nb' })).toBe(false); // control chars rejected
    expect(isFinding({ ...finding, evidence: 'a\tb' })).toBe(false);
    expect(isFinding({ ...finding, title: 'x'.repeat(81) })).toBe(false);
    expect(isFinding({ ...finding, file: '../escape.ts' })).toBe(false); // traversal-shaped file path
    expect(isFinding({ ...finding, file: 'x'.repeat(161) })).toBe(false);
  });

  test('compareFindings orders by severity rank then file/line/rule deterministically', () => {
    const base = { ...finding };
    const critical = { ...base, severity: 'CRITICAL' as const };
    const low = { ...base, severity: 'LOW' as const, ruleId: 'DG-SAST-006' };
    const laterFile = { ...base, file: 'src/zzz.ts' };
    const laterLine = { ...base, line: 13 };
    const otherRule = { ...base, ruleId: 'DG-SAST-002' };
    expect(compareFindings(critical, base)).toBeLessThan(0);
    expect(compareFindings(low, base)).toBeGreaterThan(0);
    expect(compareFindings(laterFile, base)).toBeGreaterThan(0);
    expect(compareFindings(laterLine, base)).toBeGreaterThan(0);
    expect(compareFindings(otherRule, base)).toBeGreaterThan(0);
    // The documented severity order.
    const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
    for (let i = 1; i < order.length; i += 1) {
      expect(compareFindings(
        { ...base, severity: order[i] as Finding['severity'] },
        { ...base, severity: order[i - 1] as Finding['severity'] },
      )).toBeGreaterThan(0);
    }
  });

  test('ScanResultSummary keeps the Pump 7 base shape and adds SAST fields behind one guard', () => {
    expect(isScanResultSummary({ findingsTotal: 2 })).toBe(true);
    expect(isScanResultSummary({
      findingsTotal: 2,
      findingsBySeverity: { CRITICAL: 0, HIGH: 1, MEDIUM: 1, LOW: 0, INFO: 0 },
      filesScanned: 10,
      filesSkipped: 2,
      truncated: false,
    })).toBe(true);
    expect(isScanResultSummary({})).toBe(false);
    expect(isScanResultSummary({ findingsTotal: -1 })).toBe(false);
    expect(isScanResultSummary({ findingsTotal: 2, filesScanned: -1 })).toBe(false);
    expect(isScanResultSummary({ findingsTotal: 2, findingsBySeverity: { HIGH: 1 } })).toBe(false); // all five keys
    expect(isScanResultSummary({ findingsTotal: 2, cvss: 4.2 })).toBe(false);
    expect(isScanResultSummary({ findingsTotal: 2, truncated: 'no' })).toBe(false);
    expect(isScanResultSummary({ findingsTotal: 2, extra: 1 })).toBe(false);
  });

  test('scan detail response guard accepts scan+findings and stays bounded', () => {
    const scan = {
      id: 'scan_00000000-0000-4000-8000-000000000000',
      projectId: 'prj_00000000-0000-4000-8000-000000000000',
      scanType: 'SAST',
      status: 'COMPLETED',
      createdAt: '2026-09-28T10:00:00.000Z',
      updatedAt: '2026-09-28T10:00:01.000Z',
      startedAt: '2026-09-28T10:00:00.500Z',
      completedAt: '2026-09-28T10:00:01.000Z',
      resultSummary: { findingsTotal: 1 },
    };
    const detail = { ...scan, findings: [finding] };
    expect(isScanDetailResponse({ scan: detail })).toBe(true);
    // List-shaped scan (no findings key) is NOT a detail response.
    expect(isScanDetailResponse({ scan })).toBe(false);
    // Over the hard findings cap: rejected.
    expect(isScanDetailResponse({
      scan: { ...detail, findings: Array.from({ length: MAX_FINDINGS_PER_SCAN + 1 }, () => finding) },
    })).toBe(false);
    // A findings list containing a non-finding: rejected.
    expect(isScanDetailResponse({ scan: { ...detail, findings: [finding, { bad: 1 }] } })).toBe(false);
    // Extra envelope fields: rejected (closed shape).
    expect(isScanDetailResponse({ scan: detail, extra: true })).toBe(false);
  });
});
