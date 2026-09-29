import { describe, expect, test } from 'vitest';
import {
  REPORT_DIGEST_PATTERN,
  REPORT_ID_PATTERN,
  REPORT_MAX_BYTES,
  isReportFindingSummary,
  isSecurityReportResponse,
  summarizeReportFindings,
  type Finding,
} from '../src/index.js';

const findings: Finding[] = [
  {
    id: `fnd_${'1'.repeat(24)}`, scanId: 'scan_00000000-0000-4000-8000-000000000031', scanner: 'SAST',
    ruleId: 'DG-SAST-001', severity: 'HIGH', title: 'Unsafe source construct',
    description: 'Synthetic report summary fixture.', evidence: '<redacted>', remediation: 'Use a safe alternative.',
    file: 'src/app.ts', line: 1, column: 1, fingerprint: 'a'.repeat(64),
  },
  {
    id: `fnd_${'2'.repeat(24)}`, scanId: 'scan_00000000-0000-4000-8000-000000000031', scanner: 'SECRETS',
    ruleId: 'DG-SEC-001', severity: 'MEDIUM', title: 'Potential credential-like value',
    description: 'Synthetic fixture only; not credential validity.', evidence: '<redacted>', remediation: 'Rotate if real and remove from source.',
    confidence: 'HIGH', file: 'src/config.ts', line: 3, column: 1, fingerprint: 'b'.repeat(64),
  },
];

describe('report shared contracts', () => {
  test('report identifiers, digests and byte bounds are finite and closed', () => {
    expect(REPORT_ID_PATTERN.test('rpt_0123456789abcdef01234567')).toBe(true);
    expect(REPORT_ID_PATTERN.test('rpt_../../etc/passwd')).toBe(false);
    expect(REPORT_DIGEST_PATTERN.test('a'.repeat(64))).toBe(true);
    expect(REPORT_DIGEST_PATTERN.test('not-a-digest')).toBe(false);
    expect(REPORT_MAX_BYTES).toBeLessThanOrEqual(512 * 1024);
  });

  test('finding summaries include every severity and scanner with consistent totals', () => {
    const summary = summarizeReportFindings(findings);
    expect(summary.total).toBe(2);
    expect(summary.bySeverity.HIGH).toBe(1);
    expect(summary.bySeverity.MEDIUM).toBe(1);
    expect(summary.byScanner.SAST).toBe(1);
    expect(summary.byScanner.SECRETS).toBe(1);
    expect(isReportFindingSummary(summary)).toBe(true);
    expect(isReportFindingSummary({ ...summary, total: 1 })).toBe(false);
  });

  test('report response guard rejects unbound, malformed, or expanded envelopes', () => {
    expect(isSecurityReportResponse({ report: {} })).toBe(false);
    expect(isSecurityReportResponse({ report: {}, extra: true })).toBe(false);
    expect(isSecurityReportResponse(null)).toBe(false);
  });
});
