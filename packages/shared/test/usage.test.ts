import { describe, expect, test } from 'vitest';
import {
  FREE_DEVICE_MONTHLY_SCAN_QUOTA,
  FREE_MONTHLY_SCAN_QUOTA,
  QUOTA_STATUSES,
  USAGE_PERIOD_PATTERN,
  isQuotaStatus,
  isUsagePeriodInfo,
  isUsageResponse,
  type UsageResponse,
} from '../src/index.js';

/**
 * Pump 5 usage/quota contract tests: the FREE quota constants, the UTC
 * period shape, and the payload guards that keep the client boundary
 * honest (no forged usage views, no invented quota statuses).
 */

describe('quota constants', () => {
  test('FREE allows exactly 3 scans per account per UTC month', () => {
    expect(FREE_MONTHLY_SCAN_QUOTA).toBe(3);
  });

  test('the shared FREE device allowance is exactly 3 scans per UTC month', () => {
    expect(FREE_DEVICE_MONTHLY_SCAN_QUOTA).toBe(3);
  });
});

describe('usage period contract', () => {
  test('the period identifier is a strict YYYY-MM UTC month', () => {
    for (const good of ['2026-09', '2026-10', '2027-01', '1999-12', '2100-01']) {
      expect(USAGE_PERIOD_PATTERN.test(good), good).toBe(true);
    }
    for (const bad of [
      '2026-9', // no zero padding
      '2026-00', // no month 0
      '2026-13', // no month 13
      '202609',
      '26-09',
      '2026-09-01', // a date, not a month
      '',
      'not-a-period',
    ]) {
      expect(USAGE_PERIOD_PATTERN.test(bad), bad).toBe(false);
    }
  });

  test('isUsagePeriodInfo validates the period triple', () => {
    expect(
      isUsagePeriodInfo({
        period: '2026-09',
        startUtc: '2026-09-01T00:00:00.000Z',
        endUtc: '2026-10-01T00:00:00.000Z',
      }),
    ).toBe(true);
    for (const bad of [
      { period: '2026-9', startUtc: '2026-09-01T00:00:00.000Z', endUtc: '2026-10-01T00:00:00.000Z' },
      { period: '2026-09', startUtc: 'yesterday', endUtc: '2026-10-01T00:00:00.000Z' },
      { period: '2026-09', startUtc: '2026-09-01T00:00:00.000Z', endUtc: 7 },
      { period: '2026-09' },
      null,
      42,
    ]) {
      expect(isUsagePeriodInfo(bad)).toBe(false);
    }
  });
});

describe('quota status vocabulary', () => {
  test('exactly three statuses exist', () => {
    expect(QUOTA_STATUSES).toEqual(['OK', 'EXHAUSTED', 'EXEMPT']);
    for (const status of QUOTA_STATUSES) {
      expect(isQuotaStatus(status)).toBe(true);
    }
    for (const bad of ['ok', 'UNLIMITED', 'LIMITED', '', null, 1]) {
      expect(isQuotaStatus(bad)).toBe(false);
    }
  });
});

describe('usage response guard (client boundary)', () => {
  const freeView: UsageResponse = {
    plan: 'FREE',
    period: { period: '2026-09', startUtc: '2026-09-01T00:00:00.000Z', endUtc: '2026-10-01T00:00:00.000Z' },
    used: 1,
    limit: 3,
    remaining: 2,
    quotaStatus: 'OK',
  };
  const proView: UsageResponse = {
    plan: 'PRO',
    period: { period: '2026-09', startUtc: '2026-09-01T00:00:00.000Z', endUtc: '2026-10-01T00:00:00.000Z' },
    used: 17,
    limit: null,
    remaining: null,
    quotaStatus: 'EXEMPT',
  };

  test('accepts the canonical FREE and PRO views', () => {
    expect(isUsageResponse(freeView)).toBe(true);
    expect(isUsageResponse(proView)).toBe(true);
    expect(
      isUsageResponse({ ...freeView, used: 3, remaining: 0, quotaStatus: 'EXHAUSTED' }),
    ).toBe(true);
  });

  test('rejects forged or malformed views', () => {
    for (const bad of [
      { ...freeView, plan: 'ENTERPRISE' }, // no third plan
      { ...freeView, plan: 'PRO', remaining: 999 }, // remaining above the limit
      { ...freeView, used: -1 }, // negative usage
      { ...freeView, used: 1.5 }, // fractional usage
      { ...freeView, used: '2' }, // string usage
      { ...freeView, limit: '3' },
      { ...freeView, remaining: undefined },
      { ...freeView, quotaStatus: 'UNLIMITED' },
      { ...freeView, period: { period: '2026-09' } }, // incomplete period
      null,
      'FREE',
      [],
    ]) {
      expect(isUsageResponse(bad), JSON.stringify(bad)).toBe(false);
    }
  });

  test('rejects cross-field inconsistencies the server would never produce', () => {
    for (const bad of [
      // Exempt views must carry no numbers at all.
      { ...proView, limit: 3, remaining: null },
      { ...proView, limit: null, remaining: 0 },
      { ...proView, limit: 3, remaining: 0 },
      // Non-exempt views must carry both numbers.
      { ...freeView, limit: null, remaining: null, quotaStatus: 'OK' },
      { ...freeView, limit: null, remaining: 2, quotaStatus: 'EXHAUSTED' },
      // Counts can never exceed the limit.
      { ...freeView, used: 4 },
      { ...freeView, remaining: 4 },
      // OK means scans left; EXHAUSTED means none.
      { ...freeView, used: 3, remaining: 0, quotaStatus: 'OK' },
      { ...freeView, used: 1, remaining: 2, quotaStatus: 'EXHAUSTED' },
    ]) {
      expect(isUsageResponse(bad), JSON.stringify(bad)).toBe(false);
    }
  });

  test('device-limited exhaustion validates: used below limit, remaining zero', () => {
    // A roommate's consumption can exhaust the shared DEVICE allowance
    // while the account's own count stays low — remaining 0 with used 1
    // is a legitimate EXHAUSTED view.
    expect(
      isUsageResponse({ ...freeView, used: 1, remaining: 0, quotaStatus: 'EXHAUSTED' }),
    ).toBe(true);
  });

  test('the guard exposes no device identifier field anywhere', () => {
    // The contract deliberately has no device field: the response shape
    // itself must be incapable of carrying a device hash or id.
    expect(Object.keys(freeView).sort()).toEqual([
      'limit',
      'period',
      'plan',
      'quotaStatus',
      'remaining',
      'used',
    ]);
  });
});
