import { isRecord } from './guards.js';
import { isPlan, type Plan } from './plans.js';

/**
 * Usage + quota contracts (Pump 5).
 *
 * The server-authoritative usage/quota foundation the future Scan/Job/
 * Worker system will call. Concepts:
 *
 * - Plans stay exactly FREE and PRO (Pump 4); usage never introduces a
 *   third plan.
 * - FREE accounts get `FREE_MONTHLY_SCAN_QUOTA` security scans per
 *   account per UTC calendar month.
 * - Anti-abuse: FREE accounts sharing one recognized device share
 *   `FREE_DEVICE_MONTHLY_SCAN_QUOTA` scans per device per UTC month —
 *   creating more FREE accounts on the same device does not multiply the
 *   allowance.
 * - PRO (an ACTIVE PRO entitlement, per the Pump 4 subscription logic) is
 *   exempt: no monthly limit.
 *
 * Everything here is derived server-side. Clients may render these
 * values but never supply them: plan, entitlement, usage, remaining,
 * period and device identity are all server-authoritative, and
 * consumption is only ever performed by the API's usage service.
 */

/** FREE plan: maximum security scans per ACCOUNT per UTC calendar month. */
export const FREE_MONTHLY_SCAN_QUOTA = 3;

/** Anti-abuse: maximum security scans per DEVICE per UTC calendar month, shared across FREE accounts. */
export const FREE_DEVICE_MONTHLY_SCAN_QUOTA = 3;

/** `YYYY-MM` — a UTC calendar month identifier (the authoritative usage period). */
export const USAGE_PERIOD_PATTERN = /^\d{4}-(0[1-9]|1[0-2])$/;

/**
 * A UTC calendar month period. `startUtc` is inclusive, `endUtc` is the
 * EXCLUSIVE first instant of the next month (so September is
 * 2026-09-01T00:00:00.000Z ≤ t < 2026-10-01T00:00:00.000Z). The server
 * computes the period; no client-supplied period is ever accepted.
 */
export interface UsagePeriodInfo {
  /** UTC month identifier, e.g. `2026-09`. */
  period: string;
  /** Inclusive start (ISO 8601, UTC). */
  startUtc: string;
  /** EXCLUSIVE end — first instant NOT in this period (ISO 8601, UTC). */
  endUtc: string;
}

/** Quota verdict for the current period. */
export const QUOTA_STATUSES = ['OK', 'EXHAUSTED', 'EXEMPT'] as const;
export type QuotaStatus = (typeof QUOTA_STATUSES)[number];

/** Runtime guard for {@link QuotaStatus}. */
export function isQuotaStatus(value: unknown): value is QuotaStatus {
  return typeof value === 'string' && (QUOTA_STATUSES as readonly string[]).includes(value);
}

/**
 * `GET /api/v1/usage` response — the authenticated caller's OWN usage
 * view. `remaining` is the EFFECTIVE allowance (the stricter of the
 * account and the device allowance for FREE); `limit`/`remaining` are
 * `null` for exempt (active PRO) accounts. No device identifiers, no
 * storage details, no other account's data ever appear here.
 */
export interface UsageResponse {
  plan: Plan;
  period: UsagePeriodInfo;
  /** Scans this ACCOUNT consumed in the current period (server count). */
  used: number;
  /** FREE: 3 (or the device/account limit in force). Exempt: `null`. */
  limit: number | null;
  /** Effective scans left this period. Exempt: `null`. */
  remaining: number | null;
  quotaStatus: QuotaStatus;
}

/** Guard for {@link UsagePeriodInfo}. */
export function isUsagePeriodInfo(value: unknown): value is UsagePeriodInfo {
  return (
    isRecord(value) &&
    typeof value['period'] === 'string' &&
    USAGE_PERIOD_PATTERN.test(value['period']) &&
    typeof value['startUtc'] === 'string' &&
    !Number.isNaN(Date.parse(value['startUtc'])) &&
    typeof value['endUtc'] === 'string' &&
    !Number.isNaN(Date.parse(value['endUtc']))
  );
}

function isCountOrNull(value: unknown): value is number | null {
  return value === null || (typeof value === 'number' && Number.isInteger(value) && value >= 0);
}

/** Guard for {@link UsageResponse} (client boundary — rejects forged shapes). */
export function isUsageResponse(value: unknown): value is UsageResponse {
  if (
    !isRecord(value) ||
    !isPlan(value['plan']) ||
    !isUsagePeriodInfo(value['period']) ||
    typeof value['used'] !== 'number' ||
    !Number.isInteger(value['used']) ||
    value['used'] < 0 ||
    !isCountOrNull(value['limit']) ||
    !isCountOrNull(value['remaining']) ||
    !isQuotaStatus(value['quotaStatus'])
  ) {
    return false;
  }
  // Cross-field invariants the server always maintains, so a payload
  // violating any of them is forged or corrupt:
  // - exempt views carry no numbers at all;
  // - non-exempt views carry both numbers, never above the limit;
  // - OK means scans left, EXHAUSTED means none.
  const limit = value['limit'];
  const remaining = value['remaining'];
  if (value['quotaStatus'] === 'EXEMPT') {
    return limit === null && remaining === null;
  }
  if (typeof limit !== 'number' || typeof remaining !== 'number') {
    return false;
  }
  if (value['used'] > limit || remaining > limit) {
    return false;
  }
  return value['quotaStatus'] === 'OK' ? remaining > 0 : remaining === 0;
}
