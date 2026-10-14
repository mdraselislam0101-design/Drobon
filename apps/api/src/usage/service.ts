import type { UserRecord } from '../auth/repositories.js';
import { deriveEntitlements, resolveSubscription } from '../auth/subscriptions.js';
import type { Plan, UsagePeriodInfo, UsageResponse } from '@drobon/shared';
import {
  FREE_DEVICE_MONTHLY_SCAN_QUOTA,
  FREE_MONTHLY_SCAN_QUOTA,
  hasEntitlement,
} from '@drobon/shared';
import type { UsageStore } from './store.js';

/**
 * The usage service (Pump 5) — the SINGLE authority for scan-quota
 * consumption. The future Scan/Job/Worker system calls
 * {@link UsageService.consumeScan}; it must never implement its own
 * quota logic, and nothing else in the API may mutate usage counters.
 *
 * Inputs are server-side only:
 * - the account record (plan + entitlement derived through the Pump 4
 *   subscription logic on EVERY call — client claims are never read);
 * - the server-computed device hash (opaque cookie → SHA-256);
 * - the server clock (UTC is authoritative; no client-supplied period).
 *
 * Exemption rule: only an ACTIVE PRO entitlement (the Pump 4
 * `feature:pro` verdict) is exempt. A lapsed PRO subscription
 * (INACTIVE/CANCELLED/EXPIRED) falls back to the FREE allowance — fail
 * closed, exactly like every other commercial decision in the app.
 */

export interface ConsumeDenied {
  ok: false;
  /** Uniform denial — never reveals WHICH limit tripped. */
  code: 'QUOTA_EXCEEDED';
  /** Seconds until the next UTC month begins (for Retry-After). */
  retryAfterSec: number;
  /** The unchanged usage view at denial time. */
  usage: UsageResponse;
}

export interface ConsumeGranted {
  ok: true;
  usage: UsageResponse;
}

export type ConsumeOutcome = ConsumeGranted | ConsumeDenied;

export interface UsageService {
  /** The caller's current usage view (read-only, never consumes). */
  getUsageView(record: UserRecord, deviceHash: string): UsageResponse;
  /** Consume exactly one security scan, atomically. */
  consumeScan(record: UserRecord, deviceHash: string): Promise<ConsumeOutcome>;
}

export interface UsageServiceOptions {
  store: UsageStore;
  /**
   * Clock for period math (epoch ms). Injectable so tests exercise UTC
   * month boundaries deterministically — production passes Date.now.
   */
  now?: () => number;
  /**
   * Effective-PRO override, injected at composition: `true` when the
   * account holds at least one ACTIVE admin complimentary PRO grant
   * (entitlements service). The exemption rule is unchanged — it simply
   * applies to the EFFECTIVE plan. The grant store is read-only here:
   * quota consumption can never create, extend or revoke a grant, and
   * the account's persisted subscription is never touched.
   */
  activePro?: (accountId: string) => boolean;
}

/** `YYYY-MM` for a moment in time (UTC — the quota authority). */
export function usagePeriodIdAt(timeMs: number): string {
  return new Date(timeMs).toISOString().slice(0, 7);
}

/** Inclusive start / EXCLUSIVE end of a `YYYY-MM` UTC period. */
export function usagePeriodInfo(periodId: string): UsagePeriodInfo {
  const year = Number.parseInt(periodId.slice(0, 4), 10);
  const month = Number.parseInt(periodId.slice(5, 7), 10); // 1–12
  const start = new Date(Date.UTC(year, month - 1, 1));
  const end = new Date(Date.UTC(year, month, 1)); // month rolls over naturally
  return {
    period: periodId,
    startUtc: start.toISOString(),
    endUtc: end.toISOString(),
  };
}

/** Whole seconds from `timeMs` until the next UTC month begins (≥ 1). */
export function secondsUntilNextPeriod(timeMs: number): number {
  const periodId = usagePeriodIdAt(timeMs);
  const nextStart = new Date(`${usagePeriodInfo(periodId).endUtc}`).getTime();
  return Math.max(1, Math.ceil((nextStart - timeMs) / 1000));
}

export function createUsageService(options: UsageServiceOptions): UsageService {
  const store = options.store;
  const now = options.now ?? Date.now;
  const activePro = options.activePro;

  /**
   * Active PRO entitlement per the Pump 4 decision table (server-side),
   * extended with the effective-PRO verdict for active admin grants.
   */
  const isExempt = (record: UserRecord): boolean =>
    hasEntitlement(deriveEntitlements(record), 'feature:pro') ||
    (activePro?.(record.id) ?? false);

  const view = (record: UserRecord, deviceHash: string, timeMs: number): UsageResponse => {
    const plan: Plan = activePro?.(record.id) === true
      ? 'PRO'
      : resolveSubscription(record).plan;
    const periodId = usagePeriodIdAt(timeMs);
    const used = store.getAccountUsed(record.id, periodId);
    if (isExempt(record)) {
      return {
        plan,
        period: usagePeriodInfo(periodId),
        used,
        limit: null,
        remaining: null,
        quotaStatus: 'EXEMPT',
      };
    }
    // FREE (and lapsed PRO): the effective allowance is the stricter of
    // the account quota and the shared device allowance. Only counts are
    // exposed — never the device hash or other accounts' data.
    const deviceUsed = store.getDeviceUsed(deviceHash, periodId);
    const accountRemaining = FREE_MONTHLY_SCAN_QUOTA - used;
    const deviceRemaining = FREE_DEVICE_MONTHLY_SCAN_QUOTA - deviceUsed;
    const remaining = Math.max(0, Math.min(accountRemaining, deviceRemaining));
    return {
      plan,
      period: usagePeriodInfo(periodId),
      used,
      limit: FREE_MONTHLY_SCAN_QUOTA,
      remaining,
      quotaStatus: remaining > 0 ? 'OK' : 'EXHAUSTED',
    };
  };

  return {
    getUsageView: (record, deviceHash) => view(record, deviceHash, now()),

    consumeScan: async (record, deviceHash) => {
      const timeMs = now();
      const periodId = usagePeriodIdAt(timeMs);
      if (isExempt(record)) {
        await store.consumeExempt({ accountId: record.id, period: periodId });
        return { ok: true, usage: view(record, deviceHash, timeMs) };
      }
      const outcome = await store.consumeFree({
        accountId: record.id,
        deviceHash,
        period: periodId,
        accountLimit: FREE_MONTHLY_SCAN_QUOTA,
        deviceLimit: FREE_DEVICE_MONTHLY_SCAN_QUOTA,
      });
      if (outcome !== 'OK') {
        // Rejected consumption must not increment anything — the store
        // guarantees that; the denial view is the unchanged state.
        return {
          ok: false,
          code: 'QUOTA_EXCEEDED',
          retryAfterSec: secondsUntilNextPeriod(timeMs),
          usage: view(record, deviceHash, timeMs),
        };
      }
      return { ok: true, usage: view(record, deviceHash, timeMs) };
    },
  };
}
