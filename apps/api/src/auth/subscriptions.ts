import type { Entitlement, Plan, Subscription, SubscriptionStatus } from '@drobon/shared';
import {
  entitlementsForPlan,
  isPlan,
  isSubscriptionStatus,
  legacySubscription,
} from '@drobon/shared';
import type { UserRecord } from './repositories.js';

/**
 * Subscription + entitlement decision point (Pump 4).
 *
 * This is the ONE server-authoritative place commercial entitlements are
 * derived. Inputs: the account record's persisted subscription — and
 * NOTHING else. Role, userType, request headers, query parameters,
 * cookies, body fields and client state are structurally not consulted
 * (the derivation function only ever reads `record.subscription`).
 *
 * Fail-closed rules ({@link normalizeSubscription}):
 * - no subscription record (Pump 2/3-era accounts) → FREE + ACTIVE;
 * - invalid/missing plan → FREE (invalid data can only LOSE entitlements);
 * - invalid/missing status → INACTIVE (ACTIVE is the privileged state for
 *   PRO — it is never assumed from corrupt data);
 * - invalid/missing timestamps → `null`.
 *
 * The result: `feature:pro` is granted ONLY when the store explicitly and
 * validly says `plan: 'PRO'` + `status: 'ACTIVE'` — every other shape,
 * including garbage, maps to a cell without it (shared decision table in
 * `@drobon/shared/plans.ts`).
 *
 * Why corrupt subscription data degrades instead of failing the store
 * (deliberately different from the Pump 3 role posture): a corrupt
 * authorization field makes the account's ACCESS untrustworthy, so the
 * store refuses to load (fail fast). Corrupt commercial metadata only
 * affects entitlements, so the account stays readable while entitlements
 * fail closed — a one-directional degradation that can never upgrade an
 * account, only downgrade it.
 */

/** `true` when the value is a parseable ISO timestamp or `null`. */
function isTimestampOrNull(value: unknown): value is string | null {
  return (
    value === null || (typeof value === 'string' && !Number.isNaN(Date.parse(value)))
  );
}

/**
 * Normalize persisted subscription data fail-closed. Idempotent: an
 * already-normalized {@link Subscription} passes through unchanged.
 */
export function normalizeSubscription(raw: unknown): Subscription {
  // Absent subscription = a pre-Pump-4 account: the documented legacy
  // default (FREE + ACTIVE) applies.
  if (raw === undefined || raw === null) {
    return legacySubscription();
  }
  // Present but not an object: wholly untrustworthy → fail closed.
  if (typeof raw !== 'object' || Array.isArray(raw)) {
    return { plan: 'FREE', status: 'INACTIVE', createdAt: null, updatedAt: null };
  }
  const record = raw as Record<string, unknown>;
  const plan: Plan = isPlan(record['plan']) ? record['plan'] : 'FREE';
  const status: SubscriptionStatus = isSubscriptionStatus(record['status'])
    ? record['status']
    : 'INACTIVE';
  return {
    plan,
    status,
    createdAt: isTimestampOrNull(record['createdAt']) ? record['createdAt'] : null,
    updatedAt: isTimestampOrNull(record['updatedAt']) ? record['updatedAt'] : null,
  };
}

/**
 * The effective subscription for an account record. Always normalized
 * (defensive even for in-memory records that skipped the store loader).
 */
export function resolveSubscription(record: UserRecord): Subscription {
  return normalizeSubscription(record.subscription);
}

/**
 * Server-authoritative entitlement derivation: the shared decision table
 * applied to the account's effective subscription. Role and userType are
 * deliberately NOT parameters — they can never contribute.
 */
export function deriveEntitlements(record: UserRecord): readonly Entitlement[] {
  const subscription = resolveSubscription(record);
  return entitlementsForPlan(subscription.plan, subscription.status);
}
