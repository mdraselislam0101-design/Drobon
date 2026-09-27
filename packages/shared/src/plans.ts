import { isRecord } from './guards.js';

/**
 * Plan + subscription + entitlement contracts (Pump 4).
 *
 * THREE independent concepts, deliberately never conflated:
 *
 * - `AccountRole` (authz.ts) — authorization: what the account may do.
 *   NEVER a commercial entitlement input.
 * - `UserType` (authz.ts) — classification/visibility only. NEVER a
 *   commercial entitlement input.
 * - `Plan` + `SubscriptionStatus` (here) — the commercial state. The ONLY
 *   inputs to commercial entitlement decisions.
 *
 * The decision table below is the single shared definition of "which
 * (plan, status) pair grants which entitlement". The API derives
 * entitlements exclusively from server-side account state through this
 * table; clients render the server's verdict and never recompute it.
 *
 * Pump 4 scope: exactly two plans (FREE, PRO), no payment integration,
 * no coupons, no partner/referral — those are later roadmap phases.
 */

/** The complete commercial plan vocabulary (Pump 4: exactly two). */
export const PLANS = ['FREE', 'PRO'] as const;
export type Plan = (typeof PLANS)[number];

/** Runtime guard: value is exactly one of the known plans. */
export function isPlan(value: unknown): value is Plan {
  return typeof value === 'string' && (PLANS as readonly string[]).includes(value);
}

/** Subscription lifecycle states. */
export const SUBSCRIPTION_STATUSES = ['ACTIVE', 'INACTIVE', 'CANCELLED', 'EXPIRED'] as const;
export type SubscriptionStatus = (typeof SUBSCRIPTION_STATUSES)[number];

/** Runtime guard: value is exactly one of the known statuses. */
export function isSubscriptionStatus(value: unknown): value is SubscriptionStatus {
  return (
    typeof value === 'string' &&
    (SUBSCRIPTION_STATUSES as readonly string[]).includes(value)
  );
}

/**
 * Commercial entitlement keys.
 *
 * - `plan:view` — see your own current plan/subscription (every account).
 * - `plan:manage` — change plan/subscription state. RESERVED: granted to
 *   NO (plan, status) combination in Pump 4 because no authorized
 *   mutation workflow exists yet (no payment phase) — the contract key
 *   exists so the closed vocabulary is complete, but nobody holds it.
 *   Verified by tests iterating the whole table.
 * - `feature:pro` — active PRO feature entitlement. Requires PRO + ACTIVE;
 *   every other combination fails closed.
 */
export const ENTITLEMENT_KEYS = ['plan:view', 'plan:manage', 'feature:pro'] as const;
export type Entitlement = (typeof ENTITLEMENT_KEYS)[number];

/** Runtime guard: value is exactly one of the known entitlement keys. */
export function isEntitlement(value: unknown): value is Entitlement {
  return (
    typeof value === 'string' &&
    (ENTITLEMENT_KEYS as readonly string[]).includes(value)
  );
}

/**
 * The public subscription view — the ONLY subscription shape that may
 * leave the API, and only for its owner (the authenticated account the
 * session resolves to). Timestamps are `null` when no subscription record
 * exists (accounts created before Pump 4).
 */
export interface Subscription {
  plan: Plan;
  status: SubscriptionStatus;
  /** When the subscription record was created (ISO 8601), or `null`. */
  createdAt: string | null;
  /** When the subscription record last changed (ISO 8601), or `null`. */
  updatedAt: string | null;
}

/**
 * `GET /api/v1/subscription` response — the caller's own subscription
 * plus the entitlements the server derives from it. Read-only: there is
 * deliberately no mutation endpoint in Pump 4.
 */
export interface SubscriptionResponse {
  subscription: Subscription;
  /** Server-authoritative entitlements for the current (plan, status). */
  entitlements: Entitlement[];
}

/** The entitlements every account holds regardless of commercial state. */
const BASE_ENTITLEMENTS: readonly Entitlement[] = ['plan:view'];

/** The entitlements of an ACTIVE PRO subscription. */
const ACTIVE_PRO_ENTITLEMENTS: readonly Entitlement[] = ['plan:view', 'feature:pro'];

/**
 * The decision table: entitlements granted per (plan, status). Read through
 * {@link entitlementsForPlan} — never hand-rolled elsewhere.
 *
 * Fail-closed by construction: `feature:pro` appears in exactly one cell
 * (PRO + ACTIVE); every non-ACTIVE PRO status and every FREE status maps
 * to the base set. `plan:manage` appears in NO cell in Pump 4.
 */
export const SUBSCRIPTION_ENTITLEMENTS: Readonly<
  Record<Plan, Readonly<Record<SubscriptionStatus, readonly Entitlement[]>>>
> = {
  FREE: {
    ACTIVE: BASE_ENTITLEMENTS,
    INACTIVE: BASE_ENTITLEMENTS,
    CANCELLED: BASE_ENTITLEMENTS,
    EXPIRED: BASE_ENTITLEMENTS,
  },
  PRO: {
    ACTIVE: ACTIVE_PRO_ENTITLEMENTS,
    INACTIVE: BASE_ENTITLEMENTS,
    CANCELLED: BASE_ENTITLEMENTS,
    EXPIRED: BASE_ENTITLEMENTS,
  },
};

/** The entitlements a (plan, status) pair grants (shared decision table). */
export function entitlementsForPlan(
  plan: Plan,
  status: SubscriptionStatus,
): readonly Entitlement[] {
  return SUBSCRIPTION_ENTITLEMENTS[plan][status];
}

/** Does an entitlement set contain `key`? */
export function hasEntitlement(
  entitlements: readonly Entitlement[],
  key: Entitlement,
): boolean {
  return entitlements.includes(key);
}

/**
 * The safe default for accounts created before Pump 4 (no subscription
 * record on the store): FREE + ACTIVE. Returns a fresh object each call —
 * callers may never share a mutable subscription instance.
 */
export function legacySubscription(): Subscription {
  return { plan: 'FREE', status: 'ACTIVE', createdAt: null, updatedAt: null };
}

function isTimestampOrNull(value: unknown): value is string | null {
  return (
    value === null || (typeof value === 'string' && !Number.isNaN(Date.parse(value)))
  );
}

/** Structural guard for {@link Subscription} at the client boundary. */
export function isSubscription(value: unknown): value is Subscription {
  return (
    isRecord(value) &&
    isPlan(value['plan']) &&
    isSubscriptionStatus(value['status']) &&
    isTimestampOrNull(value['createdAt']) &&
    isTimestampOrNull(value['updatedAt'])
  );
}

/** Guard for {@link SubscriptionResponse} payloads. */
export function isSubscriptionResponse(value: unknown): value is SubscriptionResponse {
  return (
    isRecord(value) &&
    isSubscription(value['subscription']) &&
    Array.isArray(value['entitlements']) &&
    value['entitlements'].every((entry) => isEntitlement(entry))
  );
}
