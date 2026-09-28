import { describe, expect, test } from 'vitest';
import {
  ENTITLEMENT_KEYS,
  PLANS,
  SUBSCRIPTION_ENTITLEMENTS,
  SUBSCRIPTION_STATUSES,
  entitlementsForPlan,
  hasEntitlement,
  isAuthUser,
  isEntitlement,
  isPlan,
  isSubscription,
  isSubscriptionResponse,
  isSubscriptionStatus,
  legacySubscription,
  type Plan,
  type SubscriptionStatus,
} from '../src/index.js';

/**
 * Pump 4 contract tests: the plan/subscription/entitlement vocabulary and
 * — most importantly — the shared DECISION TABLE. The table is the single
 * definition of which (plan, status) pair grants which entitlement; these
 * tests pin its fail-closed shape.
 */

describe('plan vocabulary', () => {
  test('exactly two plans exist: FREE and PRO', () => {
    expect(PLANS).toEqual(['FREE', 'PRO']);
  });

  test('isPlan accepts only the two known plans', () => {
    for (const plan of PLANS) {
      expect(isPlan(plan)).toBe(true);
    }
    for (const bad of ['free', 'pro', 'PRO_PLUS', 'ENTERPRISE', 'ULTIMATE', '', 1, null, undefined]) {
      expect(isPlan(bad)).toBe(false);
    }
  });

  test('isSubscriptionStatus accepts only the four known statuses', () => {
    for (const status of SUBSCRIPTION_STATUSES) {
      expect(isSubscriptionStatus(status)).toBe(true);
    }
    for (const bad of ['active', 'PAUSED', 'PAST_DUE', 'TRIALING', '', 1, null, undefined]) {
      expect(isSubscriptionStatus(bad)).toBe(false);
    }
  });

  test('isEntitlement accepts only the three known keys', () => {
    for (const key of ENTITLEMENT_KEYS) {
      expect(isEntitlement(key)).toBe(true);
    }
    for (const bad of ['feature:free', 'pro', 'plan:view:other', '', 1, null, undefined]) {
      expect(isEntitlement(bad)).toBe(false);
    }
  });
});

describe('entitlement decision table (fail closed)', () => {
  test('FREE never grants feature:pro — under any status', () => {
    for (const status of SUBSCRIPTION_STATUSES) {
      const entitlements = entitlementsForPlan('FREE', status);
      expect(entitlements).toEqual(['plan:view']);
      expect(hasEntitlement(entitlements, 'feature:pro')).toBe(false);
    }
  });

  test('PRO grants feature:pro ONLY when ACTIVE', () => {
    expect(entitlementsForPlan('PRO', 'ACTIVE')).toEqual(['plan:view', 'feature:pro']);
    for (const status of ['INACTIVE', 'CANCELLED', 'EXPIRED'] as const) {
      expect(entitlementsForPlan('PRO', status)).toEqual(['plan:view']);
    }
  });

  test('plan:manage is granted to NO (plan, status) combination', () => {
    // The contract key exists (closed vocabulary) but no cell of the table
    // grants it in Pump 4 — there is no authorized mutation workflow yet,
    // so nobody may hold a "management" entitlement.
    for (const plan of PLANS) {
      for (const status of SUBSCRIPTION_STATUSES) {
        expect(hasEntitlement(entitlementsForPlan(plan, status), 'plan:manage')).toBe(false);
      }
    }
  });

  test('the table covers every (plan, status) cell exactly once', () => {
    for (const plan of PLANS) {
      for (const status of SUBSCRIPTION_STATUSES) {
        expect(SUBSCRIPTION_ENTITLEMENTS[plan][status]).toBeDefined();
      }
    }
    expect(Object.keys(SUBSCRIPTION_ENTITLEMENTS).sort()).toEqual(['FREE', 'PRO']);
    for (const plan of PLANS) {
      expect(Object.keys(SUBSCRIPTION_ENTITLEMENTS[plan]).sort()).toEqual(
        [...SUBSCRIPTION_STATUSES].sort(),
      );
    }
  });

  test('feature:pro appears in exactly one cell of the whole table', () => {
    const granting: Array<[Plan, SubscriptionStatus]> = [];
    for (const plan of PLANS) {
      for (const status of SUBSCRIPTION_STATUSES) {
        if (hasEntitlement(entitlementsForPlan(plan, status), 'feature:pro')) {
          granting.push([plan, status]);
        }
      }
    }
    expect(granting).toEqual([['PRO', 'ACTIVE']]);
  });
});

describe('subscription payload guards', () => {
  test('isSubscription accepts the canonical shapes', () => {
    expect(
      isSubscription({
        plan: 'PRO',
        status: 'ACTIVE',
        createdAt: '2026-09-27T00:00:00.000Z',
        updatedAt: '2026-09-27T00:00:00.000Z',
      }),
    ).toBe(true);
    // Legacy-shaped record: timestamps are null, not missing strings.
    expect(isSubscription({ plan: 'FREE', status: 'ACTIVE', createdAt: null, updatedAt: null })).toBe(
      true,
    );
  });

  test('isSubscription rejects forged or malformed data', () => {
    const good = { plan: 'FREE', status: 'ACTIVE', createdAt: null, updatedAt: null };
    for (const bad of [
      { ...good, plan: 'ENTERPRISE' },
      { ...good, plan: 'pro' },
      { ...good, plan: 1 },
      { ...good, status: 'active' },
      { ...good, status: 42 },
      { ...good, createdAt: 'yesterday' },
      { ...good, updatedAt: 'not-a-date' },
      { plan: 'FREE', status: 'ACTIVE' },
      'PRO',
      null,
      42,
      [],
    ]) {
      expect(isSubscription(bad)).toBe(false);
    }
  });

  test('isSubscriptionResponse validates the full response shape', () => {
    expect(
      isSubscriptionResponse({
        subscription: { plan: 'PRO', status: 'ACTIVE', createdAt: null, updatedAt: null },
        entitlements: ['plan:view', 'feature:pro'],
      }),
    ).toBe(true);
    // Unknown entitlement keys are rejected — no client-side invention.
    expect(
      isSubscriptionResponse({
        subscription: { plan: 'PRO', status: 'ACTIVE', createdAt: null, updatedAt: null },
        entitlements: ['plan:view', 'feature:pro', 'plan:godmode'],
      }),
    ).toBe(false);
    expect(
      isSubscriptionResponse({
        subscription: { plan: 'PRO', status: 'ACTIVE', createdAt: null, updatedAt: null },
        entitlements: 'plan:view',
      }),
    ).toBe(false);
    expect(isSubscriptionResponse({ entitlements: [] })).toBe(false);
    expect(isSubscriptionResponse({ subscription: { plan: 'PRO', status: 'ACTIVE' } })).toBe(false);
    expect(isSubscriptionResponse(null)).toBe(false);
  });
});

describe('legacy default', () => {
  test('legacySubscription resolves to FREE + ACTIVE with no timestamps', () => {
    expect(legacySubscription()).toEqual({
      plan: 'FREE',
      status: 'ACTIVE',
      createdAt: null,
      updatedAt: null,
    });
  });

  test('legacySubscription returns a fresh object each call (no shared mutable state)', () => {
    const first = legacySubscription();
    first.plan = 'PRO' as Plan; // caller mutation must not leak anywhere
    expect(legacySubscription().plan).toBe('FREE');
  });
});

describe('plan material never travels on user payloads', () => {
  test('isAuthUser rejects users carrying plan/subscription fields', () => {
    const base = {
      id: 'usr_x',
      email: 'x@example.test',
      createdAt: '2026-01-01T00:00:00.000Z',
      role: 'MEMBER',
      userType: null,
    };
    expect(isAuthUser(base)).toBe(true);
    expect(isAuthUser({ ...base, plan: 'PRO' })).toBe(false);
    expect(
      isAuthUser({
        ...base,
        subscription: { plan: 'PRO', status: 'ACTIVE', createdAt: null, updatedAt: null },
      }),
    ).toBe(false);
  });
});
