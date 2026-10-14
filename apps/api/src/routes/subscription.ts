import { entitlementsForPlan, type SubscriptionResponse } from '@drobon/shared';
import { internal, unauthorized } from '../errors.js';
import type { Route } from '../http.js';
import * as v from '../lib/validate.js';
import { sendSuccess } from '../respond.js';
import type { EntitlementService } from '../entitlements/service.js';

/**
 * Subscription surface (Pump 4) — read-only by construction.
 *
 * `GET /api/v1/subscription` returns the authenticated account's OWN
 * subscription plus the entitlements the server derives from it:
 *
 * - identity comes exclusively from the session — there is no account-id
 *   parameter, path segment or header that could select another account,
 *   so cross-account reads (IDOR) are structurally impossible;
 * - ANY query string is rejected fail-closed (422) before the account is
 *   consulted, and request body/headers are never read — tampering
 *   (`?plan=PRO`, `x-plan`, a forged body) cannot change the verdict
 *   (tested);
 * - anonymous → 401; authenticated → 200; the entitlement verdict is the
 *   server's, derived from live account state on this very request;
 * - there is deliberately NO mutation endpoint: POST/PATCH/PUT/DELETE on
 *   this path 405 like any unregistered method. Subscription changes are
 *   an operator/server workflow (a later pump adds the authorized one).
 */
export function createSubscriptionRoutes(deps: {
  /** Active admin complimentary PRO grants extend the effective plan. */
  grants?: EntitlementService;
} = {}): Route[] {
  const { grants } = deps;
  return [
    {
      method: 'GET',
      path: '/api/v1/subscription',
      requireAuth: true,
      handler: async (req, res, ctx): Promise<void> => {
        v.rejectUnexpectedQuery(req);
        if (ctx.user === undefined) {
          // Defensive: requireAuth rejects anonymous requests first.
          throw unauthorized();
        }
        const { subscription, entitlements } = ctx;
        if (subscription === undefined || entitlements === undefined) {
          // Invariant: session middleware derives both from the live
          // account record whenever it sets ctx.user.
          throw internal('Subscription state missing for an authenticated session.');
        }
        // Effective-plan presentation: an ACTIVE admin complimentary PRO
        // grant lifts the effective subscription to PRO+ACTIVE without
        // ever touching the account's persisted (paid) subscription. The
        // response states its source honestly; the derived entitlements
        // always come from the shared decision table.
        const activeGrant = grants?.getActiveGrant(ctx.user.id);
        let body: SubscriptionResponse;
        if (activeGrant !== undefined) {
          body = {
            subscription: {
              plan: 'PRO',
              status: 'ACTIVE',
              createdAt: activeGrant.grantedAt,
              updatedAt: activeGrant.grantedAt,
            },
            entitlements: [...entitlementsForPlan('PRO', 'ACTIVE')],
            proEntitlementSource: 'ADMIN_GRANT',
          };
        } else {
          body = {
            subscription,
            entitlements: [...entitlements],
            ...(subscription.plan === 'PRO' && subscription.status === 'ACTIVE'
              ? { proEntitlementSource: 'PAID' as const }
              : {}),
          };
        }
        sendSuccess(res, ctx, body);
      },
    },
  ];
}
