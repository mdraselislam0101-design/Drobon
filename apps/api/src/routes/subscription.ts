import type { SubscriptionResponse } from '@drobon/shared';
import { internal, unauthorized } from '../errors.js';
import type { Route } from '../http.js';
import { sendSuccess } from '../respond.js';

/**
 * Subscription surface (Pump 4) — read-only by construction.
 *
 * `GET /api/v1/subscription` returns the authenticated account's OWN
 * subscription plus the entitlements the server derives from it:
 *
 * - identity comes exclusively from the session — there is no account-id
 *   parameter, path segment or header that could select another account,
 *   so cross-account reads (IDOR) are structurally impossible;
 * - query parameters, request headers and request body are never read —
 *   tampering (`?plan=PRO`, `x-plan`, a forged body) cannot change the
 *   verdict (tested);
 * - anonymous → 401; authenticated → 200; the entitlement verdict is the
 *   server's, derived from live account state on this very request;
 * - there is deliberately NO mutation endpoint: POST/PATCH/PUT/DELETE on
 *   this path 405 like any unregistered method. Subscription changes are
 *   an operator/server workflow (a later pump adds the authorized one).
 */
export function createSubscriptionRoutes(): Route[] {
  return [
    {
      method: 'GET',
      path: '/api/v1/subscription',
      requireAuth: true,
      handler: async (_req, res, ctx): Promise<void> => {
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
        const body: SubscriptionResponse = {
          subscription,
          entitlements: [...entitlements],
        };
        sendSuccess(res, ctx, body);
      },
    },
  ];
}
