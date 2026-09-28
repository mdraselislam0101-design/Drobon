import type { UsageResponse } from '@drobon/shared';
import type { ApiConfig } from '../config.js';
import { internal, unauthorized, validationError, quotaExceeded } from '../errors.js';
import type { Route } from '../http.js';
import type { UserRepository } from '../auth/repositories.js';
import type { UsageService } from '../usage/service.js';
import { readJsonBody } from '../lib/body.js';
import * as v from '../lib/validate.js';
import { sendSuccess } from '../respond.js';

export interface UsageRouteDeps {
  config: ApiConfig;
  users: UserRepository;
  usage: UsageService;
}

/**
 * Usage surface (Pump 5).
 *
 * `GET /api/v1/usage` (registered in EVERY environment — a real
 * user-facing feature):
 * - authentication required (anonymous → 401) via the existing router
 *   choke point; self-only by construction — there is no id parameter,
 *   so no cross-account reads exist (query/headers are never consulted);
 * - returns the caller's OWN usage view: plan, UTC period, used, limit,
 *   remaining, quota status. No device identifiers, no storage details,
 *   no other accounts' counts.
 *
 * `POST /api/v1/usage/consume` — the scan-consumption boundary probe:
 * consumes EXACTLY ONE scan for the authenticated account on the
 * current device by calling the usage service (the single quota
 * authority). Registered ONLY outside production
 * (`config.usageConsumeRoutes`) so it can never ship as a public
 * production endpoint — in production it 404s like any unknown path.
 * When the real Scan/Job system lands, its workflow calls
 * `usageService.consumeScan()` directly and this probe is removed.
 *
 * Both handlers accept NO client-supplied usage parameters: an empty
 * body (or absent body) is required — every field (plan, period, used,
 * remaining, device) is server-authoritative.
 */
export function createUsageRoutes(deps: UsageRouteDeps): Route[] {
  const { config, users, usage } = deps;

  /** Rejects any body content — the only valid payloads are none or `{}`. */
  const rejectBodyFields = async (raw: unknown): Promise<void> => {
    if (raw === undefined) {
      return;
    }
    const parsed = v.object({}).parse(raw);
    if (!parsed.ok) {
      throw validationError(parsed.issues);
    }
  };

  const routes: Route[] = [
    {
      method: 'GET',
      path: '/api/v1/usage',
      requireAuth: true,
      handler: async (_req, res, ctx): Promise<void> => {
        const actor = ctx.user;
        if (actor === undefined) {
          throw unauthorized(); // Defensive: requireAuth rejects first.
        }
        const deviceHash = ctx.deviceHash;
        if (deviceHash === undefined) {
          // Invariant: the device middleware resolves a hash for every
          // authenticated request.
          throw internal('Device identity missing for an authenticated request.');
        }
        const record = await users.findById(actor.id);
        if (record === undefined) {
          // Account vanished mid-session — the session is worthless.
          throw unauthorized();
        }
        const body: UsageResponse = usage.getUsageView(record, deviceHash);
        sendSuccess(res, ctx, body);
      },
    },
  ];

  if (config.usageConsumeRoutes) {
    routes.push({
      method: 'POST',
      path: '/api/v1/usage/consume',
      requireAuth: true,
      handler: async (req, res, ctx): Promise<void> => {
        const actor = ctx.user;
        if (actor === undefined) {
          throw unauthorized(); // Defensive: requireAuth rejects first.
        }
        // Exact validation: no body, or exactly `{}`. Any field — plan,
        // period, used, remaining, deviceId — is rejected (422): nothing
        // a client sends may influence consumption.
        if (req.headers['content-type'] !== undefined) {
          const raw = await readJsonBody(req, { maxBytes: config.bodyMaxBytes });
          await rejectBodyFields(raw);
        }
        const deviceHash = ctx.deviceHash;
        if (deviceHash === undefined) {
          throw internal('Device identity missing for an authenticated request.');
        }
        const record = await users.findById(actor.id);
        if (record === undefined) {
          throw unauthorized();
        }
        const outcome = await usage.consumeScan(record, deviceHash);
        if (!outcome.ok) {
          // Uniform 429 QUOTA_EXCEEDED + Retry-After (next UTC month).
          // Nothing was incremented; no hint which limit tripped.
          ctx.logger.info('Scan quota denied', { requestId: ctx.id, userId: record.id });
          throw quotaExceeded(outcome.retryAfterSec);
        }
        ctx.logger.info('Scan consumed', { requestId: ctx.id, userId: record.id });
        const body: UsageResponse = outcome.usage;
        sendSuccess(res, ctx, body);
      },
    });
  }

  return routes;
}
