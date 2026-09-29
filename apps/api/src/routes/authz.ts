import type { AccountRole, CapabilityResponse, CurrentUserResponse } from '@drobon/shared';
import type { ApiConfig } from '../config.js';
import { validationError, forbidden, unauthorized } from '../errors.js';
import type { Route } from '../http.js';
import {
  AUTHZ_DENIED_MESSAGE,
  assertCanReadUser,
} from '../auth/authorization.js';
import { toAuthUser, type UserRepository } from '../auth/repositories.js';
import { sendSuccess } from '../respond.js';

export interface AuthzRouteDeps {
  config: ApiConfig;
  users: UserRepository;
}

/**
 * Minimal authorization capability surface (Pump 3).
 *
 * These routes exist to make the authorization foundation observable and
 * testable — they are intentionally NOT product features and return
 * nothing beyond "granted" (no role names, no configuration, no account
 * data):
 *
 * - `GET /api/v1/authz/capabilities/member|admin|owner`
 *   declare their requirement via `Route.requireRole`; anonymous → 401,
 *   authenticated-but-insufficient → 403, sufficient → 200.
 *   Registered only when `config.authzProbeRoutes` is on (derived:
 *   never in production), so they cannot accidentally ship as public
 *   production functionality — in production they 404 like any unknown
 *   path.
 *
 * - `GET /api/v1/users?id=<userId>` — the ownership/IDOR proof surface:
 *   self-read for every account, cross-account reads only with the
 *   explicitly-declared `users:read:others` permission (ADMIN+). Unknown,
 *   malformed or unauthorized ids all answer the SAME 403 — no existence
 *   oracle, no IDOR, no role hints. Always registered (it is a real
 *   foundation primitive future admin/partner features build on).
 */
export function createAuthzRoutes(deps: AuthzRouteDeps): Route[] {
  const { config, users } = deps;

  const probe = (
    path: string,
    capability: CapabilityResponse['capability'],
    role: AccountRole,
  ): Route => ({
    method: 'GET',
    path,
    requireRole: role,
    handler: async (_req, res, ctx): Promise<void> => {
      const body: CapabilityResponse = { capability };
      sendSuccess(res, ctx, body);
    },
  });

  const routes: Route[] = [
    {
      method: 'GET',
      path: '/api/v1/users',
      requireAuth: true,
      handler: async (req, res, ctx): Promise<void> => {
        const actor = ctx.user;
        if (actor === undefined) {
          // Defensive: requireAuth should have rejected already.
          throw unauthorized();
        }
        let searchParams: URLSearchParams;
        try {
          searchParams = new URL(req.url ?? '', 'http://localhost').searchParams;
        } catch {
          searchParams = new URLSearchParams();
        }
        const unexpectedKeys = [...new Set(searchParams.keys())].filter((key) => key !== 'id');
        if (unexpectedKeys.length > 0) {
          throw validationError(
            unexpectedKeys.map((path) => ({ path, message: 'Unexpected query parameter.' })),
          );
        }
        const ids = searchParams.getAll('id');
        if (ids.length > 1) {
          throw validationError([
            { path: 'id', message: 'Query parameter id must not be repeated.' },
          ]);
        }
        const id = ids[0] ?? null;
        if (id === null || id.length === 0) {
          throw validationError([{ path: 'id', message: 'A resource id is required.' }]);
        }
        if (id.length > 64) {
          // Uniform denial — oversized ids are as inaccessible as unknown
          // ones (no probing whether they "exist" somewhere).
          throw forbidden(AUTHZ_DENIED_MESSAGE);
        }
        const target = await users.findById(id);
        // Unknown id and unauthorized id produce the identical 403.
        if (target === undefined) {
          throw forbidden(AUTHZ_DENIED_MESSAGE);
        }
        assertCanReadUser(actor, target.id);
        const body: CurrentUserResponse = { user: toAuthUser(target) };
        sendSuccess(res, ctx, body);
      },
    },
  ];

  if (config.authzProbeRoutes) {
    routes.unshift(
      probe('/api/v1/authz/capabilities/member', 'member', 'MEMBER'),
      probe('/api/v1/authz/capabilities/admin', 'admin', 'ADMIN'),
      probe('/api/v1/authz/capabilities/owner', 'owner', 'ACCOUNT_OWNER'),
    );
  }

  return routes;
}
