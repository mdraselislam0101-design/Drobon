import type { IncomingMessage, ServerResponse } from 'node:http';
import type { AccountRole, AuthUser, Entitlement, Permission, Subscription } from '@drobon/shared';
import type { AuthzContext } from '@drobon/shared';
import type { Logger } from './logger.js';

/**
 * Per-request context. Created once in {@link createApp} (see app.ts) and
 * threaded through every middleware and route handler.
 */
export interface RequestContext {
  /** Public correlation ID: echoed from `x-request-id` or server-generated. */
  id: string;
  /** Separate server-generated correlation ID; safe to put in logs. */
  logId: string;
  method: string;
  /** Normalized URL pathname (no query string, no trailing slash). */
  pathname: string;
  /** Static route template, never a client-controlled path segment. */
  logPath: string;
  /** Direct peer address. Proxy headers are never trusted (see docs). */
  ip: string;
  startedAtMs: number;
  logger: Logger;
  /**
   * Authenticated user, resolved by the session middleware from the session
   * cookie. `undefined` means anonymous. Routes opt in via
   * `Route.requireAuth` / `requireRole` / `requirePermission`.
   */
  user?: AuthUser;
  /**
   * Authorization context derived from `user` (server-side state only).
   * Set by session middleware whenever `user` is defined — handlers may
   * trust its view of role/userType.
   */
  authz?: AuthzContext;
  /**
   * Subscription state (Pump 4) derived from the LIVE account record on
   * every request — commercial state is never trusted from clients, and
   * operator store changes take effect on the next request (like role
   * changes). Set by session middleware whenever `user` is defined.
   */
  subscription?: Subscription;
  /**
   * Server-authoritative commercial entitlements derived exclusively from
   * the subscription above (shared decision table). AccountRole and
   * UserType deliberately never contribute. Set alongside `subscription`.
   */
  entitlements?: readonly Entitlement[];
  /**
   * Device identity for usage anti-abuse (Pump 5): the SHA-256 hash of
   * the opaque `drobon_device` cookie token, resolved by the device
   * middleware for authenticated requests (issuing a fresh token when
   * absent/malformed). The raw token never enters the context; usage
   * routes may trust the hash. `undefined` for anonymous requests.
   */
  deviceHash?: string;
  /**
   * Path parameters extracted from parameterized route paths (Pump 6),
   * e.g. `/api/v1/projects/:projectId` fills `params.projectId`. Empty
   * for exact-match routes. Values are raw URL path segments — handlers
   * must validate them before use (never trust them as ids by shape
   * alone... they are untrusted input like any other).
   */
  params: Record<string, string>;
}

export type NextFunction = () => Promise<void>;

export type Middleware = (
  req: IncomingMessage,
  res: ServerResponse,
  ctx: RequestContext,
  next: NextFunction,
) => Promise<void>;

export type RouteHandler = (
  req: IncomingMessage,
  res: ServerResponse,
  ctx: RequestContext,
) => Promise<void>;

export interface Route {
  method: string;
  /**
   * Route path. Either an exact pathname (`/api/v1/projects`) or a
   * parameterized path whose `:name` segments capture one path segment
   * each (`/api/v1/projects/:projectId` — captured into
   * `ctx.params.projectId`). Parameter names must be unique within a
   * path; a segment is matched verbatim (no wildcards, no regex, no
   * empty segments — the pathname is normalized without a trailing
   * slash before matching).
   */
  path: string;
  handler: RouteHandler;
  /**
   * Authentication boundary: when true, the router refuses the request
   * with 401 unless session middleware resolved an authenticated user.
   * Handlers behind this flag may rely on `ctx.user` being defined.
   */
  requireAuth?: boolean;
  /**
   * Authorization boundary (Pump 3): minimum account role. Implies
   * `requireAuth` (anonymous → 401, authenticated-but-insufficient → 403).
   * Every protected capability declares its role explicitly here or via
   * `requirePermission` — hierarchy is never assumed implicitly.
   */
  requireRole?: AccountRole;
  /**
   * Authorization boundary via the shared permission table: the required
   * role comes from `PERMISSIONS[permission]`. Implies `requireAuth`.
   */
  requirePermission?: Permission;
}

/**
 * Match a normalized request pathname against a route path.
 *
 * Exact paths (no `:` segments) compare by equality — the Pump 1–5
 * behavior, unchanged. Parameterized paths match segment by segment,
 * capturing `:name` segments into the returned params record. Returns
 * `undefined` on no match. Deliberately tiny: no wildcards, no optional
 * segments, no regex — untrusted path data stays data.
 */
export function matchRoutePath(
  routePath: string,
  pathname: string,
): Record<string, string> | undefined {
  if (!routePath.includes(':')) {
    return routePath === pathname ? {} : undefined;
  }
  const routeParts = routePath.split('/');
  const pathParts = pathname.split('/');
  if (routeParts.length !== pathParts.length) {
    return undefined;
  }
  const params: Record<string, string> = {};
  for (let index = 0; index < routeParts.length; index += 1) {
    const routePart = routeParts[index] ?? '';
    const pathPart = pathParts[index] ?? '';
    if (routePart.startsWith(':') && routePart.length > 1) {
      if (pathPart.length === 0) {
        return undefined;
      }
      try {
        params[routePart.slice(1)] = decodeURIComponent(pathPart);
      } catch {
        // Malformed percent-encoding (`%zz`) — never a match, never a 500.
        return undefined;
      }
      continue;
    }
    if (routePart !== pathPart) {
      return undefined;
    }
  }
  return params;
}
