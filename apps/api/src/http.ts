import type { IncomingMessage, ServerResponse } from 'node:http';
import type { AccountRole, AuthUser, Permission } from '@drobon/shared';
import type { AuthzContext } from '@drobon/shared';
import type { Logger } from './logger.js';

/**
 * Per-request context. Created once in {@link createApp} (see app.ts) and
 * threaded through every middleware and route handler.
 */
export interface RequestContext {
  /** Correlation ID: echoed from `x-request-id` or server-generated. */
  id: string;
  method: string;
  /** Normalized URL pathname (no query string, no trailing slash). */
  pathname: string;
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
