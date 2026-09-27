import type { IncomingMessage, ServerResponse } from 'node:http';
import type { AuthUser } from '@drobon/shared';
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
   * cookie. `undefined` means anonymous. Authorization layers in later
   * Pumps build on this boundary — routes opt in via `Route.requireAuth`.
   */
  user?: AuthUser;
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
   * Authorization-ready boundary: when true, the router refuses the request
   * with 401 unless session middleware resolved an authenticated user.
   * Handlers behind this flag may rely on `ctx.user` being defined.
   */
  requireAuth?: boolean;
}
