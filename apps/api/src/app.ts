import type { IncomingMessage, ServerResponse } from 'node:http';
import type { ApiConfig } from './config.js';
import { badRequest, internal, isAppError, methodNotAllowed, notFound, unauthorized } from './errors.js';
import type { Middleware, RequestContext, Route } from './http.js';
import { createJsonFileUserRepository } from './auth/jsonFileUserRepository.js';
import { createMemoryUserRepository } from './auth/memoryUserRepository.js';
import type { UserRepository } from './auth/repositories.js';
import { createSessionStore, type SessionStore } from './auth/sessions.js';
import { corsMiddleware } from './middleware/cors.js';
import { createAuthRateLimiter } from './middleware/authRateLimit.js';
import { originGuardMiddleware } from './middleware/originGuard.js';
import { createRateLimiter } from './middleware/rateLimit.js';
import { requestIdMiddleware } from './middleware/requestId.js';
import { securityHeadersMiddleware } from './middleware/securityHeaders.js';
import { sessionMiddleware } from './middleware/session.js';
import { sendFailure } from './respond.js';
import { createAuthRoutes } from './routes/auth.js';
import { createEchoRoutes } from './routes/echo.js';
import { createHealthRoutes } from './routes/health.js';
import { createStatusRoutes } from './routes/status.js';
import type { Logger } from './logger.js';

export interface AppDeps {
  config: ApiConfig;
  logger: Logger;
  /**
   * Extension point for future modules (scanning, admin, ...).
   * Also used by tests to inject fault routes without touching prod code.
   */
  extraRoutes?: Route[];
  /** Clock for request timing (injectable for tests). */
  now?: () => number;
  /** Clock for the rate limiter (injectable for tests). */
  rateLimitNow?: () => number;
  /**
   * Account repository. Defaults to the durable JSON store at
   * `config.authStorePath` (`:memory:` for explicitly ephemeral setups).
   * Tests inject their own instance to control persistence.
   */
  users?: UserRepository;
  /** Session store. Defaults to a fresh in-memory store (Pump 2). */
  sessions?: SessionStore;
}

export interface App {
  handle: (req: IncomingMessage, res: ServerResponse) => Promise<void>;
  routes: Route[];
  resetRateLimit: () => void;
}

/** Direct peer address only — proxy headers (`X-Forwarded-For`) are never trusted. */
function clientIp(req: IncomingMessage): string {
  return req.socket.remoteAddress ?? 'unknown';
}

/** Parse and normalize the request target to a bare pathname. */
function getPathname(req: IncomingMessage): string {
  const target = req.url ?? '/';
  let pathname: string;
  try {
    pathname = new URL(target, 'http://localhost').pathname;
  } catch {
    throw badRequest('Malformed request URL.');
  }
  if (pathname.length > 1 && pathname.endsWith('/')) {
    pathname = pathname.slice(0, -1);
  }
  return pathname;
}

/**
 * Compose middleware + router into a single request handler with centralized
 * error mapping and structured access logging.
 */
export function createApp(deps: AppDeps): App {
  const { config, logger } = deps;
  const clock = deps.now ?? Date.now;

  // Account store: durable by default (fail-fast on a corrupt document —
  // createApp throws, the process refuses to start). Tests inject their
  // own repository; `:memory:` is the explicitly-ephemeral dev opt-in.
  const users: UserRepository =
    deps.users ??
    (config.authStorePath === ':memory:'
      ? createMemoryUserRepository()
      : createJsonFileUserRepository(config.authStorePath));
  const sessions: SessionStore =
    deps.sessions ?? createSessionStore({ ttlSeconds: config.authSessionTtlSeconds });

  const routes: Route[] = [
    ...createHealthRoutes({ config }),
    ...createStatusRoutes({ config }),
    ...createEchoRoutes({ config }),
    ...createAuthRoutes({ config, users, sessions }),
    ...(deps.extraRoutes ?? []),
  ];

  const rateLimiter = createRateLimiter(
    deps.rateLimitNow === undefined
      ? {
          maxRequests: config.rateLimitMaxRequests,
          windowMs: config.rateLimitWindowMs,
        }
      : {
          maxRequests: config.rateLimitMaxRequests,
          windowMs: config.rateLimitWindowMs,
          now: deps.rateLimitNow,
        },
  );

  const authRateLimiter = createAuthRateLimiter(
    deps.rateLimitNow === undefined
      ? {
          maxRequests: config.authRateLimitMaxRequests,
          windowMs: config.authRateLimitWindowMs,
        }
      : {
          maxRequests: config.authRateLimitMaxRequests,
          windowMs: config.authRateLimitWindowMs,
          now: deps.rateLimitNow,
        },
  );

  // Pipeline order (docs/ARCHITECTURE.md): request ID → security headers →
  // CORS → global rate limit → credential-endpoint rate limit → CSRF origin
  // guard → session resolution → routing (with requireAuth boundary).
  const middlewares: Middleware[] = [
    requestIdMiddleware(),
    securityHeadersMiddleware(),
    corsMiddleware({ allowedOrigins: config.corsAllowedOrigins }),
    rateLimiter.middleware,
    authRateLimiter.middleware,
    originGuardMiddleware({ allowedOrigins: config.corsAllowedOrigins }),
    sessionMiddleware({ sessions, users, cookieSecure: config.cookieSecure }),
  ];

  const routeRequest = async (
    req: IncomingMessage,
    res: ServerResponse,
    ctx: RequestContext,
  ): Promise<void> => {
    const match = routes.find(
      (route) => route.method === ctx.method && route.path === ctx.pathname,
    );
    if (match !== undefined) {
      if (match.requireAuth === true && ctx.user === undefined) {
        // Authorization-ready boundary: one choke point for every
        // protected route. Handlers behind it can trust `ctx.user`.
        throw unauthorized();
      }
      await match.handler(req, res, ctx);
      return;
    }
    const allowed = routes
      .filter((route) => route.path === ctx.pathname)
      .map((route) => route.method);
    if (allowed.length > 0) {
      throw methodNotAllowed(allowed);
    }
    throw notFound();
  };

  const handle = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const ctx: RequestContext = {
      id: '',
      method: req.method ?? 'GET',
      pathname: '/',
      ip: clientIp(req),
      startedAtMs: clock(),
      logger,
    };
    // A dead client socket must never crash the process: a write to an
    // aborted response emits 'error' on the response stream.
    res.once('error', () => {
      logger.debug('Response stream error', { requestId: ctx.id });
    });
    try {
      ctx.pathname = getPathname(req);
      let index = -1;
      const dispatch = async (position: number): Promise<void> => {
        if (position <= index) {
          throw internal('next() called multiple times.');
        }
        index = position;
        const current = middlewares[position];
        if (current === undefined) {
          await routeRequest(req, res, ctx);
          return;
        }
        await current(req, res, ctx, () => dispatch(position + 1));
      };
      await dispatch(0);
    } catch (error) {
      if (res.headersSent) {
        logger.error('Error after response started', {
          requestId: ctx.id,
          err: error,
        });
        res.end();
      } else {
        sendFailure(res, ctx, error, config.env);
        const status = isAppError(error) ? error.statusCode : 500;
        if (status >= 500) {
          logger.error('Request failed', {
            requestId: ctx.id,
            method: ctx.method,
            path: ctx.pathname,
            status,
            err: error,
          });
        } else if (status === 429) {
          logger.warn('Request rate limited', {
            requestId: ctx.id,
            method: ctx.method,
            path: ctx.pathname,
            status,
          });
        } else {
          logger.info('Request rejected', {
            requestId: ctx.id,
            method: ctx.method,
            path: ctx.pathname,
            status,
          });
        }
      }
    } finally {
      logger.info('Request completed', {
        requestId: ctx.id,
        method: ctx.method,
        path: ctx.pathname,
        status: res.statusCode,
        durationMs: clock() - ctx.startedAtMs,
      });
    }
  };

  return {
    handle,
    routes,
    resetRateLimit: (): void => {
      rateLimiter.reset();
      authRateLimiter.reset();
    },
  };
}
