import { createRateLimiter } from './rateLimit.js';
import type { Middleware } from '../http.js';

const AUTH_PATH_PREFIX = '/api/v1/auth';

export interface AuthRateLimitOptions {
  maxRequests: number;
  windowMs: number;
  /** Clock source (injectable for tests). */
  now?: () => number;
}

/**
 * Dedicated abuse protection for credential endpoints (register/login/
 * logout). Stricter than the global limiter and scoped to `/api/v1/auth*`
 * so page traffic can never burn the login budget, and credential stuffing
 * hits a low ceiling long before the global one.
 *
 * Same single-process semantics as the global limiter (documented in
 * docs/SECURITY.md): it protects one API instance, not a fleet.
 * When it fires, its `RateLimit-*` headers intentionally replace the
 * global ones on that response — the tighter budget is the relevant one.
 */
export function createAuthRateLimiter(options: AuthRateLimitOptions): {
  middleware: Middleware;
  reset: () => void;
} {
  const limiter = createRateLimiter({
    maxRequests: options.maxRequests,
    windowMs: options.windowMs,
    ...(options.now === undefined ? {} : { now: options.now }),
    key: (ip) => `auth:${ip}`,
  });

  const middleware: Middleware = async (req, res, ctx, next): Promise<void> => {
    if (ctx.pathname === AUTH_PATH_PREFIX || ctx.pathname.startsWith(`${AUTH_PATH_PREFIX}/`)) {
      await limiter.middleware(req, res, ctx, next);
      return;
    }
    await next();
  };

  return { middleware, reset: limiter.reset };
}
