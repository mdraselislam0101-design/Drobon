import { forbidden } from '../errors.js';
import type { Middleware } from '../http.js';
import { isAllowedOrigin } from '../lib/security.js';

const UNSAFE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

/**
 * CSRF origin guard for cookie-authenticated state changes.
 *
 * Rule: an unsafe request that carries an `Origin` header must originate
 * either from an explicitly allowed CORS origin or from this server's own
 * host (same-origin, including requests arriving through the Web dev
 * proxy). Anything else is refused with 403 before any handler runs.
 *
 * Why this is sufficient in combination with the session cookie:
 * - `SameSite=Strict` already stops browsers from *sending* the cookie on
 *   cross-site requests (primary defense);
 * - this guard additionally kills "login CSRF" and any same-site-but-
 *   foreign-origin form posts, even for requests a browser would send;
 * - requests without an `Origin` header come from non-browser clients,
 *   where ambient-credential CSRF does not apply (they cannot be tricked
 *   into attaching a cookie jar they never had).
 *
 * OPTIONS preflights are exempt: the CORS middleware owns them.
 */
export function originGuardMiddleware(options: {
  allowedOrigins: readonly string[];
}): Middleware {
  return async (req, _res, ctx, next): Promise<void> => {
    if (!UNSAFE_METHODS.has(req.method ?? '')) {
      await next();
      return;
    }
    const origin = req.headers.origin;
    if (typeof origin !== 'string' || origin.length === 0) {
      await next();
      return;
    }
    if (isAllowedOrigin(origin, options.allowedOrigins)) {
      await next();
      return;
    }
    const host = req.headers.host;
    if (typeof host === 'string' && host.length > 0) {
      try {
        const originHost = new URL(origin).host;
        if (originHost.toLowerCase() === host.toLowerCase()) {
          await next();
          return;
        }
      } catch {
        // Fall through to the refusal below.
      }
    }
    ctx.logger.info('Origin guard refused request', {
      requestId: ctx.id,
      method: req.method,
      path: ctx.pathname,
    });
    throw forbidden('Request origin is not allowed.');
  };
}
