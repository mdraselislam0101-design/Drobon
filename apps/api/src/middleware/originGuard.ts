import { forbidden } from '../errors.js';
import type { Middleware } from '../http.js';
import { extractRefererOrigin, isAllowedOrigin, normalizeOrigin } from '../lib/security.js';

const UNSAFE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

function isPermittedOrigin(
  normalizedOrigin: string,
  allowedOrigins: readonly string[],
  hostHeader: string | undefined,
): boolean {
  if (isAllowedOrigin(normalizedOrigin, allowedOrigins)) {
    return true;
  }
  if (typeof hostHeader === 'string' && hostHeader.length > 0) {
    try {
      const originHost = new URL(normalizedOrigin).host;
      if (originHost.toLowerCase() === hostHeader.toLowerCase()) {
        return true;
      }
    } catch {
      // Fall through to refusal.
    }
  }
  return false;
}

/**
 * CSRF origin guard for cookie-authenticated state changes.
 *
 * Rule: an unsafe request that carries an `Origin` header must originate
 * either from an explicitly allowed CORS origin or from this server's own
 * HTTP(S) host (same-origin, including requests arriving through the Web dev
 * proxy). When `Origin` is absent on an unsafe method, if a `Referer` header
 * is present its extracted HTTP(S) origin must likewise match the allowlist
 * or same-host rule. Anything else is refused with 403 before any handler runs.
 *
 * Why this is sufficient in combination with the session cookie:
 * - `SameSite=Strict` already stops browsers from *sending* the cookie on
 *   cross-site requests (primary defense);
 * - this guard additionally kills "login CSRF" and any same-site-but-
 *   foreign-origin form posts, even for requests a browser would send;
 * - requests without `Origin` or `Referer` come from non-browser clients,
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
    const host = req.headers.host;
    if (typeof origin === 'string' && origin.length > 0) {
      const normalized = normalizeOrigin(origin);
      if (normalized !== undefined && isPermittedOrigin(normalized, options.allowedOrigins, host)) {
        await next();
        return;
      }
      ctx.logger.info('Origin guard refused request', {
        requestId: ctx.id,
        method: req.method,
        path: ctx.pathname,
      });
      throw forbidden('Request origin is not allowed.');
    }

    const referer = req.headers.referer;
    if (typeof referer === 'string' && referer.length > 0) {
      const refererOrigin = extractRefererOrigin(referer);
      if (
        refererOrigin !== undefined &&
        isPermittedOrigin(refererOrigin, options.allowedOrigins, host)
      ) {
        await next();
        return;
      }
      ctx.logger.info('Origin guard refused request', {
        requestId: ctx.id,
        method: req.method,
        path: ctx.pathname,
      });
      throw forbidden('Request origin is not allowed.');
    }

    await next();
  };
}
