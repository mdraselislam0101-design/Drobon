import type { Middleware } from '../http.js';
import { isAllowedOrigin } from '../lib/security.js';

const ALLOW_METHODS = 'GET, POST, PUT, PATCH, DELETE, OPTIONS';
const ALLOW_HEADERS = 'Content-Type, X-Request-Id, Idempotency-Key';
const MAX_AGE_SECONDS = '600';

export interface CorsOptions {
  allowedOrigins: readonly string[];
}

/**
 * Strict allowlist CORS. Behavior:
 * - no `Origin` header → not a CORS request, nothing to do;
 * - listed origin → reflected exactly (+ `Vary: Origin`), preflights answered;
 * - anything else → no CORS headers at all, so browsers block the read.
 *   Preflights from disallowed origins get a bare 204 (fail closed).
 *
 * Credentials mode (`Access-Control-Allow-Credentials: true`) is enabled
 * ONLY alongside an exact reflected origin — required since Pump 2 so the
 * browser will send/read the `httpOnly` session cookie across split-host
 * deployments. `Access-Control-Allow-Origin` is never `*`, so a hostile
 * page can never satisfy both conditions.
 */
export function corsMiddleware(options: CorsOptions): Middleware {
  return async (req, res, _ctx, next): Promise<void> => {
    const origin = req.headers.origin;
    if (typeof origin !== 'string' || origin.length === 0) {
      await next();
      return;
    }
    res.setHeader('vary', 'Origin');
    if (!isAllowedOrigin(origin, options.allowedOrigins)) {
      if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
      }
      await next();
      return;
    }
    res.setHeader('access-control-allow-origin', origin);
    res.setHeader('access-control-allow-credentials', 'true');
    // Both are response-only correlation headers; the log ID is generated
    // by this server and never reflects a caller-supplied value.
    res.setHeader('access-control-expose-headers', 'X-Request-Id, X-Log-Id');
    if (req.method === 'OPTIONS') {
      res.writeHead(204, {
        'access-control-allow-origin': origin,
        'access-control-allow-credentials': 'true',
        'access-control-allow-methods': ALLOW_METHODS,
        'access-control-allow-headers': ALLOW_HEADERS,
        'access-control-max-age': MAX_AGE_SECONDS,
      });
      res.end();
      return;
    }
    await next();
  };
}
