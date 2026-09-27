import type { Middleware } from '../http.js';

/**
 * Baseline response headers for a JSON API. The API never serves active
 * content, so the policy is maximally strict.
 *
 * Note on HSTS: it only takes effect over TLS (terminated at the edge in
 * production) and is ignored over plain HTTP.
 */
export const SECURITY_HEADERS: Record<string, string> = {
  'content-security-policy': "default-src 'none'; base-uri 'none'; frame-ancestors 'none'",
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer',
  'permissions-policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
  'cross-origin-opener-policy': 'same-origin',
  'cross-origin-resource-policy': 'same-origin',
  'strict-transport-security': 'max-age=31536000; includeSubDomains',
};

export function securityHeadersMiddleware(): Middleware {
  return async (_req, res, _ctx, next): Promise<void> => {
    for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
      res.setHeader(name, value);
    }
    await next();
  };
}
