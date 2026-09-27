import { randomUUID } from 'node:crypto';
import type { Middleware } from '../http.js';
import { isValidRequestId } from '../lib/security.js';

/**
 * Correlation-ID middleware. Echoes a valid client-supplied `x-request-id`,
 * otherwise generates a UUID. The ID is always set on the response and on
 * the request context (and therefore in every log line and response body).
 */
export function requestIdMiddleware(): Middleware {
  return async (_req, res, ctx, next): Promise<void> => {
    const header = _req.headers['x-request-id'];
    const candidate = Array.isArray(header) ? header[0] : header;
    const trimmed = candidate?.trim();
    ctx.id =
      trimmed !== undefined && trimmed.length > 0 && isValidRequestId(trimmed)
        ? trimmed
        : randomUUID();
    res.setHeader('x-request-id', ctx.id);
    await next();
  };
}
