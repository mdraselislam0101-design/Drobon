import type { ServerResponse } from 'node:http';
import type { ApiSuccess, EnvironmentName } from '@drobon/shared';
import { toErrorResponse } from './errors.js';
import type { RequestContext } from './http.js';

/** Serialize and send a JSON payload with explicit length framing. */
export function sendJson(
  res: ServerResponse,
  statusCode: number,
  body: unknown,
  headers: Record<string, string> = {},
): void {
  const payload = JSON.stringify(body);
  const finalHeaders: Record<string, string | string[]> = {
    'content-type': 'application/json; charset=utf-8',
    'content-length': String(Buffer.byteLength(payload)),
    ...headers,
  };
  // Multiple set-cookie sources must COMBINE, never overwrite: middleware
  // (stale-session clears, device-cookie issuance) sets headers via
  // `setHeader`, routes pass theirs here. `writeHead` would silently drop
  // the earlier one for the same name, so they are merged explicitly
  // (e.g. a register response can carry both a fresh device cookie and
  // the session cookie).
  const existingCookies = res.getHeader('set-cookie');
  if (existingCookies !== undefined) {
    const existingList = Array.isArray(existingCookies)
      ? existingCookies.map(String)
      : [String(existingCookies)];
    const routeCookie = headers['set-cookie'];
    if (routeCookie === undefined) {
      finalHeaders['set-cookie'] = [...existingList];
    } else {
      const routeCookieName = routeCookie.split('=', 1)[0]?.trim();
      const retained = existingList.filter(
        (entry) => entry.split('=', 1)[0]?.trim() !== routeCookieName,
      );
      finalHeaders['set-cookie'] = [...retained, routeCookie];
    }
  }
  res.writeHead(statusCode, finalHeaders);
  res.end(payload);
}

/** Send a success envelope (always includes the request ID). */
export function sendSuccess<TData>(
  res: ServerResponse,
  ctx: RequestContext,
  data: TData,
  statusCode = 200,
  headers: Record<string, string> = {},
): void {
  const body: ApiSuccess<TData> = {
    ok: true,
    data,
    meta: { requestId: ctx.id },
  };
  sendJson(res, statusCode, body, headers);
}

/** Map any thrown value through the central error contract and send it. */
export function sendFailure(
  res: ServerResponse,
  ctx: RequestContext,
  error: unknown,
  env: EnvironmentName,
): void {
  const mapped = toErrorResponse(error, { requestId: ctx.id }, env);
  sendJson(res, mapped.statusCode, mapped.body, mapped.headers);
}
