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
  res.writeHead(statusCode, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': String(Buffer.byteLength(payload)),
    ...headers,
  });
  res.end(payload);
}

/** Send a success envelope (always includes the request ID). */
export function sendSuccess<TData>(
  res: ServerResponse,
  ctx: RequestContext,
  data: TData,
  statusCode = 200,
): void {
  const body: ApiSuccess<TData> = {
    ok: true,
    data,
    meta: { requestId: ctx.id },
  };
  sendJson(res, statusCode, body);
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
