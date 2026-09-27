import type { ErrorCode } from './errors.js';

/**
 * Metadata attached to every API response. `requestId` is the correlation ID
 * that ties the HTTP response to server-side logs.
 */
export interface ResponseMeta {
  requestId: string;
}

/** Successful API response envelope. */
export interface ApiSuccess<TData> {
  ok: true;
  data: TData;
  meta: ResponseMeta;
}

/** Machine- and human-readable API error payload. Safe to expose to clients. */
export interface ApiErrorDetail {
  code: ErrorCode;
  message: string;
  details?: unknown;
}

/** Failed API response envelope. */
export interface ApiErrorBody {
  ok: false;
  error: ApiErrorDetail;
  meta: ResponseMeta;
}

/** The only response shape the API ever returns for JSON endpoints. */
export type ApiResponse<TData> = ApiSuccess<TData> | ApiErrorBody;
