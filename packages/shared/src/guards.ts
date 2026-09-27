import type { ApiErrorBody, ApiResponse, ApiSuccess } from './api.js';
import { ERROR_CODES, type ErrorCode } from './errors.js';

/** Narrow an unknown value to a plain record. */
export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Narrow an API response to its success branch. */
export function isApiSuccess<TData>(
  response: ApiResponse<TData>,
): response is ApiSuccess<TData> {
  return response.ok === true;
}

/** Narrow an API response to its error branch. */
export function isApiError<TData>(response: ApiResponse<TData>): response is ApiErrorBody {
  return response.ok === false;
}

/** Check membership in the shared error-code vocabulary. */
export function isErrorCode(value: unknown): value is ErrorCode {
  return (
    typeof value === 'string' && (ERROR_CODES as readonly string[]).includes(value)
  );
}

/**
 * Structurally validate an unknown value as an {@link ApiResponse}.
 * Returns the narrowed response, or `undefined` when the shape is invalid.
 * The `data` payload itself is NOT deep-validated — callers validate the
 * fields they consume.
 */
export function parseApiResponse<TData>(value: unknown): ApiResponse<TData> | undefined {
  if (!isRecord(value)) {
    return undefined;
  }
  if (typeof value['ok'] !== 'boolean') {
    return undefined;
  }
  const meta = value['meta'];
  if (!isRecord(meta) || typeof meta['requestId'] !== 'string') {
    return undefined;
  }
  if (value['ok'] === true) {
    if (!('data' in value)) {
      return undefined;
    }
    return { ok: true, data: value['data'] as TData, meta: { requestId: meta['requestId'] } };
  }
  const error = value['error'];
  if (!isRecord(error)) {
    return undefined;
  }
  if (!isErrorCode(error['code']) || typeof error['message'] !== 'string') {
    return undefined;
  }
  const parsed: ApiErrorBody = {
    ok: false,
    error: { code: error['code'], message: error['message'] },
    meta: { requestId: meta['requestId'] },
  };
  if ('details' in error) {
    parsed.error.details = error['details'];
  }
  return parsed as ApiResponse<TData>;
}
