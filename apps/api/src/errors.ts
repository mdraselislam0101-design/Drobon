import type {
  ApiErrorBody,
  EnvironmentName,
  ErrorCode,
  ResponseMeta,
} from '@drobon/shared';

/**
 * Application error with an explicit HTTP mapping. `expose` controls whether
 * `message` may leave the process: 4xx client errors are safe to expose,
 * 5xx server errors never are (they map to a generic message).
 */
export class AppError extends Error {
  readonly code: ErrorCode;
  readonly statusCode: number;
  readonly expose: boolean;
  readonly details?: unknown;
  readonly retryAfterSec?: number;
  readonly allowedMethods?: string[];

  constructor(options: {
    code: ErrorCode;
    statusCode: number;
    message: string;
    expose?: boolean;
    details?: unknown;
    retryAfterSec?: number;
    allowedMethods?: string[];
  }) {
    super(options.message);
    this.name = 'AppError';
    this.code = options.code;
    this.statusCode = options.statusCode;
    this.expose = options.expose ?? options.statusCode < 500;
    if (options.details !== undefined) {
      this.details = options.details;
    }
    if (options.retryAfterSec !== undefined) {
      this.retryAfterSec = options.retryAfterSec;
    }
    if (options.allowedMethods !== undefined) {
      this.allowedMethods = [...options.allowedMethods];
    }
  }
}

export function isAppError(error: unknown): error is AppError {
  return error instanceof AppError;
}

export function badRequest(message = 'Bad request.'): AppError {
  return new AppError({ code: 'BAD_REQUEST', statusCode: 400, message });
}

export function validationError(details: unknown): AppError {
  return new AppError({
    code: 'VALIDATION_ERROR',
    statusCode: 422,
    message: 'Request validation failed.',
    details,
  });
}

export function invalidJsonBody(message = 'Request body must be valid JSON.'): AppError {
  return new AppError({ code: 'INVALID_JSON', statusCode: 400, message });
}

export function payloadTooLarge(maxBytes: number): AppError {
  return new AppError({
    code: 'PAYLOAD_TOO_LARGE',
    statusCode: 413,
    message: `Request body exceeds the ${maxBytes} byte limit.`,
  });
}

export function unsupportedMediaType(): AppError {
  return new AppError({
    code: 'UNSUPPORTED_MEDIA_TYPE',
    statusCode: 415,
    message: 'Content-Type must be application/json.',
  });
}

export function notFound(message = 'Not found.'): AppError {
  return new AppError({ code: 'NOT_FOUND', statusCode: 404, message });
}

export function methodNotAllowed(allowedMethods: string[]): AppError {
  return new AppError({
    code: 'METHOD_NOT_ALLOWED',
    statusCode: 405,
    message: `Method not allowed. Allowed: ${allowedMethods.join(', ')}.`,
    allowedMethods,
  });
}

export function rateLimited(retryAfterSec: number): AppError {
  return new AppError({
    code: 'RATE_LIMITED',
    statusCode: 429,
    message: 'Rate limit exceeded. Retry later.',
    retryAfterSec,
  });
}

/**
 * Quota exhaustion (Pump 5): the FREE monthly scan allowance (account or
 * shared device) is used up. Distinct stable code (`QUOTA_EXCEEDED`) from
 * transport rate limiting (`RATE_LIMITED`) so clients can render "upgrade
 * or wait for the next UTC month" instead of "slow down". Same 429 status
 * family with `Retry-After` pointing at the next UTC month boundary.
 * Denials are uniform: they never reveal which limit tripped, other
 * accounts, or device state.
 */
export function quotaExceeded(retryAfterSec: number): AppError {
  return new AppError({
    code: 'QUOTA_EXCEEDED',
    statusCode: 429,
    message: 'Monthly free scan limit reached. Your allowance resets at the start of the next UTC month.',
    retryAfterSec,
  });
}

/**
 * Missing/invalid/expired authentication. The default message is generic on
 * purpose — it must not reveal whether the account exists.
 */
export function unauthorized(message = 'Authentication required.'): AppError {
  return new AppError({ code: 'UNAUTHORIZED', statusCode: 401, message });
}

/**
 * Credential check failure. ALWAYS the same status, code and message for
 * "unknown email", "wrong password" and "malformed stored hash" so responses
 * cannot be used to enumerate accounts.
 */
export function invalidCredentials(): AppError {
  return new AppError({ code: 'UNAUTHORIZED', statusCode: 401, message: 'Invalid email or password.' });
}

/** Policy/origin refusal (e.g. CSRF origin guard). */
export function forbidden(message = 'Request refused.'): AppError {
  return new AppError({ code: 'FORBIDDEN', statusCode: 403, message });
}

/** Uniqueness conflict (e.g. registration with an email already in use). */
export function conflict(message: string): AppError {
  return new AppError({ code: 'CONFLICT', statusCode: 409, message });
}

export function timeoutError(message = 'The operation timed out.'): AppError {
  return new AppError({ code: 'TIMEOUT', statusCode: 504, message });
}

export function unavailable(message = 'Service temporarily unavailable.'): AppError {
  return new AppError({ code: 'SERVICE_UNAVAILABLE', statusCode: 503, message });
}

/**
 * Create a 500-class error. The message is for server-side logs only and is
 * NEVER sent to clients (see {@link toErrorResponse}).
 */
export function internal(logMessage = 'Internal error.'): AppError {
  return new AppError({
    code: 'INTERNAL_ERROR',
    statusCode: 500,
    message: logMessage,
    expose: false,
  });
}

export interface MappedError {
  statusCode: number;
  body: ApiErrorBody;
  headers: Record<string, string>;
}

/**
 * Central error mapping. Guarantees:
 * - every response carries the request ID,
 * - non-exposed errors collapse to a generic message (no stacks, no internals),
 * - `details` only ever leave the process for exposed 4xx errors.
 */
export function toErrorResponse(
  error: unknown,
  meta: ResponseMeta,
  _env: EnvironmentName,
): MappedError {
  void _env;
  if (isAppError(error)) {
    const message = error.expose ? error.message : 'Internal Server Error.';
    const body: ApiErrorBody = {
      ok: false,
      error: { code: error.code, message },
      meta,
    };
    if (error.expose && error.statusCode < 500 && error.details !== undefined) {
      body.error.details = error.details;
    }
    const headers: Record<string, string> = {};
    if (error.retryAfterSec !== undefined) {
      headers['retry-after'] = String(error.retryAfterSec);
    }
    if (error.allowedMethods !== undefined) {
      headers['allow'] = error.allowedMethods.join(', ');
    }
    return { statusCode: error.statusCode, body, headers };
  }
  return {
    statusCode: 500,
    body: {
      ok: false,
      error: { code: 'INTERNAL_ERROR', message: 'Internal Server Error.' },
      meta,
    },
    headers: {},
  };
}
