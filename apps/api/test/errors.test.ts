import { describe, expect, test } from 'vitest';
import {
  badRequest,
  internal,
  invalidJsonBody,
  isAppError,
  methodNotAllowed,
  notFound,
  payloadTooLarge,
  rateLimited,
  timeoutError,
  toErrorResponse,
  unavailable,
  unsupportedMediaType,
  validationError,
} from '../src/errors.js';

describe('error factories', () => {
  test('map to the documented status codes and codes', () => {
    expect([badRequest().statusCode, badRequest().code]).toEqual([400, 'BAD_REQUEST']);
    expect([validationError([]).statusCode, validationError([]).code]).toEqual([
      422,
      'VALIDATION_ERROR',
    ]);
    expect([invalidJsonBody().statusCode, invalidJsonBody().code]).toEqual([400, 'INVALID_JSON']);
    expect([payloadTooLarge(1).statusCode, payloadTooLarge(1).code]).toEqual([
      413,
      'PAYLOAD_TOO_LARGE',
    ]);
    expect([unsupportedMediaType().statusCode, unsupportedMediaType().code]).toEqual([
      415,
      'UNSUPPORTED_MEDIA_TYPE',
    ]);
    expect([notFound().statusCode, notFound().code]).toEqual([404, 'NOT_FOUND']);
    expect([methodNotAllowed(['GET']).statusCode, methodNotAllowed(['GET']).code]).toEqual([
      405,
      'METHOD_NOT_ALLOWED',
    ]);
    expect([rateLimited(7).statusCode, rateLimited(7).code]).toEqual([429, 'RATE_LIMITED']);
    expect([timeoutError().statusCode, timeoutError().code]).toEqual([504, 'TIMEOUT']);
    expect([unavailable().statusCode, unavailable().code]).toEqual([503, 'SERVICE_UNAVAILABLE']);
    expect([internal('x').statusCode, internal('x').code]).toEqual([500, 'INTERNAL_ERROR']);
  });

  test('isAppError only matches AppError', () => {
    expect(isAppError(notFound())).toBe(true);
    expect(isAppError(new Error('nope'))).toBe(false);
    expect(isAppError('nope')).toBe(false);
  });
});

describe('toErrorResponse', () => {
  const meta = { requestId: 'req-test-9' };

  test('exposes 4xx messages with request ID', () => {
    const mapped = toErrorResponse(notFound('Missing thing.'), meta, 'production');
    expect(mapped.statusCode).toBe(404);
    expect(mapped.body).toEqual({
      ok: false,
      error: { code: 'NOT_FOUND', message: 'Missing thing.' },
      meta,
    });
  });

  test('includes validation details for exposed 4xx errors', () => {
    const mapped = toErrorResponse(validationError([{ path: 'a', message: 'bad' }]), meta, 'test');
    expect(mapped.body.error.details).toEqual([{ path: 'a', message: 'bad' }]);
  });

  test('hides internal messages in every environment', () => {
    for (const env of ['development', 'test', 'production'] as const) {
      const mapped = toErrorResponse(internal('db conn string example-secret'), meta, env);
      expect(mapped.statusCode).toBe(500);
      expect(mapped.body.error.message).toBe('Internal Server Error.');
      expect(JSON.stringify(mapped.body)).not.toContain('example-secret');
    }
  });

  test('maps unknown throws to a generic 500 without leaking internals', () => {
    const mapped = toErrorResponse(new Error('super-secret-stack-marker'), meta, 'development');
    expect(mapped.statusCode).toBe(500);
    expect(mapped.body.error.code).toBe('INTERNAL_ERROR');
    expect(JSON.stringify(mapped.body)).not.toContain('super-secret-stack-marker');
  });

  test('emits Retry-After for 429 and Allow for 405', () => {
    const limited = toErrorResponse(rateLimited(12), meta, 'test');
    expect(limited.headers['retry-after']).toBe('12');
    const wrongMethod = toErrorResponse(methodNotAllowed(['GET', 'HEAD']), meta, 'test');
    expect(wrongMethod.headers['allow']).toBe('GET, HEAD');
  });
});
