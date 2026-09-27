import { describe, expect, test } from 'vitest';
import type { ApiResponse } from '../src/api.js';
import {
  isApiError,
  isApiSuccess,
  isErrorCode,
  isRecord,
  parseApiResponse,
} from '../src/guards.js';

describe('isRecord', () => {
  test.each([
    [{}, true],
    [{ a: 1 }, true],
    [null, false],
    [undefined, false],
    [[], false],
    ['x', false],
    [42, false],
  ])('isRecord(%j) === %s', (value, expected) => {
    expect(isRecord(value)).toBe(expected);
  });
});

describe('isApiSuccess / isApiError', () => {
  test('narrows success and error envelopes', () => {
    const success: ApiResponse<string> = {
      ok: true,
      data: 'yes',
      meta: { requestId: 'req-test-1' },
    };
    const failure: ApiResponse<string> = {
      ok: false,
      error: { code: 'NOT_FOUND', message: 'missing' },
      meta: { requestId: 'req-test-2' },
    };
    expect(isApiSuccess(success)).toBe(true);
    expect(isApiError(success)).toBe(false);
    expect(isApiSuccess(failure)).toBe(false);
    expect(isApiError(failure)).toBe(true);
  });
});

describe('isErrorCode', () => {
  test.each([
    ['NOT_FOUND', true],
    ['INTERNAL_ERROR', true],
    ['NO_SUCH_CODE', false],
    ['', false],
    [null, false],
    [42, false],
  ])('isErrorCode(%j) === %s', (value, expected) => {
    expect(isErrorCode(value)).toBe(expected);
  });
});

describe('parseApiResponse', () => {
  test('accepts a valid success envelope', () => {
    const parsed = parseApiResponse<{ n: number }>({
      ok: true,
      data: { n: 1 },
      meta: { requestId: 'req-test-3' },
    });
    expect(parsed).toEqual({
      ok: true,
      data: { n: 1 },
      meta: { requestId: 'req-test-3' },
    });
  });

  test('accepts a valid error envelope including details', () => {
    const parsed = parseApiResponse<never>({
      ok: false,
      error: { code: 'RATE_LIMITED', message: 'slow down', details: { retry: true } },
      meta: { requestId: 'req-test-4' },
    });
    expect(parsed).toEqual({
      ok: false,
      error: { code: 'RATE_LIMITED', message: 'slow down', details: { retry: true } },
      meta: { requestId: 'req-test-4' },
    });
  });

  test.each([
    ['null', null],
    ['array', []],
    ['missing ok', { meta: { requestId: 'x' } }],
    ['non-boolean ok', { ok: 'yes', meta: { requestId: 'x' } }],
    ['missing meta', { ok: true, data: 1 }],
    ['non-string requestId', { ok: true, data: 1, meta: { requestId: 7 } }],
    ['success without data key', { ok: true, meta: { requestId: 'x' } }],
    ['error without error object', { ok: false, meta: { requestId: 'x' } }],
    [
      'unknown error code',
      {
        ok: false,
        error: { code: 'MADE_UP', message: 'nope' },
        meta: { requestId: 'x' },
      },
    ],
    [
      'non-string error message',
      {
        ok: false,
        error: { code: 'NOT_FOUND', message: 7 },
        meta: { requestId: 'x' },
      },
    ],
  ])('rejects %s', (_label, value) => {
    expect(parseApiResponse(value)).toBeUndefined();
  });
});
