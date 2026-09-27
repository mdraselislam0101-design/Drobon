import { describe, expect, test } from 'vitest';
import { ERROR_CODES, type ErrorCode } from '../src/errors.js';

describe('ERROR_CODES', () => {
  test('is a non-empty list of unique UPPER_SNAKE codes', () => {
    expect(ERROR_CODES.length).toBeGreaterThan(0);
    expect(new Set(ERROR_CODES).size).toBe(ERROR_CODES.length);
    for (const code of ERROR_CODES) {
      expect(code).toMatch(/^[A-Z][A-Z0-9_]*$/);
    }
  });

  test('covers the foundation error vocabulary', () => {
    const expected: ErrorCode[] = [
      'BAD_REQUEST',
      'VALIDATION_ERROR',
      'INVALID_JSON',
      'PAYLOAD_TOO_LARGE',
      'UNSUPPORTED_MEDIA_TYPE',
      'NOT_FOUND',
      'METHOD_NOT_ALLOWED',
      'RATE_LIMITED',
      'TIMEOUT',
      'INTERNAL_ERROR',
      'SERVICE_UNAVAILABLE',
    ];
    expect([...ERROR_CODES].sort()).toEqual([...expected].sort());
  });
});
