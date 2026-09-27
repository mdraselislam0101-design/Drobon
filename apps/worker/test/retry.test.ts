import { describe, expect, test } from 'vitest';
import { computeRetryDelayMs, shouldRetry, validateRetryPolicy } from '../src/retry.js';

describe('validateRetryPolicy', () => {
  test('accepts sane policies', () => {
    expect(() =>
      validateRetryPolicy({ maxAttempts: 3, baseDelayMs: 100, maxDelayMs: 1000 }),
    ).not.toThrow();
  });

  test.each([
    [{ maxAttempts: 0, baseDelayMs: 100, maxDelayMs: 1000 }],
    [{ maxAttempts: 1.5, baseDelayMs: 100, maxDelayMs: 1000 }],
    [{ maxAttempts: 2, baseDelayMs: -1, maxDelayMs: 1000 }],
    [{ maxAttempts: 2, baseDelayMs: 100, maxDelayMs: 50 }],
    [{ maxAttempts: 2, baseDelayMs: Number.NaN, maxDelayMs: 100 }],
  ])('rejects %j', (policy) => {
    expect(() => validateRetryPolicy(policy)).toThrowError();
  });
});

describe('shouldRetry', () => {
  test('allows attempts until the budget is spent', () => {
    const policy = { maxAttempts: 3, baseDelayMs: 10, maxDelayMs: 100 };
    expect(shouldRetry(policy, 1)).toBe(true);
    expect(shouldRetry(policy, 2)).toBe(true);
    expect(shouldRetry(policy, 3)).toBe(false);
  });

  test('a budget of one never retries', () => {
    const policy = { maxAttempts: 1, baseDelayMs: 10, maxDelayMs: 100 };
    expect(shouldRetry(policy, 1)).toBe(false);
  });
});

describe('computeRetryDelayMs', () => {
  test('backs off exponentially and caps at maxDelayMs', () => {
    const policy = { maxAttempts: 9, baseDelayMs: 100, maxDelayMs: 250 };
    expect(computeRetryDelayMs(policy, 1)).toBe(100);
    expect(computeRetryDelayMs(policy, 2)).toBe(200);
    expect(computeRetryDelayMs(policy, 3)).toBe(250);
    expect(computeRetryDelayMs(policy, 9)).toBe(250);
  });
});
