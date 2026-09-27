import type { RetryPolicy } from '@drobon/shared';

/** Validate a retry policy, throwing on the first problem found. */
export function validateRetryPolicy(policy: RetryPolicy): void {
  if (!Number.isInteger(policy.maxAttempts) || policy.maxAttempts < 1) {
    throw new Error('RetryPolicy.maxAttempts must be an integer >= 1.');
  }
  if (!Number.isFinite(policy.baseDelayMs) || policy.baseDelayMs < 0) {
    throw new Error('RetryPolicy.baseDelayMs must be a finite number >= 0.');
  }
  if (!Number.isFinite(policy.maxDelayMs) || policy.maxDelayMs < policy.baseDelayMs) {
    throw new Error('RetryPolicy.maxDelayMs must be finite and >= baseDelayMs.');
  }
}

/**
 * Whether another attempt is allowed after `attempt` (1-based) just finished.
 * `attempt` counts completed attempts; the budget is `maxAttempts` total.
 */
export function shouldRetry(policy: RetryPolicy, attempt: number): boolean {
  return attempt < policy.maxAttempts;
}

/**
 * Exponential backoff for the pause AFTER `attempt` (1-based):
 * `baseDelayMs * 2^(attempt-1)`, capped at `maxDelayMs`.
 */
export function computeRetryDelayMs(policy: RetryPolicy, attempt: number): number {
  const exponential = policy.baseDelayMs * 2 ** Math.max(0, attempt - 1);
  return Math.min(policy.maxDelayMs, Math.max(0, exponential));
}
