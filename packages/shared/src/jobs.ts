import type { ErrorCode } from './errors.js';

/** Lifecycle states of a background job. */
export const JOB_STATUSES = [
  'queued',
  'running',
  'succeeded',
  'failed',
  'cancelled',
  'timed_out',
] as const;

export type JobStatus = (typeof JOB_STATUSES)[number];

/** A unit of background work. `maxAttempts` is the total attempt budget (1 = no retry). */
export interface Job<TInput = unknown> {
  id: string;
  type: string;
  input: TInput;
  createdAt: string;
  maxAttempts: number;
  timeoutMs: number;
}

/** Safe, serializable job failure description. */
export interface JobFailure {
  code: ErrorCode;
  message: string;
}

/** Terminal (or terminal-bound) outcome of a job execution. */
export interface JobResult<TOutput = unknown> {
  jobId: string;
  type: string;
  status: JobStatus;
  attempts: number;
  output?: TOutput;
  error?: JobFailure;
  startedAt?: string;
  finishedAt?: string;
}

/** Retry behavior: exponential backoff `baseDelayMs * 2^(attempt-1)` capped at `maxDelayMs`. */
export interface RetryPolicy {
  maxAttempts: number;
  baseDelayMs: number;
  maxDelayMs: number;
}

/** Conservative default: a single attempt (no retries) unless overridden. */
export const DEFAULT_RETRY_POLICY: RetryPolicy = {
  maxAttempts: 1,
  baseDelayMs: 1000,
  maxDelayMs: 30_000,
};

/** Default per-attempt execution timeout. */
export const DEFAULT_JOB_TIMEOUT_MS = 30_000;

export interface CreateJobOptions {
  /** ID generator (injected so this module stays runtime-agnostic). */
  generateId: () => string;
  maxAttempts?: number;
  timeoutMs?: number;
  createdAt?: string;
}

/**
 * Build a validated {@link Job}. Throws a plain `Error` describing the first
 * invalid field — callers surface it through their own error contracts.
 */
export function createJob<TInput>(
  type: string,
  input: TInput,
  options: CreateJobOptions,
): Job<TInput> {
  if (type.trim().length === 0) {
    throw new Error('Job type must be a non-empty string.');
  }
  const maxAttempts = options.maxAttempts ?? DEFAULT_RETRY_POLICY.maxAttempts;
  if (!Number.isInteger(maxAttempts) || maxAttempts < 1) {
    throw new Error('Job maxAttempts must be an integer >= 1.');
  }
  const timeoutMs = options.timeoutMs ?? DEFAULT_JOB_TIMEOUT_MS;
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new Error('Job timeoutMs must be a finite number > 0.');
  }
  const id = options.generateId();
  if (id.trim().length === 0) {
    throw new Error('Job id generator must return a non-empty string.');
  }
  return {
    id,
    type,
    input,
    createdAt: options.createdAt ?? new Date().toISOString(),
    maxAttempts,
    timeoutMs,
  };
}
