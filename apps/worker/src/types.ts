export type { Job, JobResult, JobStatus, RetryPolicy } from '@drobon/shared';

/**
 * Execution context handed to every job handler. `signal` aborts on
 * cancellation or per-attempt timeout — handlers SHOULD observe it so
 * cancellation is prompt (the runner enforces the timeout regardless).
 */
export interface JobContext {
  jobId: string;
  type: string;
  /** 1-based attempt number within this job. */
  attempt: number;
  signal: AbortSignal;
}

export type JobHandler<TInput = unknown, TOutput = unknown> = (
  input: TInput,
  ctx: JobContext,
) => Promise<TOutput>;

/** Abortable sleep used for retry backoff (injectable for tests). */
export type SleepFunction = (ms: number, signal?: AbortSignal) => Promise<void>;
