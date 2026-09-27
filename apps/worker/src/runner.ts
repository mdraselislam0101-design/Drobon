import { randomUUID } from 'node:crypto';
import {
  DEFAULT_RETRY_POLICY,
  createJob,
  type CreateJobOptions,
  type Job,
  type JobFailure,
  type JobResult,
  type JobStatus,
  type RetryPolicy,
} from '@drobon/shared';
import { InMemoryJobQueue, type JobQueue } from './queue.js';
import { computeRetryDelayMs, validateRetryPolicy } from './retry.js';
import type { JobHandler, SleepFunction } from './types.js';

export const DEFAULT_CONCURRENCY = 1;
export const DEFAULT_MAX_RECORDS = 1000;
const MAX_ERROR_MESSAGE_LENGTH = 1000;

const defaultSleep: SleepFunction = (ms: number, signal?: AbortSignal): Promise<void> =>
  new Promise<void>((resolve) => {
    if (signal?.aborted === true) {
      resolve();
      return;
    }
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, Math.max(0, ms));
    timer.unref?.();
    const onAbort = (): void => {
      clearTimeout(timer);
      resolve();
    };
    signal?.addEventListener('abort', onAbort, { once: true });
  });

export interface SubmitOptions {
  id?: string;
  maxAttempts?: number;
  timeoutMs?: number;
}

export interface WaitOptions {
  timeoutMs?: number;
}

export interface RunnerOptions {
  handlers: Record<string, JobHandler> | Map<string, JobHandler>;
  queue?: JobQueue;
  retry?: RetryPolicy;
  concurrency?: number;
  defaultTimeoutMs?: number;
  /** Cap on retained finished-job records (oldest evicted first). */
  maxRecords?: number;
  generateId?: () => string;
  sleep?: SleepFunction;
}

export interface Runner {
  submit<TInput>(type: string, input: TInput, options?: SubmitOptions): Job<TInput>;
  cancel(jobId: string): boolean;
  getStatus(jobId: string): JobStatus | undefined;
  getResult(jobId: string): JobResult | undefined;
  waitFor(jobId: string, options?: WaitOptions): Promise<JobResult>;
  start(): void;
  stop(): Promise<void>;
  readonly pendingCount: number;
  readonly runningCount: number;
}

interface Waiter {
  resolve: (result: JobResult) => void;
  reject: (error: Error) => void;
  timer?: ReturnType<typeof setTimeout>;
}

interface JobRecord {
  job: Job;
  status: JobStatus;
  attempts: number;
  output?: unknown;
  error?: JobFailure;
  startedAt?: string;
  finishedAt?: string;
  cancelRequested: boolean;
  controller?: AbortController;
  waiters: Set<Waiter>;
}

function toFailure(error: unknown): JobFailure {
  const message = error instanceof Error ? error.message : String(error);
  return {
    code: 'INTERNAL_ERROR',
    message:
      message.length > MAX_ERROR_MESSAGE_LENGTH
        ? `${message.slice(0, MAX_ERROR_MESSAGE_LENGTH)}…`
        : message,
  };
}

/**
 * Create a job runner: FIFO dequeue, bounded concurrency, per-attempt
 * timeouts, cooperative cancellation and retry with backoff.
 *
 * Execution model:
 * - `submit()` validates, records and queues a job; workers pick it up while
 *   the runner is started.
 * - every attempt races the handler against its timeout AND the abort
 *   signal, so attempts settle no later than their timeout even when the
 *   handler ignores cancellation.
 * - timeouts and handler errors retry while the attempt budget
 *   (`min(job.maxAttempts, retry.maxAttempts)`) allows, with backoff pauses.
 * - `cancel()` removes queued jobs immediately and aborts running attempts.
 * - at-most-once execution is NOT guaranteed: a timed-out attempt may still
 *   be running in the background when its retry starts. Handlers SHOULD
 *   observe the abort signal and SHOULD be idempotent.
 */
export function createRunner(options: RunnerOptions): Runner {
  const handlers =
    options.handlers instanceof Map ? options.handlers : new Map(Object.entries(options.handlers));
  const queue = options.queue ?? new InMemoryJobQueue();
  const retry = options.retry ?? DEFAULT_RETRY_POLICY;
  validateRetryPolicy(retry);

  const concurrency = options.concurrency ?? DEFAULT_CONCURRENCY;
  if (!Number.isInteger(concurrency) || concurrency < 1) {
    throw new Error('Runner concurrency must be an integer >= 1.');
  }
  const defaultTimeoutMs = options.defaultTimeoutMs ?? 30_000;
  if (!Number.isFinite(defaultTimeoutMs) || defaultTimeoutMs <= 0) {
    throw new Error('Runner defaultTimeoutMs must be a finite number > 0.');
  }
  const maxRecords = options.maxRecords ?? DEFAULT_MAX_RECORDS;
  if (!Number.isInteger(maxRecords) || maxRecords < 1) {
    throw new Error('Runner maxRecords must be an integer >= 1.');
  }
  const generateId = options.generateId ?? ((): string => randomUUID());
  const sleep = options.sleep ?? defaultSleep;

  const records = new Map<string, JobRecord>();
  const finishedIds: string[] = [];
  let running = 0;
  let started = false;
  let stopWaiters: Array<() => void> = [];

  const snapshot = (record: JobRecord): JobResult => {
    const result: JobResult = {
      jobId: record.job.id,
      type: record.job.type,
      status: record.status,
      attempts: record.attempts,
    };
    if (record.output !== undefined) {
      result.output = record.output;
    }
    if (record.error !== undefined) {
      result.error = record.error;
    }
    if (record.startedAt !== undefined) {
      result.startedAt = record.startedAt;
    }
    if (record.finishedAt !== undefined) {
      result.finishedAt = record.finishedAt;
    }
    return result;
  };

  const finalize = (
    record: JobRecord,
    status: JobStatus,
    output?: unknown,
    error?: JobFailure,
  ): void => {
    record.status = status;
    record.finishedAt = new Date().toISOString();
    if (output !== undefined) {
      record.output = output;
    }
    if (error !== undefined) {
      record.error = error;
    }
    finishedIds.push(record.job.id);
    while (finishedIds.length > maxRecords) {
      const evicted = finishedIds.shift();
      if (evicted !== undefined && evicted !== record.job.id) {
        records.delete(evicted);
      }
    }
    const result = snapshot(record);
    for (const waiter of record.waiters) {
      if (waiter.timer !== undefined) {
        clearTimeout(waiter.timer);
      }
      waiter.resolve(result);
    }
    record.waiters.clear();
  };

  const pump = (): void => {
    if (!started) {
      return;
    }
    while (running < concurrency) {
      const job = queue.dequeue();
      if (job === undefined) {
        break;
      }
      const record = records.get(job.id);
      if (record === undefined || record.status !== 'queued') {
        continue;
      }
      running += 1;
      void execute(record).finally(() => {
        running -= 1;
        pump();
        if (running === 0 && !started) {
          const waiters = stopWaiters;
          stopWaiters = [];
          for (const resolve of waiters) {
            resolve();
          }
        }
      });
    }
  };

  const execute = async (record: JobRecord): Promise<void> => {
    const { job } = record;
    record.status = 'running';
    record.startedAt = new Date().toISOString();
    const maxAttempts = Math.min(job.maxAttempts, retry.maxAttempts);

    for (let attempt = 1; ; attempt += 1) {
      record.attempts = attempt;
      if (record.cancelRequested) {
        finalize(record, 'cancelled');
        return;
      }
      const handler = handlers.get(job.type);
      if (handler === undefined) {
        finalize(record, 'failed', undefined, {
          code: 'BAD_REQUEST',
          message: `Unknown job type: ${job.type}.`,
        });
        return;
      }
      const controller = new AbortController();
      record.controller = controller;
      let timedOut = false;
      const timer = setTimeout(() => {
        timedOut = true;
        controller.abort();
      }, job.timeoutMs);
      timer.unref?.();
      try {
        const output = await Promise.race([
          handler(job.input, {
            jobId: job.id,
            type: job.type,
            attempt,
            signal: controller.signal,
          }),
          new Promise<never>((_resolve, reject) => {
            if (controller.signal.aborted) {
              reject(new Error('Job attempt aborted.'));
              return;
            }
            controller.signal.addEventListener(
              'abort',
              () => {
                reject(new Error('Job attempt aborted.'));
              },
              { once: true },
            );
          }),
        ]);
        if (record.cancelRequested) {
          finalize(record, 'cancelled');
          return;
        }
        finalize(record, 'succeeded', output);
        return;
      } catch (error) {
        if (record.cancelRequested) {
          finalize(record, 'cancelled');
          return;
        }
        if (timedOut) {
          if (attempt < maxAttempts) {
            await sleep(computeRetryDelayMs(retry, attempt), controller.signal);
            continue;
          }
          finalize(record, 'timed_out', undefined, {
            code: 'TIMEOUT',
            message: `Job attempt exceeded its ${job.timeoutMs}ms timeout.`,
          });
          return;
        }
        if (attempt < maxAttempts) {
          await sleep(computeRetryDelayMs(retry, attempt), controller.signal);
          continue;
        }
        finalize(record, 'failed', undefined, toFailure(error));
        return;
      } finally {
        clearTimeout(timer);
        delete record.controller;
      }
    }
  };

  return {
    submit<TInput>(type: string, input: TInput, submitOptions: SubmitOptions = {}): Job<TInput> {
      if (type.trim().length === 0) {
        throw new Error('Job type must be a non-empty string.');
      }
      const customId = submitOptions.id;
      const customAttempts = submitOptions.maxAttempts;
      const jobOptions: CreateJobOptions = {
        generateId: customId !== undefined ? () => customId : generateId,
        timeoutMs: submitOptions.timeoutMs ?? defaultTimeoutMs,
      };
      if (customAttempts !== undefined) {
        jobOptions.maxAttempts = customAttempts;
      }
      const job = createJob(type, input, jobOptions);
      if (records.has(job.id)) {
        throw new Error(`Job ${job.id} already exists.`);
      }
      records.set(job.id, {
        job: job as Job,
        status: 'queued',
        attempts: 0,
        cancelRequested: false,
        waiters: new Set(),
      });
      queue.enqueue(job as Job);
      pump();
      return job;
    },

    cancel(jobId: string): boolean {
      const record = records.get(jobId);
      if (record === undefined) {
        return false;
      }
      if (record.status === 'queued') {
        if (queue.cancel(jobId)) {
          record.cancelRequested = true;
          finalize(record, 'cancelled');
          return true;
        }
      }
      if (record.status === 'running') {
        record.cancelRequested = true;
        record.controller?.abort();
        return true;
      }
      return false;
    },

    getStatus(jobId: string): JobStatus | undefined {
      return records.get(jobId)?.status;
    },

    getResult(jobId: string): JobResult | undefined {
      const record = records.get(jobId);
      if (record === undefined || record.status === 'queued' || record.status === 'running') {
        return undefined;
      }
      return snapshot(record);
    },

    waitFor(jobId: string, waitOptions: WaitOptions = {}): Promise<JobResult> {
      const record = records.get(jobId);
      if (record === undefined) {
        return Promise.reject(new Error(`Unknown job: ${jobId}.`));
      }
      if (record.status !== 'queued' && record.status !== 'running') {
        return Promise.resolve(snapshot(record));
      }
      return new Promise<JobResult>((resolve, reject) => {
        const waiter: Waiter = { resolve, reject };
        if (waitOptions.timeoutMs !== undefined) {
          waiter.timer = setTimeout(() => {
            record.waiters.delete(waiter);
            reject(new Error(`Timed out waiting for job ${jobId}.`));
          }, waitOptions.timeoutMs);
          waiter.timer.unref?.();
        }
        record.waiters.add(waiter);
      });
    },

    start(): void {
      started = true;
      pump();
    },

    stop(): Promise<void> {
      started = false;
      if (running === 0) {
        return Promise.resolve();
      }
      return new Promise<void>((resolve) => {
        stopWaiters.push(resolve);
      });
    },

    get pendingCount(): number {
      return queue.pendingCount;
    },

    get runningCount(): number {
      return running;
    },
  };
}
