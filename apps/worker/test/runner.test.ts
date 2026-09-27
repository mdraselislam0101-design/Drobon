import { describe, expect, test } from 'vitest';
import { createRunner } from '../src/runner.js';
import type { JobContext } from '../src/types.js';

const immediateSleep = async (): Promise<void> => {};

describe('createRunner', () => {
  test('runs a job to success with output and attempt count', async () => {
    const runner = createRunner({
      handlers: {
        'test.echo': async (input: unknown) => ({ got: input }),
      },
      sleep: immediateSleep,
    });
    runner.start();
    try {
      const job = runner.submit('test.echo', { hello: 'world' }, { id: 'job-1' });
      expect(job.id).toBe('job-1');
      const result = await runner.waitFor('job-1', { timeoutMs: 1000 });
      expect(result.status).toBe('succeeded');
      expect(result.attempts).toBe(1);
      expect(result.output).toEqual({ got: { hello: 'world' } });
      expect(result.error).toBeUndefined();
      expect(runner.getStatus('job-1')).toBe('succeeded');
      expect(runner.getResult('job-1')).toEqual(result);
    } finally {
      await runner.stop();
    }
  });

  test('fails unknown job types with BAD_REQUEST', async () => {
    const runner = createRunner({ handlers: {}, sleep: immediateSleep });
    runner.start();
    try {
      runner.submit('test.unknown', null, { id: 'job-2' });
      const result = await runner.waitFor('job-2', { timeoutMs: 1000 });
      expect(result.status).toBe('failed');
      expect(result.error?.code).toBe('BAD_REQUEST');
      expect(result.attempts).toBe(1);
    } finally {
      await runner.stop();
    }
  });

  test('retries handler errors with backoff, then succeeds', async () => {
    const delays: number[] = [];
    let calls = 0;
    const runner = createRunner({
      handlers: {
        'test.flaky': async () => {
          calls += 1;
          if (calls < 3) {
            throw new Error('flaky failure');
          }
          return 'recovered';
        },
      },
      retry: { maxAttempts: 3, baseDelayMs: 25, maxDelayMs: 100 },
      sleep: async (ms: number) => {
        delays.push(ms);
      },
    });
    runner.start();
    try {
      runner.submit('test.flaky', null, { id: 'job-3', maxAttempts: 3 });
      const result = await runner.waitFor('job-3', { timeoutMs: 2000 });
      expect(result.status).toBe('succeeded');
      expect(result.attempts).toBe(3);
      expect(result.output).toBe('recovered');
      expect(delays).toEqual([25, 50]);
    } finally {
      await runner.stop();
    }
  });

  test('marks jobs failed after the attempt budget is exhausted', async () => {
    const runner = createRunner({
      handlers: {
        'test.always-fails': async () => {
          throw new Error('permanent failure marker');
        },
      },
      retry: { maxAttempts: 2, baseDelayMs: 1, maxDelayMs: 5 },
      sleep: immediateSleep,
    });
    runner.start();
    try {
      runner.submit('test.always-fails', null, { id: 'job-4', maxAttempts: 2 });
      const result = await runner.waitFor('job-4', { timeoutMs: 2000 });
      expect(result.status).toBe('failed');
      expect(result.attempts).toBe(2);
      expect(result.error?.code).toBe('INTERNAL_ERROR');
      expect(result.error?.message).toContain('permanent failure marker');
    } finally {
      await runner.stop();
    }
  });

  test('truncates gigantic handler error messages', async () => {
    const runner = createRunner({
      handlers: {
        'test.chatty': async () => {
          throw new Error('x'.repeat(5000));
        },
      },
      sleep: immediateSleep,
    });
    runner.start();
    try {
      runner.submit('test.chatty', null, { id: 'job-5' });
      const result = await runner.waitFor('job-5', { timeoutMs: 1000 });
      expect(result.status).toBe('failed');
      expect((result.error?.message ?? '').length).toBeLessThanOrEqual(1001);
    } finally {
      await runner.stop();
    }
  });

  test('times out attempts that overrun their budget', async () => {
    const runner = createRunner({
      handlers: {
        'test.slow': async (_input: unknown, ctx: JobContext) => {
          await new Promise<void>((resolve) => {
            const timer = setTimeout(resolve, 500);
            ctx.signal.addEventListener('abort', () => clearTimeout(timer), { once: true });
          });
          return 'too late';
        },
      },
      sleep: immediateSleep,
    });
    runner.start();
    try {
      runner.submit('test.slow', null, { id: 'job-6', timeoutMs: 30 });
      const result = await runner.waitFor('job-6', { timeoutMs: 2000 });
      expect(result.status).toBe('timed_out');
      expect(result.error?.code).toBe('TIMEOUT');
      expect(result.attempts).toBe(1);
    } finally {
      await runner.stop();
    }
  });

  test('cancels queued jobs before they start', async () => {
    let ran = false;
    const runner = createRunner({
      handlers: {
        'test.never': async () => {
          ran = true;
          return null;
        },
      },
      sleep: immediateSleep,
    });
    // Not started: the job stays queued.
    runner.submit('test.never', null, { id: 'job-7' });
    expect(runner.pendingCount).toBe(1);
    expect(runner.cancel('job-7')).toBe(true);
    expect(runner.getStatus('job-7')).toBe('cancelled');
    runner.start();
    await runner.stop();
    expect(ran).toBe(false);
  });

  test('cancels running jobs via the abort signal', async () => {
    const runner = createRunner({
      handlers: {
        'test.cancellable': async (_input: unknown, ctx: JobContext) => {
          await new Promise<void>((_resolve, reject) => {
            ctx.signal.addEventListener('abort', () => reject(new Error('aborted')), {
              once: true,
            });
          });
          return null;
        },
      },
      sleep: immediateSleep,
    });
    runner.start();
    try {
      runner.submit('test.cancellable', null, { id: 'job-8', timeoutMs: 5000 });
      await new Promise((resolve) => setTimeout(resolve, 20));
      expect(runner.getStatus('job-8')).toBe('running');
      expect(runner.cancel('job-8')).toBe(true);
      const result = await runner.waitFor('job-8', { timeoutMs: 1000 });
      expect(result.status).toBe('cancelled');
    } finally {
      await runner.stop();
    }
  });

  test('cancel returns false for finished or unknown jobs', async () => {
    const runner = createRunner({
      handlers: { 'test.fast': async () => 'done' },
      sleep: immediateSleep,
    });
    runner.start();
    try {
      runner.submit('test.fast', null, { id: 'job-9' });
      await runner.waitFor('job-9', { timeoutMs: 1000 });
      expect(runner.cancel('job-9')).toBe(false);
      expect(runner.cancel('job-missing')).toBe(false);
    } finally {
      await runner.stop();
    }
  });

  test('waitFor rejects for unknown jobs and on waiter timeout', async () => {
    const runner = createRunner({ handlers: {}, sleep: immediateSleep });
    await expect(runner.waitFor('job-missing')).rejects.toThrowError();
    runner.submit('test.unknown', null, { id: 'job-10' });
    // Not started: job never finishes, waiter times out.
    await expect(runner.waitFor('job-10', { timeoutMs: 20 })).rejects.toThrowError(
      /Timed out waiting/,
    );
    await runner.stop();
  });

  test('respects the concurrency bound', async () => {
    let inFlight = 0;
    let maxInFlight = 0;
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const runner = createRunner({
      handlers: {
        'test.gated': async () => {
          inFlight += 1;
          maxInFlight = Math.max(maxInFlight, inFlight);
          try {
            await gate;
            return 'ok';
          } finally {
            inFlight -= 1;
          }
        },
      },
      concurrency: 2,
      sleep: immediateSleep,
    });
    runner.start();
    try {
      runner.submit('test.gated', null, { id: 'job-c1' });
      runner.submit('test.gated', null, { id: 'job-c2' });
      runner.submit('test.gated', null, { id: 'job-c3' });
      await new Promise((resolve) => setTimeout(resolve, 30));
      expect(maxInFlight).toBe(2);
      expect(runner.runningCount).toBe(2);
      release();
      await runner.waitFor('job-c3', { timeoutMs: 1000 });
      expect(maxInFlight).toBe(2);
    } finally {
      await runner.stop();
    }
  });

  test('evicts the oldest finished records past maxRecords', async () => {
    const runner = createRunner({
      handlers: { 'test.fast': async () => 'done' },
      sleep: immediateSleep,
      maxRecords: 2,
    });
    runner.start();
    try {
      runner.submit('test.fast', null, { id: 'job-e1' });
      runner.submit('test.fast', null, { id: 'job-e2' });
      runner.submit('test.fast', null, { id: 'job-e3' });
      await runner.waitFor('job-e3', { timeoutMs: 1000 });
      expect(runner.getResult('job-e1')).toBeUndefined();
      expect(runner.getResult('job-e2')?.status).toBe('succeeded');
      expect(runner.getResult('job-e3')?.status).toBe('succeeded');
    } finally {
      await runner.stop();
    }
  });

  test('stop waits for in-flight jobs to finish', async () => {
    const runner = createRunner({
      handlers: {
        'test.quick': async () => {
          await new Promise((resolve) => setTimeout(resolve, 20));
          return 'done';
        },
      },
      sleep: immediateSleep,
    });
    runner.start();
    runner.submit('test.quick', null, { id: 'job-s1' });
    await runner.stop();
    expect(runner.getStatus('job-s1')).toBe('succeeded');
  });

  test('submit validates type, id uniqueness and job options', () => {
    const runner = createRunner({ handlers: {}, sleep: immediateSleep });
    expect(() => runner.submit('   ', null)).toThrowError();
    expect(() => runner.submit('t', null, { timeoutMs: 0 })).toThrowError();
    expect(() => runner.submit('t', null, { maxAttempts: 0 })).toThrowError();
    runner.submit('t', null, { id: 'dup' });
    expect(() => runner.submit('t', null, { id: 'dup' })).toThrowError();
  });

  test('constructor validates concurrency, timeout and record cap', () => {
    expect(() => createRunner({ handlers: {}, concurrency: 0 })).toThrowError();
    expect(() => createRunner({ handlers: {}, defaultTimeoutMs: 0 })).toThrowError();
    expect(() => createRunner({ handlers: {}, maxRecords: 0 })).toThrowError();
    expect(() =>
      createRunner({
        handlers: {},
        retry: { maxAttempts: 0, baseDelayMs: 0, maxDelayMs: 0 },
      }),
    ).toThrowError();
  });
});
