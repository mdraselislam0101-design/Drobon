import { describe, expect, test } from 'vitest';
import {
  DEFAULT_JOB_TIMEOUT_MS,
  DEFAULT_RETRY_POLICY,
  JOB_STATUSES,
  createJob,
} from '../src/jobs.js';

describe('JOB_STATUSES', () => {
  test('is a unique non-empty vocabulary', () => {
    expect(JOB_STATUSES.length).toBeGreaterThan(0);
    expect(new Set(JOB_STATUSES).size).toBe(JOB_STATUSES.length);
  });
});

describe('DEFAULT_RETRY_POLICY', () => {
  test('is conservative (single attempt) and internally consistent', () => {
    expect(DEFAULT_RETRY_POLICY.maxAttempts).toBe(1);
    expect(DEFAULT_RETRY_POLICY.baseDelayMs).toBeGreaterThanOrEqual(0);
    expect(DEFAULT_RETRY_POLICY.maxDelayMs).toBeGreaterThanOrEqual(
      DEFAULT_RETRY_POLICY.baseDelayMs,
    );
    expect(DEFAULT_JOB_TIMEOUT_MS).toBeGreaterThan(0);
  });
});

describe('createJob', () => {
  test('builds a job with defaults', () => {
    const job = createJob('scan.target', { host: 'example.test' }, {
      generateId: () => 'job-test-1',
    });
    expect(job.id).toBe('job-test-1');
    expect(job.type).toBe('scan.target');
    expect(job.input).toEqual({ host: 'example.test' });
    expect(job.maxAttempts).toBe(DEFAULT_RETRY_POLICY.maxAttempts);
    expect(job.timeoutMs).toBe(DEFAULT_JOB_TIMEOUT_MS);
    expect(Number.isNaN(Date.parse(job.createdAt))).toBe(false);
  });

  test('honors overrides', () => {
    const job = createJob('t', null, {
      generateId: () => 'job-test-2',
      maxAttempts: 3,
      timeoutMs: 5000,
      createdAt: '2026-01-01T00:00:00.000Z',
    });
    expect(job.maxAttempts).toBe(3);
    expect(job.timeoutMs).toBe(5000);
    expect(job.createdAt).toBe('2026-01-01T00:00:00.000Z');
  });

  test.each([
    ['blank type', '   ', { generateId: () => 'x' }],
    ['zero attempts', 't', { generateId: () => 'x', maxAttempts: 0 }],
    ['fractional attempts', 't', { generateId: () => 'x', maxAttempts: 1.5 }],
    ['zero timeout', 't', { generateId: () => 'x', timeoutMs: 0 }],
    ['negative timeout', 't', { generateId: () => 'x', timeoutMs: -5 }],
    ['blank id', 't', { generateId: () => '  ' }],
  ])('throws for %s', (_label, type, options) => {
    expect(() => createJob(type, null, options)).toThrowError();
  });
});
