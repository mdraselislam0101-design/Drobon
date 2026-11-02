import { describe, expect, test } from 'vitest';
import { hashPassword } from '../src/auth/passwords.js';
import type { UserRecord } from '../src/auth/repositories.js';
import type { ScanEngine } from '../src/scans/engines.js';
import { isRetryableFailure } from '../src/scans/processor.js';
import {
  configureFixtureDastTarget, readJson, sessionCookieFrom, startTestServer, type TestServer,
} from './helpers.js';

/**
 * Bounded retry with exponential backoff (audit finding P1-3).
 *
 * Rules under test:
 * - ONLY a transient engine crash (`SCAN_ENGINE_ERROR`) is retried; every
 *   deterministic outcome stays terminal on the first attempt;
 * - the retry is durable (QUEUED + `retryAt`) and increments `attempt`, so a
 *   restart cannot lose it and the history is visible;
 * - attempts are bounded by config and never exceed the shared hard limit;
 * - a scan is never double-charged: the same record is re-executed.
 */

const PW = 'retry-pw-test';

async function seedUser(server: TestServer, email: string): Promise<void> {
  const record: UserRecord = {
    id: `usr_${email.split('@')[0] ?? 'seed'}`, email,
    passwordHash: await hashPassword(PW, 1024),
    createdAt: '2026-09-01T00:00:00.000Z', role: 'MEMBER', userType: null,
  };
  if (!(await server.users.create(record))) throw new Error('Seed collision');
}

async function login(server: TestServer, email: string): Promise<string> {
  const res = await fetch(`${server.baseUrl}/api/v1/auth/login`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: PW }),
  });
  expect(res.status).toBe(200);
  const session = sessionCookieFrom(res);
  const probe = await fetch(`${server.baseUrl}/api/v1/me`, { headers: { cookie: session } });
  const device = probe.headers.getSetCookie()
    .find((entry) => entry.startsWith('drobon_device='))?.split(';')[0]?.slice('drobon_device='.length) ?? '';
  return device === '' ? session : `${session}; drobon_device=${device}`;
}

async function prepare(server: TestServer, email: string): Promise<{ cookie: string; projectId: string }> {
  await seedUser(server, email);
  const cookie = await login(server, email);
  const res = await fetch(`${server.baseUrl}/api/v1/projects`, {
    method: 'POST', headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify({ name: 'Retry target' }),
  });
  expect(res.status).toBe(201);
  const body = (await readJson(res)) as { data: { project: { id: string } } };
  const projectId = body.data.project.id;
  await configureFixtureDastTarget(server, cookie, projectId);
  await fetch(`${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/sources`, {
    method: 'PUT', headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify({ files: [{ path: 'src/app.js', content: 'const x = 1;\n' }] }),
  });
  return { cookie, projectId };
}

async function requestScan(server: TestServer, cookie: string, projectId: string): Promise<string> {
  const res = await fetch(`${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/scans`, {
    method: 'POST', headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify({ scanType: 'SAST' }),
  });
  expect(res.status).toBe(201);
  const body = (await readJson(res)) as { data: { scan: { id: string } } };
  return body.data.scan.id;
}

async function sleep(ms: number): Promise<void> {
  await new Promise((resolve) => { setTimeout(resolve, ms); });
}

describe('retry classification', () => {
  test('only a transient engine crash is retryable', () => {
    expect(isRetryableFailure('SCAN_ENGINE_ERROR')).toBe(true);
    for (const code of ['SAST_INPUT_INVALID', 'SAST_TARGET_NOT_FOUND', 'SAST_SCAN_TIMEOUT',
      'DAST_TARGET_BLOCKED', 'SCAN_CANCELLED', 'SCAN_INTERRUPTED', undefined]) {
      expect(isRetryableFailure(code)).toBe(false);
    }
  });
});

describe('processor retry with backoff', () => {
  test('a transient crash is requeued (durable, attempt 1) and later succeeds', async () => {
    let calls = 0;
    const flaky: ScanEngine = {
      scanType: 'SAST',
      execute: async () => {
        calls += 1;
        if (calls === 1) throw new Error('transient engine crash');
        return { kind: 'completed', resultSummary: { findingsTotal: 0 } as never, findings: [] };
      },
    };
    const server = await startTestServer({ scanEngines: [flaky], scanMaxAttempts: 2, scanRetryBaseDelayMs: 100 });
    try {
      const { cookie, projectId } = await prepare(server, 'flaky@example.test');
      const scanId = await requestScan(server, cookie, projectId);

      await server.scanProcessor.drain();
      const afterFirst = await server.scans.findByProjectAndId(projectId, scanId);
      // Durable retry state: still queued, attempt counted, backoff recorded.
      expect(afterFirst?.status).toBe('QUEUED');
      expect(afterFirst?.attempt).toBe(1);
      expect(afterFirst?.retryAt).toBeDefined();
      expect(afterFirst?.failureCode).toBeUndefined();
      // The backoff instant is respected: an immediate drain does nothing.
      await server.scanProcessor.drain();
      expect(calls).toBe(1);

      await sleep(150);
      await server.scanProcessor.drain();
      const done = await server.scans.findByProjectAndId(projectId, scanId);
      expect(calls).toBe(2);
      expect(done?.status).toBe('COMPLETED');
      expect(done?.attempt).toBe(2);
      expect(done?.retryAt).toBeUndefined();
    } finally {
      await server.stop();
    }
  });

  test('attempts are bounded — the scan ends FAILED once they are exhausted', async () => {
    const broken: ScanEngine = {
      scanType: 'SAST',
      execute: async () => { throw new Error('always broken'); },
    };
    const server = await startTestServer({ scanEngines: [broken], scanMaxAttempts: 2, scanRetryBaseDelayMs: 100 });
    try {
      const { cookie, projectId } = await prepare(server, 'broken@example.test');
      const scanId = await requestScan(server, cookie, projectId);

      await server.scanProcessor.drain();
      expect((await server.scans.findByProjectAndId(projectId, scanId))?.status).toBe('QUEUED');
      await sleep(150);
      await server.scanProcessor.drain();
      const failed = await server.scans.findByProjectAndId(projectId, scanId);
      expect(failed?.status).toBe('FAILED');
      expect(failed?.failureCode).toBe('SCAN_ENGINE_ERROR');
      expect(failed?.attempt).toBe(2);
      // No third attempt is scheduled.
      await sleep(150);
      await server.scanProcessor.drain();
      expect((await server.scans.findByProjectAndId(projectId, scanId))?.attempt).toBe(2);
    } finally {
      await server.stop();
    }
  });

  test('a deterministic engine failure is never retried', async () => {
    const deterministic: ScanEngine = {
      scanType: 'SAST',
      execute: async () => ({
        kind: 'failed',
        failureCode: 'SAST_TARGET_NOT_FOUND',
        failureMessage: 'Upload a source snapshot before requesting a SAST scan.',
      }),
    };
    const server = await startTestServer({ scanEngines: [deterministic], scanMaxAttempts: 3, scanRetryBaseDelayMs: 100 });
    try {
      const { cookie, projectId } = await prepare(server, 'deterministic@example.test');
      const scanId = await requestScan(server, cookie, projectId);
      await server.scanProcessor.drain();
      const stored = await server.scans.findByProjectAndId(projectId, scanId);
      expect(stored?.status).toBe('FAILED');
      expect(stored?.failureCode).toBe('SAST_TARGET_NOT_FOUND');
      expect(stored?.attempt).toBe(1);
      expect(stored?.retryAt).toBeUndefined();
    } finally {
      await server.stop();
    }
  });
});
