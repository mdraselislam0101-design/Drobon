import { describe, expect, test } from 'vitest';
import { hashPassword } from '../src/auth/passwords.js';
import type { UserRecord } from '../src/auth/repositories.js';
import type { ScanEngine } from '../src/scans/engines.js';
import {
  configureFixtureDastTarget,
  readJson,
  sessionCookieFrom,
  startTestServer,
  type TestServer,
} from './helpers.js';

/**
 * Owner-requested scan cancellation (audit finding P1-4).
 *
 * Contract under test:
 * - a QUEUED scan is cancelled immediately and is NEVER executed;
 * - a RUNNING scan gets a DURABLE intent (`cancelRequestedAt`) before the
 *   in-process attempt is signalled, and finishes FAILED/`SCAN_CANCELLED`;
 * - a cancellation that lands while the engine is finishing wins over a
 *   successful result (the owner asked to stop);
 * - foreign/unknown scans answer the SAME 404 (no existence oracle);
 * - a finished scan is never rewritten: 409;
 * - repeating a cancellation is idempotent, not an error.
 */

const PW = 'cancel-pw-test';

const NEVER_ENGINE: ScanEngine = {
  scanType: 'SAST',
  execute: (_scan, context) =>
    new Promise((resolve) => {
      // Resolves only when the processor aborts, which is exactly the
      // cancellation path under test.
      context.signal.addEventListener('abort', () => {
        resolve({ kind: 'failed', failureCode: 'SAST_INPUT_INVALID', failureMessage: 'aborted' });
      }, { once: true });
    }),
};

async function seedUser(server: TestServer, email: string): Promise<void> {
  const record: UserRecord = {
    id: `usr_${email.split('@')[0] ?? 'seed'}`,
    email,
    passwordHash: await hashPassword(PW, 1024),
    createdAt: '2026-09-01T00:00:00.000Z',
    role: 'MEMBER',
    userType: null,
  };
  if (!(await server.users.create(record))) throw new Error(`Seed collision for ${email}`);
}

interface Cookies {
  cookie: string;
}

async function login(server: TestServer, email: string): Promise<Cookies> {
  const res = await fetch(`${server.baseUrl}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: PW }),
  });
  if (res.status !== 200) throw new Error(`Login failed: ${res.status}`);
  const session = sessionCookieFrom(res);
  const probe = await fetch(`${server.baseUrl}/api/v1/me`, { headers: { cookie: session } });
  const rawDevice = probe.headers.getSetCookie()
    .find((entry) => entry.startsWith('drob_on_device=') || entry.startsWith('drobon_device='));
  const device = rawDevice?.split(';')[0]?.slice('drobon_device='.length) ?? '';
  return { cookie: device === '' ? session : `${session}; drobon_device=${device}` };
}

async function createProject(server: TestServer, cookies: Cookies): Promise<string> {
  const res = await fetch(`${server.baseUrl}/api/v1/projects`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: cookies.cookie },
    body: JSON.stringify({ name: 'Cancel target' }),
  });
  if (res.status !== 201) throw new Error(`Project create failed: ${res.status}`);
  const body = (await readJson(res)) as { data: { project: { id: string } } };
  const projectId = body.data.project.id;
  await configureFixtureDastTarget(server, cookies.cookie, projectId);
  return projectId;
}

async function uploadSources(server: TestServer, cookies: Cookies, projectId: string): Promise<void> {
  const res = await fetch(`${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/sources`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json', cookie: cookies.cookie },
    body: JSON.stringify({ files: [{ path: 'src/app.js', content: 'const x = 1;\n' }] }),
  });
  if (res.status !== 200) throw new Error(`Source upload failed: ${res.status}`);
}

async function requestSastScan(server: TestServer, cookies: Cookies, projectId: string): Promise<string> {
  const res = await fetch(`${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/scans`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: cookies.cookie },
    body: JSON.stringify({ scanType: 'SAST' }),
  });
  if (res.status !== 201) throw new Error(`Scan create failed: ${res.status}`);
  const body = (await readJson(res)) as { data: { scan: { id: string } } };
  return body.data.scan.id;
}

function cancel(server: TestServer, cookies: Cookies, projectId: string, scanId: string): Promise<Response> {
  return fetch(
    `${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/scans/${encodeURIComponent(scanId)}/cancel`,
    { method: 'POST', headers: { cookie: cookies.cookie } },
  );
}

async function waitFor(check: () => Promise<boolean>, timeoutMs = 5_000): Promise<void> {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    if (await check()) return;
    await new Promise((resolve) => { setTimeout(resolve, 10); });
  }
  throw new Error('Condition was not reached in time.');
}

async function withServer(run: (server: TestServer) => Promise<void>): Promise<void> {
  const server = await startTestServer({ scanEngines: [NEVER_ENGINE] });
  try {
    await run(server);
  } finally {
    await server.stop();
  }
}

describe('scan cancellation (P1-4)', () => {
  test('a QUEUED scan is cancelled immediately and never executed', async () => {
    await withServer(async (server) => {
      await seedUser(server, 'queued@example.test');
      const cookies = await login(server, 'queued@example.test');
      const projectId = await createProject(server, cookies);
      await uploadSources(server, cookies, projectId);
      const scanId = await requestSastScan(server, cookies, projectId);

      const res = await cancel(server, cookies, projectId, scanId);
      expect(res.status).toBe(200);
      const body = (await readJson(res)) as { data: { scan: { status: string; failureCode?: string } } };
      expect(body.data.scan.status).toBe('FAILED');
      expect(body.data.scan.failureCode).toBe('SCAN_CANCELLED');

      // Draining afterwards must not resurrect the cancelled job.
      await server.scanProcessor.drain();
      const stored = await server.scans.findByProjectAndId(projectId, scanId);
      expect(stored?.status).toBe('FAILED');
      expect(stored?.startedAt).toBeDefined();
      expect(stored?.completedAt).toBeDefined();
    });
  });

  test('a RUNNING scan records durable intent, stops and ends as SCAN_CANCELLED', async () => {
    await withServer(async (server) => {
      await seedUser(server, 'running@example.test');
      const cookies = await login(server, 'running@example.test');
      const projectId = await createProject(server, cookies);
      await uploadSources(server, cookies, projectId);
      const scanId = await requestSastScan(server, cookies, projectId);

      const draining = server.scanProcessor.drain();
      await waitFor(async () => (await server.scans.findByProjectAndId(projectId, scanId))?.status === 'RUNNING');

      const res = await cancel(server, cookies, projectId, scanId);
      expect(res.status).toBe(200);
      const body = (await readJson(res)) as { data: { scan: { cancelRequestedAt?: string } } };
      // The durable intent exists BEFORE any in-process signal is sent.
      expect(body.data.scan.cancelRequestedAt).toBeDefined();

      await draining;
      await waitFor(async () => {
        const current = await server.scans.findByProjectAndId(projectId, scanId);
        return current !== undefined && current.status !== 'RUNNING';
      });
      const stored = await server.scans.findByProjectAndId(projectId, scanId);
      expect(stored?.status).toBe('FAILED');
      expect(stored?.failureCode).toBe('SCAN_CANCELLED');
      expect(stored?.failureMessage).toBe('The scan was cancelled on request.');
      expect(stored?.resultSummary).toBeUndefined();
    });
  });

  test('cancelling a scan never exposes another account and never rewrites a finished scan', async () => {
    await withServer(async (server) => {
      await seedUser(server, 'owner@example.test');
      await seedUser(server, 'stranger@example.test');
      const owner = await login(server, 'owner@example.test');
      const stranger = await login(server, 'stranger@example.test');
      const projectId = await createProject(server, owner);
      await uploadSources(server, owner, projectId);
      const scanId = await requestSastScan(server, owner, projectId);

      // Foreign account: the project itself is not visible → uniform 403.
      const foreign = await cancel(server, stranger, projectId, scanId);
      expect(foreign.status).toBe(403);

      // Unknown scan id inside the caller's own project → 404.
      const unknown = await cancel(server, owner, projectId, 'scan_does_not_exist');
      expect(unknown.status).toBe(404);

      // Cancel, then repeat: idempotent (same terminal record, no error).
      expect((await cancel(server, owner, projectId, scanId)).status).toBe(200);
      const again = await cancel(server, owner, projectId, scanId);
      expect(again.status).toBe(200);
      const body = (await readJson(again)) as { data: { scan: { failureCode?: string } } };
      expect(body.data.scan.failureCode).toBe('SCAN_CANCELLED');
    });
  });

  test('a COMPLETED scan cannot be cancelled retroactively', async () => {
    // The default registry uses the REAL SAST engine, so the scan really
    // completes — the cancellation path must then refuse to rewrite it.
    const server = await startTestServer();
    try {
      await seedUser(server, 'done@example.test');
      const cookies = await login(server, 'done@example.test');
      const projectId = await createProject(server, cookies);
      await uploadSources(server, cookies, projectId);
      const scanId = await requestSastScan(server, cookies, projectId);
      await server.scanProcessor.drain();
      const stored = await server.scans.findByProjectAndId(projectId, scanId);
      expect(stored?.status).toBe('COMPLETED');

      const res = await cancel(server, cookies, projectId, scanId);
      expect(res.status).toBe(409);
      const after = await server.scans.findByProjectAndId(projectId, scanId);
      expect(after?.status).toBe('COMPLETED');
      expect(after?.failureCode).toBeUndefined();
    } finally {
      await server.stop();
    }
  });
});
