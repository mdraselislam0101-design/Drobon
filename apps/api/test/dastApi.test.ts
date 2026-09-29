import { afterEach, describe, expect, test } from 'vitest';
import { hashPassword } from '../src/auth/passwords.js';
import { createMemoryUserRepository } from '../src/auth/memoryUserRepository.js';
import type { UserRecord, UserRepository } from '../src/auth/repositories.js';
import { createDastTargetPolicy } from '../src/scans/dast/target.js';
import {
  cleanupTempStoreDir,
  configureFixtureDastTarget,
  makeTempStoreDir,
  readJson,
  sessionCookieFrom,
  startTestServer,
  type TestServer,
} from './helpers.js';

const PASSWORD = 'dast-test-password';
const SAFE_IP = '93.184.216.34';
const FIXTURE_COOKIE = 'FIXTURE_COOKIE_SECRET_DO_NOT_LEAK';
const OWNER_PROJECT = 'Target app';

type Cookies = { session: string; device?: string };

async function seed(repo: UserRepository, email: string, id: string): Promise<void> {
  const user: UserRecord = {
    id,
    email,
    passwordHash: await hashPassword(PASSWORD, 1024),
    createdAt: '2026-09-28T00:00:00.000Z',
    role: 'MEMBER',
    userType: null,
  };
  if (!(await repo.create(user))) throw new Error('Unexpected DAST API test user collision.');
}

function cookieHeader(cookies: Cookies): string {
  return cookies.device === undefined ? cookies.session : `${cookies.session}; drobon_device=${cookies.device}`;
}

async function login(server: TestServer, email: string): Promise<Cookies> {
  const response = await fetch(`${server.baseUrl}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: PASSWORD }),
  });
  if (response.status !== 200) throw new Error(`DAST API test login failed: ${response.status}`);
  const session = sessionCookieFrom(response);
  const probe = await fetch(`${server.baseUrl}/api/v1/me`, { headers: { cookie: session } });
  const rawDevice = probe.headers.getSetCookie().find((value) => value.startsWith('drobon_device='));
  const device = rawDevice?.split(';')[0]?.slice('drobon_device='.length);
  return device === undefined ? { session } : { session, device };
}

async function createProject(server: TestServer, cookies: Cookies): Promise<string> {
  const response = await fetch(`${server.baseUrl}/api/v1/projects`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: cookieHeader(cookies) },
    body: JSON.stringify({ name: OWNER_PROJECT }),
  });
  if (response.status !== 201) throw new Error(`DAST test project creation failed: ${response.status}`);
  const body = await readJson(response) as { data: { project: { id: string } } };
  return body.data.project.id;
}

async function setTarget(server: TestServer, cookies: Cookies, projectId: string, targetUrl: string): Promise<Response> {
  return fetch(`${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/dast-target`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json', cookie: cookieHeader(cookies) },
    body: JSON.stringify({ targetUrl }),
  });
}

async function requestDast(server: TestServer, cookies: Cookies, projectId: string, key = 'dast-key-0001', body = { scanType: 'DAST' }): Promise<Response> {
  return fetch(`${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/scans`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'idempotency-key': key,
      cookie: cookieHeader(cookies),
    },
    body: JSON.stringify(body),
  });
}

async function getUsage(server: TestServer, cookies: Cookies): Promise<{ used: number }> {
  const response = await fetch(`${server.baseUrl}/api/v1/usage`, { headers: { cookie: cookieHeader(cookies) } });
  const body = await readJson(response) as { data: { used: number } };
  return { used: body.data.used };
}

const servers: TestServer[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.stop()));
});

async function start(users: UserRepository, resolve?: (host: string) => Promise<readonly string[]>): Promise<TestServer> {
  const server = await startTestServer({
    users,
    ...(resolve === undefined ? {} : { dastTargetPolicy: createDastTargetPolicy({ resolve }) }),
  });
  servers.push(server);
  return server;
}

describe('project-associated DAST target configuration and API lifecycle', () => {
  test('target configuration is owner-only, strict, validated, persisted, and removable', async () => {
    const users = createMemoryUserRepository();
    await seed(users, 'owner@example.test', 'usr_dast_owner');
    await seed(users, 'other@example.test', 'usr_dast_other');
    const server = await start(users, async (host) => host === '127.0.0.1' ? ['127.0.0.1'] : [SAFE_IP]);
    const owner = await login(server, 'owner@example.test');
    const other = await login(server, 'other@example.test');
    const projectId = await createProject(server, owner);
    const foreign = await createProject(server, other);

    const anonymous = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/dast-target`, {
      method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ targetUrl: 'https://app.example.org/' }),
    });
    expect(anonymous.status).toBe(401);
    expect((await setTarget(server, other, projectId, 'https://app.example.org/')).status).toBe(403);

    for (const targetUrl of [
      'http://127.0.0.1/', 'http://localhost/', 'http://169.254.169.254/latest/meta-data/',
      'ftp://app.example.org/', 'https://user:pass@app.example.org/',
      'https://app.example.org/?secret=1', 'https://app.example.org:8443/',
    ]) {
      expect((await setTarget(server, owner, projectId, targetUrl)).status, targetUrl).toBe(422);
    }
    const massAssignment = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/dast-target`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', cookie: cookieHeader(owner) },
      body: JSON.stringify({ targetUrl: 'https://app.example.org/', projectId: foreign, ownerId: 'usr_dast_other' }),
    });
    expect(massAssignment.status).toBe(422);

    const set = await setTarget(server, owner, projectId, 'https://APP.example.org/');
    expect(set.status).toBe(200);
    const setBody = await readJson(set) as { data: { project: { id: string; dastTargetUrl?: string; ownerId?: string } } };
    expect(setBody.data.project.dastTargetUrl).toBe('https://app.example.org/');
    expect(setBody.data.project.ownerId).toBeUndefined();
    const readBack = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}`, { headers: { cookie: cookieHeader(owner) } });
    expect((await readJson(readBack) as { data: { project: { dastTargetUrl?: string } } }).data.project.dastTargetUrl).toBe('https://app.example.org/');

    const foreignWrite = await setTarget(server, owner, foreign, 'https://app.example.org/');
    expect(foreignWrite.status).toBe(403);
    const cleared = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/dast-target`, {
      method: 'DELETE', headers: { cookie: cookieHeader(owner) },
    });
    expect(cleared.status).toBe(200);
    const clearedRead = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}`, { headers: { cookie: cookieHeader(owner) } });
    expect((await readJson(clearedRead) as { data: { project: { dastTargetUrl?: string } } }).data.project.dastTargetUrl).toBeUndefined();

    // Archived projects reject DAST target mutations with 409 PROJECT_ARCHIVED.
    const archived = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/archive`, {
      method: 'POST', headers: { cookie: cookieHeader(owner) },
    });
    expect(archived.status).toBe(200);
    const archivedPut = await setTarget(server, owner, projectId, 'https://app.example.org/');
    expect(archivedPut.status).toBe(409);
    expect((await readJson(archivedPut) as { error: { code: string } }).error.code).toBe('PROJECT_ARCHIVED');
    const archivedDelete = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/dast-target`, {
      method: 'DELETE', headers: { cookie: cookieHeader(owner) },
    });
    expect(archivedDelete.status).toBe(409);
    expect((await readJson(archivedDelete) as { error: { code: string } }).error.code).toBe('PROJECT_ARCHIVED');
  });

  test('missing or newly-private DNS targets fail before consuming the existing quota', async () => {
    const users = createMemoryUserRepository();
    await seed(users, 'owner@example.test', 'usr_dast_quota');
    let answer = SAFE_IP;
    const server = await start(users, async (host) => host === '127.0.0.1' ? ['127.0.0.1'] : [answer]);
    const owner = await login(server, 'owner@example.test');
    const projectId = await createProject(server, owner);

    const absent = await requestDast(server, owner, projectId);
    expect(absent.status).toBe(409);
    expect(await getUsage(server, owner)).toEqual({ used: 0 });

    expect((await setTarget(server, owner, projectId, 'https://app.example.org/')).status).toBe(200);
    answer = '127.0.0.1'; // Resolver rebinding after configuration.
    const rebound = await requestDast(server, owner, projectId, 'dast-key-rejected');
    expect(rebound.status).toBe(409);
    expect(await getUsage(server, owner)).toEqual({ used: 0 });

    answer = SAFE_IP;
    const created = await requestDast(server, owner, projectId, 'dast-key-valid-1');
    expect(created.status).toBe(201);
    const replay = await requestDast(server, owner, projectId, 'dast-key-valid-1');
    expect(replay.status).toBe(200);
    expect(await getUsage(server, owner)).toEqual({ used: 1 });

    expect((await setTarget(server, owner, projectId, 'https://other.example.org/')).status).toBe(200);
    const changedTargetReplay = await requestDast(server, owner, projectId, 'dast-key-valid-1');
    expect(changedTargetReplay.status).toBe(409);
    expect(await getUsage(server, owner)).toEqual({ used: 1 });
  });

  test('scan executes one synthetic fixture exchange and persists observed DAST findings/results without raw response secrets', async () => {
    const users = createMemoryUserRepository();
    await seed(users, 'owner@example.test', 'usr_dast_result');
    const server = await start(users);
    const owner = await login(server, 'owner@example.test');
    const projectId = await createProject(server, owner);
    expect((await setTarget(server, owner, projectId, 'https://fixture.example.org/')).status).toBe(200);
    const created = await requestDast(server, owner, projectId);
    expect(created.status).toBe(201);
    const createdBody = await readJson(created) as { data: { scan: { id: string; targetUrl?: string; status: string } } };
    expect(createdBody.data.scan.status).toBe('QUEUED');
    expect(createdBody.data.scan.targetUrl).toBe('https://fixture.example.org/');

    await server.scanProcessor.drain();
    const detailResponse = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans/${createdBody.data.scan.id}`, {
      headers: { cookie: cookieHeader(owner) },
    });
    expect(detailResponse.status).toBe(200);
    const detailBody = await readJson(detailResponse) as {
      data: { scan: { status: string; scanType: string; resultSummary?: { requestsMade?: number; redirectsFollowed?: number; findingsTotal?: number }; dast?: { requestCount: number; observations: Array<{ endpoint: string; method: string; status: number; headers: string[] }> }; findings: Array<{ scanner?: string; targetUrl?: string; endpoint?: string; evidence: string }> } };
    };
    const scan = detailBody.data.scan;
    expect(scan.status).toBe('COMPLETED');
    expect(scan.scanType).toBe('DAST');
    expect(scan.resultSummary).toMatchObject({ requestsMade: 1, redirectsFollowed: 0, findingsTotal: scan.findings.length });
    expect(scan.dast?.requestCount).toBe(1);
    expect(scan.dast?.observations).toHaveLength(1);
    expect(scan.findings.length).toBeGreaterThan(0);
    expect(scan.findings.every((finding) => finding.scanner === 'DAST' && finding.targetUrl === 'https://fixture.example.org/')).toBe(true);
    const serialized = JSON.stringify(detailBody);
    expect(serialized).not.toContain(FIXTURE_COOKIE);
    expect(serialized).not.toContain('<script');
    expect(serialized).not.toContain('fixture-only/1.0');
    expect(serialized).toContain('Server: present');
  });

  test('durable target configuration, completed observations, and findings survive an API restart', async () => {
    const dir = makeTempStoreDir('dast-durable');
    const users = createMemoryUserRepository();
    await seed(users, 'owner@example.test', 'usr_dast_durable');
    const policy = createDastTargetPolicy({ resolve: async (host) => host === 'fixture.example.org' ? [SAFE_IP] : [] });
    const durable = () => startTestServer({
      users,
      projectStoreDir: dir,
      scanStoreDir: dir,
      dastTargetPolicy: policy,
      // The test helper's transport returns a fixed synthetic response;
      // this proves persistence, not a real target network exchange.
    });
    let first: TestServer | undefined;
    let second: TestServer | undefined;
    try {
      first = await durable();
      const owner = await login(first, 'owner@example.test');
      const projectId = await createProject(first, owner);
      await configureFixtureDastTarget(first, cookieHeader(owner), projectId);
      const created = await requestDast(first, owner, projectId, 'dast-durable-1');
      const createdBody = await readJson(created) as { data: { scan: { id: string } } };
      await first.scanProcessor.drain();
      const firstDetail = await fetch(`${first.baseUrl}/api/v1/projects/${projectId}/scans/${createdBody.data.scan.id}`, {
        headers: { cookie: cookieHeader(owner) },
      });
      expect((await readJson(firstDetail) as { data: { scan: { status: string } } }).data.scan.status).toBe('COMPLETED');
      await first.stop();
      first = undefined;

      second = await durable();
      const ownerAfterRestart = await login(second, 'owner@example.test');
      const projectResponse = await fetch(`${second.baseUrl}/api/v1/projects/${projectId}`, {
        headers: { cookie: cookieHeader(ownerAfterRestart) },
      });
      expect((await readJson(projectResponse) as { data: { project: { dastTargetUrl?: string } } }).data.project.dastTargetUrl)
        .toBe('https://fixture.example.org/');
      const detailResponse = await fetch(`${second.baseUrl}/api/v1/projects/${projectId}/scans/${createdBody.data.scan.id}`, {
        headers: { cookie: cookieHeader(ownerAfterRestart) },
      });
      const persisted = await readJson(detailResponse) as { data: { scan: { status: string; targetUrl?: string; resultSummary?: { requestsMade?: number }; dast?: { observations: unknown[] }; findings: unknown[] } } };
      expect(persisted.data.scan.status).toBe('COMPLETED');
      expect(persisted.data.scan.targetUrl).toBe('https://fixture.example.org/');
      expect(persisted.data.scan.resultSummary?.requestsMade).toBe(1);
      expect(persisted.data.scan.dast?.observations).toHaveLength(1);
      expect(persisted.data.scan.findings.length).toBeGreaterThan(0);
    } finally {
      if (first !== undefined) await first.stop();
      if (second !== undefined) await second.stop();
      cleanupTempStoreDir(dir);
    }
  });

  test('client cannot supply a target or server-authoritative scan claims in the request body', async () => {
    const users = createMemoryUserRepository();
    await seed(users, 'owner@example.test', 'usr_dast_injection');
    const server = await start(users);
    const owner = await login(server, 'owner@example.test');
    const projectId = await createProject(server, owner);
    await configureFixtureDastTarget(server, cookieHeader(owner), projectId);
    for (const body of [
      { scanType: 'DAST', targetUrl: 'https://elsewhere.example.org/' },
      { scanType: 'DAST', projectId },
      { scanType: 'DAST', ownerId: 'usr_attacker' },
      { scanType: 'DAST', plan: 'PRO', userType: 'PENTESTER' },
    ]) {
      expect((await requestDast(server, owner, projectId, `dast-injection-${Math.random().toString(36).slice(2, 8)}`, body)).status).toBe(422);
    }
    expect(await getUsage(server, owner)).toEqual({ used: 0 });
  });
});
