import { afterEach, describe, expect, test } from 'vitest';
import { hashPassword } from '../src/auth/passwords.js';
import { createMemoryUserRepository } from '../src/auth/memoryUserRepository.js';
import { createSessionStore, type SessionStore } from '../src/auth/sessions.js';
import type { UserRecord, UserRepository } from '../src/auth/repositories.js';
import { readJson, startTestServer, type TestServer } from './helpers.js';

/**
 * Authorization security regression (Pump 3): forged/expired sessions,
 * method tricks, smuggled authorization headers, client-supplied role
 * headers, header/CORS regressions on denial paths, and log disclosure.
 * No shortcuts — every case goes through the real pipeline.
 */

const PW = 'authz-sec-pw-test-1';

async function seed(repo: UserRepository, role: UserRecord['role']): Promise<void> {
  await repo.create({
    id: `usr_sec-${role.toLowerCase()}`,
    email: `${role.toLowerCase()}@example.test`,
    passwordHash: await hashPassword(PW, 1024),
    createdAt: '2026-09-27T00:00:00.000Z',
    role,
    userType: 'PENTESTER',
  });
}

async function login(server: TestServer, email: string): Promise<string> {
  const res = await fetch(`${server.baseUrl}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: PW }),
  });
  const raw = res.headers.getSetCookie().find((c) => c.startsWith('drobon_session='));
  return raw === undefined ? '' : (raw.split(';')[0] ?? '');
}

const servers: TestServer[] = [];
afterEach(async () => {
  while (servers.length > 0) {
    const server = servers.pop();
    if (server !== undefined) {
      await server.stop();
    }
  }
});

describe('forged and broken authentication never reaches authorization', () => {
  test('garbage and forged session cookies are 401 on every capability', async () => {
    const users = createMemoryUserRepository();
    await seed(users, 'MEMBER');
    const server = await startTestServer({ users, logLevel: 'info' });
    servers.push(server);

    for (const cookie of [
      'drobon_session=not-a-real-token',
      `drobon_session=${'A'.repeat(64)}`,
      'drobon_session=; Path=/',
      `drobon_session=${Buffer.from('forged').toString('base64url')}`,
      'drobon_session=' + ' '.repeat(8),
    ]) {
      const res = await fetch(`${server.baseUrl}/api/v1/authz/capabilities/admin`, {
        headers: { cookie },
      });
      expect(res.status).toBe(401);
    }
  });

  test('expired sessions are 401, not 403', async () => {
    const users = createMemoryUserRepository();
    await seed(users, 'MEMBER');
    let clockMs = Date.now();
    const sessions: SessionStore = createSessionStore({
      ttlSeconds: 60,
      now: () => clockMs,
    });
    const server = await startTestServer({ users, sessions });
    servers.push(server);
    const cookie = await login(server, 'member@example.test');
    expect(
      (await fetch(`${server.baseUrl}/api/v1/authz/capabilities/admin`, { headers: { cookie } }))
        .status,
    ).toBe(403); // valid session, insufficient role

    clockMs += 61_000; // cross the absolute TTL
    const expired = await fetch(`${server.baseUrl}/api/v1/authz/capabilities/admin`, {
      headers: { cookie },
    });
    expect(expired.status).toBe(401);
  });

  test('malformed/alternative authorization headers do not authenticate', async () => {
    const users = createMemoryUserRepository();
    await seed(users, 'ACCOUNT_OWNER'); // strongest role — still cookie-only auth
    const server = await startTestServer({ users });
    servers.push(server);
    for (const headers of [
      { authorization: 'Bearer forged-admin-token' },
      { authorization: 'Basic YWRtaW46YWRtaW4=' },
      { authorization: 'Bearer null' },
      { 'x-api-key': 'ADMIN-test' },
      { 'x-access-token': 'ACCOUNT_OWNER-test' },
      { cookie: 'session=admin' },
    ]) {
      const res = await fetch(`${server.baseUrl}/api/v1/authz/capabilities/owner`, { headers });
      expect(res.status).toBe(401);
    }
  });
});

describe('client-supplied authorization state is ignored', () => {
  test('role/userType headers never influence decisions', async () => {
    const users = createMemoryUserRepository();
    await seed(users, 'MEMBER');
    const server = await startTestServer({ users });
    servers.push(server);
    const cookie = await login(server, 'member@example.test');

    for (const headers of [
      { 'x-role': 'ADMIN', 'x-user-role': 'ACCOUNT_OWNER' },
      { 'x-account-role': 'ADMIN' },
      { 'x-user-type': 'SECURITY_PROFESSIONAL' },
      { 'x-forwarded-role': 'ADMIN' },
      { role: 'ACCOUNT_OWNER' },
    ]) {
      const res = await fetch(`${server.baseUrl}/api/v1/authz/capabilities/admin`, {
        headers: { cookie, ...headers },
      });
      expect(res.status).toBe(403);
      const body = await readJson(res);
      expect(JSON.stringify(body)).not.toContain('granted');
    }
  });

  test('HTTP method tricks do not bypass the role boundary', async () => {
    const users = createMemoryUserRepository();
    await seed(users, 'MEMBER');
    const server = await startTestServer({ users });
    servers.push(server);
    const cookie = await login(server, 'member@example.test');

    for (const method of ['POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'] as const) {
      const res = await fetch(`${server.baseUrl}/api/v1/authz/capabilities/admin`, {
        method,
        headers: {
          cookie,
          ...(method === 'POST' ? { 'content-type': 'application/json' } : {}),
        },
        ...(method === 'POST' ? { body: '{}' } : {}),
      });
      // Unknown method on a known path → 405 (never a grant). OPTIONS is
      // owned by the CORS layer (preflight, no credentials path).
      expect([405, 204]).toContain(res.status);
      expect(res.status).not.toBe(200);
    }
  });
});

describe('denial responses and logs stay clean', () => {
  test('403 denials carry the full security-header set (no regression)', async () => {
    const users = createMemoryUserRepository();
    await seed(users, 'MEMBER');
    const server = await startTestServer({
      users,
      corsAllowedOrigins: ['http://app.example.test'],
    });
    servers.push(server);
    const cookie = await login(server, 'member@example.test');
    const res = await fetch(`${server.baseUrl}/api/v1/authz/capabilities/owner`, {
      headers: { cookie, origin: 'http://app.example.test' },
    });
    expect(res.status).toBe(403);
    expect(res.headers.get('content-security-policy')).toContain("default-src 'none'");
    expect(res.headers.get('x-content-type-options')).toBe('nosniff');
    expect(res.headers.get('x-frame-options')).toBe('DENY');
    expect(res.headers.get('x-request-id')).toBeTruthy();
    expect(res.headers.get('ratelimit-limit')).toBeTruthy();
    // CORS contract intact on the denial path: exact reflection + Vary.
    expect(res.headers.get('access-control-allow-origin')).toBe('http://app.example.test');
    expect(res.headers.get('vary')).toContain('Origin');
  });

  test('denial logs never disclose role configuration, emails or tokens', async () => {
    const users = createMemoryUserRepository();
    await seed(users, 'MEMBER');
    const server = await startTestServer({ users, logLevel: 'info' });
    servers.push(server);
    const cookie = await login(server, 'member@example.test');

    // Produce a mix of authentication and authorization outcomes.
    await fetch(`${server.baseUrl}/api/v1/authz/capabilities/admin`, { headers: { cookie } });
    await fetch(`${server.baseUrl}/api/v1/authz/capabilities/owner`, { headers: { cookie } });
    await fetch(`${server.baseUrl}/api/v1/authz/capabilities/admin`); // 401
    await fetch(`${server.baseUrl}/api/v1/users?id=usr_missing`, { headers: { cookie } });

    const joined = server.logs.join('\n');
    expect(joined).not.toContain('ADMIN');
    expect(joined).not.toContain('ACCOUNT_OWNER');
    expect(joined).not.toContain('member@example.test');
    expect(joined).not.toContain('users:read');
    expect(joined).not.toContain('Bearer');
    expect(joined).not.toContain('scrypt$');
    // …but the outcomes are still observable for operations.
    expect(joined).toContain('"status":403');
    expect(joined).toContain('"status":401');
  });

  test('error responses contain no stack traces or secrets', async () => {
    const users = createMemoryUserRepository();
    await seed(users, 'ADMIN');
    const server = await startTestServer({ users, env: 'development' });
    servers.push(server);
    const cookie = await login(server, 'admin@example.test');
    const res = await fetch(`${server.baseUrl}/api/v1/authz/capabilities/owner`, {
      headers: { cookie },
    });
    expect(res.status).toBe(403);
    const raw = JSON.stringify(await readJson(res));
    expect(raw).not.toMatch(/at .*\.ts:\d+/);
    expect(raw).not.toContain('stack');
    expect(raw).not.toContain('scrypt$');
    expect(raw).not.toContain('password');
  });
});
