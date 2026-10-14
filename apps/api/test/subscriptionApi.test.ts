import { request as httpRequest } from 'node:http';
import { afterEach, describe, expect, test } from 'vitest';
import { hashPassword } from '../src/auth/passwords.js';
import { createMemoryUserRepository } from '../src/auth/memoryUserRepository.js';
import type { UserRecord, UserRepository } from '../src/auth/repositories.js';
import { readJson, sessionCookieFrom, startTestServer, type TestServer } from './helpers.js';

/**
 * Pump 4 subscription endpoint — `GET /api/v1/subscription`.
 *
 * Security matrix covered here (over real HTTP, through the real pipeline):
 * registration defaults, mass-assignment, anonymous 401, self-only reads
 * (IDOR), header/query/cookie/body tampering, method safety (no mutation
 * endpoint exists) and log hygiene. The role/userType/status matrices live
 * in `subscriptionMatrix.test.ts`.
 */

const PW = 'subscription-pw-test';

interface SeedOptions {
  role?: UserRecord['role'];
  userType?: UserRecord['userType'];
  subscription?: Subscription;
}

type Subscription = NonNullable<UserRecord['subscription']>;

async function seedUser(
  repo: UserRepository,
  email: string,
  options: SeedOptions = {},
): Promise<UserRecord> {
  const record: UserRecord = {
    id: `usr_${email.split('@')[0] ?? 'seed'}`,
    email,
    passwordHash: await hashPassword(PW, 1024),
    createdAt: '2026-09-27T00:00:00.000Z',
    role: options.role ?? 'MEMBER',
    userType: options.userType ?? null,
    ...(options.subscription === undefined
      ? {}
      : { subscription: options.subscription }),
  };
  const created = await repo.create(record);
  if (!created) {
    throw new Error(`Seed collision for ${email}`);
  }
  return record;
}

async function cookieFor(server: TestServer, email: string, pw = PW): Promise<string> {
  const res = await fetch(`${server.baseUrl}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: pw }),
  });
  if (res.status !== 200) {
    throw new Error(`Login failed with status ${res.status}.`);
  }
  return sessionCookieFrom(res);
}

async function register(server: TestServer, email: string, pw: string): Promise<string> {
  const res = await fetch(`${server.baseUrl}/api/v1/auth/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: pw }),
  });
  if (res.status !== 201) {
    throw new Error(`Registration failed with status ${res.status}.`);
  }
  return sessionCookieFrom(res);
}

function get(server: TestServer, cookie?: string, query = ''): Promise<Response> {
  return fetch(`${server.baseUrl}/api/v1/subscription${query}`, {
    ...(cookie === undefined ? {} : { headers: { cookie } }),
  });
}

/** Raw GET with a request body (fetch forbids it; the server must not care). */
function getWithBody(
  server: TestServer,
  cookie: string,
  body: string,
): Promise<{ status: number; body: unknown }> {
  const url = new URL(`${server.baseUrl}/api/v1/subscription`);
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      {
        hostname: url.hostname,
        port: url.port,
        path: url.pathname,
        method: 'GET',
        headers: {
          cookie,
          'content-type': 'application/json',
          'content-length': String(Buffer.byteLength(body)),
        },
      },
      (res) => {
        let raw = '';
        res.on('data', (chunk) => {
          raw += String(chunk);
        });
        res.on('end', () => {
          try {
            resolve({ status: res.statusCode ?? 0, body: JSON.parse(raw) as unknown });
          } catch {
            resolve({ status: res.statusCode ?? 0, body: raw });
          }
        });
      },
    );
    req.on('error', reject);
    req.end(body);
  });
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

describe('GET /api/v1/subscription — authentication', () => {
  test('anonymous requests are rejected with the exact 401 envelope', async () => {
    const server = await startTestServer();
    servers.push(server);
    const res = await get(server);
    expect(res.status).toBe(401);
    expect(await readJson(res)).toEqual({
      ok: false,
      error: { code: 'UNAUTHORIZED', message: 'Authentication required.' },
      meta: { requestId: expect.any(String) },
    });
  });

  test('a forged session cookie is anonymous, not another account', async () => {
    const server = await startTestServer();
    servers.push(server);
    const res = await get(server, 'drobon_session=forged-token-value');
    expect(res.status).toBe(401);
    const body = await readJson(res);
    expect(JSON.stringify(body)).not.toContain('PRO');
  });
});

describe('registration defaults and mass-assignment', () => {
  test('a newly registered account is FREE + ACTIVE with server-written timestamps', async () => {
    const server = await startTestServer();
    servers.push(server);
    const cookie = await register(server, 'fresh@example.test', 'fresh-pw-test-1');
    const res = await get(server, cookie);
    expect(res.status).toBe(200);
    const body = (await readJson(res)) as {
      data: {
        subscription: Subscription;
        entitlements: string[];
      };
    };
    expect(body.data.subscription.plan).toBe('FREE');
    expect(body.data.subscription.status).toBe('ACTIVE');
    expect(body.data.subscription.createdAt).toEqual(expect.any(String));
    expect(Number.isNaN(Date.parse(body.data.subscription.createdAt ?? ''))).toBe(false);
    expect(body.data.subscription.updatedAt).toEqual(expect.any(String));
    expect(body.data.entitlements).toEqual(['plan:view']);
    // The persisted record carries the same server-assigned state.
    const stored = await server.users.findByEmail('fresh@example.test');
    expect(stored?.subscription).toEqual(body.data.subscription);
  });

  test('plan/subscription keys in the register payload are rejected (422)', async () => {
    const server = await startTestServer();
    servers.push(server);
    for (const extra of [
      { plan: 'PRO' },
      { plan: 'FREE' },
      { subscription: { plan: 'PRO', status: 'ACTIVE', createdAt: null, updatedAt: null } },
      { entitlements: ['feature:pro'] },
    ]) {
      const res = await fetch(`${server.baseUrl}/api/v1/auth/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email: 'tamper@example.test', password: PW, ...extra }),
      });
      expect(res.status).toBe(422);
      const body = await readJson(res);
      expect(JSON.stringify(body)).toContain('Unexpected property');
    }
    // The account was never created — and a clean registration is still FREE.
    expect(await server.users.findByEmail('tamper@example.test')).toBeUndefined();
    const cookie = await register(server, 'tamper@example.test', PW);
    const sub = await get(server, cookie);
    const body = (await readJson(sub)) as { data: { subscription: Subscription; entitlements: string[] } };
    expect(body.data.subscription.plan).toBe('FREE');
  });

  test('userType cannot select a plan — a PENTESTER registration is still FREE', async () => {
    const server = await startTestServer();
    servers.push(server);
    const res = await fetch(`${server.baseUrl}/api/v1/auth/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'pentester@example.test', password: PW, userType: 'PENTESTER' }),
    });
    expect(res.status).toBe(201);
    const cookie = sessionCookieFrom(res);
    const sub = await get(server, cookie);
    const body = (await readJson(sub)) as { data: { subscription: Subscription; entitlements: string[] } };
    expect(body.data.subscription.plan).toBe('FREE');
    expect(body.data.entitlements).toEqual(['plan:view']);
  });
});

describe('server state is the only path to PRO', () => {
  test('a seeded PRO + ACTIVE account reads PRO with the PRO entitlement', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'pro@example.test', {
      subscription: {
        plan: 'PRO',
        status: 'ACTIVE',
        createdAt: '2026-09-01T00:00:00.000Z',
        updatedAt: '2026-09-02T00:00:00.000Z',
      },
    });
    const server = await startTestServer({ users });
    servers.push(server);
    const cookie = await cookieFor(server, 'pro@example.test');
    const res = await get(server, cookie);
    expect(res.status).toBe(200);
    const body = (await readJson(res)) as { data: { subscription: Subscription; entitlements: string[] } };
    expect(body.data.subscription).toEqual({
      plan: 'PRO',
      status: 'ACTIVE',
      createdAt: '2026-09-01T00:00:00.000Z',
      updatedAt: '2026-09-02T00:00:00.000Z',
    });
    expect(body.data.entitlements).toEqual(['plan:view', 'feature:pro']);
  });
});

describe('self-only reads (no IDOR)', () => {
  test('query parameters fail closed (422) — they cannot select another account or a plan (Pump 5)', async () => {
    const users = createMemoryUserRepository();
    const proRecord = await seedUser(users, 'pro-target@example.test', {
      subscription: { plan: 'PRO', status: 'ACTIVE', createdAt: null, updatedAt: null },
    });
    const server = await startTestServer({ users });
    servers.push(server);
    const attacker = await register(server, 'attacker@example.test', PW);

    // Every id-shaped parameter names the PRO account; every plan-shaped
    // parameter claims PRO. All are rejected BEFORE the account is consulted.
    for (const query of [
      `?userId=${proRecord.id}`,
      `?accountId=${proRecord.id}`,
      `?id=${proRecord.id}`,
      `?email=pro-target@example.test`,
      `?plan=PRO`,
      `?plan=PRO&userId=${proRecord.id}`,
      `?subscription={"plan":"PRO","status":"ACTIVE"}`,
    ]) {
      const res = await get(server, attacker, query);
      expect(res.status).toBe(422);
      const body = (await readJson(res)) as { error: { code: string } };
      expect(body.error.code).toBe('VALIDATION_ERROR');
    }
    // A clean request still returns the ATTACKER's own FREE state.
    const cleanRes = await get(server, attacker);
    expect(cleanRes.status).toBe(200);
    const cleanBody = (await readJson(cleanRes)) as { data: { subscription: Subscription } };
    expect(cleanBody.data.subscription.plan).toBe('FREE');
    expect(cleanBody.data.subscription.status).toBe('ACTIVE');
    // The PRO account's own cookie still reads its own PRO state.
    const proCookie = await cookieFor(server, 'pro-target@example.test');
    const own = (await (await get(server, proCookie)).json()) as {
      data: { subscription: Subscription };
    };
    expect(own.data.subscription.plan).toBe('PRO');
  });

  test('path manipulation finds no other route and leaks nothing', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'pro-target@example.test', {
      subscription: { plan: 'PRO', status: 'ACTIVE', createdAt: null, updatedAt: null },
    });
    const server = await startTestServer({ users });
    servers.push(server);
    const cookie = await register(server, 'wanderer@example.test', PW);
    for (const path of [
      '/api/v1/subscription/usr_pro-target',
      '/api/v1/subscription/pro-target@example.test',
      '/api/v1/subscription/PRO',
      '/api/v1/subscriptions',
      '/api/v1/users/subscription',
    ]) {
      const res = await fetch(`${server.baseUrl}${path}`, { headers: { cookie } });
      expect(res.status).toBe(404);
      const body = await readJson(res);
      expect(JSON.stringify(body)).not.toContain('PRO');
    }
  });
});

describe('client tampering cannot grant PRO', () => {
  test('request headers claiming PRO or another identity are ignored', async () => {
    const users = createMemoryUserRepository();
    const proRecord = await seedUser(users, 'pro-header@example.test', {
      subscription: { plan: 'PRO', status: 'ACTIVE', createdAt: null, updatedAt: null },
    });
    const server = await startTestServer({ users });
    servers.push(server);
    const cookie = await register(server, 'free@example.test', PW);
    for (const headers of [
      { 'x-plan': 'PRO' },
      { 'x-subscription-plan': 'PRO' },
      { 'x-user-id': proRecord.id },
      { 'x-account-id': proRecord.id },
      { 'x-role': 'ACCOUNT_OWNER', 'x-user-type': 'PENTESTER', 'x-plan': 'PRO' },
      { authorization: 'Bearer pro-header@example.test' },
    ]) {
      const res = await fetch(`${server.baseUrl}/api/v1/subscription`, {
        headers: { cookie, ...headers },
      });
      expect(res.status).toBe(200);
      const body = (await readJson(res)) as { data: { subscription: Subscription; entitlements: string[] } };
      expect(body.data.subscription.plan).toBe('FREE');
      expect(body.data.entitlements).toEqual(['plan:view']);
    }
  });

  test('extra cookies claiming a plan are ignored alongside the session', async () => {
    const server = await startTestServer();
    servers.push(server);
    const cookie = await register(server, 'cookie-tamper@example.test', PW);
    for (const cookieHeader of [
      `plan=PRO; ${cookie}`,
      `${cookie}; plan=PRO`,
      `subscription=PRO; drobon_extra=1; ${cookie}`,
    ]) {
      const res = await fetch(`${server.baseUrl}/api/v1/subscription`, {
        headers: { cookie: cookieHeader },
      });
      expect(res.status).toBe(200);
      const body = (await readJson(res)) as { data: { subscription: Subscription; entitlements: string[] } };
      expect(body.data.subscription.plan).toBe('FREE');
    }
  });

  test('a GET request body claiming PRO is never read', async () => {
    const server = await startTestServer();
    servers.push(server);
    const cookie = await register(server, 'body-tamper@example.test', PW);
    const result = await getWithBody(
      server,
      cookie,
      JSON.stringify({ plan: 'PRO', status: 'ACTIVE', userId: 'usr_somebody-else' }),
    );
    expect(result.status).toBe(200);
    const body = result.body as { data: { subscription: Subscription; entitlements: string[] } };
    expect(body.data.subscription.plan).toBe('FREE');
    expect(body.data.entitlements).toEqual(['plan:view']);
  });
});

describe('no mutation endpoint exists', () => {
  test('POST/PATCH/PUT/DELETE all answer 405 and change nothing', async () => {
    const server = await startTestServer();
    servers.push(server);
    const cookie = await register(server, 'immutable@example.test', PW);
    for (const method of ['POST', 'PATCH', 'PUT', 'DELETE']) {
      const res = await fetch(`${server.baseUrl}/api/v1/subscription`, {
        method,
        headers: { cookie, 'content-type': 'application/json' },
        ...(method === 'DELETE'
          ? {}
          : { body: JSON.stringify({ plan: 'PRO', status: 'ACTIVE' }) }),
      });
      expect(res.status).toBe(405);
      expect(res.headers.get('allow')).toBe('GET');
      const body = await readJson(res);
      expect(body).toEqual({
        ok: false,
        error: { code: 'METHOD_NOT_ALLOWED', message: 'Method not allowed. Allowed: GET.' },
        meta: { requestId: expect.any(String) },
      });
    }
    // Nothing changed: the subscription is still FREE + ACTIVE.
    const after = (await (await get(server, cookie)).json()) as {
      data: { subscription: Subscription };
    };
    expect(after.data.subscription.plan).toBe('FREE');
    expect(after.data.subscription.status).toBe('ACTIVE');
  });
});

describe('log hygiene', () => {
  test('subscription requests log no plan state, emails, passwords or tokens', async () => {
    const users = createMemoryUserRepository();
    await seedUser(users, 'pro-logs@example.test', {
      subscription: { plan: 'PRO', status: 'ACTIVE', createdAt: null, updatedAt: null },
    });
    const server = await startTestServer({ users, logLevel: 'info' });
    servers.push(server);
    await get(server); // anonymous 401
    const free = await register(server, 'free-logs@example.test', 'free-logs-pw-1');
    await get(server, free);
    const pro = await cookieFor(server, 'pro-logs@example.test');
    await get(server, pro);
    await fetch(`${server.baseUrl}/api/v1/subscription?plan=PRO`, { headers: { cookie: free } });

    const logs = server.logs.join('\n');
    expect(logs).not.toContain('pro-logs@example.test');
    expect(logs).not.toContain('free-logs@example.test');
    expect(logs).not.toContain('free-logs-pw-1');
    expect(logs).not.toContain(free);
    expect(logs).not.toContain(pro);
    // Plan/entitlement state is not logged either — the standard request
    // lines carry only method/path/status/duration.
    expect(logs).not.toContain('feature:pro');
    expect(logs).not.toContain('"plan"');
    expect(logs).not.toContain('plan:view');
  });
});
