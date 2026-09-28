import { afterEach, describe, expect, test } from 'vitest';
import { hashPassword } from '../src/auth/passwords.js';
import { createMemoryUserRepository } from '../src/auth/memoryUserRepository.js';
import type { UserRecord, UserRepository } from '../src/auth/repositories.js';
import { readJson, sessionCookieFrom, startTestServer, type TestServer } from './helpers.js';

/**
 * Pump 5 usage endpoint — `GET /api/v1/usage` (always registered) and the
 * dev/test-gated `POST /api/v1/usage/consume` scan-consumption probe.
 *
 * Covered here (over real HTTP, fixed clock for deterministic periods):
 * authentication, self-only reads, the authorization matrix (roles and
 * user types never exempt; only active PRO does), lapsed-PRO fallback,
 * consumption + exhaustion + denial immutability, exact validation,
 * client tampering, production gating of the probe, device-cookie
 * issuance attributes, multi-cookie responses and log hygiene.
 */

const PW = 'usage-pw-test';

/** Fixed mid-month moment — deterministic periods and Retry-After values. */
const NOW_MS = Date.UTC(2026, 8, 15, 12, 0, 0);
/** Whole seconds from NOW_MS until 2026-10-01T00:00:00Z. */
const RETRY_AFTER = 1_339_200;

type Subscription = NonNullable<UserRecord['subscription']>;

const FREE_ACTIVE: Subscription = {
  plan: 'FREE',
  status: 'ACTIVE',
  createdAt: '2026-09-01T00:00:00.000Z',
  updatedAt: '2026-09-01T00:00:00.000Z',
};

const PRO_ACTIVE: Subscription = { ...FREE_ACTIVE, plan: 'PRO' };

const SEPTEMBER = {
  period: '2026-09',
  startUtc: '2026-09-01T00:00:00.000Z',
  endUtc: '2026-10-01T00:00:00.000Z',
};

async function seedUser(
  repo: UserRepository,
  email: string,
  fields: Partial<Pick<UserRecord, 'role' | 'userType' | 'subscription'>> = {},
): Promise<UserRecord> {
  const record: UserRecord = {
    id: `usr_${email.split('@')[0] ?? 'seed'}`,
    email,
    passwordHash: await hashPassword(PW, 1024),
    createdAt: '2026-09-01T00:00:00.000Z',
    role: fields.role ?? 'MEMBER',
    userType: fields.userType ?? null,
    ...(fields.subscription === undefined ? {} : { subscription: fields.subscription }),
  };
  if (!(await repo.create(record))) {
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

/** The device cookie pair (name=value) issued to an authenticated caller. */
async function deviceCookieFor(server: TestServer, session: string): Promise<string> {
  const res = await fetch(`${server.baseUrl}/api/v1/me`, { headers: { cookie: session } });
  const raw = res.headers
    .getSetCookie()
    .find((entry) => entry.startsWith('drobon_device='));
  if (raw === undefined) {
    throw new Error('Expected a drobon_device Set-Cookie header.');
  }
  return raw.split(';')[0] ?? '';
}

async function getUsage(
  server: TestServer,
  cookie: string,
  query = '',
): Promise<{ res: Response; body: unknown }> {
  const res = await fetch(`${server.baseUrl}/api/v1/usage${query}`, {
    headers: { cookie },
  });
  return { res, body: await readJson(res) };
}

async function consume(
  server: TestServer,
  cookie: string,
  body?: string,
): Promise<{ res: Response; body: unknown }> {
  const init: RequestInit =
    body === undefined
      ? { method: 'POST', headers: { cookie } }
      : { method: 'POST', headers: { cookie, 'content-type': 'application/json' }, body };
  const res = await fetch(`${server.baseUrl}/api/v1/usage/consume`, init);
  return { res, body: await readJson(res) };
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

async function usageServer(overrides: Parameters<typeof startTestServer>[0] = {}) {
  const users = createMemoryUserRepository();
  const server = await startTestServer({ users, usageNow: () => NOW_MS, ...overrides });
  servers.push(server);
  return { server, users };
}

describe('GET /api/v1/usage — authentication and self-only access', () => {
  test('anonymous requests are rejected with the exact 401 envelope', async () => {
    const { server } = await usageServer();
    const res = await fetch(`${server.baseUrl}/api/v1/usage`);
    expect(res.status).toBe(401);
    expect(await readJson(res)).toEqual({
      ok: false,
      error: { code: 'UNAUTHORIZED', message: 'Authentication required.' },
      meta: { requestId: expect.any(String) },
    });
  });

  test('a fresh FREE account sees the exact 3-scan September view', async () => {
    const { server, users } = await usageServer();
    const session = await cookieFor(server, 'free@example.test').catch(async () => {
      await seedUser(users, 'free@example.test');
      return cookieFor(server, 'free@example.test');
    });
    // (seedUser above is registered lazily; simpler path first)
    const device = await deviceCookieFor(server, session);
    const { res, body } = await getUsage(server, `${session}; ${device}`);
    expect(res.status).toBe(200);
    expect(body).toEqual({
      ok: true,
      data: {
        plan: 'FREE',
        period: SEPTEMBER,
        used: 0,
        limit: 3,
        remaining: 3,
        quotaStatus: 'OK',
      },
      meta: { requestId: expect.any(String) },
    });
  });

  test('no account-id parameter exists — query tampering returns own usage', async () => {
    const { server, users } = await usageServer();
    await seedUser(users, 'other@example.test', {
      subscription: { ...FREE_ACTIVE },
    });
    await seedUser(users, 'self@example.test');
    const other = await users.findByEmail('other@example.test');
    const session = await cookieFor(server, 'self@example.test');
    const device = await deviceCookieFor(server, session);
    for (const query of [
      `?userId=${other?.id ?? ''}`,
      `?accountId=${other?.id ?? ''}`,
      `?email=other@example.test`,
      `?used=0&remaining=99&plan=PRO`,
      `?period=2027-01`,
    ]) {
      const { res, body } = await getUsage(server, `${session}; ${device}`, query);
      expect(res.status).toBe(200);
      expect((body as { data: { used: number } }).data.used).toBe(0);
      expect((body as { data: { plan: string } }).data.plan).toBe('FREE');
      expect((body as { data: { period: { period: string } } }).data.period.period).toBe('2026-09');
    }
  });
});

describe('usage authorization matrix (roles/user types never exempt)', () => {
  test('every role on the FREE plan gets the 3-scan allowance', async () => {
    const { server, users } = await usageServer();
    for (const role of ['MEMBER', 'ADMIN', 'ACCOUNT_OWNER'] as const) {
      await seedUser(users, `${role.toLowerCase()}@example.test`, { role, subscription: FREE_ACTIVE });
    }
    for (const role of ['MEMBER', 'ADMIN', 'ACCOUNT_OWNER'] as const) {
      const session = await cookieFor(server, `${role.toLowerCase()}@example.test`);
      const device = await deviceCookieFor(server, session);
      const { body } = await getUsage(server, `${session}; ${device}`);
      expect((body as { data: { limit: number | null } }).data.limit).toBe(3);
      expect((body as { data: { quotaStatus: string } }).data.quotaStatus).toBe('OK');
    }
  });

  test('every user type on the FREE plan gets the 3-scan allowance', async () => {
    const { server, users } = await usageServer();
    for (const userType of ['DEVELOPER', 'STUDENT', 'SECURITY_PROFESSIONAL', 'PENTESTER'] as const) {
      await seedUser(users, `${userType.toLowerCase()}@example.test`, { userType, subscription: FREE_ACTIVE });
    }
    for (const userType of ['DEVELOPER', 'STUDENT', 'SECURITY_PROFESSIONAL', 'PENTESTER'] as const) {
      const session = await cookieFor(server, `${userType.toLowerCase()}@example.test`);
      const device = await deviceCookieFor(server, session);
      const { body } = await getUsage(server, `${session}; ${device}`);
      expect((body as { data: { limit: number | null } }).data.limit).toBe(3);
    }
  });

  test('only ACTIVE PRO is exempt — and a lapsed PRO falls back to FREE', async () => {
    const { server, users } = await usageServer();
    await seedUser(users, 'pro-active@example.test', { subscription: PRO_ACTIVE });
    await seedUser(users, 'pro-expired@example.test', {
      subscription: { ...PRO_ACTIVE, status: 'EXPIRED' },
    });
    await seedUser(users, 'pro-cancelled@example.test', {
      subscription: { ...PRO_ACTIVE, status: 'CANCELLED' },
    });

    const activeSession = await cookieFor(server, 'pro-active@example.test');
    const activeDevice = await deviceCookieFor(server, activeSession);
    const { body: active } = await getUsage(server, `${activeSession}; ${activeDevice}`);
    expect((active as { data: { quotaStatus: string; limit: number | null; remaining: number | null; plan: string } }).data).toMatchObject({
      plan: 'PRO',
      quotaStatus: 'EXEMPT',
      limit: null,
      remaining: null,
    });

    for (const email of ['pro-expired@example.test', 'pro-cancelled@example.test']) {
      const session = await cookieFor(server, email);
      const device = await deviceCookieFor(server, session);
      const { body } = await getUsage(server, `${session}; ${device}`);
      // Lapsed PRO: honest plan label, but the FREE allowance applies.
      expect((body as { data: { quotaStatus: string; limit: number | null } }).data.quotaStatus).toBe('OK');
      expect((body as { data: { limit: number | null } }).data.limit).toBe(3);
    }
  });

  test('cross-account usage reads are structurally impossible', async () => {
    const { server, users } = await usageServer();
    await seedUser(users, 'a@example.test');
    await seedUser(users, 'b@example.test');
    const sessionA = await cookieFor(server, 'a@example.test');
    const sessionB = await cookieFor(server, 'b@example.test');
    const deviceA = await deviceCookieFor(server, sessionA);
    const deviceB = await deviceCookieFor(server, sessionB);
    // Consume on B so the two views differ.
    await consume(server, `${sessionB}; ${deviceB}`, '{}');
    // A's read (with any parameter noise) is still A's own view.
    const { body } = await getUsage(server, `${sessionA}; ${deviceA}`, '?userId=usr_b');
    expect((body as { data: { used: number } }).data.used).toBe(0);
    // B's view shows its own consumption.
    const bView = await getUsage(server, `${sessionB}; ${deviceB}`);
    expect((bView.body as { data: { used: number } }).data.used).toBe(1);
  });
});

describe('POST /api/v1/usage/consume — the scan-consumption probe', () => {
  test('consumes exactly one scan per call and returns the updated view', async () => {
    const { server } = await usageServer();
    const res = await fetch(`${server.baseUrl}/api/v1/auth/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'consume@example.test', password: PW }),
    });
    expect(res.status).toBe(201);
    const session = sessionCookieFrom(res);
    const device = await deviceCookieFor(server, session);
    for (const [index, expectedRemaining] of [3, 2, 1].entries()) {
      const { res: consumeRes, body } = await consume(server, `${session}; ${device}`, '{}');
      expect(consumeRes.status).toBe(200);
      expect((body as { data: { used: number; remaining: number } }).data.used).toBe(index + 1);
      expect((body as { data: { used: number; remaining: number } }).data.remaining).toBe(
        expectedRemaining - 1 === 2 && index === 0 ? 2 : expectedRemaining - 1,
      );
    }
  });

  test('no request body at all is accepted (nothing to validate)', async () => {
    const { server } = await usageServer();
    const session = await cookieFor(server, await registerOn(server));
    const device = await deviceCookieFor(server, session);
    const { res, body } = await consume(server, `${session}; ${device}`);
    expect(res.status).toBe(200);
    expect((body as { data: { used: number } }).data.used).toBe(1);
  });

  test('the 4th consumption is denied with the exact QUOTA_EXCEEDED contract', async () => {
    const { server } = await usageServer();
    const session = await cookieFor(server, await registerOn(server));
    const device = await deviceCookieFor(server, session);
    for (let index = 0; index < 3; index += 1) {
      const { res } = await consume(server, `${session}; ${device}`, '{}');
      expect(res.status).toBe(200);
    }
    const denied = await consume(server, `${session}; ${device}`, '{}');
    expect(denied.res.status).toBe(429);
    expect(denied.res.headers.get('retry-after')).toBe(String(RETRY_AFTER));
    expect(denied.body).toEqual({
      ok: false,
      error: {
        code: 'QUOTA_EXCEEDED',
        message:
          'Monthly free scan limit reached. Your allowance resets at the start of the next UTC month.',
      },
      meta: { requestId: expect.any(String) },
    });
    // The denial did not increment anything: still 3 used, 0 remaining.
    const view = await getUsage(server, `${session}; ${device}`);
    expect((view.body as { data: { used: number; remaining: number; quotaStatus: string } }).data).toMatchObject(
      { used: 3, remaining: 0, quotaStatus: 'EXHAUSTED' },
    );
    // And a 5th attempt is denied identically (no drift).
    const again = await consume(server, `${session}; ${device}`, '{}');
    expect(again.res.status).toBe(429);
  });

  test('client-supplied fields in the body are rejected (exact validation)', async () => {
    const { server } = await usageServer();
    const session = await cookieFor(server, await registerOn(server));
    const device = await deviceCookieFor(server, session);
    for (const body of [
      JSON.stringify({ plan: 'PRO' }),
      JSON.stringify({ remaining: 99 }),
      JSON.stringify({ used: 0 }),
      JSON.stringify({ period: '2027-01' }),
      JSON.stringify({ deviceId: 'whatever' }),
      JSON.stringify({ quota: 100 }),
    ]) {
      const { res, body: parsed } = await consume(server, `${session}; ${device}`, body);
      expect(res.status).toBe(422);
      expect(JSON.stringify(parsed)).toContain('Unexpected property');
    }
    // Nothing was consumed by the rejected attempts.
    const view = await getUsage(server, `${session}; ${device}`);
    expect((view.body as { data: { used: number } }).data.used).toBe(0);
  });

  test('anonymous consumption is rejected with 401', async () => {
    const { server } = await usageServer();
    const res = await fetch(`${server.baseUrl}/api/v1/usage/consume`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{}',
    });
    expect(res.status).toBe(401);
  });

  test('manual usage mutation methods do not exist (405 + Allow: GET)', async () => {
    const { server } = await usageServer();
    const session = await cookieFor(server, await registerOn(server));
    const device = await deviceCookieFor(server, session);
    for (const method of ['POST', 'PATCH', 'PUT', 'DELETE']) {
      const init: RequestInit =
        method === 'DELETE'
          ? { method, headers: { cookie: `${session}; ${device}` } }
          : {
              method,
              headers: { cookie: `${session}; ${device}`, 'content-type': 'application/json' },
              body: JSON.stringify({ used: 0 }),
            };
      const res = await fetch(`${server.baseUrl}/api/v1/usage`, init);
      expect(res.status).toBe(405);
      expect(res.headers.get('allow')).toBe('GET');
    }
  });
});

describe('production gating of the consumption probe', () => {
  test('the probe 404s outside development/test, GET /usage stays live', async () => {
    const { server } = await usageServer({ usageConsumeRoutes: false });
    const session = await cookieFor(server, await registerOn(server));
    const device = await deviceCookieFor(server, session);
    const probe = await consume(server, `${session}; ${device}`, '{}');
    expect(probe.res.status).toBe(404);
    // The real user-facing endpoint keeps working.
    const view = await getUsage(server, `${session}; ${device}`);
    expect(view.res.status).toBe(200);
    // Anonymous access to /usage is still 401, not 404.
    const anon = await fetch(`${server.baseUrl}/api/v1/usage`);
    expect(anon.status).toBe(401);
  });
});

describe('device cookie issuance', () => {
  test('an authenticated request without a device cookie gets a hardened one', async () => {
    const { server } = await usageServer();
    const session = await cookieFor(server, await registerOn(server));
    const res = await fetch(`${server.baseUrl}/api/v1/usage`, { headers: { cookie: session } });
    const raw = res.headers.getSetCookie().find((entry) => entry.startsWith('drobon_device='));
    expect(raw).toBeDefined();
    expect(raw).toContain('HttpOnly');
    expect(raw).toContain('SameSite=Strict');
    expect(raw).toContain('Path=/');
    expect(raw).toContain('Max-Age=34560000');
    expect(raw).not.toContain('Secure'); // dev/test: no Secure attribute
    // Opaque: exactly the 43-char base64url shape, nothing else encoded.
    const value = (raw ?? '').split(';')[0]?.split('=')[1] ?? '';
    expect(value).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(value).not.toContain('@');
    // The issued cookie is immediately usable and stable across requests.
    const reuse = await fetch(`${server.baseUrl}/api/v1/usage`, {
      headers: { cookie: `${session}; drobon_device=${value}` },
    });
    expect(reuse.headers.getSetCookie().some((entry) => entry.startsWith('drobon_device='))).toBe(false);
  });

  test('production adds the Secure attribute to the device cookie', async () => {
    const { server } = await usageServer({ cookieSecure: true });
    const session = await cookieFor(server, await registerOn(server));
    const res = await fetch(`${server.baseUrl}/api/v1/usage`, { headers: { cookie: session } });
    const raw = res.headers.getSetCookie().find((entry) => entry.startsWith('drobon_device='));
    expect(raw).toContain('Secure');
    expect(raw).toContain('HttpOnly');
    expect(raw).toContain('SameSite=Strict');
  });

  test('a response can carry a device cookie AND a session cookie together', async () => {
    const { server } = await usageServer();
    const session = await cookieFor(server, await registerOn(server));
    // Logout is authenticated (session middleware resolved ctx.user) and
    // has no device cookie yet → the response must carry BOTH the fresh
    // device cookie and the session-clearing cookie.
    const res = await fetch(`${server.baseUrl}/api/v1/auth/logout`, {
      method: 'POST',
      headers: { cookie: session },
    });
    const cookies = res.headers.getSetCookie();
    expect(cookies.some((entry) => entry.startsWith('drobon_device='))).toBe(true);
    expect(
      cookies.some(
        (entry) =>
          entry.startsWith('drobon_session=;') && entry.includes('Max-Age=0'),
      ),
    ).toBe(true);
  });

  test('anonymous requests are not issued device cookies', async () => {
    const { server } = await usageServer();
    const res = await fetch(`${server.baseUrl}/api/v1/usage`);
    expect(res.status).toBe(401);
    expect(res.headers.getSetCookie().some((entry) => entry.startsWith('drobon_device='))).toBe(false);
  });
});

describe('tampering and log hygiene', () => {
  test('headers/cookies claiming PRO or fake usage never change the verdict', async () => {
    const { server } = await usageServer();
    const session = await cookieFor(server, await registerOn(server));
    const device = await deviceCookieFor(server, session);
    for (const headers of [
      { 'x-plan': 'PRO' },
      { 'x-remaining': '99' },
      { 'x-used': '0' },
      { 'x-device-id': 'someone-else' },
      { plan: 'PRO' },
      { 'x-plan': 'PRO', 'x-quota': 'unlimited' },
    ]) {
      const res = await fetch(`${server.baseUrl}/api/v1/usage`, {
        headers: { cookie: `${session}; ${device}; plan=PRO; used=0`, ...headers },
      });
      expect(res.status).toBe(200);
      const body = (await readJson(res)) as { data: { plan: string; used: number; limit: number | null } };
      expect(body.data.plan).toBe('FREE');
      expect(body.data.used).toBe(0);
      expect(body.data.limit).toBe(3);
    }
  });

  test('no device hash or account material appears in responses or logs', async () => {
    const { server } = await usageServer({ logLevel: 'info' });
    const session = await cookieFor(server, await registerOn(server));
    const device = await deviceCookieFor(server, session);
    const deviceValue = device.split('=')[1] ?? '';
    await getUsage(server, `${session}; ${device}`);
    await consume(server, `${session}; ${device}`, '{}');
    const denied = await consume(server, `${session}; ${device}`, '{}');
    void denied;
    const logs = server.logs.join('\n');
    // The raw device token and any hash of it never appear.
    expect(logs).not.toContain(deviceValue);
    expect(logs).not.toContain('drobon_device');
    expect(logs).not.toContain('deviceHash');
    expect(logs).not.toContain('consume@example.test');
    expect(logs).not.toContain(PW);
    expect(logs).not.toContain(session.split('=')[1] ?? '');
    // Usage bodies expose counts only — no device identifier field.
    const view = await getUsage(server, `${session}; ${device}`);
    expect(JSON.stringify(view.body)).not.toContain('device');
    expect(JSON.stringify(view.body)).not.toContain(deviceValue);
  });
});

/** Register a fresh account and return its email. */
async function registerOn(server: TestServer): Promise<string> {
  const email = `consume-${Math.random().toString(36).slice(2, 10)}@example.test`;
  const res = await fetch(`${server.baseUrl}/api/v1/auth/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: PW }),
  });
  if (res.status !== 201) {
    throw new Error(`Registration failed with status ${res.status}.`);
  }
  return email;
}
