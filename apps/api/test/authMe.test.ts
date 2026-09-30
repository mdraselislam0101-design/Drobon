import { afterAll, beforeAll, describe, expect, test } from 'vitest';
import type { UserRepository } from '../src/auth/repositories.js';
import { sessionCookieFrom, startTestServer, type TestServer } from './helpers.js';
import { me, register, sessionFor } from './authFixtures.js';

const PW = 'me-pw-test-1'; // fixture marker: test

describe('GET /api/v1/me', () => {
  let server: TestServer;
  let cookie: string;
  beforeAll(async () => {
    server = await startTestServer();
    cookie = await sessionFor(server, 'me@example.test', PW);
  });
  afterAll(async () => {
    await server.stop();
  });

  test('returns exactly the public account information for a session', async () => {
    const { res, body } = await me(server, cookie);
    expect(res.status).toBe(200);
    const payload = body as { ok: true; data: { user: Record<string, unknown> } };
    // Exact shape: password, hash, token, internal fields — none of it.
    // role/userType are the Pump 3 public authorization fields (server-
    // assigned, non-sensitive).
    expect(payload.data.user).toEqual({
      id: expect.any(String),
      email: 'me@example.test',
      createdAt: expect.any(String),
      role: 'MEMBER',
      userType: null,
    });
    expect(res.headers.get('x-request-id')).toBeTruthy();
  });

  test('missing credentials get a generic 401', async () => {
    const { res, body } = await me(server);
    expect(res.status).toBe(401);
    const payload = body as { error: { code: string; message: string } };
    expect(payload.error.code).toBe('UNAUTHORIZED');
    expect(payload.error.message).toBe('Authentication required.');
  });

  test('garbage cookies are rejected and actively cleared', async () => {
    const res = await fetch(`${server.baseUrl}/api/v1/me`, {
      headers: { cookie: 'drobon_session=not-a-real-token' },
    });
    expect(res.status).toBe(401);
    const cleared = res.headers
      .getSetCookie()
      .find((entry) => entry.startsWith('drobon_session='));
    expect(cleared).toContain('Max-Age=0');
  });

  test('Bearer-style Authorization headers do not authenticate', async () => {
    // The API has exactly one credential mechanism: the session cookie.
    const res = await fetch(`${server.baseUrl}/api/v1/me`, {
      headers: { authorization: 'Bearer forged-token-test' },
    });
    expect(res.status).toBe(401);
  });

  test('the boundary holds after the account disappears', async () => {
    const orphan = await startTestServer();
    try {
      const reg = await register(orphan, 'soon-gone@example.test', PW);
      const session = sessionCookieFrom(reg.res);
      expect((await me(orphan, session)).res.status).toBe(200);
      // Simulate the account being removed while the session still exists:
      // swap in a repository that no longer knows the user.
      const gone: UserRepository = {
        create: async () => false,
        findByEmail: async () => undefined,
        findById: async () => undefined,
        activatePro: async () => 'NOT_FOUND',
        setUserType: async () => undefined,
        adminPage: async () => ({ accounts: [], total: 0 }),
        adminCounts: async () => ({ total: 0, byPlan: { FREE: 0, PRO: 0 }, bySubscriptionStatus: { ACTIVE: 0, INACTIVE: 0, CANCELLED: 0, EXPIRED: 0 }, byRole: { MEMBER: 0, ADMIN: 0, ACCOUNT_OWNER: 0 }, byUserType: { DEVELOPER: 0, STUDENT: 0, SECURITY_PROFESSIONAL: 0, PENTESTER: 0, NONE: 0 } }),
      };
      const replaced = await startTestServer({ users: gone });
      try {
        // Same cookie against a server whose store lost the user → 401.
        const after = await me(replaced, session);
        expect(after.res.status).toBe(401);
      } finally {
        await replaced.stop();
      }
    } finally {
      await orphan.stop();
    }
  });

  test('method and path tricks do not bypass the boundary', async () => {
    const post = await fetch(`${server.baseUrl}/api/v1/me`, {
      method: 'POST',
      headers: { cookie },
    });
    expect(post.status).toBe(405);
    const put = await fetch(`${server.baseUrl}/api/v1/me`, {
      method: 'PUT',
      headers: { cookie },
    });
    expect(put.status).toBe(405);
    const wrongCase = await fetch(`${server.baseUrl}/API/v1/me`, {
      headers: { cookie },
    });
    expect(wrongCase.status).toBe(404);
  });

  test('other public routes keep working without credentials', async () => {
    const status = await fetch(`${server.baseUrl}/api/v1/status`);
    expect(status.status).toBe(200);
    const livez = await fetch(`${server.baseUrl}/livez`);
    expect(livez.status).toBe(200);
  });
});
