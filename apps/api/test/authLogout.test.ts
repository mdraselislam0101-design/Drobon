import { afterAll, beforeAll, describe, expect, test } from 'vitest';
import { sessionCookieFrom, startTestServer, type TestServer } from './helpers.js';
import { login, logout, me, register } from './authFixtures.js';

const PW = 'logout-pw-test-1'; // fixture marker: test

describe('POST /api/v1/auth/logout', () => {
  let server: TestServer;
  let cookie: string;
  beforeAll(async () => {
    server = await startTestServer();
    const registered = await register(server, 'out@example.test', PW);
    cookie = sessionCookieFrom(registered.res);
  });
  afterAll(async () => {
    await server.stop();
  });

  test('revokes the session server-side and clears the cookie', async () => {
    expect((await me(server, cookie)).res.status).toBe(200);
    const { res, body } = await logout(server, cookie);
    expect(res.status).toBe(200);
    expect(body.loggedOut).toBe(true);
    const cleared = res.headers
      .getSetCookie()
      .find((entry) => entry.startsWith('drobon_session='));
    expect(cleared).toContain('Max-Age=0');
    // Server-side revocation is immediate: the same token is dead.
    expect((await me(server, cookie)).res.status).toBe(401);
  });

  test('repeated logout is safe (idempotent 200)', async () => {
    const first = await logout(server, cookie);
    const second = await logout(server, cookie);
    expect(first.res.status).toBe(200);
    expect(second.res.status).toBe(200);
    expect(second.body.loggedOut).toBe(false);
  });

  test('logout without a session still succeeds', async () => {
    const { res, body } = await logout(server);
    expect(res.status).toBe(200);
    expect(body.loggedOut).toBe(false);
  });

  test('logout with a garbage cookie succeeds without side effects', async () => {
    const { res, body } = await logout(server, 'drobon_session=garbage-cookie-value');
    expect(res.status).toBe(200);
    expect(body.loggedOut).toBe(false);
    // Someone else's garbage must not touch an unrelated live session.
    const fresh = await register(server, 'keep@example.test', PW);
    const keepCookie = sessionCookieFrom(fresh.res);
    await logout(server, 'drobon_session=garbage-cookie-value');
    expect((await me(server, keepCookie)).res.status).toBe(200);
    // And logging out does not require a body or content type.
    const bare = await fetch(`${server.baseUrl}/api/v1/auth/logout`, { method: 'POST' });
    expect(bare.status).toBe(200);
  });

  test('a login after logout issues a working replacement session', async () => {
    await logout(server, cookie);
    const again = await login(server, 'out@example.test', PW);
    expect(again.res.status).toBe(200);
    const newCookie = sessionCookieFrom(again.res);
    expect((await me(server, newCookie)).res.status).toBe(200);
    expect((await me(server, cookie)).res.status).toBe(401);
  });
});
