import { afterAll, beforeAll, describe, expect, test } from 'vitest';
import { createSessionStore } from '../src/auth/sessions.js';
import { sessionCookieFrom, startTestServer, type TestServer } from './helpers.js';
import { login, me, register, withoutRequestId } from './authFixtures.js';

const PW = 'login-pw-test-1'; // fixture marker: test

describe('POST /api/v1/auth/login', () => {
  let server: TestServer;
  beforeAll(async () => {
    server = await startTestServer();
    await register(server, 'known@example.test', PW);
  });
  afterAll(async () => {
    await server.stop();
  });

  test('valid credentials return the user and a fresh session', async () => {
    const { res, body } = await login(server, 'known@example.test', PW);
    expect(res.status).toBe(200);
    const payload = body as { ok: true; data: { user: { email: string } } };
    expect(payload.data.user.email).toBe('known@example.test');
    const cookie = sessionCookieFrom(res);
    const meResult = await me(server, cookie);
    expect(meResult.res.status).toBe(200);
  });

  test('login is case/whitespace-insensitive on the email', async () => {
    const { res } = await login(server, '  KNOWN@example.test ', PW);
    expect(res.status).toBe(200);
  });

  test('wrong password and unknown email are indistinguishable', async () => {
    const wrongPassword = await login(server, 'known@example.test', 'wrong-password-test');
    const unknownEmail = await login(server, 'ghost@example.test', 'wrong-password-test');
    expect(wrongPassword.res.status).toBe(401);
    expect(unknownEmail.res.status).toBe(401);
    expect(withoutRequestId(wrongPassword.body)).toEqual(withoutRequestId(unknownEmail.body));
    const payload = wrongPassword.body as { error: { code: string; message: string } };
    expect(payload.error.code).toBe('UNAUTHORIZED');
    expect(payload.error.message).toBe('Invalid email or password.');
    // Generic — names both factors without revealing which one failed.
    for (const revealing of ['unknown', 'not found', 'incorrect', 'no account', 'wrong password']) {
      expect(payload.error.message.toLowerCase()).not.toContain(revealing);
    }
  });

  test('malformed email on login is a format error, not a credential answer', async () => {
    const { res, body } = await login(server, 'not-an-email', PW);
    expect(res.status).toBe(422);
    expect((body as { error: { code: string } }).error.code).toBe('VALIDATION_ERROR');
  });

  test('each login issues a distinct session', async () => {
    const a = await login(server, 'known@example.test', PW);
    const b = await login(server, 'known@example.test', PW);
    const tokenA = sessionCookieFrom(a.res);
    const tokenB = sessionCookieFrom(b.res);
    expect(tokenA).not.toBe(tokenB);
    expect((await me(server, tokenA)).res.status).toBe(200);
    expect((await me(server, tokenB)).res.status).toBe(200);
  });

  test('expired sessions stop authenticating immediately', async () => {
    let nowMs = 5_000_000;
    const shortSessions = createSessionStore({ ttlSeconds: 60, now: () => nowMs });
    const expiring = await startTestServer({ sessions: shortSessions });
    try {
      await register(expiring, 'victim@example.test', PW);
      const { res } = await login(expiring, 'victim@example.test', PW);
      const cookie = sessionCookieFrom(res);
      expect((await me(expiring, cookie)).res.status).toBe(200);
      nowMs += 61_000; // cross the absolute TTL
      const after = await me(expiring, cookie);
      expect(after.res.status).toBe(401);
      expect((after.body as { error: { code: string } }).error.code).toBe('UNAUTHORIZED');
    } finally {
      await expiring.stop();
    }
  });

  test('credential endpoints share a dedicated rate-limit budget', async () => {
    const limited = await startTestServer({ authRateLimitMaxRequests: 3 });
    try {
      const statuses: number[] = [];
      for (let attempt = 0; attempt < 4; attempt += 1) {
        const { res } = await login(limited, 'known@example.test', 'brute-force-test');
        statuses.push(res.status);
      }
      expect(statuses).toEqual([401, 401, 401, 429]);
      const final = await login(limited, 'known@example.test', 'brute-force-test');
      expect(final.res.status).toBe(429);
      expect(final.res.headers.get('retry-after')).toBeTruthy();
      const body = final.body as { error: { code: string } };
      expect(body.error.code).toBe('RATE_LIMITED');
      // The global budget is untouched: unrelated endpoints still answer.
      const live = await fetch(`${limited.baseUrl}/livez`);
      expect(live.status).toBe(200);
      // And the limiter is resettable between test cases.
      limited.resetRateLimit();
      const afterReset = await login(limited, 'known@example.test', 'brute-force-test');
      expect(afterReset.res.status).toBe(401);
    } finally {
      await limited.stop();
    }
  });
});
