import { writeFileSync } from 'node:fs';
import { afterAll, beforeAll, describe, expect, test } from 'vitest';
import { createJsonFileUserRepository } from '../src/auth/jsonFileUserRepository.js';
import { createLogger } from '../src/logger.js';
import { startServer } from '../src/server.js';
import {
  cleanupTempStoreDir,
  makeTempStoreDir,
  sessionCookieFrom,
  startTestServer,
  type TestServer,
} from './helpers.js';
import { login, me, register } from './authFixtures.js';

const PW = 'security-pw-test-1'; // fixture marker: test

describe('auth security controls', () => {
  describe('session cookie hardening', () => {
    let server: TestServer;
    beforeAll(async () => {
      server = await startTestServer({ authSessionTtlSeconds: 120 });
    });
    afterAll(async () => {
      await server.stop();
    });

    test('issue sets HttpOnly, SameSite=Strict, Path=/ and a bounded Max-Age', async () => {
      const { res } = await register(server, 'cookie@example.test', PW);
      const setCookie = res.headers
        .getSetCookie()
        .find((entry) => entry.startsWith('drobon_session='));
      expect(setCookie).toBeDefined();
      expect(setCookie).toContain('HttpOnly');
      expect(setCookie).toContain('SameSite=Strict');
      expect(setCookie).toContain('Path=/');
      expect(setCookie).toContain('Max-Age=120');
      expect(setCookie).not.toContain('Domain');
      // Non-production environments stay plain-HTTP compatible.
      expect(setCookie).not.toContain('Secure');
    });

    test('production config flips the Secure attribute on', async () => {
      const prod = await startTestServer({ cookieSecure: true });
      try {
        const { res } = await register(prod, 'secure-cookie@example.test', PW);
        const setCookie = res.headers
          .getSetCookie()
          .find((entry) => entry.startsWith('drobon_session='));
        expect(setCookie).toContain('Secure');
      } finally {
        await prod.stop();
      }
    });

    test('the token itself never appears in any response body', async () => {
      const { res, body } = await register(server, 'leak@example.test', PW);
      const token = sessionCookieFrom(res).slice('drobon_session='.length);
      expect(JSON.stringify(body)).not.toContain(token);
      const meResult = await me(server, `drobon_session=${token}`);
      expect(JSON.stringify(meResult.body)).not.toContain(token);
      expect(JSON.stringify(meResult.body)).not.toContain('scrypt$');
    });
  });

  describe('CSRF origin guard', () => {
    let server: TestServer;
    beforeAll(async () => {
      server = await startTestServer({
        corsAllowedOrigins: ['https://app.example.test'],
      });
    });
    afterAll(async () => {
      await server.stop();
    });

    test('unsafe requests from a foreign origin are refused with 403', async () => {
      for (const path of ['/api/v1/auth/register', '/api/v1/auth/login', '/api/v1/echo']) {
        const res = await fetch(`${server.baseUrl}${path}`, {
          method: 'POST',
          headers: { 'content-type': 'application/json', origin: 'https://evil.example.test' },
          body: JSON.stringify({ email: 'csrf@example.test', password: PW, message: 'hi' }),
        });
        expect(res.status).toBe(403);
        const body = (await res.json()) as { error: { code: string } };
        expect(body.error.code).toBe('FORBIDDEN');
      }
      // Nothing was created by the refused registration.
      const probe = await login(server, 'csrf@example.test', PW);
      expect(probe.res.status).toBe(401);
    });

    test('allowed origins and same-host origins pass the guard', async () => {
      const allowed = await fetch(`${server.baseUrl}/api/v1/echo`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          origin: 'https://app.example.test',
        },
        body: JSON.stringify({ message: 'allowed-origin-test' }),
      });
      expect(allowed.status).toBe(200);

      const sameHost = await fetch(`${server.baseUrl}/api/v1/echo`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          origin: server.baseUrl, // Origin equals this server's own host
        },
        body: JSON.stringify({ message: 'same-host-test' }),
      });
      expect(sameHost.status).toBe(200);
    });

    test('requests without Origin (non-browser clients) pass the guard', async () => {
      const res = await fetch(`${server.baseUrl}/api/v1/echo`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ message: 'no-origin-test' }),
      });
      expect(res.status).toBe(200);
    });

    test('safe methods and preflights are unaffected', async () => {
      const get = await fetch(`${server.baseUrl}/livez`, {
        headers: { origin: 'https://evil.example.test' },
      });
      expect(get.status).toBe(200);
      const preflight = await fetch(`${server.baseUrl}/api/v1/echo`, {
        method: 'OPTIONS',
        headers: {
          origin: 'https://evil.example.test',
          'access-control-request-method': 'POST',
        },
      });
      expect(preflight.status).toBe(204);
      expect(preflight.headers.get('access-control-allow-origin')).toBeNull();
    });

    test('a registered session from an allowed origin reads back through CORS', async () => {
      const reg = await register(server, 'cors-session@example.test', PW, {
        headers: { origin: 'https://app.example.test' },
      });
      expect(reg.res.status).toBe(201);
      expect(reg.res.headers.get('access-control-allow-origin')).toBe(
        'https://app.example.test',
      );
      expect(reg.res.headers.get('access-control-allow-credentials')).toBe('true');
      const cookie = sessionCookieFrom(reg.res);
      const read = await fetch(`${server.baseUrl}/api/v1/me`, {
        headers: { origin: 'https://app.example.test', cookie },
      });
      expect(read.status).toBe(200);
      expect(read.headers.get('access-control-allow-origin')).toBe(
        'https://app.example.test',
      );
      // A hostile origin can never read that response — no CORS headers.
      const hostile = await fetch(`${server.baseUrl}/api/v1/me`, {
        headers: { origin: 'https://evil.example.test', cookie },
      });
      expect(hostile.status).toBe(200); // request reaches the API...
      expect(hostile.headers.get('access-control-allow-origin')).toBeNull(); // ...but the browser blocks the read
      expect(hostile.headers.get('access-control-allow-credentials')).toBeNull();
    });
  });

  describe('information disclosure and logging hygiene', () => {
    let server: TestServer;
    const marker = 'LogMarker-pw-should-never-appear-test-42';
    beforeAll(async () => {
      // Capture logs at info level so auth events are recorded.
      server = await startTestServer({ logLevel: 'info', authStorePath: ':memory:' });
      await register(server, 'logs@example.test', marker);
      await login(server, 'logs@example.test', 'wrong-pw-never-matches');
      await login(server, 'logs@example.test', marker);
      await logoutAndMe(server);
    });
    afterAll(async () => {
      await server.stop();
    });

    test('logs never contain passwords, hashes, emails or tokens', () => {
      const joined = server.logs.join('\n');
      expect(joined).not.toContain(marker); // plaintext password
      expect(joined).not.toContain('scrypt$'); // password hash
      expect(joined).not.toContain('logs@example.test'); // account email
      expect(joined).not.toContain('drobon_session='); // cookie material
      // But the events themselves were logged with correlation IDs.
      expect(joined).toContain('Account registered');
      expect(joined).toContain('Login failed');
      expect(joined).toContain('Login succeeded');
    });

    test('failed-login responses carry no account details beyond the contract', async () => {
      const { res, body } = await login(server, 'logs@example.test', 'wrong-pw-never-matches');
      expect(res.status).toBe(401);
      const text = JSON.stringify(body);
      expect(text).not.toContain('scrypt$');
      expect(text).not.toContain('usr_');
      expect(text).not.toContain('logs@example.test');
    });

    test('auth responses keep the full security-header set', async () => {
      const res = await fetch(`${server.baseUrl}/api/v1/me`);
      expect(res.status).toBe(401);
      expect(res.headers.get('x-content-type-options')).toBe('nosniff');
      expect(res.headers.get('x-frame-options')).toBe('DENY');
      expect(res.headers.get('referrer-policy')).toBe('no-referrer');
      // API responses ship the locked-down API CSP (no script sources).
      expect(res.headers.get('content-security-policy')).toContain("default-src 'none'");
      expect(res.headers.get('content-security-policy')).toContain("frame-ancestors 'none'");
    });
  });

  describe('durable store wiring (default createApp path)', () => {
    test('no injected repository means createApp builds the JSON file store', async () => {
      const dir = makeTempStoreDir('drobon-store-wiring');
      const storePath = `${dir}/users.json`;
      try {
        // Deliberately minimal deps: NO `users`, NO `sessions` — exercising
        // exactly what `index.ts` runs in production.
        const started = await startServer({
          config: {
            env: 'test',
            host: '127.0.0.1',
            port: 0,
            logLevel: 'error',
            corsAllowedOrigins: [],
            rateLimitMaxRequests: 1000,
            rateLimitWindowMs: 60_000,
            bodyMaxBytes: 1_048_576,
            version: '0.0.0-test',
            authStorePath: storePath,
            authScryptCost: 1024,
            authSessionTtlSeconds: 3600,
            authRateLimitMaxRequests: 1000,
            authRateLimitWindowMs: 60_000,
            cookieSecure: false,
            authzProbeRoutes: true,
            usageStorePath: `${dir}/usage.json`,
            usageConsumeRoutes: true,
            projectStorePath: `${dir}/projects.json`,
            scanStorePath: `${dir}/scans.json`,
            sourceStorePath: ':memory:',
          },
          logger: createLogger({ level: 'error', out: () => undefined }),
        });
        try {
          const res = await fetch(`${started.url}/api/v1/auth/register`, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ email: 'durable@example.test', password: PW }),
          });
          expect(res.status).toBe(201);
        } finally {
          await started.stop();
        }
        // A brand-new repository (a restarted process) reads the account
        // back from disk — this is what makes authentication durable.
        const restarted = createJsonFileUserRepository(storePath);
        const record = await restarted.findByEmail('durable@example.test');
        expect(record).toBeDefined();
        expect(record?.passwordHash.startsWith('scrypt$')).toBe(true);
      } finally {
        cleanupTempStoreDir(dir);
      }
    });

    test('a corrupt store refuses to start (fail fast, no silent reset)', () => {
      const dir = makeTempStoreDir('drobon-store-corrupt');
      try {
        writeFileSync(`${dir}/users.json`, '{not json', 'utf8');
        expect(() => createJsonFileUserRepository(`${dir}/users.json`)).toThrow(/corrupt/);
      } finally {
        cleanupTempStoreDir(dir);
      }
    });
  });
});

async function logoutAndMe(server: TestServer): Promise<void> {
  const reg = await register(server, 'temp-logout@example.test', PW);
  const cookie = sessionCookieFrom(reg.res);
  await fetch(`${server.baseUrl}/api/v1/auth/logout`, {
    method: 'POST',
    headers: { cookie },
  });
}
