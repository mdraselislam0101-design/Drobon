import { afterAll, beforeAll, describe, expect, test } from 'vitest';
import { startTestServer, type TestServer } from './helpers.js';

describe('CORS', () => {
  let server: TestServer;
  beforeAll(async () => {
    server = await startTestServer({
      corsAllowedOrigins: ['https://app.example.test'],
    });
  });
  afterAll(async () => {
    await server.stop();
  });

  test('requests without Origin get no CORS headers', async () => {
    const res = await fetch(`${server.baseUrl}/livez`);
    expect(res.status).toBe(200);
    expect(res.headers.get('access-control-allow-origin')).toBeNull();
  });

  test('allowed origins are reflected exactly with Vary: Origin', async () => {
    const res = await fetch(`${server.baseUrl}/livez`, {
      headers: { origin: 'https://app.example.test' },
    });
    expect(res.status).toBe(200);
    expect(res.headers.get('access-control-allow-origin')).toBe('https://app.example.test');
    expect(res.headers.get('vary')).toContain('Origin');
  });

  test('disallowed origins get no ACAO header (browser blocks the read)', async () => {
    const res = await fetch(`${server.baseUrl}/livez`, {
      headers: { origin: 'https://evil.example.test' },
    });
    expect(res.status).toBe(200);
    expect(res.headers.get('access-control-allow-origin')).toBeNull();
  });

  test('subdomain lookalikes are not allowed', async () => {
    const res = await fetch(`${server.baseUrl}/livez`, {
      headers: { origin: 'https://app.example.test.evil.test' },
    });
    expect(res.headers.get('access-control-allow-origin')).toBeNull();
  });

  test('allowed preflights are answered with method/header allowlists', async () => {
    const res = await fetch(`${server.baseUrl}/api/v1/echo`, {
      method: 'OPTIONS',
      headers: {
        origin: 'https://app.example.test',
        'access-control-request-method': 'POST',
      },
    });
    expect(res.status).toBe(204);
    expect(res.headers.get('access-control-allow-origin')).toBe('https://app.example.test');
    expect(res.headers.get('access-control-allow-credentials')).toBe('true');
    expect(res.headers.get('access-control-allow-methods')).toContain('POST');
    expect(res.headers.get('access-control-allow-headers')).toContain('X-Request-Id');
  });

  test('disallowed preflights fail closed with a bare 204', async () => {
    const res = await fetch(`${server.baseUrl}/api/v1/echo`, {
      method: 'OPTIONS',
      headers: {
        origin: 'https://evil.example.test',
        'access-control-request-method': 'POST',
      },
    });
    expect(res.status).toBe(204);
    expect(res.headers.get('access-control-allow-origin')).toBeNull();
  });

  // Pump 1 asserted credentials were never enabled. Pump 2 introduced the
  // httpOnly session cookie, which REQUIRES credentialed CORS for split-host
  // deployments. The invariant was strengthened, not removed: credentials
  // are allowed only with an exact reflected origin — never with a missing
  // ACAO, never with `*`.
  test('credentials are enabled only alongside an exact reflected origin', async () => {
    const allowed = await fetch(`${server.baseUrl}/livez`, {
      headers: { origin: 'https://app.example.test' },
    });
    expect(allowed.headers.get('access-control-allow-credentials')).toBe('true');
    expect(allowed.headers.get('access-control-allow-origin')).toBe(
      'https://app.example.test',
    );

    const denied = await fetch(`${server.baseUrl}/livez`, {
      headers: { origin: 'https://evil.example.test' },
    });
    expect(denied.headers.get('access-control-allow-credentials')).toBeNull();
    expect(denied.headers.get('access-control-allow-origin')).toBeNull();

    const noOrigin = await fetch(`${server.baseUrl}/livez`);
    expect(noOrigin.headers.get('access-control-allow-credentials')).toBeNull();

    // Wildcards must never appear in either header.
    for (const res of [allowed, denied, noOrigin]) {
      expect(res.headers.get('access-control-allow-origin')).not.toBe('*');
    }
  });
});
