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

  test('credentials mode is never enabled', async () => {
    const res = await fetch(`${server.baseUrl}/livez`, {
      headers: { origin: 'https://app.example.test' },
    });
    expect(res.headers.get('access-control-allow-credentials')).toBeNull();
  });
});
