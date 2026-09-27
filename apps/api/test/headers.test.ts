import { afterAll, beforeAll, describe, expect, test } from 'vitest';
import { SECURITY_HEADERS } from '../src/middleware/securityHeaders.js';
import { startTestServer, type TestServer } from './helpers.js';

describe('security headers', () => {
  let server: TestServer;
  beforeAll(async () => {
    server = await startTestServer();
  });
  afterAll(async () => {
    await server.stop();
  });

  test('every baseline header is present on success responses', async () => {
    const res = await fetch(`${server.baseUrl}/livez`);
    for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
      expect(res.headers.get(name), `header ${name}`).toBe(value);
    }
  });

  test('baseline headers are also present on error responses', async () => {
    const res = await fetch(`${server.baseUrl}/does-not-exist`);
    expect(res.status).toBe(404);
    for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
      expect(res.headers.get(name), `header ${name}`).toBe(value);
    }
  });

  test('responses carry a JSON content type with nosniff protection', async () => {
    const res = await fetch(`${server.baseUrl}/livez`);
    expect(res.headers.get('content-type')).toContain('application/json');
    expect(res.headers.get('x-content-type-options')).toBe('nosniff');
  });

  test('no server fingerprint header is exposed', async () => {
    const res = await fetch(`${server.baseUrl}/livez`);
    expect(res.headers.get('x-powered-by')).toBeNull();
    expect(res.headers.get('server')).toBeNull();
  });
});
