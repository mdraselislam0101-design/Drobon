import { afterAll, beforeAll, describe, expect, test } from 'vitest';
import { readJson, startTestServer, type TestServer } from './helpers.js';

describe('health routes', () => {
  let server: TestServer;
  beforeAll(async () => {
    server = await startTestServer({ version: '9.9.9-test' });
  });
  afterAll(async () => {
    await server.stop();
  });

  test('GET /livez reports liveness with the shared envelope', async () => {
    const res = await fetch(`${server.baseUrl}/livez`);
    expect(res.status).toBe(200);
    expect(await readJson(res)).toEqual({
      ok: true,
      data: { status: 'ok', service: 'drobon-aegis-api', version: '9.9.9-test' },
      meta: { requestId: expect.any(String) },
    });
  });

  test('GET /readyz reports readiness with checks', async () => {
    const res = await fetch(`${server.baseUrl}/readyz`);
    expect(res.status).toBe(200);
    expect(await readJson(res)).toEqual({
      ok: true,
      data: {
        status: 'ready',
        service: 'drobon-aegis-api',
        version: '9.9.9-test',
        checks: { configuration: 'ok' },
      },
      meta: { requestId: expect.any(String) },
    });
  });

  test('POST /livez is rejected with 405 and an Allow header', async () => {
    const res = await fetch(`${server.baseUrl}/livez`, { method: 'POST' });
    expect(res.status).toBe(405);
    expect(res.headers.get('allow')).toBe('GET');
    const body = (await readJson(res)) as { ok: boolean; error: { code: string } };
    expect(body.ok).toBe(false);
    expect(body.error.code).toBe('METHOD_NOT_ALLOWED');
  });

  test('unknown paths return 404 with the error envelope', async () => {
    const res = await fetch(`${server.baseUrl}/nope`);
    expect(res.status).toBe(404);
    const body = (await readJson(res)) as { ok: boolean; error: { code: string } };
    expect(body.error.code).toBe('NOT_FOUND');
  });

  test('trailing slashes are normalized', async () => {
    const res = await fetch(`${server.baseUrl}/livez/`);
    expect(res.status).toBe(200);
  });
});
