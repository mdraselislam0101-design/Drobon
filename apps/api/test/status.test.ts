import { afterAll, beforeAll, describe, expect, test } from 'vitest';
import { readJson, startTestServer, type TestServer } from './helpers.js';

describe('GET /api/v1/status', () => {
  let server: TestServer;
  beforeAll(async () => {
    server = await startTestServer();
  });
  afterAll(async () => {
    await server.stop();
  });

  test('returns service identity matching the shared StatusResponse contract', async () => {
    const res = await fetch(`${server.baseUrl}/api/v1/status`);
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('application/json');
    const body = (await readJson(res)) as {
      ok: boolean;
      data: { service: string; version: string; environment: string; time: string };
      meta: { requestId: string };
    };
    expect(body.ok).toBe(true);
    expect(body.data.service).toBe('drobon-aegis-api');
    expect(body.data.version).toBe('0.0.0-test');
    expect(body.data.environment).toBe('test');
    expect(Number.isNaN(Date.parse(body.data.time))).toBe(false);
    expect(typeof body.meta.requestId).toBe('string');
  });
});
