import { afterAll, beforeAll, describe, expect, test } from 'vitest';
import { readJson, startTestServer, type TestServer } from './helpers.js';

describe('request IDs', () => {
  let server: TestServer;
  beforeAll(async () => {
    server = await startTestServer();
  });
  afterAll(async () => {
    await server.stop();
  });

  test('a valid client-supplied ID is echoed in header and body', async () => {
    const res = await fetch(`${server.baseUrl}/livez`, {
      headers: { 'x-request-id': 'client-supplied-test-id' },
    });
    expect(res.headers.get('x-request-id')).toBe('client-supplied-test-id');
    const body = (await readJson(res)) as { meta: { requestId: string } };
    expect(body.meta.requestId).toBe('client-supplied-test-id');
  });

  test('a missing ID is generated', async () => {
    const res = await fetch(`${server.baseUrl}/livez`);
    const header = res.headers.get('x-request-id');
    expect(header).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );
    const body = (await readJson(res)) as { meta: { requestId: string } };
    expect(body.meta.requestId).toBe(header);
  });

  test('an invalid ID is replaced, never echoed', async () => {
    const res = await fetch(`${server.baseUrl}/livez`, {
      headers: { 'x-request-id': 'bad id with spaces <>' },
    });
    const header = res.headers.get('x-request-id');
    expect(header).not.toBe('bad id with spaces <>');
    const body = (await readJson(res)) as { meta: { requestId: string } };
    expect(body.meta.requestId).toBe(header);
  });

  test('error responses also carry the request ID', async () => {
    const res = await fetch(`${server.baseUrl}/missing`, {
      headers: { 'x-request-id': 'error-path-test-id' },
    });
    expect(res.status).toBe(404);
    expect(res.headers.get('x-request-id')).toBe('error-path-test-id');
    const body = (await readJson(res)) as { meta: { requestId: string } };
    expect(body.meta.requestId).toBe('error-path-test-id');
  });
});
