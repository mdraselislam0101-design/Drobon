import { afterAll, beforeAll, describe, expect, test } from 'vitest';
import { readJson, startTestServer, type TestServer } from './helpers.js';

describe('POST /api/v1/echo', () => {
  let server: TestServer;
  beforeAll(async () => {
    server = await startTestServer({ bodyMaxBytes: 1024 });
  });
  afterAll(async () => {
    await server.stop();
  });

  const post = (body: unknown, init?: RequestInit): Promise<Response> =>
    fetch(`${server.baseUrl}/api/v1/echo`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: typeof body === 'string' ? body : JSON.stringify(body),
      ...init,
    });

  test('echoes a valid message with code-point length', async () => {
    const res = await post({ message: '  hello 👋 ' });
    expect(res.status).toBe(200);
    const body = (await readJson(res)) as {
      ok: boolean;
      data: { message: string; length: number; receivedAt: string };
    };
    expect(body.data.message).toBe('hello 👋');
    expect(body.data.length).toBe(7);
    expect(Number.isNaN(Date.parse(body.data.receivedAt))).toBe(false);
  });

  test('rejects a blank message with 422 and field issues', async () => {
    const res = await post({ message: '   ' });
    expect(res.status).toBe(422);
    const body = (await readJson(res)) as {
      error: { code: string; details: Array<{ path: string }> };
    };
    expect(body.error.code).toBe('VALIDATION_ERROR');
    expect(body.error.details[0]?.path).toBe('message');
  });

  test('rejects unknown properties with 422 (strict objects)', async () => {
    const res = await post({ message: 'hi', admin: true });
    expect(res.status).toBe(422);
  });

  test('rejects malformed JSON with 400 INVALID_JSON', async () => {
    const res = await post('{oops');
    expect(res.status).toBe(400);
    const body = (await readJson(res)) as { error: { code: string } };
    expect(body.error.code).toBe('INVALID_JSON');
  });

  test('rejects an empty body with 400', async () => {
    const res = await post('');
    expect(res.status).toBe(400);
  });

  test('rejects a wrong content type with 415', async () => {
    const res = await fetch(`${server.baseUrl}/api/v1/echo`, {
      method: 'POST',
      headers: { 'content-type': 'text/plain' },
      body: 'hello',
    });
    expect(res.status).toBe(415);
    const body = (await readJson(res)) as { error: { code: string } };
    expect(body.error.code).toBe('UNSUPPORTED_MEDIA_TYPE');
  });

  test('rejects an oversized body with 413', async () => {
    const res = await post({ message: 'x'.repeat(2048) });
    expect(res.status).toBe(413);
    const body = (await readJson(res)) as { error: { code: string } };
    expect(body.error.code).toBe('PAYLOAD_TOO_LARGE');
  });

  test('rejects GET with 405', async () => {
    const res = await fetch(`${server.baseUrl}/api/v1/echo`);
    expect(res.status).toBe(405);
    expect(res.headers.get('allow')).toBe('POST');
  });
});
