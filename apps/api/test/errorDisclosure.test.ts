import { request as httpRequest } from 'node:http';
import { afterAll, beforeAll, describe, expect, test } from 'vitest';
import { internal } from '../src/errors.js';
import type { Route } from '../src/http.js';
import { sendSuccess } from '../src/respond.js';
import { startTestServer, type TestServer } from './helpers.js';

const SECRET_MARKER = 'shx-internal-disclosure-marker-9f8e7d6c5b';

describe('unsafe error disclosure', () => {
  let server: TestServer;
  beforeAll(async () => {
    const extraRoutes: Route[] = [
      {
        method: 'GET',
        path: '/test/boom-apperror',
        handler: async (): Promise<void> => {
          throw internal(`query failed: conn=${SECRET_MARKER}`);
        },
      },
      {
        method: 'GET',
        path: '/test/boom-unknown',
        handler: async (): Promise<void> => {
          throw new Error(`unexpected: ${SECRET_MARKER}`);
        },
      },
      {
        method: 'GET',
        path: '/test/ok-after-boom',
        handler: async (_req, res, ctx): Promise<void> => {
          sendSuccess(res, ctx, { fine: true });
        },
      },
    ];
    server = await startTestServer({ extraRoutes });
  });
  afterAll(async () => {
    await server.stop();
  });

  test('AppError 500s never leak the internal message', async () => {
    const res = await fetch(`${server.baseUrl}/test/boom-apperror`);
    expect(res.status).toBe(500);
    const text = await res.text();
    expect(text).not.toContain(SECRET_MARKER);
    const body = JSON.parse(text) as { error: { code: string; message: string } };
    expect(body.error.code).toBe('INTERNAL_ERROR');
    expect(body.error.message).toBe('Internal Server Error.');
  });

  test('unknown throws never leak message or stack', async () => {
    const res = await fetch(`${server.baseUrl}/test/boom-unknown`);
    expect(res.status).toBe(500);
    const text = await res.text();
    expect(text).not.toContain(SECRET_MARKER);
    expect(text).not.toContain('at ');
    expect(text).not.toContain('Error:');
  });

  test('the server keeps serving after a 500', async () => {
    await fetch(`${server.baseUrl}/test/boom-unknown`);
    const res = await fetch(`${server.baseUrl}/test/ok-after-boom`);
    expect(res.status).toBe(200);
  });

  test('the server survives a client aborting mid-request', async () => {
    await new Promise<void>((resolve) => {
      const req = httpRequest(
        `${server.baseUrl}/api/v1/echo`,
        { method: 'POST', headers: { 'content-type': 'application/json' } },
        () => {},
      );
      req.on('error', () => {
        resolve();
      });
      req.write('{"message": "partial');
      req.destroy();
      setTimeout(resolve, 200);
    });
    const res = await fetch(`${server.baseUrl}/livez`);
    expect(res.status).toBe(200);
  });

  test('500s retain a safe log correlation ID without disclosing the exception or caller-supplied ID', async () => {
    server.logs.length = 0;
    const response = await fetch(`${server.baseUrl}/test/boom-unknown`, {
      headers: { 'x-request-id': 'disclosure-log-test' },
    });
    const logId = response.headers.get('x-log-id');
    expect(logId).toMatch(/^[0-9a-f-]{36}$/);
    expect(response.headers.get('x-request-id')).toBe('disclosure-log-test');
    const joined = server.logs.join('\n');
    expect(joined).toContain(logId);
    expect(joined).toContain('Request failed');
    expect(joined).toContain('[REDACTED]');
    expect(joined).not.toContain('disclosure-log-test');
    expect(joined).not.toContain(SECRET_MARKER);
  });
});
