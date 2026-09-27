import { afterAll, beforeAll, describe, expect, test } from 'vitest';
import { isAuthUser } from '@drobon/shared';
import { readJson, sessionCookieFrom, startTestServer, type TestServer } from './helpers.js';
import { login, me, register } from './authFixtures.js';

const PW = 'register-pw-test-1'; // fixture marker: test

describe('POST /api/v1/auth/register', () => {
  let server: TestServer;
  beforeAll(async () => {
    server = await startTestServer();
  });
  afterAll(async () => {
    await server.stop();
  });

  test('creates an account, establishes a session and returns only public fields', async () => {
    const { res, body, user } = await register(server, 'Alice@Example.test', PW);
    expect(res.status).toBe(201);
    expect(isAuthUser(user)).toBe(true);
    expect(user?.email).toBe('alice@example.test'); // normalized
    expect(user?.id).toMatch(/^usr_/);
    // Exact public shape: nothing but the three allowed fields.
    expect(user).toEqual({
      id: expect.any(String),
      email: 'alice@example.test',
      createdAt: expect.any(String),
    });
    expect(JSON.stringify(body)).not.toContain('scrypt$');
    expect(JSON.stringify(body)).not.toContain('password');
    // Auto-login: the issued cookie immediately authenticates /me.
    const cookie = sessionCookieFrom(res);
    const meResult = await me(server, cookie);
    expect(meResult.res.status).toBe(200);
  });

  test('rejects invalid email format with field-level validation', async () => {
    const { res, body } = await register(server, 'not-an-email', PW);
    expect(res.status).toBe(422);
    const payload = body as { error: { code: string; details?: unknown } };
    expect(payload.error.code).toBe('VALIDATION_ERROR');
    expect(payload.error.details).toEqual([
      { path: 'email', message: 'Enter a valid email address.' },
    ]);
  });

  test('rejects weak passwords and never echoes them', async () => {
    const { res, body } = await register(server, 'weak@example.test', 'ab');
    expect(res.status).toBe(422);
    const payload = body as {
      error: { code: string; details?: Array<{ path: string; message: string }> };
    };
    expect(payload.error.code).toBe('VALIDATION_ERROR');
    expect(payload.error.details?.[0]?.path).toBe('password');
    expect(payload.error.details?.[0]?.message).toContain('at least 8');
    // The submitted value must not appear anywhere in the response.
    expect(JSON.stringify(body)).not.toContain('"ab"');
  });

  test('rejects missing fields and non-object bodies', async () => {
    const missingPw = await fetch(`${server.baseUrl}/api/v1/auth/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'x@example.test' }),
    });
    expect(missingPw.status).toBe(422);
    const missingEmail = await fetch(`${server.baseUrl}/api/v1/auth/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ password: 'pw-test-long-enough' }),
    });
    expect(missingEmail.status).toBe(422);
    const malformed = await fetch(`${server.baseUrl}/api/v1/auth/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{oops',
    });
    expect(malformed.status).toBe(400);
    expect(((await readJson(malformed)) as { error: { code: string } }).error.code).toBe(
      'INVALID_JSON',
    );
    const noContentType = await fetch(`${server.baseUrl}/api/v1/auth/register`, {
      method: 'POST',
      body: JSON.stringify({ email: 'x@example.test', password: 'pw-test-long-enough' }),
    });
    expect(noContentType.status).toBe(415);
  });

  test('rejects unknown properties (mass assignment)', async () => {
    const res = await fetch(`${server.baseUrl}/api/v1/auth/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        email: 'mass@example.test',
        password: 'pw-test-long-enough',
        role: 'admin',
        isAdmin: true,
      }),
    });
    expect(res.status).toBe(422);
    const body = (await readJson(res)) as { error: { details?: Array<{ path: string }> } };
    const paths = (body.error.details ?? []).map((issue) => issue.path);
    expect(paths).toContain('role');
    expect(paths).toContain('isAdmin');
    // No account may have been created by the rejected request.
    const probe = await login(server, 'mass@example.test', 'pw-test-long-enough');
    expect(probe.res.status).toBe(401);
  });

  test('duplicate registration returns 409 and leaves the account intact', async () => {
    const first = await register(server, 'dup@example.test', 'original-pw-test');
    expect(first.res.status).toBe(201);
    const second = await register(server, 'dup@example.test', 'attacker-pw-test');
    expect(second.res.status).toBe(409);
    const body = second.body as { error: { code: string; message: string } };
    expect(body.error.code).toBe('CONFLICT');
    expect(JSON.stringify(body)).not.toContain('scrypt$');
    // The original password still works — the loser's attempt changed nothing.
    const asOriginal = await login(server, 'dup@example.test', 'original-pw-test');
    expect(asOriginal.res.status).toBe(200);
    const asAttacker = await login(server, 'dup@example.test', 'attacker-pw-test');
    expect(asAttacker.res.status).toBe(401);
  });

  test('duplicate registration costs the same request shape as a fresh one', async () => {
    await register(server, 'timing1@example.test', 'timing-pw-test-1');
    const { res, body } = await register(server, 'timing1@example.test', 'timing-pw-test-2');
    expect(res.status).toBe(409);
    // Both responses use the standard envelope with a correlation ID.
    expect((body as { ok: boolean }).ok).toBe(false);
    expect((body as { meta: { requestId: string } }).meta.requestId.length).toBeGreaterThan(0);
  });

  test('correlation IDs flow through registration (echoed and logged)', async () => {
    const { res, body } = await register(server, 'corr@example.test', PW, {
      headers: { 'x-request-id': 'req-register-test-1' },
    });
    expect(res.status).toBe(201);
    expect((body as { meta: { requestId: string } }).meta.requestId).toBe(
      'req-register-test-1',
    );
    expect(res.headers.get('x-request-id')).toBe('req-register-test-1');
  });
});
