import { describe, expect, test, vi } from 'vitest';
import {
  isAuthResponse,
  isAuthUser,
  isCurrentUserResponse,
  isLogoutResponse,
} from '@drobon/shared';
import { ApiClientError, createApiClient } from '../src/api/client.js';
import { TEST_USER, unauthorizedError } from './appFixtures.js';

type FetchImpl = typeof fetch;

function jsonResponse(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function envelope(data: unknown): unknown {
  return { ok: true, data, meta: { requestId: 'req-auth-client-1' } };
}

function errorEnvelope(code: string, message: string, details?: unknown): unknown {
  return {
    ok: false,
    error: details === undefined ? { code, message } : { code, message, details },
    meta: { requestId: 'req-auth-client-err' },
  };
}

describe('auth API client', () => {
  test('postRegister posts the credentials with cookie credentials mode', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () => jsonResponse(envelope({ user: TEST_USER })));
    const client = createApiClient({ baseUrl: '', fetchImpl });
    const result = await client.postRegister('a@example.test', 'pw-test-1');
    expect(isAuthResponse(result)).toBe(true);
    const [url, init] = (fetchImpl as ReturnType<typeof vi.fn>).mock.calls[0] as [
      string,
      RequestInit,
    ];
    expect(url).toBe('/api/v1/auth/register');
    expect(init.method).toBe('POST');
    expect(init.credentials).toBe('include'); // session cookie flow
    expect(JSON.parse(String(init.body))).toEqual({
      email: 'a@example.test',
      password: 'pw-test-1',
    });
  });

  test('postLogin and postLogout hit the right endpoints', async () => {
    const fetchImpl: FetchImpl = vi.fn(async (url: unknown) => {
      if (String(url).includes('/login')) {
        return jsonResponse(envelope({ user: TEST_USER }));
      }
      return jsonResponse(envelope({ loggedOut: true }));
    });
    const client = createApiClient({ baseUrl: '', fetchImpl });
    await client.postLogin('a@example.test', 'pw-test-1');
    await client.postLogout();
    const urls = (fetchImpl as ReturnType<typeof vi.fn>).mock.calls.map(
      ([url]) => url as string,
    );
    expect(urls).toEqual(['/api/v1/auth/login', '/api/v1/auth/logout']);
  });

  test('getMe returns the current user envelope', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () => jsonResponse(envelope({ user: TEST_USER })));
    const client = createApiClient({ baseUrl: '', fetchImpl });
    const result = await client.getMe();
    expect(isCurrentUserResponse(result)).toBe(true);
    const [url, init] = (fetchImpl as ReturnType<typeof vi.fn>).mock.calls[0] as [
      string,
      RequestInit,
    ];
    expect(url).toBe('/api/v1/me');
    expect(init.method).toBeUndefined(); // GET
    expect(init.credentials).toBe('include');
  });

  test('401s surface as http ApiClientError with the shared code', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () =>
      jsonResponse(errorEnvelope('UNAUTHORIZED', 'Authentication required.'), 401),
    );
    const client = createApiClient({ baseUrl: '', fetchImpl });
    await expect(client.getMe()).rejects.toMatchObject({
      name: 'ApiClientError',
      kind: 'http',
      status: 401,
      code: 'UNAUTHORIZED',
    });
  });

  test('422 details (field issues) are carried on the error', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () =>
      jsonResponse(
        errorEnvelope('VALIDATION_ERROR', 'Request validation failed.', [
          { path: 'password', message: 'Password must be at least 8 characters.' },
        ]),
        422,
      ),
    );
    const client = createApiClient({ baseUrl: '', fetchImpl });
    try {
      await client.postRegister('a@example.test', 'pw');
      expect.unreachable('expected a validation error');
    } catch (error: unknown) {
      expect(error).toBeInstanceOf(ApiClientError);
      expect((error as ApiClientError).details).toEqual([
        { path: 'password', message: 'Password must be at least 8 characters.' },
      ]);
    }
  });

  test('auth payloads that fail the shared guards are rejected', async () => {
    // Wrong: user carries a password field (disclosure attempt).
    const leaky = { user: { ...TEST_USER, password: 'leaked-test-value' } };
    const fetchImpl: FetchImpl = vi.fn(async () => jsonResponse(envelope(leaky)));
    const client = createApiClient({ baseUrl: '', fetchImpl });
    await expect(client.getMe()).rejects.toMatchObject({ kind: 'invalid-response' });
    expect(isAuthUser(leaky.user)).toBe(false);
  });

  test('non-object user payloads are rejected too', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () => jsonResponse(envelope({ user: null })));
    const client = createApiClient({ baseUrl: '', fetchImpl });
    await expect(client.postLogin('a@example.test', 'pw-test-1')).rejects.toMatchObject({
      kind: 'invalid-response',
    });
    const logoutImpl: FetchImpl = vi.fn(async () => jsonResponse(envelope({ loggedOut: 'yes' })));
    const logoutClient = createApiClient({ baseUrl: '', fetchImpl: logoutImpl });
    await expect(logoutClient.postLogout()).rejects.toMatchObject({
      kind: 'invalid-response',
    });
    expect(isLogoutResponse({ loggedOut: 'yes' })).toBe(false);
  });

  test('network failure keeps its user-safe message', async () => {
    const failing: FetchImpl = vi.fn(async () => {
      throw new TypeError('Failed to fetch');
    });
    const client = createApiClient({ baseUrl: '', fetchImpl: failing });
    await expect(client.postLogin('a@example.test', 'pw-test-1')).rejects.toMatchObject({
      kind: 'network',
      message: 'Could not reach the server. Check your connection and try again.',
    });
  });

  test('the 401 fixture matches the server contract', () => {
    const error = unauthorizedError();
    expect(error.status).toBe(401);
    expect(error.code).toBe('UNAUTHORIZED');
  });
});
