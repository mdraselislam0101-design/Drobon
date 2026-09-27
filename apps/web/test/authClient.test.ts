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

describe('authorization API client (Pump 3)', () => {
  test('getCapability hits the level endpoint with cookie credentials', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () =>
      jsonResponse(envelope({ capability: 'admin' })),
    );
    const client = createApiClient({ baseUrl: '', fetchImpl });
    const result = await client.getCapability('admin');
    expect(result).toEqual({ capability: 'admin' });
    const [url, init] = (fetchImpl as ReturnType<typeof vi.fn>).mock.calls[0] as [
      string,
      RequestInit,
    ];
    expect(url).toBe('/api/v1/authz/capabilities/admin');
    expect(init.method ?? 'GET').toBe('GET');
    expect(init.credentials).toBe('include');
  });

  test('403 capability denials surface as an http error with FORBIDDEN', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () =>
      jsonResponse(
        errorEnvelope('FORBIDDEN', 'You do not have access to this resource.'),
        403,
      ),
    );
    const client = createApiClient({ baseUrl: '', fetchImpl });
    await expect(client.getCapability('owner')).rejects.toMatchObject({
      kind: 'http',
      status: 403,
      code: 'FORBIDDEN',
    });
  });

  test('capability payloads failing the shared guard are rejected', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () =>
      jsonResponse(envelope({ capability: 'root' })),
    );
    const client = createApiClient({ baseUrl: '', fetchImpl });
    await expect(client.getCapability('member')).rejects.toMatchObject({
      kind: 'invalid-response',
    });
  });

  test('getUserById encodes the id and validates the user payload', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () => jsonResponse(envelope({ user: TEST_USER })));
    const client = createApiClient({ baseUrl: '', fetchImpl });
    const result = await client.getUserById('usr_x/../y');
    expect(isCurrentUserResponse(result)).toBe(true);
    const [url] = (fetchImpl as ReturnType<typeof vi.fn>).mock.calls[0] as [string];
    expect(url).toBe('/api/v1/users?id=usr_x%2F..%2Fy');
  });

  test('getUserById maps 403 (IDOR denial) onto the shared error contract', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () =>
      jsonResponse(
        errorEnvelope('FORBIDDEN', 'You do not have access to this resource.'),
        403,
      ),
    );
    const client = createApiClient({ baseUrl: '', fetchImpl });
    await expect(client.getUserById('usr_other')).rejects.toMatchObject({
      status: 403,
      code: 'FORBIDDEN',
    });
  });

  test('authz payloads never adopt a client-forged role shape', async () => {
    // The user guard is strict: unknown role strings fail the payload.
    const fetchImpl: FetchImpl = vi.fn(async () =>
      jsonResponse(
        envelope({ user: { ...TEST_USER, role: 'SUPERADMIN' } }),
      ),
    );
    const client = createApiClient({ baseUrl: '', fetchImpl });
    await expect(client.getUserById('usr_self')).rejects.toMatchObject({
      kind: 'invalid-response',
    });
  });
});

describe('subscription API client (Pump 4)', () => {
  test('getSubscription hits the read-only endpoint with cookie credentials', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () =>
      jsonResponse(
        envelope({
          subscription: {
            plan: 'PRO',
            status: 'ACTIVE',
            createdAt: '2026-09-01T00:00:00.000Z',
            updatedAt: '2026-09-01T00:00:00.000Z',
          },
          entitlements: ['plan:view', 'feature:pro'],
        }),
      ),
    );
    const client = createApiClient({ baseUrl: '', fetchImpl });
    const result = await client.getSubscription();
    expect(result.subscription.plan).toBe('PRO');
    expect(result.entitlements).toContain('feature:pro');
    const [url, init] = (fetchImpl as ReturnType<typeof vi.fn>).mock.calls[0] as [
      string,
      RequestInit,
    ];
    expect(url).toBe('/api/v1/subscription');
    expect(init.method ?? 'GET').toBe('GET');
    expect(init.credentials).toBe('include');
  });

  test('anonymous 401s surface as http ApiClientError with UNAUTHORIZED', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () =>
      jsonResponse(errorEnvelope('UNAUTHORIZED', 'Authentication required.'), 401),
    );
    const client = createApiClient({ baseUrl: '', fetchImpl });
    await expect(client.getSubscription()).rejects.toMatchObject({
      kind: 'http',
      status: 401,
      code: 'UNAUTHORIZED',
    });
  });

  test('subscription payloads failing the shared guard are rejected', async () => {
    // Forged plan, unknown entitlement keys, missing halves — all fail
    // closed at the client boundary as invalid-response.
    const bad = [
      { subscription: { plan: 'ENTERPRISE', status: 'ACTIVE', createdAt: null, updatedAt: null }, entitlements: [] },
      { subscription: { plan: 'PRO', status: 'active', createdAt: null, updatedAt: null }, entitlements: [] },
      { subscription: { plan: 'PRO', status: 'ACTIVE', createdAt: 'nope', updatedAt: null }, entitlements: [] },
      { subscription: { plan: 'PRO', status: 'ACTIVE', createdAt: null, updatedAt: null }, entitlements: ['feature:pro', 'plan:godmode'] },
      { subscription: { plan: 'PRO', status: 'ACTIVE', createdAt: null, updatedAt: null } },
      { entitlements: ['plan:view'] },
      null,
    ];
    for (const payload of bad) {
      const fetchImpl: FetchImpl = vi.fn(async () => jsonResponse(envelope(payload)));
      const client = createApiClient({ baseUrl: '', fetchImpl });
      await expect(client.getSubscription()).rejects.toMatchObject({
        kind: 'invalid-response',
      });
    }
  });

  test('the client exposes no subscription mutation method', () => {
    const client = createApiClient({ baseUrl: '', fetchImpl: vi.fn() });
    const methods = Object.keys(client).filter((key) => key.toLowerCase().includes('subscription'));
    // Only the read exists — there is no post/patch/put/delete to call.
    expect(methods).toEqual(['getSubscription']);
  });
});

describe('usage API client (Pump 5)', () => {
  test('getUsage hits the read-only endpoint with cookie credentials', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () =>
      jsonResponse(
        envelope({
          plan: 'FREE',
          period: {
            period: '2026-09',
            startUtc: '2026-09-01T00:00:00.000Z',
            endUtc: '2026-10-01T00:00:00.000Z',
          },
          used: 3,
          limit: 3,
          remaining: 0,
          quotaStatus: 'EXHAUSTED',
        }),
      ),
    );
    const client = createApiClient({ baseUrl: '', fetchImpl });
    const result = await client.getUsage();
    expect(result.quotaStatus).toBe('EXHAUSTED');
    expect(result.remaining).toBe(0);
    const [url, init] = (fetchImpl as ReturnType<typeof vi.fn>).mock.calls[0] as [
      string,
      RequestInit,
    ];
    expect(url).toBe('/api/v1/usage');
    expect(init.method ?? 'GET').toBe('GET');
    expect(init.credentials).toBe('include');
  });

  test('the PRO exempt view (null limit/remaining) validates too', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () =>
      jsonResponse(
        envelope({
          plan: 'PRO',
          period: {
            period: '2026-09',
            startUtc: '2026-09-01T00:00:00.000Z',
            endUtc: '2026-10-01T00:00:00.000Z',
          },
          used: 12,
          limit: null,
          remaining: null,
          quotaStatus: 'EXEMPT',
        }),
      ),
    );
    const client = createApiClient({ baseUrl: '', fetchImpl });
    const result = await client.getUsage();
    expect(result.quotaStatus).toBe('EXEMPT');
    expect(result.limit).toBeNull();
  });

  test('anonymous 401s surface as http ApiClientError with UNAUTHORIZED', async () => {
    const fetchImpl: FetchImpl = vi.fn(async () =>
      jsonResponse(errorEnvelope('UNAUTHORIZED', 'Authentication required.'), 401),
    );
    const client = createApiClient({ baseUrl: '', fetchImpl });
    await expect(client.getUsage()).rejects.toMatchObject({
      kind: 'http',
      status: 401,
      code: 'UNAUTHORIZED',
    });
  });

  test('usage payloads failing the shared guard are rejected', async () => {
    // Forged plans, negative counts, invented statuses, malformed
    // periods — all fail closed at the client boundary.
    const bad = [
      { plan: 'ENTERPRISE', period: { period: '2026-09', startUtc: '2026-09-01T00:00:00.000Z', endUtc: '2026-10-01T00:00:00.000Z' }, used: 0, limit: 3, remaining: 3, quotaStatus: 'OK' },
      { plan: 'FREE', period: { period: '2026-09', startUtc: '2026-09-01T00:00:00.000Z', endUtc: '2026-10-01T00:00:00.000Z' }, used: -1, limit: 3, remaining: 4, quotaStatus: 'OK' },
      { plan: 'FREE', period: { period: '2026-09', startUtc: '2026-09-01T00:00:00.000Z', endUtc: '2026-10-01T00:00:00.000Z' }, used: 1, limit: 3, remaining: '2', quotaStatus: 'OK' },
      { plan: 'FREE', period: { period: '2026-09', startUtc: '2026-09-01T00:00:00.000Z', endUtc: '2026-10-01T00:00:00.000Z' }, used: 1, limit: 3, remaining: 2, quotaStatus: 'UNLIMITED' },
      { plan: 'FREE', period: { period: '2026-9', startUtc: '2026-09-01T00:00:00.000Z', endUtc: '2026-10-01T00:00:00.000Z' }, used: 1, limit: 3, remaining: 2, quotaStatus: 'OK' },
      { plan: 'FREE', period: { period: '2026-09' }, used: 1, limit: 3, remaining: 2, quotaStatus: 'OK' },
      { plan: 'FREE', used: 1, limit: 3, remaining: 2, quotaStatus: 'OK' },
      null,
    ];
    for (const payload of bad) {
      const fetchImpl: FetchImpl = vi.fn(async () => jsonResponse(envelope(payload)));
      const client = createApiClient({ baseUrl: '', fetchImpl });
      await expect(client.getUsage()).rejects.toMatchObject({
        kind: 'invalid-response',
      });
    }
  });

  test('the client exposes no usage mutation method', () => {
    const client = createApiClient({ baseUrl: '', fetchImpl: vi.fn() });
    const methods = Object.keys(client).filter((key) => key.toLowerCase().includes('usage'));
    // Only the read exists — consumption is a server-side decision the
    // browser can never trigger on its own.
    expect(methods).toEqual(['getUsage']);
  });
});
