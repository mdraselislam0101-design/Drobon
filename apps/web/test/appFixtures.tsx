import { act, render } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { vi } from 'vitest';
import type {
  AuthResponse,
  CapabilityResponse,
  CurrentUserResponse,
  HealthResponse,
  LogoutResponse,
  StatusResponse,
  SubscriptionResponse,
  UsageResponse,
} from '@drobon/shared';
import { ApiClientError, type ApiClient } from '../src/api/client.js';
import { AppRoutes } from '../src/routes.js';

/** A 401 ApiClientError, as the API returns for anonymous requests. */
export function unauthorizedError(message = 'Authentication required.'): ApiClientError {
  return new ApiClientError({
    kind: 'http',
    message,
    status: 401,
    code: 'UNAUTHORIZED',
    requestId: 'req-test-401',
  });
}

/** A 403 ApiClientError, as the API returns for denied capabilities. */
export function forbiddenError(
  message = 'You do not have access to this resource.',
): ApiClientError {
  return new ApiClientError({
    kind: 'http',
    message,
    status: 403,
    code: 'FORBIDDEN',
    requestId: 'req-test-403',
  });
}

export const TEST_USER = {
  id: 'usr_test_1',
  email: 'user@example.test',
  createdAt: '2026-01-01T00:00:00.000Z',
  role: 'MEMBER',
  userType: null,
} as const;

/**
 * Full ApiClient double. Defaults model the anonymous world (GET /me →
 * 401); individual suites override the methods they exercise.
 */
export function stubClient(overrides: Partial<ApiClient> = {}): ApiClient {
  return {
    getStatus: vi.fn(async (): Promise<StatusResponse> => ({
      service: 'drobon-aegis-api',
      version: '0.1.0-test',
      environment: 'test',
      time: '2026-01-01T00:00:00.000Z',
    })),
    getLivez: vi.fn(async (): Promise<HealthResponse> => ({
      status: 'ok',
      service: 's',
      version: 'v',
    })),
    postEcho: vi.fn(async (message: string) => ({
      message,
      length: message.length,
      receivedAt: '2026-01-01T00:00:00.000Z',
    })),
    getMe: vi.fn(async (): Promise<CurrentUserResponse> => {
      throw unauthorizedError();
    }),
    postRegister: vi.fn(
      async (email: string): Promise<AuthResponse> => ({ user: { ...TEST_USER, email } }),
    ),
    postLogin: vi.fn(
      async (email: string): Promise<AuthResponse> => ({ user: { ...TEST_USER, email } }),
    ),
    postLogout: vi.fn(async (): Promise<LogoutResponse> => ({ loggedOut: true })),
    // Pump 3 defaults: a MEMBER world — member capability granted,
    // higher capabilities denied, privileged lookup denied.
    getCapability: vi.fn(
      async (level: 'member' | 'admin' | 'owner'): Promise<CapabilityResponse> => {
        if (level !== 'member') {
          throw forbiddenError();
        }
        return { capability: 'member' };
      },
    ),
    getUserById: vi.fn(async () => {
      throw forbiddenError();
    }),
    // Pump 4 default: the FREE world — FREE + ACTIVE, no PRO entitlement.
    getSubscription: vi.fn(async (): Promise<SubscriptionResponse> => ({
      subscription: {
        plan: 'FREE',
        status: 'ACTIVE',
        createdAt: '2026-01-01T00:00:00.000Z',
        updatedAt: '2026-01-01T00:00:00.000Z',
      },
      entitlements: ['plan:view'],
    })),
    // Pump 5 default: a fresh FREE usage view (nothing consumed this
    // UTC month). Suites override it to model exhaustion or PRO.
    getUsage: vi.fn(async (): Promise<UsageResponse> => ({
      plan: 'FREE',
      period: {
        period: '2026-09',
        startUtc: '2026-09-01T00:00:00.000Z',
        endUtc: '2026-10-01T00:00:00.000Z',
      },
      used: 0,
      limit: 3,
      remaining: 3,
      quotaStatus: 'OK',
    })),
    ...overrides,
  };
}

/** Mount the real route tree at `path` and flush the session probe. */
export async function renderAt(
  path: string,
  client: ApiClient = stubClient(),
  locationState?: unknown,
): Promise<void> {
  render(
    <MemoryRouter
      initialEntries={[
        locationState === undefined ? path : { pathname: path, state: locationState },
      ]}
    >
      <AppRoutes client={client} appName="Test App" appVersion="0.1.0-test" />
    </MemoryRouter>,
  );
  await act(async () => {
    await Promise.resolve();
  });
}
