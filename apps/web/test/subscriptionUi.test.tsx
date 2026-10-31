import { screen, waitFor } from '@testing-library/react';
import { describe, expect, test, vi } from 'vitest';
import type { SubscriptionResponse } from '@drobon/shared';
import { ApiClientError, type ApiClient } from '../src/api/client.js';
import { renderAt, stubClient, TEST_USER } from './appFixtures.js';

/**
 * Pump 4 web tests — the Account page plan section.
 *
 * Rules under test:
 * - the section renders ONLY what the server returned (plan, status and
 *   the entitlement verdict — never a local recomputation from the plan);
 * - failures fail CLOSED: no plan is shown at all, never a silent PRO;
 * - there is no plan state in URL parameters, localStorage or
 *   sessionStorage (display comes from the API response only).
 */

const FREE_RESPONSE: SubscriptionResponse = {
  subscription: {
    plan: 'FREE',
    status: 'ACTIVE',
    createdAt: '2026-09-01T00:00:00.000Z',
    updatedAt: '2026-09-01T00:00:00.000Z',
  },
  entitlements: ['plan:view'],
};

const PRO_RESPONSE: SubscriptionResponse = {
  subscription: {
    plan: 'PRO',
    status: 'ACTIVE',
    createdAt: '2026-09-01T00:00:00.000Z',
    updatedAt: '2026-09-02T00:00:00.000Z',
  },
  entitlements: ['plan:view', 'feature:pro'],
};

/** A signed-in FREE member by default (see appFixtures TEST_USER). */
function signedInClient(overrides: Partial<ApiClient> = {}): ApiClient {
  return stubClient({
    getMe: vi.fn(async () => ({ user: TEST_USER })),
    getSubscription: vi.fn(async () => FREE_RESPONSE),
    ...overrides,
  });
}

describe('Account page — plan & subscription section', () => {
  test('renders the server-provided FREE plan, status and closed PRO verdict', async () => {
    await renderAt('/account', signedInClient());
    expect(await screen.findByTestId('plan-badge')).toHaveTextContent('Plan: FREE');
    expect(screen.getByTestId('subscription-status-badge')).toHaveTextContent('Status: ACTIVE');
    expect(screen.getByTestId('pro-entitlement')).toHaveTextContent('Not enabled');
    expect(screen.getByTestId('pro-verdict')).toHaveTextContent('Not enabled');
    expect(screen.getByTestId('plan-panel')).toHaveTextContent('2026-09-01T00:00:00.000Z');
    // The PRO verdict is closed — no "Enabled" anywhere on the page.
    expect(screen.queryByText('Enabled')).toBeNull();
  });

  test('renders PRO only when the server says PRO (and the entitlement list agrees)', async () => {
    await renderAt('/account', signedInClient({ getSubscription: vi.fn(async () => PRO_RESPONSE) }));
    expect(await screen.findByTestId('plan-badge')).toHaveTextContent('Plan: PRO');
    expect(screen.getByTestId('subscription-status-badge')).toHaveTextContent('Status: ACTIVE');
    expect(screen.getByTestId('pro-entitlement')).toHaveTextContent('Enabled');
    expect(screen.getByTestId('pro-source-badge')).toHaveTextContent('PRO source not verified');
    expect(screen.getByTestId('pro-source-badge')).not.toHaveTextContent('paid subscription');
  });

  test('a lapsed PRO subscription shows the honest state: PRO label, no entitlement', async () => {
    const lapsed: SubscriptionResponse = {
      subscription: { ...PRO_RESPONSE.subscription, status: 'EXPIRED' },
      entitlements: ['plan:view'],
    };
    await renderAt('/account', signedInClient({ getSubscription: vi.fn(async () => lapsed) }));
    expect(await screen.findByTestId('plan-badge')).toHaveTextContent('Plan: PRO');
    expect(screen.getByTestId('subscription-status-badge')).toHaveTextContent('Status: EXPIRED');
    expect(screen.getByTestId('pro-entitlement')).toHaveTextContent('Not enabled');
  });

  test('the PRO verdict comes from the entitlement list, never a local plan computation', async () => {
    // Deliberately inconsistent-but-structurally-valid payload: plan says
    // PRO, the server entitlement list does NOT contain feature:pro. The
    // page must render the SERVER's verdict (Not enabled), not "Enabled"
    // derived from the plan string.
    const inconsistent: SubscriptionResponse = {
      subscription: { ...PRO_RESPONSE.subscription },
      entitlements: ['plan:view'],
    };
    await renderAt(
      '/account',
      signedInClient({ getSubscription: vi.fn(async () => inconsistent) }),
    );
    expect(await screen.findByTestId('plan-badge')).toHaveTextContent('Plan: PRO');
    expect(screen.getByTestId('pro-entitlement')).toHaveTextContent('Not enabled');
  });

  test('API failure fails closed: an honest error, never a silent PRO', async () => {
    const client = signedInClient({
      getSubscription: vi.fn(async () => {
        throw new ApiClientError({
          kind: 'network',
          message: 'Could not reach the server. Check your connection and try again.',
          requestId: 'req-plan-down',
        });
      }),
    });
    await renderAt('/account', client);
    expect(await screen.findByTestId('plan-error')).toBeDefined();
    expect(screen.getByTestId('plan-error')).toHaveTextContent('Could not load your plan');
    // No plan value is invented while the API is unreachable.
    expect(screen.queryByTestId('plan-badge')).toBeNull();
    expect(screen.queryByText(/Plan: PRO/)).toBeNull();
    expect(screen.queryByText(/Plan: FREE/)).toBeNull();
    expect(screen.queryByTestId('pro-entitlement')).toBeNull();
  });

  test('a 401 on the subscription read surfaces as an honest error, not a plan', async () => {
    const client = signedInClient({
      getSubscription: vi.fn(async () => {
        throw new ApiClientError({
          kind: 'http',
          message: 'Authentication required.',
          status: 401,
          code: 'UNAUTHORIZED',
          requestId: 'req-plan-401',
        });
      }),
    });
    await renderAt('/account', client);
    expect(await screen.findByTestId('plan-error')).toBeDefined();
    expect(screen.queryByTestId('plan-badge')).toBeNull();
  });

  test('retry recovers after a failure (and still renders only the server data)', async () => {
    let calls = 0;
    const getSubscription = vi.fn(async (): Promise<SubscriptionResponse> => {
      calls += 1;
      if (calls === 1) {
        throw new ApiClientError({
          kind: 'network',
          message: 'Could not reach the server. Check your connection and try again.',
          requestId: 'req-plan-retry',
        });
      }
      return PRO_RESPONSE;
    });
    await renderAt('/account', signedInClient({ getSubscription }));
    expect(await screen.findByTestId('plan-error')).toBeDefined();
    screen.getByRole('button', { name: 'Try again' }).click();
    expect(await screen.findByTestId('plan-badge')).toHaveTextContent('Plan: PRO');
    expect(getSubscription).toHaveBeenCalledTimes(2);
  });

  test('plan state never leaks into URL parameters or web storage', async () => {
    await renderAt('/account', signedInClient());
    await waitFor(() => expect(screen.getByTestId('plan-badge')).toBeDefined());
    // No plan string in the URL…
    expect(globalThis.location.href).not.toMatch(/plan|subscription|PRO/i);
    // …and nothing plan-shaped was persisted to web storage.
    expect(globalThis.localStorage.length).toBe(0);
    expect(globalThis.sessionStorage.length).toBe(0);
  });
});
