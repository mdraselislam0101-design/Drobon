import { screen } from '@testing-library/react';
import { describe, expect, test, vi } from 'vitest';
import type { SubscriptionResponse, UsageResponse } from '@drobon/shared';
import type { ApiClient } from '../src/api/client.js';
import { renderAt, stubClient, TEST_USER } from './appFixtures.js';

function signedIn(userType: 'DEVELOPER' | 'STUDENT' | null, overrides: Partial<ApiClient> = {}): ApiClient {
  return stubClient({
    getMe: vi.fn(async () => ({ user: { ...TEST_USER, userType } })),
    ...overrides,
  });
}

describe('Developer workspace dashboard UX', () => {
  test('shows server-derived account activity and FREE usage without an overall security verdict', async () => {
    const client = signedIn('DEVELOPER');
    await renderAt('/dashboard', client);
    expect(await screen.findByRole('heading', { name: 'Security overview' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Developer dashboard' })).toHaveAttribute('href', '/dashboard');
    expect(screen.getByRole('link', { name: 'My projects' })).toHaveAttribute('href', '/projects');
    expect(screen.queryByRole('link', { name: 'Platform operations' })).toBeNull();
    expect(screen.queryByRole('link', { name: 'Payment review' })).toBeNull();
    const planCard = screen.getByRole('heading', { name: 'Plan & usage' }).parentElement;
    expect(planCard).toHaveTextContent(/Server-reported plan: FREE/);
    expect(planCard).toHaveTextContent(/0 used of 3 · 3 remaining/);
    expect(screen.getByText(/No projects yet/)).toBeInTheDocument();
    expect(screen.getByText(/not a claim that every security area is clear or assessed/)).toBeInTheDocument();
    expect(screen.queryByText(/All clear/i)).toBeNull();
    expect(client.getSecurityOverview).toHaveBeenCalledTimes(1);
    expect(client.getUsage).toHaveBeenCalledTimes(1);
    expect(client.getSubscription).toHaveBeenCalledTimes(1);
  });

  test('Developer PRO summary displays only the server entitlement and exempt usage verdict', async () => {
    const client = signedIn('DEVELOPER', {
      getSubscription: vi.fn(async (): Promise<SubscriptionResponse> => ({
        subscription: { plan: 'PRO', status: 'ACTIVE', createdAt: '2026-09-01T00:00:00.000Z', updatedAt: '2026-09-01T00:00:00.000Z' },
        entitlements: ['plan:view', 'feature:pro'],
      })),
      getUsage: vi.fn(async (): Promise<UsageResponse> => ({
        plan: 'PRO',
        period: { period: '2026-09', startUtc: '2026-09-01T00:00:00.000Z', endUtc: '2026-10-01T00:00:00.000Z' },
        used: 5, limit: null, remaining: null, quotaStatus: 'EXEMPT',
      })),
    });
    await renderAt('/dashboard', client);
    expect(await screen.findByRole('heading', { name: 'Security overview' })).toBeInTheDocument();
    const planCard = screen.getByRole('heading', { name: 'Plan & usage' }).parentElement;
    expect(planCard).toHaveTextContent(/Server-reported plan: PRO/);
    expect(planCard).toHaveTextContent(/5 used · quota exempt/);
    expect(planCard).toHaveTextContent(/PRO entitlement: granted by server/);
  });

  test('non-Developer classification cannot enter the Developer dashboard by direct navigation', async () => {
    const client = signedIn('STUDENT');
    await renderAt('/dashboard', client);
    expect(await screen.findByRole('heading', { name: 'Projects' })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Security overview' })).toBeNull();
    expect(screen.queryByRole('link', { name: 'Developer dashboard' })).toBeNull();
    expect(screen.queryByRole('link', { name: 'Platform operations' })).toBeNull();
    expect(client.getSecurityOverview).not.toHaveBeenCalled();
  });
});
