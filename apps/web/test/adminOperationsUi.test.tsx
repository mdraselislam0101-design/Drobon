import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, test, vi } from 'vitest';
import type { AdminDashboardResponse } from '@drobon/shared';
import { ApiClientError, type ApiClient } from '../src/api/client.js';
import { renderAt, stubClient, TEST_USER } from './appFixtures.js';

const snapshot: AdminDashboardResponse = {
  asOf: '2026-09-29T12:00:00.000Z',
  accounts: { state: 'AVAILABLE', total: 7, free: 6, pro: 1, subscriptionByStatus: { ACTIVE: 7, INACTIVE: 0, CANCELLED: 0, EXPIRED: 0 } },
  projects: { state: 'AVAILABLE', total: 3, active: 2, archived: 1 },
  scans: { state: 'AVAILABLE', total: 12, byStatus: { QUEUED: 1, RUNNING: 1, COMPLETED: 8, FAILED: 1, TIMED_OUT: 1 }, byType: { SAST: 8, SCA: 2, SECRETS: 1, DAST: 1 }, recentlyCompleted: 4 },
  payments: { state: 'AVAILABLE', total: 2, byStatus: { PENDING: 1, UNDER_REVIEW: 0, APPROVING: 0, APPROVED: 1, REJECTED: 0, CANCELLED: 0 }, submittedAmountMinorUnits: 200_000, approvedAmountMinorUnits: 100_000, currency: 'BDT' },
  findings: { state: 'AVAILABLE', bySeverity: { CRITICAL: 0, HIGH: 2, MEDIUM: 3, LOW: 1, INFO: 0 }, byLifecycleState: { OPEN: 4, ACKNOWLEDGED: 0, IN_PROGRESS: 1, RESOLVED: 1, FALSE_POSITIVE: 0, REOPENED: 0 }, unresolved: 5, dastObservations: 3, scaNotAssessed: 2 },
  system: { api: 'SERVING', web: 'NOT_ASSESSED', accountPersistence: 'LOADED_AT_STARTUP', paymentPersistence: 'EPHEMERAL', apiAttachedScanProcessor: 'NOT_STARTED', separateWorker: 'NOT_INTEGRATED', assistantFeature: 'DETERMINISTIC_READ_ONLY', aiProvider: 'NONE', paymentGateway: 'UNAVAILABLE', vulnerabilityDataset: 'NO_DATA_LOADED', securityDataset: 'SEPARATE_NOT_LOADED' },
};

function signedIn(overrides: Partial<ApiClient> = {}): ApiClient {
  return stubClient({ getMe: vi.fn(async () => ({ user: { ...TEST_USER, role: 'ADMIN' as const } })), ...overrides });
}

describe('platform operations dashboard UI', () => {
  test('renders persisted counts and conservative integration status wording', async () => {
    const getAdminDashboard = vi.fn(async () => snapshot);
    await renderAt('/admin/operations', signedIn({ getAdminDashboard }));
    expect(await screen.findByRole('heading', { name: 'Operations dashboard' })).toBeInTheDocument();
    expect(screen.getByText('Payment requests')).toBeInTheDocument();
    expect(screen.getByText('Submitted amount')).toBeInTheDocument();
    expect(screen.getByText(/not revenue/)).toBeInTheDocument();
    expect(screen.getByText('NOT_INTEGRATED')).toBeInTheDocument();
    expect(screen.getByText('NOT_ASSESSED')).toBeInTheDocument();
    expect(screen.getByText('UNAVAILABLE')).toBeInTheDocument();
    expect(screen.queryByText(/Coverage: payment events only/)).not.toBeInTheDocument();
  });

  test('shows UNAVAILABLE for a failed store aggregate and never substitutes zero', async () => {
    const partial = { ...snapshot, accounts: { state: 'UNAVAILABLE' as const } };
    await renderAt('/admin/operations', signedIn({ getAdminDashboard: vi.fn(async () => partial) }));
    expect(await screen.findByText('Account aggregates unavailable')).toBeInTheDocument();
    expect(screen.queryByText('0 FREE · 0 PRO')).toBeNull();
  });

  test('shows read-only bounded account data and explicit audit scope', async () => {
    const user = userEvent.setup();
    const getAdminDashboard = vi.fn(async () => snapshot);
    const getAdminAccounts = vi.fn(async () => ({ accounts: [{
      accountId: 'usr_synthetic_01', email: 's***@example.test', role: 'MEMBER' as const, userType: null,
      plan: 'FREE' as const, subscriptionStatus: 'ACTIVE' as const, createdAt: '2026-09-01T00:00:00.000Z',
      effectivePlan: 'FREE' as const, proEntitlementSource: null,
      accountStatus: 'UNAVAILABLE' as const, paymentRequestCount: 0, latestPaymentStatus: null,
    }], page: 1, pageSize: 25, total: 1 }));
    const getAdminAudit = vi.fn(async () => ({ events: [], page: 1, pageSize: 50, total: 0, coverage: 'PAYMENT_EVENTS_ONLY' as const }));
    await renderAt('/admin/operations', signedIn({ getAdminDashboard, getAdminAccounts, getAdminAudit }));
    await user.click(await screen.findByRole('button', { name: 'Accounts' }));
    expect(await screen.findByText('s***@example.test')).toBeInTheDocument();
    expect(screen.getByText(/no account role, UserType, or subscription mutation/i)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /delete|promote|change role/i })).toBeNull();
    await user.click(screen.getByRole('button', { name: 'Payment audit' }));
    expect(await screen.findByText(/Coverage: payment events only/)).toBeInTheDocument();
    expect(getAdminAudit).toHaveBeenCalledWith({ page: 1, pageSize: 50 }, expect.any(AbortSignal));
  });

  test('a server denial does not disclose or retain operations data', async () => {
    const getAdminDashboard = vi.fn(async () => { throw new ApiClientError({ kind: 'http', message: 'Forbidden.', status: 403, requestId: 'admin-denied' }); });
    await renderAt('/admin/operations', signedIn({ getAdminDashboard }));
    expect(await screen.findByRole('alert')).toHaveTextContent('live ADMIN role');
    expect(screen.queryByText('7')).toBeNull();
  });
});
