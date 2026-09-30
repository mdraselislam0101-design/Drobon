import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, test, vi } from 'vitest';
import type { AdminPaymentConfigResponse } from '@drobon/shared';
import { ApiClientError, type ApiClient } from '../src/api/client.js';
import { renderAt, stubClient, TEST_USER } from './appFixtures.js';

/**
 * Phase 20 UI coverage: the AccountPage classification switch and the
 * AdminPaymentsPage payment-configuration panel. The UI is presentation —
 * every assertion here mirrors a behavior already enforced server-side by
 * the API suites; these tests prove the surfaces drive the right calls.
 */

const baseDestination = {
  methodId: 'pmd_00000000-0000-4000-8000-000000000001',
  method: 'MANUAL_TRANSFER' as const,
  displayName: 'bKash',
  accountNumber: '01711111111',
  instructions: 'Send within 24h',
  enabled: true,
};

const adminConfig: AdminPaymentConfigResponse = {
  proPriceMinorUnits: 100_000,
  currency: 'BDT',
  destinations: [baseDestination],
  updatedAt: '2026-09-30T00:00:00.000Z',
  audit: [{
    entryId: 'pca_00000000-0000-4000-8000-000000000001',
    at: '2026-09-30T00:00:00.000Z',
    actorId: 'usr_platform_admin',
    action: 'PAYMENT_CONFIG_PRICE_UPDATED',
    detail: 'PRO price changed from 90000 to 100000 minor units.',
  }],
};

function signedIn(overrides: Partial<ApiClient> = {}): ApiClient {
  return stubClient({ getMe: vi.fn(async () => ({ user: { ...TEST_USER } })), ...overrides });
}

function adminSignedIn(overrides: Partial<ApiClient> = {}): ApiClient {
  return stubClient({ getMe: vi.fn(async () => ({ user: { ...TEST_USER, role: 'ADMIN' as const } })), ...overrides });
}

describe('Phase 20 — AccountPage workspace classification switch', () => {
  test('renders the four classifications honestly and saves through the API', async () => {
    const user = userEvent.setup();
    const updateUserType = vi.fn(async () => ({ user: { ...TEST_USER, userType: 'STUDENT' as const } }));
    await renderAt('/account', signedIn({ updateUserType }));

    const panel = await screen.findByTestId('usertype-panel');
    expect(panel).toBeInTheDocument();
    // Honest copy: classification never claims permission effects.
    expect(screen.getByText(/not a permission/i)).toBeInTheDocument();
    expect(screen.getByTestId('usertype-option-DEVELOPER')).toBeInTheDocument();
    expect(screen.getByTestId('usertype-option-STUDENT')).toBeInTheDocument();
    expect(screen.getByTestId('usertype-option-SECURITY_PROFESSIONAL')).toBeInTheDocument();
    expect(screen.getByTestId('usertype-option-PENTESTER')).toBeInTheDocument();

    const save = screen.getByTestId('usertype-save');
    expect(save).toBeDisabled(); // nothing selected beyond the current state
    await user.click(screen.getByTestId('usertype-option-STUDENT').querySelector('input') as HTMLElement);
    expect(save).toBeEnabled();
    await user.click(save);
    expect(updateUserType).toHaveBeenCalledWith('STUDENT');
    expect(await screen.findByTestId('usertype-saved')).toBeInTheDocument();
  });

  test('surfaces a server rejection without claiming success', async () => {
    const user = userEvent.setup();
    const updateUserType = vi.fn(async () => { throw new ApiClientError({ kind: 'http', message: 'Request failed.', status: 422 }); });
    await renderAt('/account', signedIn({ updateUserType }));
    await user.click((await screen.findByTestId('usertype-option-PENTESTER')).querySelector('input') as HTMLElement);
    await user.click(screen.getByTestId('usertype-save'));
    expect(await screen.findByTestId('usertype-error')).toBeInTheDocument();
    expect(screen.queryByTestId('usertype-saved')).toBeNull();
  });
});

describe('Phase 20 — AdminPaymentsPage payment configuration panel', () => {
  test('shows the restricted notice when the API answers 403 (reviewer without platform-admin grant)', async () => {
    await renderAt('/admin/payments', adminSignedIn({ getAdminPaymentConfig: vi.fn(async () => { throw new ApiClientError({ kind: 'http', message: 'Forbidden.', status: 403 }); }) }));
    expect(await screen.findByTestId('payment-config-denied')).toBeInTheDocument();
    expect(screen.queryByTestId('payment-config-panel')).toBeNull();
  });

  test('renders server configuration and drives price/destination mutations through the API', async () => {
    const user = userEvent.setup();
    const getAdminPaymentConfig = vi.fn(async () => adminConfig);
    const updateAdminPaymentPrice = vi.fn(async () => ({ ...adminConfig, proPriceMinorUnits: 120_000 }));
    const updateAdminPaymentMethod = vi.fn(async (): Promise<AdminPaymentConfigResponse> => ({
      ...adminConfig,
      destinations: [{ ...baseDestination, enabled: false }],
    }));
    const addAdminPaymentMethod = vi.fn(async (): Promise<{ destination: AdminPaymentConfigResponse['destinations'][number] }> => ({
      destination: { ...baseDestination, methodId: 'pmd_00000000-0000-4000-8000-000000000002', displayName: 'Nagad', accountNumber: '01822222222' },
    }));
    await renderAt('/admin/payments', adminSignedIn({
      getAdminPaymentConfig,
      updateAdminPaymentPrice,
      updateAdminPaymentMethod,
      addAdminPaymentMethod,
      getAdminPayments: vi.fn(async () => ({ payments: [], page: 1, pageSize: 50, total: 0 })),
    }));

    const panel = await screen.findByTestId('payment-config-panel');
    expect(panel).toBeInTheDocument();
    expect(screen.getByText(/Current server price: BDT 1000.00/)).toBeInTheDocument();
    expect(screen.getByText('bKash')).toBeInTheDocument();
    expect(screen.getByText('01711111111')).toBeInTheDocument();

    // Price change → BDT input converts to server minor units.
    const priceInput = screen.getByTestId('payment-config-price-input');
    await user.clear(priceInput);
    await user.type(priceInput, '1200');
    await user.click(screen.getByTestId('payment-config-save-price'));
    expect(updateAdminPaymentPrice).toHaveBeenCalledWith(120_000);
    expect(await screen.findByTestId('payment-config-notice')).toBeInTheDocument();

    // Disable toggle → enabled:false patch for the exact destination.
    await user.click(screen.getByTestId('payment-config-toggle-pmd_00000000-0000-4000-8000-000000000001'));
    expect(updateAdminPaymentMethod).toHaveBeenCalledWith(
      'pmd_00000000-0000-4000-8000-000000000001',
      { enabled: false },
    );

    // Add destination → POST with an 8–128 char idempotency key.
    await user.type(screen.getByTestId('payment-config-new-name'), 'Nagad');
    await user.type(screen.getByTestId('payment-config-new-account'), '01822222222');
    await user.click(screen.getByTestId('payment-config-add-method'));
    expect(addAdminPaymentMethod).toHaveBeenCalledTimes(1);
    const [input, key] = addAdminPaymentMethod.mock.calls[0] as unknown as [Record<string, unknown>, string];
    expect(input).toMatchObject({ displayName: 'Nagad', accountNumber: '01822222222' });
    expect(key.length).toBeGreaterThanOrEqual(8);
    expect(key.length).toBeLessThanOrEqual(128);

    // Audit trail is rendered from the server's masked entries.
    expect(screen.getByTestId('payment-config-audit')).toBeInTheDocument();
    expect(screen.getByText(/PRO price changed from 90000 to 100000 minor units/)).toBeInTheDocument();
  });

  test('add button stays disabled until the inputs are usable (client-side ergonomics only)', async () => {
    await renderAt('/admin/payments', adminSignedIn({
      getAdminPaymentConfig: vi.fn(async () => adminConfig),
      getAdminPayments: vi.fn(async () => ({ payments: [], page: 1, pageSize: 50, total: 0 })),
    }));
    const add = await screen.findByTestId('payment-config-add-method');
    expect(add).toBeDisabled();
  });
});
