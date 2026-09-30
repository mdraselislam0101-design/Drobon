import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, test, vi } from 'vitest';
import type { AdminPaymentSummary, PaymentConfigResponse, PaymentSummary } from '@drobon/shared';
import { ApiClientError, type ApiClient } from '../src/api/client.js';
import { renderAt, stubClient, TEST_USER } from './appFixtures.js';

const payment: PaymentSummary = {
  paymentId: 'pay_00000000-0000-4000-8000-000000000001',
  plan: 'PRO', amountMinorUnits: 100_000, currency: 'BDT', paymentMethod: 'MANUAL_TRANSFER',
  reference: 'TXN-ABC123', status: 'PENDING', createdAt: '2026-09-29T10:00:00.000Z',
  submittedAt: '2026-09-29T10:00:00.000Z', updatedAt: '2026-09-29T10:00:00.000Z',
  reviewedAt: null, approvedAt: null, rejectedAt: null, rejectionReason: null,
};
const config: PaymentConfigResponse = {
  currentPlan: 'FREE', proPriceMinorUnits: 100_000, currency: 'BDT',
  manualPaymentMethods: ['MANUAL_TRANSFER'],
  manualPaymentInstructions: 'Payment instructions are not configured. Contact support before sending funds.',
  onlineGateway: 'UNAVAILABLE', coupons: 'SUPPORTED',
};
function signedInClient(overrides: Partial<ApiClient> = {}): ApiClient {
  return stubClient({ getMe: vi.fn(async () => ({ user: { ...TEST_USER, role: 'ADMIN' as const } })), ...overrides });
}

describe('Account payment panel', () => {
  test('shows server pricing, honest manual instructions and gateway unavailable state', async () => {
    await renderAt('/account', signedInClient({ getPaymentConfig: vi.fn(async () => config) }));
    expect(await screen.findByTestId('payment-panel')).toHaveTextContent('BDT 1000.00');
    expect(screen.getByText(/Online payment processing is currently unavailable/)).toBeInTheDocument();
    expect(screen.getByText(/not proof of successful payment/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Submit for manual review' })).toBeInTheDocument();
    expect(screen.queryByText(/Payment successful/i)).toBeNull();
  });

  test('submits only the displayed price and manual reference; never claims verification', async () => {
    const user = userEvent.setup();
    const createPayment = vi.fn(async () => ({ payment }));
    await renderAt('/account', signedInClient({ getPaymentConfig: vi.fn(async () => config), createPayment }));
    await user.type(await screen.findByLabelText('Payment transaction/reference'), 'TXN-ABC123');
    await user.click(screen.getByRole('button', { name: 'Submit for manual review' }));
    await waitFor(() => expect(createPayment).toHaveBeenCalledWith({
      plan: 'PRO', amountMinorUnits: 100_000, currency: 'BDT', paymentMethod: 'MANUAL_TRANSFER', reference: 'TXN-ABC123',
    }));
    expect(await screen.findByRole('status')).toHaveTextContent('It has not been verified.');
    expect(screen.getByTestId(`payment-${payment.paymentId}`)).toHaveTextContent('PENDING');
    expect(screen.getByTestId(`payment-${payment.paymentId}`)).toHaveTextContent('not verified');
    expect(screen.queryByText(/PRO active/i)).toBeNull();
  });

  test('PRO only suppresses new purchase when the server configuration reports PRO', async () => {
    await renderAt('/account', signedInClient({ getPaymentConfig: vi.fn(async () => ({ ...config, currentPlan: 'PRO' as const })) }));
    expect(await screen.findByTestId('payment-current-plan')).toHaveTextContent('PRO');
    expect(screen.queryByRole('button', { name: 'Submit for manual review' })).toBeNull();
    expect(screen.getByText(/payment status alone does not grant access/i)).toBeInTheDocument();
  });

  test('owner can cancel only the pending request from the account UI', async () => {
    const user = userEvent.setup();
    const cancelled = { ...payment, status: 'CANCELLED' as const };
    const cancelPayment = vi.fn(async () => ({ payment: cancelled }));
    await renderAt('/account', signedInClient({
      getPaymentConfig: vi.fn(async () => config),
      getPaymentHistory: vi.fn(async () => ({ payments: [payment], page: 1, pageSize: 20, total: 1 })),
      cancelPayment,
    }));
    await user.click(await screen.findByRole('button', { name: 'Cancel pending request' }));
    await waitFor(() => expect(cancelPayment).toHaveBeenCalledWith(payment.paymentId));
    expect(await screen.findByTestId(`payment-${payment.paymentId}`)).toHaveTextContent('CANCELLED');
    expect(screen.getByRole('status')).toHaveTextContent('No entitlement was changed.');
  });

  test('shows only own rejection details and reason as plain text', async () => {
    const rejected = { ...payment, status: 'REJECTED' as const, rejectionReason: '<script>unsafe</script> reference mismatch', rejectedAt: '2026-09-29T11:00:00.000Z' };
    await renderAt('/account', signedInClient({
      getPaymentConfig: vi.fn(async () => config),
      getPaymentHistory: vi.fn(async () => ({ payments: [rejected], page: 1, pageSize: 20, total: 1 })),
    }));
    const row = await screen.findByTestId(`payment-${payment.paymentId}`);
    expect(row).toHaveTextContent('<script>unsafe</script> reference mismatch');
    expect(row.querySelector('script')).toBeNull();
  });
});

describe('Platform payment review UI', () => {
  test('normal account admin gets an honest restricted state and no payment data', async () => {
    const getAdminPayments = vi.fn(async () => { throw new ApiClientError({ kind: 'http', message: 'Forbidden.', status: 403, requestId: 'r' }); });
    await renderAt('/admin/payments', signedInClient({ getAdminPayments }));
    expect(await screen.findByRole('alert')).toHaveTextContent('restricted to explicitly authorized platform reviewers');
    expect(screen.queryByText('TXN-ABC123')).toBeNull();
  });

  test('tells reviewer when a credential-like reference has been masked', async () => {
    const record: AdminPaymentSummary = { ...payment, reference: 'REDACTED', accountId: 'usr_owner_1', submittedByUserId: 'usr_owner_1', reviewerId: null };
    await renderAt('/admin/payments', signedInClient({ getAdminPayments: vi.fn(async () => ({ payments: [record], page: 1, pageSize: 50, total: 1 })) }));
    expect(await screen.findByText('Masked by sensitive-data guard.')).toBeInTheDocument();
    expect(screen.getByText('REDACTED')).toBeInTheDocument();
  });

  test('authorized reviewer UI exposes bounded payment details, requires rejection reason and can audit', async () => {
    const user = userEvent.setup();
    const record: AdminPaymentSummary = { ...payment, accountId: 'usr_owner_1', submittedByUserId: 'usr_owner_1', reviewerId: null };
    const getAdminPayments = vi.fn(async () => ({ payments: [record], page: 1, pageSize: 50, total: 1 }));
    const rejectPayment = vi.fn(async () => ({ payment: { ...payment, status: 'REJECTED' as const, rejectionReason: 'Reference mismatch.' } }));
    const getPaymentAudit = vi.fn(async () => ({ events: [] }));
    await renderAt('/admin/payments', signedInClient({ getAdminPayments, rejectPayment, getPaymentAudit }));
    expect(await screen.findByTestId(`admin-payment-${payment.paymentId}`)).toHaveTextContent('usr_owner_1');
    const rejectButton = screen.getByRole('button', { name: 'Reject with reason' });
    expect(rejectButton).toBeDisabled();
    await user.type(screen.getByLabelText(`Reason shown to the requester`), 'Reference mismatch.');
    await user.click(rejectButton);
    await waitFor(() => expect(rejectPayment).toHaveBeenCalledWith(payment.paymentId, 'Reference mismatch.'));
    await user.click(screen.getByRole('button', { name: 'View audit events' }));
    await waitFor(() => expect(getPaymentAudit).toHaveBeenCalledWith(payment.paymentId));
  });
});
