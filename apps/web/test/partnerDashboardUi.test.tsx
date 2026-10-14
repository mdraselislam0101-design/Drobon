import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, test, vi } from 'vitest';
import type {
  AdminCommissionResponse,
  AdminCommissionsResponse,
  AdminPartnerResponse,
  AdminPartnersResponse,
  PartnerDashboardResponse,
  PaymentConfigResponse,
  PaymentDetailResponse,
  PaymentQuoteResponse,
  PaymentSummary,
} from '@drobon/shared';
import { ApiClientError, type ApiClient } from '../src/api/client.js';
import { renderAt, stubClient, TEST_USER } from './appFixtures.js';

/**
 * Pump 7 web suite: the partner dashboard renders ONLY the aggregate
 * projection the server sends (no customer data exists in the fixture or
 * the DOM), non-partners get an honest 404 verdict, and the admin console
 * exposes partner activation/coupon/commission controls wired to the
 * server-authoritative API.
 */

const dashboard: PartnerDashboardResponse = {
  partner: {
    partnerId: 'ptr_00000000-0000-4000-8000-00000000000a',
    status: 'ACTIVE',
    coupon: { couponCode: 'AEGIS-UI', status: 'ACTIVE', discountPercent: 10, commissionPercent: 5, expiresAt: null, createdAt: '2026-09-01T00:00:00.000Z', updatedAt: '2026-09-01T00:00:00.000Z' },
    complimentaryPro: { granted: true, grantedAt: '2026-09-01T00:00:00.000Z' },
    createdAt: '2026-09-01T00:00:00.000Z',
    updatedAt: '2026-09-01T00:00:00.000Z',
  },
  aggregates: {
    attributedPayments: 3,
    approvedPayments: 2,
    rejectedPayments: 1,
    cancelledPayments: 0,
    collectedAmountMinorUnits: 180_000,
    commission: { pendingAmountMinorUnits: 4_500, availableAmountMinorUnits: 4_500, paidAmountMinorUnits: 0, earnedAmountMinorUnits: 9_000 },
    currency: 'BDT',
  },
};

const paymentConfig: PaymentConfigResponse = {
  currentPlan: 'FREE', proPriceMinorUnits: 100_000, currency: 'BDT',
  manualPaymentMethods: ['MANUAL_TRANSFER'],
  manualPaymentInstructions: 'Payment instructions are not configured. Contact support before sending funds.',
  manualPaymentDestinations: [],
  onlineGateway: 'UNAVAILABLE', coupons: 'SUPPORTED',
};

const createdPayment: PaymentSummary = {
  paymentId: 'pay_00000000-0000-4000-8000-000000000099',
  plan: 'PRO', amountMinorUnits: 90_000, currency: 'BDT', paymentMethod: 'MANUAL_TRANSFER',
  reference: 'TXN-COUPON-1', status: 'PENDING', createdAt: '2026-09-29T10:00:00.000Z',
  submittedAt: '2026-09-29T10:00:00.000Z', updatedAt: '2026-09-29T10:00:00.000Z',
  reviewedAt: null, approvedAt: null, rejectedAt: null, rejectionReason: null,
  attribution: { couponCode: 'AEGIS-UI', baseAmountMinorUnits: 100_000, discountAmountMinorUnits: 10_000 },
};

function signedInClient(overrides: Partial<ApiClient> = {}): ApiClient {
  return stubClient({ getMe: vi.fn(async () => ({ user: { ...TEST_USER } })), ...overrides });
}

describe('partner dashboard (aggregate-only surface)', () => {
  test('renders coupon identity, aggregate counts and commission totals — never customer-level fields', async () => {
    await renderAt('/partner/dashboard', signedInClient({ getPartnerDashboard: vi.fn(async () => dashboard) }));
    expect(await screen.findByTestId('partner-coupon-code')).toHaveTextContent('AEGIS-UI');
    const aggregates = await screen.findByTestId('partner-aggregates');
    expect(aggregates).toHaveTextContent('3');
    expect(screen.getByTestId('partner-earned')).toHaveTextContent('BDT 90.00');
    expect(screen.getByTestId('partner-pro')).toHaveTextContent('entitlement only, never revenue');
    // Privacy: nothing in this view may carry customer identifiers.
    for (const forbidden of ['customer', 'buyer@', 'reference', 'TrxID']) {
      expect(aggregates.textContent?.toLowerCase()).not.toContain(forbidden.toLowerCase());
    }
  });

  test('a non-partner account gets an honest not-partner verdict, not a fake dashboard', async () => {
    await renderAt('/partner/dashboard', signedInClient({
      getPartnerDashboard: vi.fn(async () => { throw new ApiClientError({ kind: 'http', message: 'Not found.', status: 404, code: 'NOT_FOUND', requestId: 'req-np' }); }),
    }));
    expect(await screen.findByTestId('partner-not-found')).toHaveTextContent('No partner record exists for this account');
    expect(screen.queryByTestId('partner-aggregates')).toBeNull();
  });

  test('API failure degrades to an honest error state', async () => {
    await renderAt('/partner/dashboard', signedInClient({
      getPartnerDashboard: vi.fn(async () => { throw new ApiClientError({ kind: 'http', message: 'Unavailable.', status: 500, code: 'INTERNAL', requestId: 'req-x' }); }),
    }));
    // The server-provided verdict is surfaced verbatim; the fallback only
    // applies to non-ApiClient failures.
    expect(await screen.findByText('Unavailable.')).toBeInTheDocument();
  });
});

describe('admin partners & commissions console', () => {
  const partners: AdminPartnersResponse = {
    partners: [{
      partnerId: 'ptr_00000000-0000-4000-8000-00000000000a',
      userId: 'usr_partner_ui', email: 'partner-ui@example.test', status: 'ACTIVE',
      coupon: { couponCode: 'AEGIS-UI', status: 'ACTIVE', discountPercent: 10, commissionPercent: 5, expiresAt: null, createdAt: '2026-09-01T00:00:00.000Z', updatedAt: '2026-09-01T00:00:00.000Z' },
      complimentaryProGrantedAt: '2026-09-01T00:00:00.000Z',
      createdAt: '2026-09-01T00:00:00.000Z', updatedAt: '2026-09-01T00:00:00.000Z', deactivatedAt: null,
    }],
    page: 1, pageSize: 50, total: 1,
  };
  const commissions: AdminCommissionsResponse = {
    commissions: [{
      commissionId: 'cms_00000000-0000-4000-8000-000000000001',
      partnerId: 'ptr_00000000-0000-4000-8000-00000000000a',
      paymentId: 'pay_00000000-0000-4000-8000-000000000001',
      couponCode: 'AEGIS-UI', status: 'PENDING', currency: 'BDT',
      baseAmountMinorUnits: 100_000, discountAmountMinorUnits: 10_000, collectedAmountMinorUnits: 90_000,
      commissionPercent: 5, commissionAmountMinorUnits: 4_500,
      createdAt: '2026-09-01T00:00:00.000Z', updatedAt: '2026-09-01T00:00:00.000Z', availableAt: null, paidAt: null,
    }],
    page: 1, pageSize: 50, total: 1,
  };

  function adminClient(overrides: Partial<ApiClient> = {}): ApiClient {
    return signedInClient({
      getMe: vi.fn(async () => ({ user: { ...TEST_USER, role: 'ADMIN' as const } })),
      getAdminPartners: vi.fn(async () => partners),
      getAdminCommissions: vi.fn(async () => commissions),
      ...overrides,
    });
  }

  test('lists partners with coupon and rules, and commissions with the server-computed business split', async () => {
    await renderAt('/admin/partners', adminClient());
    const row = await screen.findByTestId('admin-partner-ptr_00000000-0000-4000-8000-00000000000a');
    expect(row).toHaveTextContent('AEGIS-UI');
    expect(row).toHaveTextContent('partner-ui@example.test');
    const commissionRow = await screen.findByTestId('admin-commission-cms_00000000-0000-4000-8000-000000000001');
    expect(commissionRow).toHaveTextContent('5% → BDT 45.00');
    expect(commissionRow).toHaveTextContent('business keeps BDT 855.00');
    expect(screen.getByRole('button', { name: 'Mark available' })).toBeInTheDocument();
  });

  test('activation form sends exactly the typed server-validated fields', async () => {
    const user = userEvent.setup();
    const activatePartner = vi.fn(async (): Promise<AdminPartnerResponse> => ({ partner: partners.partners[0] ?? { partnerId: 'ptr_x', userId: 'u', email: 'e', status: 'ACTIVE', coupon: { couponCode: 'C', status: 'ACTIVE', discountPercent: 0, commissionPercent: 0, expiresAt: null, createdAt: 't', updatedAt: 't' }, complimentaryProGrantedAt: 't', createdAt: 't', updatedAt: 't', deactivatedAt: null } }));
    await renderAt('/admin/partners', adminClient({ activatePartner }));
    await user.type(await screen.findByLabelText('Existing account ID'), 'usr_new_partner');
    await user.type(screen.getByLabelText('Unique coupon code'), 'AEGIS-NEW');
    await user.click(screen.getByRole('button', { name: 'Activate partner' }));
    await waitFor(() => expect(activatePartner).toHaveBeenCalledWith({ userId: 'usr_new_partner', couponCode: 'AEGIS-NEW', discountPercent: 10, commissionPercent: 5 }));
    expect(await screen.findByTestId('partner-notice')).toHaveTextContent('entitlement only');
  });

  test('commission settlement buttons drive the lifecycle transitions only', async () => {
    const user = userEvent.setup();
    const transitionCommission = vi.fn(async (): Promise<AdminCommissionResponse> => ({ commission: { ...commissions.commissions[0]!, status: 'AVAILABLE' as const } }));
    await renderAt('/admin/partners', adminClient({ transitionCommission }));
    await user.click(await screen.findByRole('button', { name: 'Mark available' }));
    await waitFor(() => expect(transitionCommission).toHaveBeenCalledWith('cms_00000000-0000-4000-8000-000000000001', 'AVAILABLE'));
  });

  test('non-allowlisted ADMIN receives the restricted-console verdict', async () => {
    await renderAt('/admin/partners', adminClient({
      getAdminPartners: vi.fn(async () => { throw new ApiClientError({ kind: 'http', message: 'Forbidden.', status: 403, code: 'FORBIDDEN', requestId: 'req-403' }); }),
    }));
    expect(await screen.findByText('Partner operations require an explicitly authorized platform administrator.')).toBeInTheDocument();
  });

  test('deactivate/reactivate and coupon rules round-trip through the API', async () => {
    const user = userEvent.setup();
    const setPartnerStatus = vi.fn(async (): Promise<AdminPartnerResponse> => ({ partner: { ...partners.partners[0]!, status: 'DEACTIVATED' as const } }));
    const updatePartnerCoupon = vi.fn(async (): Promise<AdminPartnerResponse> => ({ partner: partners.partners[0]! }));
    await renderAt('/admin/partners', adminClient({ setPartnerStatus, updatePartnerCoupon }));
    await user.click(await screen.findByRole('button', { name: 'Deactivate partner' }));
    await waitFor(() => expect(setPartnerStatus).toHaveBeenCalledWith('ptr_00000000-0000-4000-8000-00000000000a', 'DEACTIVATED'));
    const discountInput = screen.getByLabelText('Discount %');
    await user.clear(discountInput);
    await user.type(discountInput, '25');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(updatePartnerCoupon).toHaveBeenCalledWith('ptr_00000000-0000-4000-8000-00000000000a', { discountPercent: 25 }));
  });
});

describe('payment panel coupon flow', () => {
  const quoteWithCoupon: PaymentQuoteResponse = {
    baseAmountMinorUnits: 100_000, currency: 'BDT',
    coupon: { code: 'AEGIS-UI', discountPercent: 10, discountAmountMinorUnits: 10_000, finalAmountMinorUnits: 90_000 },
  };

  test('checking a coupon shows the server-quoted discount and final amount', async () => {
    const user = userEvent.setup();
    await renderAt('/account', signedInClient({
      getPaymentConfig: vi.fn(async () => paymentConfig),
      getPaymentQuote: vi.fn(async () => quoteWithCoupon),
    }));
    await user.type(await screen.findByLabelText(/Partner coupon code/), 'AEGIS-UI');
    await user.click(screen.getByRole('button', { name: 'Check coupon' }));
    expect(await screen.findByTestId('coupon-notice')).toHaveTextContent('Coupon AEGIS-UI accepted: 10% discount');
    expect(screen.getByTestId('payment-final-amount')).toHaveTextContent('BDT 900.00');
  });

  test('submitting with a coupon sends the server-quoted final amount plus the code', async () => {
    const user = userEvent.setup();
    const createPayment = vi.fn(async (): Promise<PaymentDetailResponse> => ({ payment: createdPayment }));
    await renderAt('/account', signedInClient({
      getPaymentConfig: vi.fn(async () => paymentConfig),
      getPaymentQuote: vi.fn(async () => quoteWithCoupon),
      createPayment,
    }));
    await user.type(await screen.findByLabelText(/Partner coupon code/), 'AEGIS-UI');
    await user.click(screen.getByRole('button', { name: 'Check coupon' }));
    await screen.findByTestId('payment-final-amount');
    await user.type(screen.getByLabelText('Payment transaction/reference'), 'TXN-COUPON-1');
    await user.click(screen.getByRole('button', { name: 'Submit for manual review' }));
    await waitFor(() => expect(createPayment).toHaveBeenCalledWith({
      plan: 'PRO', amountMinorUnits: 90_000, currency: 'BDT', paymentMethod: 'MANUAL_TRANSFER',
      reference: 'TXN-COUPON-1', couponCode: 'AEGIS-UI',
    }));
  });

  test('an invalid coupon surfaces the server verdict without breaking the form', async () => {
    const user = userEvent.setup();
    await renderAt('/account', signedInClient({
      getPaymentConfig: vi.fn(async () => paymentConfig),
      getPaymentQuote: vi.fn(async () => { throw new ApiClientError({ kind: 'http', message: 'This coupon is not currently valid.', status: 422, code: 'VALIDATION_ERROR', requestId: 'req-c' }); }),
    }));
    await user.type(await screen.findByLabelText(/Partner coupon code/), 'NOPE-CODE');
    await user.click(screen.getByRole('button', { name: 'Check coupon' }));
    expect(await screen.findByTestId('coupon-notice')).toHaveTextContent('not currently valid');
    expect(screen.getByRole('button', { name: 'Submit for manual review' })).toBeEnabled();
  });
});
