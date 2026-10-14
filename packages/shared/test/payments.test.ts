import { describe, expect, test } from 'vitest';
import {
  PAYMENT_AUDIT_ACTIONS,
  PAYMENT_METHODS,
  PAYMENT_STATUSES,
  isAdminPaymentConfigResponse,
  isAdminPaymentsResponse,
  isPaymentAuditResponse,
  isPaymentConfigAuditEntry,
  isPaymentConfigResponse,
  isPaymentDetailResponse,
  isPaymentHistoryResponse,
  isPaymentMethod,
  isPaymentMethodDestination,
  isPaymentStatus,
  isPaymentSummary,
} from '../src/payments.js';

const payment = {
  paymentId: 'pay_00000000-0000-4000-8000-000000000001',
  plan: 'PRO',
  amountMinorUnits: 100_000,
  currency: 'BDT',
  paymentMethod: 'MANUAL_TRANSFER',
  reference: 'TXN-ABC123',
  status: 'PENDING',
  createdAt: '2026-09-29T10:00:00.000Z',
  submittedAt: '2026-09-29T10:00:00.000Z',
  updatedAt: '2026-09-29T10:00:00.000Z',
  reviewedAt: null,
  approvedAt: null,
  rejectedAt: null,
  rejectionReason: null,
} as const;

const destination = {
  methodId: 'pmd_00000000-0000-4000-8000-000000000001',
  method: 'MANUAL_TRANSFER',
  displayName: 'bKash',
  accountNumber: '01711111111',
  instructions: 'Send within 24h',
  enabled: true,
} as const;

const config = {
  currentPlan: 'FREE',
  proPriceMinorUnits: 100_000,
  currency: 'BDT',
  manualPaymentMethods: ['MANUAL_TRANSFER'],
  manualPaymentInstructions: 'Contact support before sending funds.',
  manualPaymentDestinations: [destination],
  onlineGateway: 'UNAVAILABLE',
  coupons: 'SUPPORTED',
} as const;

const adminConfig = {
  proPriceMinorUnits: 100_000,
  currency: 'BDT',
  destinations: [destination],
  updatedAt: '2026-09-30T00:00:00.000Z',
  audit: [{
    entryId: 'pca_00000000-0000-4000-8000-000000000001',
    at: '2026-09-30T00:00:00.000Z',
    actorId: 'usr_platform_admin',
    action: 'PAYMENT_CONFIG_PRICE_UPDATED',
    detail: 'PRO price changed from 100000 to 110000 minor units.',
  }],
} as const;

const event = {
  eventId: 'evt_00000000-0000-4000-8000-000000000001',
  paymentId: payment.paymentId,
  accountId: 'usr_account_1',
  actorId: 'usr_account_1',
  action: 'PAYMENT_CREATED',
  previousStatus: null,
  newStatus: 'PENDING',
  timestamp: '2026-09-29T10:00:00.000Z',
  reason: null,
} as const;

describe('Pump 15 payment contracts', () => {
  test('exposes only the manual method and explicit state/audit vocabularies', () => {
    expect(PAYMENT_METHODS).toEqual(['MANUAL_TRANSFER']);
    expect(PAYMENT_STATUSES).toEqual(['PENDING', 'UNDER_REVIEW', 'APPROVING', 'APPROVED', 'REJECTED', 'CANCELLED']);
    expect(PAYMENT_AUDIT_ACTIONS).toContain('PAYMENT_CANCELLED');
    expect(isPaymentMethod('ONLINE_GATEWAY')).toBe(false);
    expect(isPaymentStatus('SUCCESS')).toBe(false);
  });

  test('accepts bounded server payment, config, self-history and reviewer projections', () => {
    expect(isPaymentSummary(payment)).toBe(true);
    expect(isPaymentDetailResponse({ payment })).toBe(true);
    expect(isPaymentConfigResponse(config)).toBe(true);
    expect(isPaymentHistoryResponse({ payments: [payment], page: 1, pageSize: 20, total: 1 })).toBe(true);
    expect(isAdminPaymentsResponse({
      payments: [{ ...payment, accountId: 'usr_account_1', submittedByUserId: 'usr_account_1', reviewerId: null }],
      page: 1, pageSize: 20, total: 1,
    })).toBe(true);
    expect(isPaymentAuditResponse({ events: [event] })).toBe(true);
  });

  test('rejects altered price/state claims, malformed references and unbounded paging/audit data', () => {
    expect(isPaymentSummary({ ...payment, amountMinorUnits: -1 })).toBe(false);
    expect(isPaymentSummary({ ...payment, status: 'SUCCESS' })).toBe(false);
    expect(isPaymentSummary({ ...payment, reference: 'not a normalized reference' })).toBe(false);
    expect(isPaymentConfigResponse({ ...config, onlineGateway: 'AVAILABLE' })).toBe(false);
    expect(isPaymentHistoryResponse({ payments: [payment], page: 0, pageSize: 20, total: 1 })).toBe(false);
    expect(isPaymentHistoryResponse({ payments: [payment], page: 1, pageSize: 101, total: 1 })).toBe(false);
    expect(isPaymentAuditResponse({ events: Array.from({ length: 101 }, () => event) })).toBe(false);
  });

  test('Phase 20 payment-configuration contracts: destinations, admin view and audit entries', () => {
    expect(isPaymentMethodDestination(destination)).toBe(true);
    expect(isPaymentConfigResponse(config)).toBe(true);
    expect(isAdminPaymentConfigResponse(adminConfig)).toBe(true);
    expect(isPaymentConfigAuditEntry(adminConfig.audit[0])).toBe(true);
    // Config without the destination list is no longer a valid wire shape.
    const legacy = { ...config } as Record<string, unknown>;
    delete legacy['manualPaymentDestinations'];
    expect(isPaymentConfigResponse(legacy)).toBe(false);
    // Destinations are bounded and shape-checked.
    expect(isPaymentMethodDestination({ ...destination, methodId: 'pmd_not-a-uuid' })).toBe(false);
    expect(isPaymentMethodDestination({ ...destination, method: 'ONLINE_GATEWAY' })).toBe(false);
    expect(isPaymentMethodDestination({ ...destination, accountNumber: '12' })).toBe(false);
    expect(isPaymentMethodDestination({ ...destination, enabled: 'yes' })).toBe(false);
    expect(isPaymentConfigResponse({ ...config, manualPaymentDestinations: [{ ...destination, methodId: 'x' }] })).toBe(false);
    // Admin view rejects forged prices, unbounded audit and unknown actions.
    expect(isAdminPaymentConfigResponse({ ...adminConfig, proPriceMinorUnits: 0 })).toBe(false);
    expect(isAdminPaymentConfigResponse({ ...adminConfig, audit: Array.from({ length: 201 }, () => adminConfig.audit[0]) })).toBe(false);
    expect(isPaymentConfigAuditEntry({ ...adminConfig.audit[0], action: 'PAYMENT_CONFIG_DELETED' })).toBe(false);
  });
});
