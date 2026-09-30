import { describe, expect, test } from 'vitest';
import {
  PAYMENT_AUDIT_ACTIONS,
  PAYMENT_METHODS,
  PAYMENT_STATUSES,
  isAdminPaymentsResponse,
  isPaymentAuditResponse,
  isPaymentConfigResponse,
  isPaymentDetailResponse,
  isPaymentHistoryResponse,
  isPaymentMethod,
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

const config = {
  currentPlan: 'FREE',
  proPriceMinorUnits: 100_000,
  currency: 'BDT',
  manualPaymentMethods: ['MANUAL_TRANSFER'],
  manualPaymentInstructions: 'Contact support before sending funds.',
  onlineGateway: 'UNAVAILABLE',
  coupons: 'SUPPORTED',
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
});
