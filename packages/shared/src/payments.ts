import { isRecord } from './guards.js';

/** Pump 15 payment vocabulary. Online payment integrations remain unavailable. */
export const PAYMENT_METHODS = ['MANUAL_TRANSFER'] as const;
export type PaymentMethod = (typeof PAYMENT_METHODS)[number];
export function isPaymentMethod(value: unknown): value is PaymentMethod {
  return typeof value === 'string' && (PAYMENT_METHODS as readonly string[]).includes(value);
}

export const PAYMENT_STATUSES = [
  'PENDING',
  'UNDER_REVIEW',
  'APPROVING',
  'APPROVED',
  'REJECTED',
  'CANCELLED',
] as const;
export type PaymentStatus = (typeof PAYMENT_STATUSES)[number];
export function isPaymentStatus(value: unknown): value is PaymentStatus {
  return typeof value === 'string' && (PAYMENT_STATUSES as readonly string[]).includes(value);
}

export const PAYMENT_AUDIT_ACTIONS = [
  'PAYMENT_CREATED',
  'PAYMENT_SUBMITTED',
  'PAYMENT_REVIEW_STARTED',
  'PAYMENT_APPROVAL_STARTED',
  'PAYMENT_APPROVED',
  'PAYMENT_REJECTED',
  'PAYMENT_CANCELLED',
] as const;
export type PaymentAuditAction = (typeof PAYMENT_AUDIT_ACTIONS)[number];
export function isPaymentAuditAction(value: unknown): value is PaymentAuditAction {
  return typeof value === 'string' && (PAYMENT_AUDIT_ACTIONS as readonly string[]).includes(value);
}

export interface PaymentSummary {
  paymentId: string;
  plan: 'PRO';
  amountMinorUnits: number;
  currency: 'BDT';
  paymentMethod: PaymentMethod;
  reference: string;
  status: PaymentStatus;
  createdAt: string;
  submittedAt: string;
  updatedAt: string;
  reviewedAt: string | null;
  approvedAt: string | null;
  rejectedAt: string | null;
  rejectionReason: string | null;
}

/** Reviewer-only projection. Account identifiers are never in owner views. */
export interface AdminPaymentSummary extends PaymentSummary {
  accountId: string;
  submittedByUserId: string;
  reviewerId: string | null;
}

export interface PaymentConfigResponse {
  currentPlan: 'FREE' | 'PRO';
  proPriceMinorUnits: number;
  currency: 'BDT';
  manualPaymentMethods: PaymentMethod[];
  manualPaymentInstructions: string;
  onlineGateway: 'UNAVAILABLE';
  coupons: 'NOT_IMPLEMENTED';
}

export interface PaymentHistoryResponse {
  payments: PaymentSummary[];
  page: number;
  pageSize: number;
  total: number;
}

export interface PaymentDetailResponse {
  payment: PaymentSummary;
}

export interface AdminPaymentsResponse {
  payments: AdminPaymentSummary[];
  page: number;
  pageSize: number;
  total: number;
}

export interface PaymentAuditEvent {
  eventId: string;
  paymentId: string;
  accountId: string;
  actorId: string;
  action: PaymentAuditAction;
  previousStatus: PaymentStatus | null;
  newStatus: PaymentStatus;
  timestamp: string;
  reason: string | null;
}

export interface PaymentAuditResponse {
  events: PaymentAuditEvent[];
}

function isTimestamp(value: unknown): value is string {
  return typeof value === 'string' && !Number.isNaN(Date.parse(value));
}

function isPage(value: unknown): value is number {
  return Number.isSafeInteger(value) && typeof value === 'number' && value >= 1;
}

function isPageSize(value: unknown): value is number {
  return Number.isSafeInteger(value) && typeof value === 'number' && value >= 1 && value <= 50;
}

function isPaymentId(value: unknown): value is string {
  return typeof value === 'string' && /^pay_[0-9a-f-]{36}$/i.test(value);
}

export function isPaymentSummary(value: unknown): value is PaymentSummary {
  return (
    isRecord(value) &&
    isPaymentId(value['paymentId']) &&
    value['plan'] === 'PRO' &&
    typeof value['amountMinorUnits'] === 'number' &&
    Number.isSafeInteger(value['amountMinorUnits']) &&
    value['amountMinorUnits'] > 0 &&
    value['currency'] === 'BDT' &&
    isPaymentMethod(value['paymentMethod']) &&
    typeof value['reference'] === 'string' &&
    /^[A-Z0-9][A-Z0-9._-]{5,63}$/.test(value['reference']) &&
    isPaymentStatus(value['status']) &&
    isTimestamp(value['createdAt']) &&
    isTimestamp(value['submittedAt']) &&
    isTimestamp(value['updatedAt']) &&
    (value['reviewedAt'] === null || isTimestamp(value['reviewedAt'])) &&
    (value['approvedAt'] === null || isTimestamp(value['approvedAt'])) &&
    (value['rejectedAt'] === null || isTimestamp(value['rejectedAt'])) &&
    (value['rejectionReason'] === null || (typeof value['rejectionReason'] === 'string' && value['rejectionReason'].length <= 300))
  );
}

export function isPaymentConfigResponse(value: unknown): value is PaymentConfigResponse {
  return (
    isRecord(value) &&
    (value['currentPlan'] === 'FREE' || value['currentPlan'] === 'PRO') &&
    typeof value['proPriceMinorUnits'] === 'number' &&
    Number.isSafeInteger(value['proPriceMinorUnits']) &&
    value['proPriceMinorUnits'] > 0 &&
    value['currency'] === 'BDT' &&
    Array.isArray(value['manualPaymentMethods']) &&
    value['manualPaymentMethods'].every(isPaymentMethod) &&
    typeof value['manualPaymentInstructions'] === 'string' &&
    value['manualPaymentInstructions'].length > 0 && value['manualPaymentInstructions'].length <= 500 &&
    value['onlineGateway'] === 'UNAVAILABLE' &&
    value['coupons'] === 'NOT_IMPLEMENTED'
  );
}

function isHistoryPage(value: Record<string, unknown>, payments: unknown[]): boolean {
  return isPage(value['page']) && isPageSize(value['pageSize']) &&
    Number.isSafeInteger(value['total']) && typeof value['total'] === 'number' && value['total'] >= 0 &&
    payments.length <= value['pageSize'];
}

export function isPaymentHistoryResponse(value: unknown): value is PaymentHistoryResponse {
  return (
    isRecord(value) &&
    Array.isArray(value['payments']) &&
    value['payments'].every(isPaymentSummary) &&
    isHistoryPage(value, value['payments'])
  );
}

export function isPaymentDetailResponse(value: unknown): value is PaymentDetailResponse {
  return isRecord(value) && isPaymentSummary(value['payment']);
}

export function isAdminPaymentsResponse(value: unknown): value is AdminPaymentsResponse {
  return (
    isRecord(value) &&
    Array.isArray(value['payments']) &&
    value['payments'].every((entry) =>
      isPaymentSummary(entry) &&
      isRecord(entry) &&
      typeof entry['accountId'] === 'string' && entry['accountId'].length > 0 &&
      typeof entry['submittedByUserId'] === 'string' && entry['submittedByUserId'].length > 0 &&
      (entry['reviewerId'] === null || (typeof entry['reviewerId'] === 'string' && entry['reviewerId'].length > 0)),
    ) &&
    isHistoryPage(value, value['payments'])
  );
}

export function isPaymentAuditResponse(value: unknown): value is PaymentAuditResponse {
  return (
    isRecord(value) &&
    Array.isArray(value['events']) && value['events'].length <= 100 &&
    value['events'].every((event) =>
      isRecord(event) &&
      typeof event['eventId'] === 'string' && /^evt_[0-9a-f-]{36}$/i.test(event['eventId']) &&
      isPaymentId(event['paymentId']) &&
      typeof event['accountId'] === 'string' && event['accountId'].length > 0 &&
      typeof event['actorId'] === 'string' && event['actorId'].length > 0 &&
      isPaymentAuditAction(event['action']) &&
      (event['previousStatus'] === null || isPaymentStatus(event['previousStatus'])) &&
      isPaymentStatus(event['newStatus']) &&
      isTimestamp(event['timestamp']) &&
      (event['reason'] === null || (typeof event['reason'] === 'string' && event['reason'].length <= 300)),
    )
  );
}
