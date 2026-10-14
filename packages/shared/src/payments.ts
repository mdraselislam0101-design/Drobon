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
  'PAYMENT_COUPON_ATTRIBUTED',
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

/** Coupon attribution projection (Pump 7). Absent when no coupon was applied. */
export interface PaymentAttributionSummary {
  couponCode: string;
  baseAmountMinorUnits: number;
  discountAmountMinorUnits: number;
}

export interface PaymentSummary {
  paymentId: string;
  plan: 'PRO';
  /** Final collected amount (after any coupon discount). */
  amountMinorUnits: number;
  attribution?: PaymentAttributionSummary;
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

/**
 * A platform-configured manual-transfer destination (Phase 20). Managed
 * exclusively by platform admins via `PATCH/POST /api/v1/admin/payment-config…`.
 * The transfer METHOD contract (`MANUAL_TRANSFER`) is unchanged — destinations
 * are the server-authoritative "where do I send the money" metadata shown to
 * users. Account numbers are transfer targets (safe to show to the payer);
 * audit records still mask them.
 */
export interface PaymentMethodDestination {
  methodId: string;
  method: PaymentMethod;
  displayName: string;
  accountNumber: string;
  instructions: string;
  enabled: boolean;
}

export const PAYMENT_CONFIG_AUDIT_ACTIONS = [
  'PAYMENT_CONFIG_PRICE_UPDATED',
  'PAYMENT_CONFIG_METHOD_ADDED',
  'PAYMENT_CONFIG_METHOD_UPDATED',
] as const;
export type PaymentConfigAuditAction = (typeof PAYMENT_CONFIG_AUDIT_ACTIONS)[number];
export function isPaymentConfigAuditAction(value: unknown): value is PaymentConfigAuditAction {
  return typeof value === 'string' && (PAYMENT_CONFIG_AUDIT_ACTIONS as readonly string[]).includes(value);
}

/** Bounded audit entry for an admin payment-configuration change. */
export interface PaymentConfigAuditEntry {
  entryId: string;
  at: string;
  actorId: string;
  action: PaymentConfigAuditAction;
  /** Human-readable change summary with account numbers masked. */
  detail: string;
}

export interface PaymentConfigResponse {
  currentPlan: 'FREE' | 'PRO';
  proPriceMinorUnits: number;
  currency: 'BDT';
  manualPaymentMethods: PaymentMethod[];
  manualPaymentInstructions: string;
  /** Currently ENABLED transfer destinations (disabled ones are never offered). */
  manualPaymentDestinations: PaymentMethodDestination[];
  onlineGateway: 'UNAVAILABLE';
  coupons: 'SUPPORTED';
}

/** Platform-admin view of the live payment configuration (Phase 20). */
export interface AdminPaymentConfigResponse {
  proPriceMinorUnits: number;
  currency: 'BDT';
  /** ALL destinations, enabled and disabled. */
  destinations: PaymentMethodDestination[];
  updatedAt: string;
  audit: PaymentConfigAuditEntry[];
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
    (value['rejectionReason'] === null || (typeof value['rejectionReason'] === 'string' && value['rejectionReason'].length <= 300)) &&
    (value['attribution'] === undefined || isAttributionSummary(value['attribution']))
  );
}

function isAttributionSummary(value: unknown): value is PaymentAttributionSummary {
  return (
    isRecord(value) &&
    typeof value['couponCode'] === 'string' && /^[A-Z0-9][A-Z0-9-]{2,39}$/.test(value['couponCode']) &&
    typeof value['baseAmountMinorUnits'] === 'number' &&
    Number.isSafeInteger(value['baseAmountMinorUnits']) && value['baseAmountMinorUnits'] > 0 &&
    typeof value['discountAmountMinorUnits'] === 'number' &&
    Number.isSafeInteger(value['discountAmountMinorUnits']) && value['discountAmountMinorUnits'] >= 0
  );
}

export function isPaymentMethodDestination(value: unknown): value is PaymentMethodDestination {
  return (
    isRecord(value) &&
    typeof value['methodId'] === 'string' && /^pmd_[0-9a-f-]{36}$/i.test(value['methodId']) &&
    isPaymentMethod(value['method']) &&
    typeof value['displayName'] === 'string' && value['displayName'].length >= 1 && value['displayName'].length <= 80 &&
    typeof value['accountNumber'] === 'string' && value['accountNumber'].length >= 4 && value['accountNumber'].length <= 40 &&
    typeof value['instructions'] === 'string' && value['instructions'].length <= 300 &&
    typeof value['enabled'] === 'boolean'
  );
}

export function isPaymentConfigAuditEntry(value: unknown): value is PaymentConfigAuditEntry {
  return (
    isRecord(value) &&
    typeof value['entryId'] === 'string' && /^pca_[0-9a-f-]{36}$/i.test(value['entryId']) &&
    isTimestamp(value['at']) &&
    typeof value['actorId'] === 'string' && value['actorId'].length > 0 &&
    isPaymentConfigAuditAction(value['action']) &&
    typeof value['detail'] === 'string' && value['detail'].length > 0 && value['detail'].length <= 300
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
    Array.isArray(value['manualPaymentDestinations']) &&
    value['manualPaymentDestinations'].every(isPaymentMethodDestination) &&
    value['onlineGateway'] === 'UNAVAILABLE' &&
    value['coupons'] === 'SUPPORTED'
  );
}

export function isAdminPaymentConfigResponse(value: unknown): value is AdminPaymentConfigResponse {
  return (
    isRecord(value) &&
    typeof value['proPriceMinorUnits'] === 'number' &&
    Number.isSafeInteger(value['proPriceMinorUnits']) &&
    value['proPriceMinorUnits'] > 0 &&
    value['currency'] === 'BDT' &&
    Array.isArray(value['destinations']) &&
    value['destinations'].every(isPaymentMethodDestination) &&
    isTimestamp(value['updatedAt']) &&
    Array.isArray(value['audit']) &&
    value['audit'].length <= 200 &&
    value['audit'].every(isPaymentConfigAuditEntry)
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
