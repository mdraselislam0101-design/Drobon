/**
 * Partner / coupon / commission domain contract (Pump 7).
 *
 * The coupon code IS the partner attribution — there is deliberately no
 * separate referral-code system. All monetary values are minor units
 * (poisha) in BDT, computed exclusively on the server. Partners ever see
 * only their OWN aggregate statistics: never customer identities,
 * payment references, projects, scans, findings or reports.
 */

export const PARTNER_STATUSES = ['ACTIVE', 'DEACTIVATED'] as const;
export type PartnerStatus = (typeof PARTNER_STATUSES)[number];
export function isPartnerStatus(value: unknown): value is PartnerStatus {
  return typeof value === 'string' && (PARTNER_STATUSES as readonly string[]).includes(value);
}

export const COUPON_STATUSES = ['ACTIVE', 'INACTIVE'] as const;
export type CouponStatus = (typeof COUPON_STATUSES)[number];
export function isCouponStatus(value: unknown): value is CouponStatus {
  return typeof value === 'string' && (COUPON_STATUSES as readonly string[]).includes(value);
}

/** Lifecycle: created PENDING at payment approval → admin releases AVAILABLE → admin settles PAID. */
export const COMMISSION_STATUSES = ['PENDING', 'AVAILABLE', 'PAID'] as const;
export type CommissionStatus = (typeof COMMISSION_STATUSES)[number];
export function isCommissionStatus(value: unknown): value is CommissionStatus {
  return typeof value === 'string' && (COMMISSION_STATUSES as readonly string[]).includes(value);
}

export const PARTNER_AUDIT_ACTIONS = [
  'PARTNER_ACTIVATED',
  'PARTNER_DEACTIVATED',
  'PARTNER_REACTIVATED',
  'COUPON_STATE_CHANGED',
  'COUPON_CONFIGURATION_CHANGED',
  'COMMISSION_CREATED',
  'COMMISSION_AVAILABLE',
  'COMMISSION_PAID',
] as const;
export type PartnerAuditAction = (typeof PARTNER_AUDIT_ACTIONS)[number];
export function isPartnerAuditAction(value: unknown): value is PartnerAuditAction {
  return typeof value === 'string' && (PARTNER_AUDIT_ACTIONS as readonly string[]).includes(value);
}

/** Coupon codes normalize to uppercase; 3–40 chars allowing dashes (e.g. AEGIS-A). */
export const COUPON_CODE_PATTERN = /^[A-Z0-9][A-Z0-9-]{2,39}$/;
export function normalizeCouponCode(raw: string): string {
  return raw.trim().toUpperCase();
}

export const PARTNER_ID_PATTERN = /^ptr_[0-9a-f-]{36}$/i;
export const COMMISSION_ID_PATTERN = /^cms_[0-9a-f-]{36}$/i;

export const MIN_COUPON_DISCOUNT_PERCENT = 0;
export const MAX_COUPON_DISCOUNT_PERCENT = 90;
export const MIN_COMMISSION_PERCENT = 0;
export const MAX_COMMISSION_PERCENT = 50;

export interface PartnerCouponSummary {
  couponCode: string;
  status: CouponStatus;
  discountPercent: number;
  commissionPercent: number;
  expiresAt: string | null;
  createdAt: string;
  updatedAt: string;
}

/** Aggregate-only projection — the ONLY statistics a partner may ever receive. */
export interface PartnerCommissionTotals {
  pendingAmountMinorUnits: number;
  availableAmountMinorUnits: number;
  paidAmountMinorUnits: number;
  earnedAmountMinorUnits: number;
}

export interface PartnerAggregates {
  attributedPayments: number;
  approvedPayments: number;
  rejectedPayments: number;
  cancelledPayments: number;
  collectedAmountMinorUnits: number;
  commission: PartnerCommissionTotals;
  currency: 'BDT';
}

export interface PartnerDashboardResponse {
  partner: {
    partnerId: string;
    status: PartnerStatus;
    coupon: PartnerCouponSummary;
    complimentaryPro: { granted: true; grantedAt: string };
    createdAt: string;
    updatedAt: string;
  };
  aggregates: PartnerAggregates;
}

export interface PartnerAuditEvent {
  eventId: string;
  action: PartnerAuditAction;
  actorId: string;
  at: string;
  detail: string | null;
}

export interface AdminPartnerSummary {
  partnerId: string;
  userId: string;
  email: string;
  status: PartnerStatus;
  coupon: PartnerCouponSummary;
  complimentaryProGrantedAt: string;
  createdAt: string;
  updatedAt: string;
  deactivatedAt: string | null;
}

export interface AdminPartnersResponse {
  partners: AdminPartnerSummary[];
  page: number;
  pageSize: number;
  total: number;
}

export interface AdminPartnerResponse {
  partner: AdminPartnerSummary;
}

export interface AdminPartnerDetailResponse {
  partner: AdminPartnerSummary;
  aggregates: PartnerAggregates;
  audit: PartnerAuditEvent[];
}

/** Attribution inspection: identifiers, status and amounts only — never references or PII. */
export interface AdminPartnerPaymentSummary {
  paymentId: string;
  accountId: string;
  status: import('./payments.js').PaymentStatus;
  amountMinorUnits: number;
  currency: 'BDT';
  createdAt: string;
  approvedAt: string | null;
}

export interface AdminPartnerPaymentsResponse {
  payments: AdminPartnerPaymentSummary[];
  page: number;
  pageSize: number;
  total: number;
}

export interface CommissionSummary {
  commissionId: string;
  partnerId: string;
  paymentId: string;
  couponCode: string;
  status: CommissionStatus;
  currency: 'BDT';
  baseAmountMinorUnits: number;
  discountAmountMinorUnits: number;
  collectedAmountMinorUnits: number;
  commissionPercent: number;
  commissionAmountMinorUnits: number;
  createdAt: string;
  updatedAt: string;
  availableAt: string | null;
  paidAt: string | null;
}

export interface AdminCommissionsResponse {
  commissions: CommissionSummary[];
  page: number;
  pageSize: number;
  total: number;
}

export interface AdminCommissionResponse {
  commission: CommissionSummary;
}

export interface PaymentQuoteResponse {
  baseAmountMinorUnits: number;
  currency: 'BDT';
  coupon: null | {
    code: string;
    discountPercent: number;
    discountAmountMinorUnits: number;
    finalAmountMinorUnits: number;
  };
}

function isTimestamp(value: unknown): value is string {
  return typeof value === 'string' && !Number.isNaN(Date.parse(value));
}

function isNullableTimestamp(value: unknown): value is string | null {
  return value === null || isTimestamp(value);
}

function isPercent(value: unknown, max: number): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= max;
}

function isMoney(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function isCouponSummary(value: unknown): value is PartnerCouponSummary {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const r = value as Record<string, unknown>;
  return (
    typeof r['couponCode'] === 'string' && COUPON_CODE_PATTERN.test(r['couponCode']) &&
    isCouponStatus(r['status']) &&
    isPercent(r['discountPercent'], MAX_COUPON_DISCOUNT_PERCENT) &&
    isPercent(r['commissionPercent'], MAX_COMMISSION_PERCENT) &&
    isNullableTimestamp(r['expiresAt']) && isTimestamp(r['createdAt']) && isTimestamp(r['updatedAt'])
  );
}

function isAggregates(value: unknown): value is PartnerAggregates {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const r = value as Record<string, unknown>;
  const c = r['commission'];
  return (
    isMoney(r['attributedPayments']) && isMoney(r['approvedPayments']) &&
    isMoney(r['rejectedPayments']) && isMoney(r['cancelledPayments']) &&
    isMoney(r['collectedAmountMinorUnits']) && r['currency'] === 'BDT' &&
    typeof c === 'object' && c !== null && !Array.isArray(c) &&
    isMoney((c as Record<string, unknown>)['pendingAmountMinorUnits']) &&
    isMoney((c as Record<string, unknown>)['availableAmountMinorUnits']) &&
    isMoney((c as Record<string, unknown>)['paidAmountMinorUnits']) &&
    isMoney((c as Record<string, unknown>)['earnedAmountMinorUnits'])
  );
}

function isAdminPartnerSummary(value: unknown): value is AdminPartnerSummary {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const r = value as Record<string, unknown>;
  return (
    typeof r['partnerId'] === 'string' && PARTNER_ID_PATTERN.test(r['partnerId']) &&
    typeof r['userId'] === 'string' && r['userId'].length > 0 &&
    typeof r['email'] === 'string' && r['email'].length > 0 &&
    isPartnerStatus(r['status']) && isCouponSummary(r['coupon']) &&
    isTimestamp(r['complimentaryProGrantedAt']) && isTimestamp(r['createdAt']) &&
    isTimestamp(r['updatedAt']) && isNullableTimestamp(r['deactivatedAt'])
  );
}

function isAuditEvent(value: unknown): value is PartnerAuditEvent {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const r = value as Record<string, unknown>;
  return (
    typeof r['eventId'] === 'string' && r['eventId'].length > 0 &&
    isPartnerAuditAction(r['action']) &&
    typeof r['actorId'] === 'string' && r['actorId'].length > 0 &&
    isTimestamp(r['at']) &&
    (r['detail'] === null || (typeof r['detail'] === 'string' && r['detail'].length <= 200))
  );
}

export function isPartnerDashboardResponse(value: unknown): value is PartnerDashboardResponse {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const r = value as Record<string, unknown>;
  const p = r['partner'];
  if (typeof p !== 'object' || p === null || Array.isArray(p) || !isAggregates(r['aggregates'])) return false;
  const partner = p as Record<string, unknown>;
  const comp = partner['complimentaryPro'];
  return (
    typeof partner['partnerId'] === 'string' && PARTNER_ID_PATTERN.test(partner['partnerId']) &&
    isPartnerStatus(partner['status']) && isCouponSummary(partner['coupon']) &&
    typeof comp === 'object' && comp !== null && !Array.isArray(comp) &&
    (comp as Record<string, unknown>)['granted'] === true &&
    isTimestamp((comp as Record<string, unknown>)['grantedAt']) &&
    isTimestamp(partner['createdAt']) && isTimestamp(partner['updatedAt'])
  );
}

export function isAdminPartnersResponse(value: unknown): value is AdminPartnersResponse {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const r = value as Record<string, unknown>;
  return Array.isArray(r['partners']) && (r['partners'] as unknown[]).every(isAdminPartnerSummary) &&
    Number.isSafeInteger(r['page']) && Number.isSafeInteger(r['pageSize']) && Number.isSafeInteger(r['total']);
}

export function isAdminPartnerResponse(value: unknown): value is AdminPartnerResponse {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  return isAdminPartnerSummary((value as Record<string, unknown>)['partner']);
}

export function isAdminPartnerDetailResponse(value: unknown): value is AdminPartnerDetailResponse {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const r = value as Record<string, unknown>;
  return isAdminPartnerSummary(r['partner']) && isAggregates(r['aggregates']) &&
    Array.isArray(r['audit']) && (r['audit'] as unknown[]).every(isAuditEvent);
}

export function isAdminPartnerPaymentsResponse(value: unknown): value is AdminPartnerPaymentsResponse {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const r = value as Record<string, unknown>;
  if (!Array.isArray(r['payments'])) return false;
  return (r['payments'] as unknown[]).every((p) => {
    if (typeof p !== 'object' || p === null || Array.isArray(p)) return false;
    const row = p as Record<string, unknown>;
    return typeof row['paymentId'] === 'string' && typeof row['accountId'] === 'string' &&
      isMoney(row['amountMinorUnits']) && row['currency'] === 'BDT' &&
      isTimestamp(row['createdAt']) && isNullableTimestamp(row['approvedAt']);
  });
}

function isCommissionSummary(value: unknown): value is CommissionSummary {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const r = value as Record<string, unknown>;
  return (
    typeof r['commissionId'] === 'string' && COMMISSION_ID_PATTERN.test(r['commissionId']) &&
    typeof r['partnerId'] === 'string' && PARTNER_ID_PATTERN.test(r['partnerId']) &&
    typeof r['paymentId'] === 'string' && typeof r['couponCode'] === 'string' &&
    isCommissionStatus(r['status']) && r['currency'] === 'BDT' &&
    isMoney(r['baseAmountMinorUnits']) && isMoney(r['discountAmountMinorUnits']) &&
    isMoney(r['collectedAmountMinorUnits']) && isMoney(r['commissionAmountMinorUnits']) &&
    isPercent(r['commissionPercent'], MAX_COMMISSION_PERCENT) &&
    isTimestamp(r['createdAt']) && isTimestamp(r['updatedAt']) &&
    isNullableTimestamp(r['availableAt']) && isNullableTimestamp(r['paidAt'])
  );
}

export function isAdminCommissionsResponse(value: unknown): value is AdminCommissionsResponse {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const r = value as Record<string, unknown>;
  return Array.isArray(r['commissions']) && (r['commissions'] as unknown[]).every(isCommissionSummary) &&
    Number.isSafeInteger(r['page']) && Number.isSafeInteger(r['pageSize']) && Number.isSafeInteger(r['total']);
}

export function isAdminCommissionResponse(value: unknown): value is AdminCommissionResponse {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  return isCommissionSummary((value as Record<string, unknown>)['commission']);
}

export function isPaymentQuoteResponse(value: unknown): value is PaymentQuoteResponse {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const r = value as Record<string, unknown>;
  if (!isMoney(r['baseAmountMinorUnits']) || r['currency'] !== 'BDT') return false;
  const c = r['coupon'];
  if (c === null) return true;
  if (typeof c !== 'object' || Array.isArray(c)) return false;
  const coupon = c as Record<string, unknown>;
  return typeof coupon['code'] === 'string' && COUPON_CODE_PATTERN.test(coupon['code']) &&
    isPercent(coupon['discountPercent'], MAX_COUPON_DISCOUNT_PERCENT) &&
    isMoney(coupon['discountAmountMinorUnits']) && isMoney(coupon['finalAmountMinorUnits']);
}
