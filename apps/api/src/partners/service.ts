import { randomUUID } from 'node:crypto';
import type {
  AdminCommissionResponse,
  AdminCommissionsResponse,
  AdminPartnerDetailResponse,
  AdminPartnerPaymentsResponse,
  AdminPartnerResponse,
  AdminPartnersResponse,
  CommissionStatus,
  CommissionSummary,
  PartnerAggregates,
  PartnerAuditEvent,
  PartnerDashboardResponse,
} from '@drobon/shared';
import { normalizeCouponCode } from '@drobon/shared';
import { conflict, notFound, validationError } from '../errors.js';
import { redactAssistantText } from '../assistant/redaction.js';
import type { UserRepository } from '../auth/repositories.js';
import type { PaymentRecord } from '../payments/store.js';
import type { CommissionRecord, PartnerListFilters, CommissionListFilters, PartnerRecord, PartnerStore } from './store.js';

/** Read-only payment surface the partner domain may use for attribution aggregates. */
export interface PaymentReadModel {
  listAll(): PaymentRecord[];
}

export interface CouponDecision {
  ok: boolean;
  couponCode: string;
  partnerId?: string;
  discountPercent?: number;
  commissionPercent?: number;
}

export interface PartnerService {
  /** Resolve a coupon to a redemption decision (partner ACTIVE, coupon ACTIVE, unexpired). */
  resolveCoupon(rawCode: string): CouponDecision;
  activatePartner(adminId: string, input: {
    userId: string;
    couponCode: string;
    discountPercent: number;
    commissionPercent: number;
  }): Promise<AdminPartnerResponse>;
  listPartners(filters: PartnerListFilters, page: number, pageSize: number): AdminPartnersResponse;
  getPartnerDetail(partnerId: string): AdminPartnerDetailResponse;
  setPartnerStatus(partnerId: string, status: 'ACTIVE' | 'DEACTIVATED', adminId: string): Promise<AdminPartnerResponse>;
  updateCoupon(partnerId: string, patch: {
    status?: 'ACTIVE' | 'INACTIVE';
    discountPercent?: number;
    commissionPercent?: number;
    expiresAt?: string | null;
  }, adminId: string): Promise<AdminPartnerResponse>;
  listPartnerPayments(partnerId: string, page: number, pageSize: number): AdminPartnerPaymentsResponse;
  listCommissions(filters: CommissionListFilters, page: number, pageSize: number): AdminCommissionsResponse;
  transitionCommission(commissionId: string, to: 'AVAILABLE' | 'PAID', adminId: string): Promise<AdminCommissionResponse>;
  dashboard(userId: string): PartnerDashboardResponse;
  /** Idempotent commission settlement for an APPROVED payment with coupon attribution. */
  settleCommissionForPayment(payment: PaymentRecord, actorId: string): Promise<void>;
  /** Startup recovery: settle commissions for any APPROVED attributed payment that lacks one. */
  recoverUnsettledCommissions(): Promise<void>;
}

function percentInt(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0 && value <= 100;
}

function auditEvent(action: PartnerAuditEvent['action'], actorId: string, at: string, detail: string | null): PartnerAuditEvent {
  const redacted = detail === null ? null : redactAssistantText(detail).text.slice(0, 200);
  return { eventId: `evt_${randomUUID()}`, action, actorId, at, detail: redacted };
}

function toCommissionSummary(record: CommissionRecord): CommissionSummary {
  return {
    commissionId: record.commissionId,
    partnerId: record.partnerId,
    paymentId: record.paymentId,
    couponCode: record.couponCode,
    status: record.status,
    currency: record.currency,
    baseAmountMinorUnits: record.baseAmountMinorUnits,
    discountAmountMinorUnits: record.discountAmountMinorUnits,
    collectedAmountMinorUnits: record.collectedAmountMinorUnits,
    commissionPercent: record.commissionPercent,
    commissionAmountMinorUnits: record.commissionAmountMinorUnits,
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
    availableAt: record.availableAt,
    paidAt: record.paidAt,
  };
}

function toAdminPartnerSummary(record: PartnerRecord) {
  return {
    partnerId: record.partnerId,
    userId: record.userId,
    email: record.email,
    status: record.status,
    coupon: { ...record.coupon },
    complimentaryProGrantedAt: record.complimentaryProGrantedAt,
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
    deactivatedAt: record.deactivatedAt,
  };
}

export function createPartnerService(options: {
  store: PartnerStore;
  users: UserRepository;
  payments: PaymentReadModel;
  now?: () => number;
}): PartnerService {
  const { store, users, payments } = options;
  const now = options.now ?? Date.now;
  const timestamp = (): string => new Date(now()).toISOString();

  const resolveCoupon = (rawCode: string): CouponDecision => {
    const couponCode = normalizeCouponCode(rawCode);
    const partner = store.getPartnerByCoupon(couponCode);
    if (partner === undefined || partner.status !== 'ACTIVE' || partner.coupon.status !== 'ACTIVE') {
      return { ok: false, couponCode };
    }
    if (partner.coupon.expiresAt !== null && Date.parse(partner.coupon.expiresAt) <= now()) {
      return { ok: false, couponCode };
    }
    return {
      ok: true,
      couponCode,
      partnerId: partner.partnerId,
      discountPercent: partner.coupon.discountPercent,
      commissionPercent: partner.coupon.commissionPercent,
    };
  };

  const aggregatesFor = (partner: PartnerRecord): PartnerAggregates => {
    const attributed = payments.listAll().filter((payment) => payment.attribution?.partnerId === partner.partnerId);
    const commissions = store.listCommissionsForPartner(partner.partnerId);
    const sum = (list: CommissionRecord[], statuses: readonly CommissionStatus[]): number =>
      list.filter((commission) => statuses.includes(commission.status)).reduce((total, commission) => total + commission.commissionAmountMinorUnits, 0);
    const pending = sum(commissions, ['PENDING']);
    const available = sum(commissions, ['AVAILABLE']);
    const paid = sum(commissions, ['PAID']);
    return {
      attributedPayments: attributed.length,
      approvedPayments: attributed.filter((payment) => payment.status === 'APPROVED').length,
      rejectedPayments: attributed.filter((payment) => payment.status === 'REJECTED').length,
      cancelledPayments: attributed.filter((payment) => payment.status === 'CANCELLED').length,
      collectedAmountMinorUnits: attributed.filter((payment) => payment.status === 'APPROVED').reduce((total, payment) => total + payment.amountMinorUnits, 0),
      commission: {
        pendingAmountMinorUnits: pending,
        availableAmountMinorUnits: available,
        paidAmountMinorUnits: paid,
        earnedAmountMinorUnits: pending + available + paid,
      },
      currency: 'BDT',
    };
  };

  const service: PartnerService = {
    resolveCoupon,
    activatePartner: async (adminId, input) => {
      const user = await users.findById(input.userId);
      if (user === undefined) throw validationError([{ path: 'userId', message: 'The selected account does not exist.' }]);
      if (!percentInt(input.discountPercent) || input.discountPercent > 90) {
        throw validationError([{ path: 'discountPercent', message: 'Discount must be an integer percent between 0 and 90.' }]);
      }
      if (!percentInt(input.commissionPercent) || input.commissionPercent > 50) {
        throw validationError([{ path: 'commissionPercent', message: 'Commission must be an integer percent between 0 and 50.' }]);
      }
      const couponCode = normalizeCouponCode(input.couponCode);
      const at = timestamp();
      const record: PartnerRecord = {
        partnerId: `ptr_${randomUUID()}`,
        userId: user.id,
        email: user.email,
        status: 'ACTIVE',
        coupon: { couponCode, status: 'ACTIVE', discountPercent: input.discountPercent, commissionPercent: input.commissionPercent, expiresAt: null, createdAt: at, updatedAt: at },
        complimentaryProGrantedAt: at,
        createdAt: at,
        updatedAt: at,
        deactivatedAt: null,
        audit: [auditEvent('PARTNER_ACTIVATED', adminId, at, `Partner activated with coupon ${couponCode}.`)],
      };
      const stored = await store.createPartner(record);
      if (stored.kind === 'USER_EXISTS') throw conflict('This account already has a partner identity.');
      if (stored.kind === 'COUPON_EXISTS') throw conflict('This coupon code is already assigned to another partner.');
      // Complimentary PRO: entitlement only — never a payment, revenue or commission event.
      const activation = await users.activatePro(user.id, at);
      if (activation === 'NOT_FOUND') {
        // Compensation for the impossible-account case: do not leave a silent half-state.
        await store.updatePartnerStatus(record.partnerId, 'DEACTIVATED', timestamp(), auditEvent('PARTNER_DEACTIVATED', adminId, timestamp(), 'Activation reversed: account missing.'));
        throw new Error('Partner activation references a missing account.');
      }
      return { partner: toAdminPartnerSummary(record) };
    },
    listPartners: (filters, page, pageSize) => {
      const result = store.listPartners(filters, page, pageSize);
      return { partners: result.partners.map(toAdminPartnerSummary), page, pageSize, total: result.total };
    },
    getPartnerDetail: (partnerId) => {
      const record = store.getPartnerById(partnerId);
      if (record === undefined) throw notFound();
      return {
        partner: toAdminPartnerSummary(record),
        aggregates: aggregatesFor(record),
        audit: record.audit.slice(-50).map((event) => ({ ...event })),
      };
    },
    setPartnerStatus: async (partnerId, status, adminId) => {
      const current = store.getPartnerById(partnerId);
      if (current === undefined) throw notFound();
      const at = timestamp();
      const event = auditEvent(status === 'DEACTIVATED' ? 'PARTNER_DEACTIVATED' : 'PARTNER_REACTIVATED', adminId, at, `Partner ${status === 'DEACTIVATED' ? 'deactivated' : 'reactivated'}.`);
      const result = await store.updatePartnerStatus(partnerId, status, at, event);
      if (result.kind === 'NOT_FOUND') throw notFound();
      return { partner: toAdminPartnerSummary(result.partner) };
    },
    updateCoupon: async (partnerId, patch, adminId) => {
      const current = store.getPartnerById(partnerId);
      if (current === undefined) throw notFound();
      const issues: Array<{ path: string; message: string }> = [];
      if (patch.discountPercent !== undefined && (!percentInt(patch.discountPercent) || patch.discountPercent > 90)) {
        issues.push({ path: 'discountPercent', message: 'Discount must be an integer percent between 0 and 90.' });
      }
      if (patch.commissionPercent !== undefined && (!percentInt(patch.commissionPercent) || patch.commissionPercent > 50)) {
        issues.push({ path: 'commissionPercent', message: 'Commission must be an integer percent between 0 and 50.' });
      }
      if (patch.expiresAt !== undefined && patch.expiresAt !== null && (Number.isNaN(Date.parse(patch.expiresAt)))) {
        issues.push({ path: 'expiresAt', message: 'Expiry must be an ISO 8601 timestamp or null.' });
      }
      if (issues.length > 0) throw validationError(issues);
      const at = timestamp();
      const events: PartnerAuditEvent[] = [];
      if (patch.status !== undefined && patch.status !== current.coupon.status) {
        events.push(auditEvent('COUPON_STATE_CHANGED', adminId, at, `Coupon ${current.coupon.couponCode} ${patch.status === 'ACTIVE' ? 'activated' : 'deactivated'}.`));
      }
      if ((patch.discountPercent !== undefined && patch.discountPercent !== current.coupon.discountPercent) ||
          (patch.commissionPercent !== undefined && patch.commissionPercent !== current.coupon.commissionPercent) ||
          (patch.expiresAt !== undefined && patch.expiresAt !== current.coupon.expiresAt)) {
        events.push(auditEvent('COUPON_CONFIGURATION_CHANGED', adminId, at, `Coupon ${current.coupon.couponCode} configuration updated.`));
      }
      const result = await store.updateCoupon(partnerId, patch, at, events);
      if (result.kind === 'NOT_FOUND') throw notFound();
      return { partner: toAdminPartnerSummary(result.partner) };
    },
    listPartnerPayments: (partnerId, page, pageSize) => {
      const record = store.getPartnerById(partnerId);
      if (record === undefined) throw notFound();
      const all = payments.listAll()
        .filter((payment) => payment.attribution?.partnerId === partnerId)
        .sort((a, b) => (a.createdAt > b.createdAt ? -1 : a.createdAt < b.createdAt ? 1 : a.paymentId.localeCompare(b.paymentId)));
      const offset = (page - 1) * pageSize;
      return {
        payments: all.slice(offset, offset + pageSize).map((payment) => ({
          paymentId: payment.paymentId,
          accountId: payment.accountId,
          status: payment.status,
          amountMinorUnits: payment.amountMinorUnits,
          currency: payment.currency,
          createdAt: payment.createdAt,
          approvedAt: payment.approvedAt,
        })),
        page,
        pageSize,
        total: all.length,
      };
    },
    listCommissions: (filters, page, pageSize) => {
      const result = store.listCommissions(filters, page, pageSize);
      return { commissions: result.commissions.map(toCommissionSummary), page, pageSize, total: result.total };
    },
    transitionCommission: async (commissionId, to, adminId) => {
      const current = store.getCommission(commissionId);
      if (current === undefined) throw notFound();
      const at = timestamp();
      const event = auditEvent(to === 'AVAILABLE' ? 'COMMISSION_AVAILABLE' : 'COMMISSION_PAID', adminId, at, `Commission ${commissionId} marked ${to.toLowerCase()}.`);
      const result = await store.transitionCommission(commissionId, to, at, event);
      if (!('commission' in result)) {
        if (result.kind === 'NOT_FOUND') throw notFound();
        throw conflict('This commission cannot transition from its current state.');
      }
      return { commission: toCommissionSummary(result.commission) };
    },
    dashboard: (userId) => {
      const record = store.getPartnerByUserId(userId);
      if (record === undefined) throw notFound();
      return {
        partner: {
          partnerId: record.partnerId,
          status: record.status,
          coupon: { ...record.coupon },
          complimentaryPro: { granted: true as const, grantedAt: record.complimentaryProGrantedAt },
          createdAt: record.createdAt,
          updatedAt: record.updatedAt,
        },
        aggregates: aggregatesFor(record),
      };
    },
    settleCommissionForPayment: async (payment, actorId) => {
      const attribution = payment.attribution;
      if (attribution === undefined) return;
      const partner = store.getPartnerById(attribution.partnerId);
      if (partner === undefined) return;
      const at = timestamp();
      const collectedAmountMinorUnits = payment.amountMinorUnits;
      const commissionAmountMinorUnits = Math.floor((collectedAmountMinorUnits * attribution.commissionPercent) / 100);
      const record: CommissionRecord = {
        commissionId: `cms_${randomUUID()}`,
        partnerId: partner.partnerId,
        paymentId: payment.paymentId,
        couponCode: attribution.couponCode,
        status: 'PENDING',
        currency: 'BDT',
        baseAmountMinorUnits: attribution.baseAmountMinorUnits,
        discountAmountMinorUnits: attribution.discountAmountMinorUnits,
        collectedAmountMinorUnits,
        commissionPercent: attribution.commissionPercent,
        commissionAmountMinorUnits,
        createdAt: at,
        updatedAt: at,
        availableAt: null,
        paidAt: null,
      };
      const created = await store.createCommission(record);
      if (created.kind === 'CREATED') {
        await store.appendAudit(partner.partnerId, auditEvent('COMMISSION_CREATED', actorId, at, `Commission ${record.commissionId} created for payment ${payment.paymentId}.`));
      }
    },
    recoverUnsettledCommissions: async () => {
      for (const payment of payments.listAll()) {
        if (payment.status === 'APPROVED' && payment.attribution !== undefined && store.getCommissionByPayment(payment.paymentId) === undefined) {
          await service.settleCommissionForPayment(payment, 'system:partner-recovery');
        }
      }
    },
  };
  return service;
}
