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
  Subscription,
} from '@drobon/shared';
import { normalizeCouponCode } from '@drobon/shared';
import { conflict, notFound, unavailable, validationError } from '../errors.js';
import { redactAssistantText } from '../assistant/redaction.js';
import type { UserRepository } from '../auth/repositories.js';
import { resolveSubscription } from '../auth/subscriptions.js';
import { createAccountMutationLock, type AccountMutationLock } from '../auth/accountMutationLock.js';
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
  /** Stop serving traffic if an uncertain cross-store write cannot be compensated. */
  isConsistencyBlocked(): boolean;
  /** Quarantine historical partial activations before serving traffic. */
  recoverInterruptedActivations(): Promise<void>;
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
  withAccountMutation?: AccountMutationLock;
}): PartnerService {
  const { store, users, payments } = options;
  const now = options.now ?? Date.now;
  const timestamp = (): string => new Date(now()).toISOString();

  const withAccountMutation = options.withAccountMutation ?? createAccountMutationLock();
  // Legacy records do not prove whether the old second write succeeded.
  // Quarantine suspect records in memory, without rewriting historical data.
  const quarantined = new Set<string>();
  let consistencyBlocked = false;
  let activeMutations = 0;
  const hidden = (record: PartnerRecord): boolean =>
    record.activationPending !== undefined || record.activationRecovery === 'INCOMPLETE' || quarantined.has(record.partnerId);

  const compensate = async (userId: string, at: string, previous: Subscription | null): Promise<void> => {
    try {
      const restored = await users.restorePartnerSubscription?.(userId, at, previous);
      if (restored !== 'RESTORED') throw new Error('Conditional account compensation did not apply.');
    } catch {
      // The app refuses subsequent traffic. Restart recovery must reconcile
      // the durable intent before any request can observe an uncertain state.
      consistencyBlocked = true;
      throw unavailable('Partner activation requires recovery before requests can continue.');
    }
  };

  const finishPending = async (record: PartnerRecord, actorId: string): Promise<PartnerRecord> => {
    const user = await users.findById(record.userId);
    if (user === undefined) throw validationError([{ path: 'userId', message: 'The selected account does not exist.' }]);
    const prior = user.subscription === undefined ? null : { ...user.subscription };
    const alreadyPro = prior?.plan === 'PRO' && prior.status === 'ACTIVE';
    if (!alreadyPro && users.restorePartnerSubscription === undefined) {
      throw unavailable('The account repository cannot safely recover partner activation.');
    }
    const at = timestamp();
    const intent = await store.refreshPendingActivation(record.partnerId, at, prior);
    if (intent === undefined) throw conflict('Partner activation changed; retry the request.');
    // Hold the application traffic gate while the two stores can disagree.
    activeMutations += 1;
    try {
      let activation: 'ACTIVATED' | 'ALREADY_ACTIVE' | 'NOT_FOUND';
      try {
        activation = await users.activatePro(record.userId, at);
      } catch (error) {
        // A repository may throw after a write; verify before deciding whether
        // the account must be restored. Failure to inspect is unsafe.
        if (!alreadyPro) {
          try {
            const after = await users.findById(record.userId);
            if (after === undefined) { consistencyBlocked = true; }
            else if (after.subscription?.plan === 'PRO' && after.subscription.status === 'ACTIVE' &&
                     after.subscription.createdAt === at && after.subscription.updatedAt === at) {
              await compensate(record.userId, at, prior);
            } else if (JSON.stringify(after.subscription ?? null) !== JSON.stringify(prior)) {
              consistencyBlocked = true;
            }
          } catch { consistencyBlocked = true; }
        }
        if (consistencyBlocked) throw unavailable('Partner activation requires recovery before requests can continue.');
        throw error;
      }
      if (activation === 'NOT_FOUND') throw new Error('Partner activation references a missing account.');
      try {
        const finished = await store.finishActivation(record.partnerId, at,
          auditEvent('PARTNER_ACTIVATED', actorId, at, `Partner activated with coupon ${record.coupon.couponCode}.`));
        if (finished === undefined) throw new Error('Partner activation state changed.');
        quarantined.delete(record.partnerId);
        return finished;
      } catch (error) {
        // A collaborator can throw after successfully committing; in that case
        // the durable active partner and account PRO are already consistent.
        let observed: PartnerRecord | undefined;
        try {
          observed = store.getPartnerById(record.partnerId);
        } catch {
          // We cannot safely compensate if the final partner write might
          // already have committed. Keep the gate closed for restart recovery.
          consistencyBlocked = true;
          throw unavailable('Partner activation requires recovery before requests can continue.');
        }
        if (observed === undefined || (observed.status !== 'ACTIVE' && observed.activationPending === undefined)) {
          consistencyBlocked = true;
          throw unavailable('Partner activation requires recovery before requests can continue.');
        }
        if (observed.status === 'ACTIVE' && observed.activationPending === undefined) {
          quarantined.delete(record.partnerId);
          return observed;
        }
        if (activation === 'ACTIVATED') await compensate(record.userId, at, prior);
        throw error;
      }
    } finally {
      activeMutations -= 1;
    }
  };

  const resolveCoupon = (rawCode: string): CouponDecision => {
    const couponCode = normalizeCouponCode(rawCode);
    const partner = store.getPartnerByCoupon(couponCode);
    if (partner === undefined || hidden(partner) || partner.status !== 'ACTIVE' || partner.coupon.status !== 'ACTIVE') {
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
    activatePartner: (adminId, input) => withAccountMutation(input.userId, async () => {
      const user = await users.findById(input.userId);
      if (user === undefined) throw validationError([{ path: 'userId', message: 'The selected account does not exist.' }]);
      if (!percentInt(input.discountPercent) || input.discountPercent > 90) {
        throw validationError([{ path: 'discountPercent', message: 'Discount must be an integer percent between 0 and 90.' }]);
      }
      if (!percentInt(input.commissionPercent) || input.commissionPercent > 50) {
        throw validationError([{ path: 'commissionPercent', message: 'Commission must be an integer percent between 0 and 50.' }]);
      }
      const couponCode = normalizeCouponCode(input.couponCode);
      const sameInput = (partner: PartnerRecord): boolean => partner.coupon.couponCode === couponCode &&
        partner.coupon.discountPercent === input.discountPercent && partner.coupon.commissionPercent === input.commissionPercent;
      let existing = store.getPartnerByUserId(user.id);
      if (existing !== undefined) {
        if (!sameInput(existing)) throw conflict('This account already has a partner identity.');
        if (existing.activationPending !== undefined) return { partner: toAdminPartnerSummary(await finishPending(existing, adminId)) };
        if (existing.activationRecovery === 'INCOMPLETE' || quarantined.has(existing.partnerId)) {
          const at = timestamp();
          existing = await store.prepareLegacyActivation(existing.partnerId, at, user.subscription ?? null,
            auditEvent('PARTNER_DEACTIVATED', adminId, at, 'Historical incomplete activation explicitly retried.'));
          if (existing === undefined) throw conflict('Partner activation changed; retry the request.');
          return { partner: toAdminPartnerSummary(await finishPending(existing, adminId)) };
        }
        if (existing.status === 'ACTIVE') return { partner: toAdminPartnerSummary(existing) };
        throw conflict('This account already has a partner identity.');
      }
      if (users.restorePartnerSubscription === undefined && !(resolveSubscription(user).plan === 'PRO' && resolveSubscription(user).status === 'ACTIVE')) {
        throw unavailable('The account repository cannot safely recover partner activation.');
      }
      const at = timestamp();
      const record: PartnerRecord = {
        partnerId: `ptr_${randomUUID()}`,
        userId: user.id,
        email: user.email,
        status: 'DEACTIVATED',
        coupon: { couponCode, status: 'ACTIVE', discountPercent: input.discountPercent, commissionPercent: input.commissionPercent, expiresAt: null, createdAt: at, updatedAt: at },
        // This timestamp is not exposed until the pending intent is finalized.
        complimentaryProGrantedAt: at,
        activationPending: { initiatedAt: at, previousSubscription: user.subscription === undefined ? null : { ...user.subscription } },
        createdAt: at,
        updatedAt: at,
        deactivatedAt: at,
        audit: [],
      };
      const stored = await store.createPartner(record);
      if (stored.kind === 'COUPON_EXISTS') throw conflict('This coupon code is already assigned to another partner.');
      if (stored.kind === 'USER_EXISTS') {
        const prior = store.getPartnerByUserId(user.id);
        if (prior !== undefined && sameInput(prior) && prior.activationPending !== undefined) {
          return { partner: toAdminPartnerSummary(await finishPending(prior, adminId)) };
        }
        throw conflict('This account already has a partner identity.');
      }
      if (!('partner' in stored)) throw new Error('Partner activation failed.');
      return { partner: toAdminPartnerSummary(await finishPending(stored.partner, adminId)) };
    }),
    listPartners: (filters, page, pageSize) => {
      const all = store.listAllPartners().filter((record) => !hidden(record) && (filters.status === undefined || record.status === filters.status))
        .sort((a, b) => (a.createdAt > b.createdAt ? -1 : a.createdAt < b.createdAt ? 1 : a.partnerId.localeCompare(b.partnerId)));
      const offset = (page - 1) * pageSize;
      return { partners: all.slice(offset, offset + pageSize).map(toAdminPartnerSummary), page, pageSize, total: all.length };
    },
    getPartnerDetail: (partnerId) => {
      const record = store.getPartnerById(partnerId);
      if (record === undefined || hidden(record)) throw notFound();
      return {
        partner: toAdminPartnerSummary(record),
        aggregates: aggregatesFor(record),
        audit: record.audit.slice(-50).map((event) => ({ ...event })),
      };
    },
    setPartnerStatus: async (partnerId, status, adminId) => {
      const current = store.getPartnerById(partnerId);
      if (current === undefined) throw notFound();
      if (hidden(current)) throw conflict('Incomplete activation requires an explicit matching activation retry.');
      const at = timestamp();
      const event = auditEvent(status === 'DEACTIVATED' ? 'PARTNER_DEACTIVATED' : 'PARTNER_REACTIVATED', adminId, at, `Partner ${status === 'DEACTIVATED' ? 'deactivated' : 'reactivated'}.`);
      const result = await store.updatePartnerStatus(partnerId, status, at, event);
      if (result.kind === 'NOT_FOUND') throw notFound();
      return { partner: toAdminPartnerSummary(result.partner) };
    },
    updateCoupon: async (partnerId, patch, adminId) => {
      const current = store.getPartnerById(partnerId);
      if (current === undefined) throw notFound();
      if (hidden(current)) throw conflict('Incomplete activation requires an explicit matching activation retry.');
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
      if (record === undefined || hidden(record)) throw notFound();
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
      if (record === undefined || hidden(record)) throw notFound();
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
    isConsistencyBlocked: () => consistencyBlocked || activeMutations > 0,
    recoverInterruptedActivations: async () => {
      // A timestamp is not a transaction identifier. If an approval for the
      // same account might have made it PRO, never infer that a pending
      // partner grant succeeded, even when the timestamps are identical.
      // APPROVING matters too: payment recovery runs after partner recovery.
      const possiblyPaidAccounts = new Set(payments.listAll()
        .filter((payment) => payment.plan === 'PRO' && (payment.status === 'APPROVING' || payment.status === 'APPROVED'))
        .map((payment) => payment.accountId));
      for (const record of store.listAllPartners()) {
        const user = await users.findById(record.userId);
        const subscription = user === undefined ? undefined : resolveSubscription(user);
        if (record.grantModel === 'PARTNER_STORE_V1') {
          // Compatibility for any record created by the interrupted earlier
          // implementation: migrate its real grant back to the account before traffic.
          if (user === undefined) throw new Error('Partner grant references a missing account.');
          const at = timestamp();
          if (await users.activatePro(record.userId, at) === 'NOT_FOUND') throw new Error('Partner grant account disappeared.');
          await store.migrateAtomicGrant(record.partnerId, at,
            auditEvent('PARTNER_ACTIVATED', 'system:partner-recovery', at, 'Existing complimentary grant restored to the account subscription.'));
        } else if (record.activationPending !== undefined) {
          const pending = record.activationPending;
          const previous = pending.previousSubscription;
          const wasAlreadyPro = previous?.plan === 'PRO' && previous.status === 'ACTIVE';
          // Do not treat an unrelated later payment's PRO grant as proof that
          // this partner attempt succeeded. Timestamps are only a conservative
          // same-process signal, not a unique or cross-process transaction ID.
          const matchesAccount = subscription?.plan === 'PRO' && subscription.status === 'ACTIVE' &&
            (wasAlreadyPro
              ? subscription.createdAt === previous.createdAt && subscription.updatedAt === previous.updatedAt
              : !possiblyPaidAccounts.has(record.userId) && subscription.createdAt === pending.initiatedAt && subscription.updatedAt === pending.initiatedAt);
          if (matchesAccount) {
            const at = timestamp();
            const completed = await store.finishActivation(record.partnerId, at,
              auditEvent('PARTNER_ACTIVATED', 'system:partner-recovery', at, 'Interrupted activation completed after account verification.'));
            if (completed === undefined) throw new Error('Interrupted partner activation could not be recovered.');
          } else {
            // Keep both historical files intact; an explicit matching retry
            // can finish the intent without modifying an existing paid grant.
            quarantined.add(record.partnerId);
          }
        } else if (record.activationRecovery === 'INCOMPLETE' ||
                   (record.status === 'ACTIVE' && !(subscription?.plan === 'PRO' && subscription.status === 'ACTIVE'))) {
          quarantined.add(record.partnerId);
        }
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
