import { randomUUID } from 'node:crypto';
import type {
  AdminPaymentSummary,
  PaymentAuditEvent,
  PaymentAuditResponse,
  PaymentConfigResponse,
  PaymentDetailResponse,
  PaymentHistoryResponse,
  PaymentMethod,
  PaymentSummary,
  PaymentStatus,
} from '@drobon/shared';
import type { ApiConfig } from '../config.js';
import { conflict, notFound, validationError } from '../errors.js';
import { redactAssistantText } from '../assistant/redaction.js';
import type { UserRepository } from '../auth/repositories.js';
import type { PaymentAdminCounts, PaymentAdminFilters, PaymentAuditFilters, PaymentRecord, PaymentStore } from './store.js';

/** Provider boundary. No charge, verification or webhook methods exist until a real integration is configured. */
export interface PaymentProvider {
  readonly id: 'none';
  availability(): 'UNAVAILABLE';
}

const unavailablePaymentProvider: PaymentProvider = {
  id: 'none',
  availability: () => 'UNAVAILABLE',
};

export interface PaymentService {
  config(currentPlan: 'FREE' | 'PRO'): PaymentConfigResponse;
  create(input: {
    accountId: string;
    userId: string;
    currentPlan: 'FREE' | 'PRO';
    plan: 'PRO';
    amountMinorUnits: number;
    currency: 'BDT';
    paymentMethod: PaymentMethod;
    reference: string;
    idempotencyKey: string;
  }): Promise<{ payment: PaymentSummary; created: boolean }>;
  getForAccount(paymentId: string, accountId: string): PaymentDetailResponse;
  history(accountId: string, page: number, pageSize: number): PaymentHistoryResponse;
  adminList(page: number, pageSize: number, filters?: PaymentAdminFilters): {
    payments: AdminPaymentSummary[]; page: number; pageSize: number; total: number;
  };
  adminCounts(): PaymentAdminCounts;
  accountStats(accountIds: readonly string[]): ReadonlyMap<string, { requestCount: number; latestPaymentStatus: PaymentStatus | null }>;
  adminAudit(page: number, pageSize: number, filters: PaymentAuditFilters): PaymentAuditResponse & { page: number; pageSize: number; total: number };
  getForAdmin(paymentId: string): AdminPaymentSummary;
  audit(paymentId: string): PaymentAuditResponse;
  review(paymentId: string, reviewerId: string): Promise<PaymentSummary>;
  approve(paymentId: string, reviewerId: string): Promise<PaymentSummary>;
  reject(paymentId: string, reviewerId: string, reason: string): Promise<PaymentSummary>;
  cancel(paymentId: string, accountId: string, actorId: string): Promise<PaymentSummary>;
  recoverInterruptedApprovals(): Promise<void>;
}

function toSummary(record: PaymentRecord): PaymentSummary {
  return {
    paymentId: record.paymentId,
    plan: record.plan,
    amountMinorUnits: record.amountMinorUnits,
    currency: record.currency,
    paymentMethod: record.paymentMethod,
    reference: record.reference,
    status: record.status,
    createdAt: record.createdAt,
    submittedAt: record.submittedAt,
    updatedAt: record.updatedAt,
    reviewedAt: record.reviewedAt,
    approvedAt: record.approvedAt,
    rejectedAt: record.rejectedAt,
    rejectionReason: record.rejectionReason,
  };
}

function redactedTextForOperations(value: string | null, maxLength: number): string | null {
  return value === null ? null : redactAssistantText(value).text.slice(0, maxLength);
}

function safeAdminReference(value: string): string {
  const result = redactAssistantText(value);
  return result.redacted ? 'REDACTED' : result.text.slice(0, 64);
}

function toAdminSummary(record: PaymentRecord): AdminPaymentSummary {
  return {
    ...toSummary(record),
    reference: safeAdminReference(record.reference),
    rejectionReason: redactedTextForOperations(record.rejectionReason, 300),
    accountId: record.accountId,
    submittedByUserId: record.submittedByUserId,
    reviewerId: record.reviewerId,
  };
}

function auditEvent(input: {
  paymentId: string;
  accountId: string;
  actorId: string;
  action: PaymentAuditEvent['action'];
  previousStatus: PaymentStatus | null;
  newStatus: PaymentStatus;
  timestamp: string;
  reason?: string | null;
}): PaymentAuditEvent {
  return {
    eventId: `evt_${randomUUID()}`,
    paymentId: input.paymentId,
    accountId: input.accountId,
    actorId: input.actorId,
    action: input.action,
    previousStatus: input.previousStatus,
    newStatus: input.newStatus,
    timestamp: input.timestamp,
    reason: input.reason ?? null,
  };
}

function normalizeReference(value: string): { reference: string; key: string } {
  const normalized = value.trim().toUpperCase();
  return { reference: normalized, key: `MANUAL_TRANSFER:${normalized}` };
}

function normalizeRejectionReason(raw: string): string {
  const redactedText = redactAssistantText(raw).text;
  let withoutControls = '';
  for (const character of redactedText) {
    const code = character.charCodeAt(0);
    withoutControls += code < 32 || code === 127 ? ' ' : character;
  }
  return withoutControls.trim().replace(/\s+/g, ' ');
}

export function createPaymentService(options: {
  config: ApiConfig;
  store: PaymentStore;
  users: UserRepository;
  now?: () => number;
  provider?: PaymentProvider;
}): PaymentService {
  const { config, store, users } = options;
  const now = options.now ?? Date.now;
  const provider = options.provider ?? unavailablePaymentProvider;
  const timestamp = (): string => new Date(now()).toISOString();

  const approveSaga = async (payment: PaymentRecord, reviewerId: string): Promise<PaymentSummary> => {
    const activation = await users.activatePro(payment.accountId, timestamp());
    if (activation === 'NOT_FOUND') {
      // Keep APPROVING durable so a later operator retry or restart recovery
      // can detect the incomplete saga; never mark the payment approved.
      throw new Error('Payment approval references a missing account.');
    }
    const current = store.get(payment.paymentId);
    if (current === undefined) throw new Error('Payment disappeared during approval.');
    const result = await store.finishApproval(
      payment.paymentId,
      timestamp(),
      auditEvent({
        paymentId: current.paymentId,
        accountId: current.accountId,
        actorId: reviewerId,
        action: 'PAYMENT_APPROVED',
        previousStatus: 'APPROVING',
        newStatus: 'APPROVED',
        timestamp: timestamp(),
        reason: activation === 'ALREADY_ACTIVE' ? 'Approved; existing server-side PRO entitlement remained active.' : null,
      }),
    );
    if (!('payment' in result)) throw new Error('Payment approval state changed unexpectedly.');
    return toSummary(result.payment);
  };

  return {
    config: (currentPlan) => ({
      currentPlan,
      proPriceMinorUnits: config.proPriceMinorUnits,
      currency: 'BDT',
      manualPaymentMethods: [...config.manualPaymentMethods],
      manualPaymentInstructions: config.manualPaymentInstructions,
      onlineGateway: provider.availability(),
      coupons: 'NOT_IMPLEMENTED',
    }),
    create: async (input) => {
      const { reference, key: referenceKey } = normalizeReference(input.reference);
      const previous = store.findByIdempotency(input.accountId, input.idempotencyKey);
      if (previous !== undefined) {
        const sameRequest = previous.plan === input.plan && previous.paymentMethod === input.paymentMethod &&
          previous.referenceKey === referenceKey && previous.amountMinorUnits === input.amountMinorUnits && previous.currency === input.currency;
        if (!sameRequest) throw conflict('The idempotency key was already used for a different payment request.');
        // Preserve a completed/accepted retry even if price configuration or
        // current entitlement changed after the original request was stored.
        return { payment: toSummary(previous), created: false };
      }
      const issues: Array<{ path: string; message: string }> = [];
      if (input.plan !== 'PRO') issues.push({ path: 'plan', message: 'Only the PRO plan is available for upgrade.' });
      if (!/^[A-Za-z0-9][A-Za-z0-9._-]{5,63}$/.test(input.reference)) issues.push({ path: 'reference', message: 'Payment reference must be 6–64 normalized characters.' });
      if (!Number.isSafeInteger(input.amountMinorUnits) || input.amountMinorUnits < 1) issues.push({ path: 'amountMinorUnits', message: 'Amount must be a positive integer in minor currency units.' });
      if (input.amountMinorUnits !== config.proPriceMinorUnits) issues.push({ path: 'amountMinorUnits', message: 'Amount does not match the server-configured PRO price.' });
      if (input.currency !== 'BDT') issues.push({ path: 'currency', message: 'Currency does not match the server-configured price.' });
      if (!config.manualPaymentMethods.includes(input.paymentMethod)) issues.push({ path: 'paymentMethod', message: 'This manual payment method is unavailable.' });
      if (issues.length > 0) throw validationError(issues);
      if (input.currentPlan !== 'FREE') throw conflict('A PRO upgrade request is available only to FREE accounts.');
      const createdAt = timestamp();
      const paymentId = `pay_${randomUUID()}`;
      const payment: PaymentRecord = {
        paymentId,
        accountId: input.accountId,
        submittedByUserId: input.userId,
        plan: 'PRO',
        amountMinorUnits: config.proPriceMinorUnits,
        currency: 'BDT',
        paymentMethod: input.paymentMethod,
        reference,
        referenceKey,
        idempotencyKey: input.idempotencyKey,
        status: 'PENDING',
        createdAt,
        submittedAt: createdAt,
        updatedAt: createdAt,
        reviewedAt: null,
        approvedAt: null,
        rejectedAt: null,
        reviewerId: null,
        rejectionReason: null,
      };
      const events = [
        auditEvent({ paymentId, accountId: input.accountId, actorId: input.userId, action: 'PAYMENT_CREATED', previousStatus: null, newStatus: 'PENDING', timestamp: createdAt }),
        auditEvent({ paymentId, accountId: input.accountId, actorId: input.userId, action: 'PAYMENT_SUBMITTED', previousStatus: 'PENDING', newStatus: 'PENDING', timestamp: createdAt }),
      ];
      const result = await store.create(payment, events);
      if (result.kind === 'ACTIVE_EXISTS') throw conflict('An active PRO payment request already exists for this account.');
      if (result.kind === 'DUPLICATE_REFERENCE') throw conflict('This payment reference has already been submitted.');
      if (result.kind === 'IDEMPOTENCY_MISMATCH') throw conflict('The idempotency key was already used for a different payment request.');
      if (!('payment' in result)) throw conflict('A payment request could not be created.');
      return { payment: toSummary(result.payment), created: result.kind === 'CREATED' };
    },
    getForAccount: (paymentId, accountId) => {
      const record = store.get(paymentId);
      if (record === undefined || record.accountId !== accountId) throw notFound();
      return { payment: toSummary(record) };
    },
    history: (accountId, page, pageSize) => {
      const all = store.listForAccount(accountId);
      const offset = (page - 1) * pageSize;
      return { payments: all.slice(offset, offset + pageSize).map(toSummary), page, pageSize, total: all.length };
    },
    adminList: (page, pageSize, filters = {}) => {
      const result = store.adminPage(filters, page, pageSize);
      return { payments: result.payments.map(toAdminSummary), page, pageSize, total: result.total };
    },
    adminCounts: () => store.adminCounts(),
    accountStats: (accountIds) => store.accountStats(accountIds),
    adminAudit: (page, pageSize, filters) => {
      const result = store.adminAuditPage(filters, page, pageSize);
      return { events: result.events.map((event) => ({ ...event, reason: redactedTextForOperations(event.reason, 300) })), page, pageSize, total: result.total };
    },
    getForAdmin: (paymentId) => {
      const record = store.get(paymentId);
      if (record === undefined) throw notFound();
      return toAdminSummary(record);
    },
    audit: (paymentId) => {
      if (store.get(paymentId) === undefined) throw notFound();
      return { events: store.listAudit(paymentId).slice(-100).map((event) => ({ ...event, reason: redactedTextForOperations(event.reason, 300) })) };
    },
    review: async (paymentId, reviewerId) => {
      const current = store.get(paymentId);
      if (current === undefined) throw notFound();
      const at = timestamp();
      const result = await store.beginReview(paymentId, reviewerId, at, auditEvent({ paymentId, accountId: current.accountId, actorId: reviewerId, action: 'PAYMENT_REVIEW_STARTED', previousStatus: current.status, newStatus: 'UNDER_REVIEW', timestamp: at }));
      if (result.kind === 'NOT_FOUND') throw notFound();
      if (result.kind === 'INVALID_STATE') throw conflict('This payment cannot enter review from its current state.');
      if (!('payment' in result)) throw conflict('Payment review could not be completed.');
      return toSummary(result.payment);
    },
    approve: async (paymentId, reviewerId) => {
      const current = store.get(paymentId);
      if (current === undefined) throw notFound();
      const at = timestamp();
      const started = await store.beginApproval(paymentId, reviewerId, at, auditEvent({ paymentId, accountId: current.accountId, actorId: reviewerId, action: 'PAYMENT_APPROVAL_STARTED', previousStatus: current.status, newStatus: 'APPROVING', timestamp: at }));
      if (started.kind === 'NOT_FOUND') throw notFound();
      if (started.kind === 'INVALID_STATE') throw conflict('This payment cannot be approved from its current state.');
      if (!('payment' in started)) throw conflict('Payment approval could not be started.');
      if (started.kind === 'IDEMPOTENT') return toSummary(started.payment);
      const approvingActor = started.kind === 'RESUME' ? started.payment.reviewerId ?? reviewerId : reviewerId;
      return approveSaga(started.payment, approvingActor);
    },
    reject: async (paymentId, reviewerId, rawReason) => {
      const reason = normalizeRejectionReason(rawReason);
      if (reason.length < 3 || reason.length > 300) throw validationError([{ path: 'reason', message: 'Provide a rejection reason of 3–300 characters.' }]);
      const current = store.get(paymentId);
      if (current === undefined) throw notFound();
      const at = timestamp();
      const result = await store.reject(paymentId, reviewerId, reason, at, auditEvent({ paymentId, accountId: current.accountId, actorId: reviewerId, action: 'PAYMENT_REJECTED', previousStatus: current.status, newStatus: 'REJECTED', timestamp: at, reason }));
      if (result.kind === 'NOT_FOUND') throw notFound();
      if (result.kind === 'INVALID_STATE') throw conflict('This payment cannot be rejected from its current state.');
      if (!('payment' in result)) throw conflict('Payment rejection could not be completed.');
      return toSummary(result.payment);
    },
    cancel: async (paymentId, accountId, actorId) => {
      const current = store.get(paymentId);
      if (current === undefined || current.accountId !== accountId) throw notFound();
      const at = timestamp();
      const result = await store.cancel(paymentId, accountId, at, auditEvent({
        paymentId, accountId, actorId, action: 'PAYMENT_CANCELLED', previousStatus: current.status,
        newStatus: 'CANCELLED', timestamp: at,
      }));
      if (result.kind === 'NOT_FOUND') throw notFound();
      if (result.kind === 'INVALID_STATE') throw conflict('This payment cannot be cancelled from its current state.');
      if (!('payment' in result)) throw conflict('Payment cancellation could not be completed.');
      return toSummary(result.payment);
    },
    recoverInterruptedApprovals: async () => {
      for (const record of store.listAll()) {
        if (record.status === 'APPROVING') await approveSaga(record, record.reviewerId ?? 'system:payment-recovery');
      }
    },
  };
}
