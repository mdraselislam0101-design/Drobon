import { writePrivateJson } from '../lib/writePrivateJson.js';
import { readFileSync } from 'node:fs';
import type { PaymentAuditAction, PaymentAuditEvent, PaymentMethod, PaymentStatus } from '@drobon/shared';
import { isPaymentAuditAction, isPaymentMethod, isPaymentStatus } from '@drobon/shared';

/** Private payment record. Idempotency data is never projected to HTTP. */
/** Coupon attribution snapshot (Pump 7). Frozen at creation; totals derive from it. */
export interface PaymentAttribution {
  couponCode: string;
  partnerId: string;
  baseAmountMinorUnits: number;
  discountAmountMinorUnits: number;
  commissionPercent: number;
}

export interface PaymentRecord {
  paymentId: string;
  accountId: string;
  submittedByUserId: string;
  plan: 'PRO';
  amountMinorUnits: number;
  attribution?: PaymentAttribution;
  currency: 'BDT';
  paymentMethod: 'MANUAL_TRANSFER';
  reference: string;
  referenceKey: string;
  idempotencyKey: string;
  status: PaymentStatus;
  createdAt: string;
  submittedAt: string;
  updatedAt: string;
  reviewedAt: string | null;
  approvedAt: string | null;
  rejectedAt: string | null;
  reviewerId: string | null;
  rejectionReason: string | null;
}

export interface PaymentAdminFilters {
  status?: PaymentStatus;
  paymentMethod?: PaymentMethod;
  accountId?: string;
  from?: string;
  to?: string;
}

export interface PaymentAuditFilters {
  action?: PaymentAuditAction;
  accountId?: string;
  paymentId?: string;
  from?: string;
  to?: string;
}

export interface PaymentAdminCounts {
  total: number;
  byStatus: Record<PaymentStatus, number>;
  submittedAmountMinorUnits: number;
  approvedAmountMinorUnits: number;
}

export interface PaymentStore {
  create(record: PaymentRecord, initialEvents: PaymentAuditEvent[]): Promise<
    | { kind: 'CREATED' | 'IDEMPOTENT'; payment: PaymentRecord }
    | { kind: 'ACTIVE_EXISTS' | 'DUPLICATE_REFERENCE' | 'IDEMPOTENCY_MISMATCH' }
  >;
  get(paymentId: string): PaymentRecord | undefined;
  findByIdempotency(accountId: string, idempotencyKey: string): PaymentRecord | undefined;
  listForAccount(accountId: string): PaymentRecord[];
  listAll(): PaymentRecord[];
  /** True only when an approved payment audit and subscription timestamp support paid activation. */
  hasConfirmedProActivation(accountId: string, subscriptionCreatedAt: string | null): boolean;
  adminPage(filters: PaymentAdminFilters, page: number, pageSize: number): { payments: PaymentRecord[]; total: number };
  adminCounts(): PaymentAdminCounts;
  accountStats(accountIds: readonly string[]): ReadonlyMap<string, { requestCount: number; latestPaymentStatus: PaymentStatus | null }>;
  listAudit(paymentId: string): PaymentAuditEvent[];
  adminAuditPage(filters: PaymentAuditFilters, page: number, pageSize: number): { events: PaymentAuditEvent[]; total: number };
  beginReview(paymentId: string, reviewerId: string, at: string, event: PaymentAuditEvent): Promise<
    | { kind: 'UPDATED' | 'IDEMPOTENT'; payment: PaymentRecord }
    | { kind: 'NOT_FOUND' | 'INVALID_STATE' }
  >;
  beginApproval(paymentId: string, reviewerId: string, at: string, event: PaymentAuditEvent): Promise<
    | { kind: 'STARTED' | 'RESUME' | 'IDEMPOTENT'; payment: PaymentRecord }
    | { kind: 'NOT_FOUND' | 'INVALID_STATE' }
  >;
  finishApproval(paymentId: string, at: string, event: PaymentAuditEvent): Promise<
    | { kind: 'UPDATED' | 'IDEMPOTENT'; payment: PaymentRecord }
    | { kind: 'NOT_FOUND' | 'INVALID_STATE' }
  >;
  reject(paymentId: string, reviewerId: string, reason: string, at: string, event: PaymentAuditEvent): Promise<
    | { kind: 'UPDATED' | 'IDEMPOTENT'; payment: PaymentRecord }
    | { kind: 'NOT_FOUND' | 'INVALID_STATE' }
  >;
  cancel(paymentId: string, accountId: string, at: string, event: PaymentAuditEvent): Promise<
    | { kind: 'UPDATED' | 'IDEMPOTENT'; payment: PaymentRecord }
    | { kind: 'NOT_FOUND' | 'INVALID_STATE' }
  >;
}

interface StoreDocument {
  version: 1;
  payments: PaymentRecord[];
  auditEvents: PaymentAuditEvent[];
}

const MAX_PAYMENT_RECORDS = 100_000;
const MAX_PAYMENT_AUDIT_EVENTS = 500_000;
const ACTIVE_STATUSES = new Set<PaymentStatus>(['PENDING', 'UNDER_REVIEW', 'APPROVING', 'APPROVED']);
const EMPTY_DOCUMENT: StoreDocument = { version: 1, payments: [], auditEvents: [] };

function validTimestamp(value: unknown): value is string {
  return typeof value === 'string' && !Number.isNaN(Date.parse(value));
}

function isNullableTimestamp(value: unknown): value is string | null {
  return value === null || validTimestamp(value);
}

function isPaymentRecord(value: unknown): value is PaymentRecord {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const r = value as Record<string, unknown>;
  return (
    typeof r['paymentId'] === 'string' && /^pay_[0-9a-f-]{36}$/i.test(r['paymentId']) &&
    typeof r['accountId'] === 'string' && r['accountId'].length > 0 &&
    typeof r['submittedByUserId'] === 'string' && r['submittedByUserId'].length > 0 &&
    r['plan'] === 'PRO' && Number.isSafeInteger(r['amountMinorUnits']) && (r['amountMinorUnits'] as number) > 0 &&
    r['currency'] === 'BDT' && isPaymentMethod(r['paymentMethod']) &&
    typeof r['reference'] === 'string' && r['reference'].length >= 6 && r['reference'].length <= 64 &&
    typeof r['referenceKey'] === 'string' && r['referenceKey'].length > 0 &&
    typeof r['idempotencyKey'] === 'string' && r['idempotencyKey'].length >= 8 && r['idempotencyKey'].length <= 128 &&
    isPaymentStatus(r['status']) && validTimestamp(r['createdAt']) && validTimestamp(r['submittedAt']) && validTimestamp(r['updatedAt']) &&
    isNullableTimestamp(r['reviewedAt']) && isNullableTimestamp(r['approvedAt']) && isNullableTimestamp(r['rejectedAt']) &&
    (r['reviewerId'] === null || (typeof r['reviewerId'] === 'string' && r['reviewerId'].length > 0)) &&
    (r['rejectionReason'] === null || (typeof r['rejectionReason'] === 'string' && r['rejectionReason'].length <= 300)) &&
    (r['attribution'] === undefined || isAttribution(r['attribution']))
  );
}

function isAttribution(value: unknown): value is PaymentAttribution {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const r = value as Record<string, unknown>;
  const int = (v: unknown): v is number => Number.isSafeInteger(v) && typeof v === 'number' && v >= 0;
  return (
    typeof r['couponCode'] === 'string' && /^[A-Z0-9][A-Z0-9-]{2,39}$/.test(r['couponCode']) &&
    typeof r['partnerId'] === 'string' && /^ptr_[0-9a-f-]{36}$/i.test(r['partnerId']) &&
    int(r['baseAmountMinorUnits']) && (r['baseAmountMinorUnits'] as number) > 0 &&
    int(r['discountAmountMinorUnits']) && int(r['commissionPercent']) && (r['commissionPercent'] as number) <= 100
  );
}

function isAuditEvent(value: unknown): value is PaymentAuditEvent {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const r = value as Record<string, unknown>;
  return (
    typeof r['eventId'] === 'string' && /^evt_[0-9a-f-]{36}$/i.test(r['eventId']) &&
    typeof r['paymentId'] === 'string' && typeof r['accountId'] === 'string' && typeof r['actorId'] === 'string' &&
    isPaymentAuditAction(r['action']) &&
    (r['previousStatus'] === null || isPaymentStatus(r['previousStatus'])) && isPaymentStatus(r['newStatus']) &&
    validTimestamp(r['timestamp']) && (r['reason'] === null || (typeof r['reason'] === 'string' && r['reason'].length <= 300))
  );
}

function loadDocument(path: string): StoreDocument {
  let raw: string;
  try {
    raw = readFileSync(path, 'utf8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { ...EMPTY_DOCUMENT, payments: [], auditEvents: [] };
    throw new Error(`Cannot read payment store at ${path}: ${(error as NodeJS.ErrnoException).code ?? 'I/O error'}`);
  }
  let parsed: unknown;
  try { parsed = JSON.parse(raw) as unknown; } catch {
    throw new Error(`Payment store at ${path} is not valid JSON — refusing to start with corrupt payment data.`);
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error(`Payment store at ${path} has an unexpected shape — refusing to start.`);
  }
  const doc = parsed as Record<string, unknown>;
  if (doc['version'] !== 1 || !Array.isArray(doc['payments']) || !Array.isArray(doc['auditEvents']) ||
      doc['payments'].length > MAX_PAYMENT_RECORDS || doc['auditEvents'].length > MAX_PAYMENT_AUDIT_EVENTS ||
      !doc['payments'].every(isPaymentRecord) || !doc['auditEvents'].every(isAuditEvent)) {
    throw new Error(`Payment store at ${path} has invalid records — refusing to start.`);
  }
  const payments = doc['payments'] as PaymentRecord[];
  const ids = new Set<string>();
  const refs = new Set<string>();
  const idempotency = new Set<string>();
  for (const p of payments) {
    const idem = `${p.accountId}\0${p.idempotencyKey}`;
    if (ids.has(p.paymentId) || refs.has(p.referenceKey) || idempotency.has(idem)) {
      throw new Error(`Payment store at ${path} contains duplicate identity/reference data — refusing to start.`);
    }
    ids.add(p.paymentId); refs.add(p.referenceKey); idempotency.add(idem);
  }
  const paymentIds = new Set(ids);
  if ((doc['auditEvents'] as PaymentAuditEvent[]).some((event) => !paymentIds.has(event.paymentId))) {
    throw new Error(`Payment store at ${path} contains an orphan audit event — refusing to start.`);
  }
  return { version: 1, payments: payments.map((p) => ({ ...p })), auditEvents: (doc['auditEvents'] as PaymentAuditEvent[]).map((e) => ({ ...e })) };
}

function createStore(initial: StoreDocument, persist: (document: StoreDocument) => void): PaymentStore {
  let payments = new Map(initial.payments.map((p) => [p.paymentId, { ...p }]));
  let auditEvents = initial.auditEvents.map((e) => ({ ...e }));
  // An APPROVED payment alone is not proof that it activated this PRO:
  // partner grants or legacy PRO may already have existed. The approval
  // audit records ALREADY_ACTIVE explicitly; only a successful activation
  // with a matching subscription timestamp supports a paid-source claim.
  const buildPaidActivationIndex = (records: Map<string, PaymentRecord>, events: PaymentAuditEvent[]): Map<string, Array<{ from: number; to: number }>> => {
    const activations = new Map<string, string>();
    for (const event of events) {
      if (event.action === 'PAYMENT_APPROVED' && event.previousStatus === 'APPROVING' &&
          event.newStatus === 'APPROVED' && event.reason === null) {
        activations.set(event.paymentId, event.accountId);
      }
    }
    const result = new Map<string, Array<{ from: number; to: number }>>();
    for (const payment of records.values()) {
      if (payment.status !== 'APPROVED' || payment.approvedAt === null || activations.get(payment.paymentId) !== payment.accountId) continue;
      const from = Date.parse(payment.submittedAt);
      const to = Date.parse(payment.approvedAt);
      if (!Number.isFinite(from) || !Number.isFinite(to) || from > to) continue;
      const ranges = result.get(payment.accountId) ?? [];
      ranges.push({ from, to });
      result.set(payment.accountId, ranges);
    }
    return result;
  };
  let paidActivations = buildPaidActivationIndex(payments, auditEvents);
  let queue: Promise<unknown> = Promise.resolve();
  const exclusive = <T>(task: () => T): Promise<T> => {
    const run = queue.then(task, task);
    queue = run.catch(() => undefined);
    return run;
  };
  const commit = (nextPayments: Map<string, PaymentRecord>, nextEvents: PaymentAuditEvent[]): void => {
    if (nextPayments.size > MAX_PAYMENT_RECORDS || nextEvents.length > MAX_PAYMENT_AUDIT_EVENTS) {
      throw new Error('Payment store capacity reached.');
    }
    const doc: StoreDocument = { version: 1, payments: [...nextPayments.values()], auditEvents: nextEvents };
    persist(doc);
    payments = nextPayments;
    auditEvents = nextEvents;
    paidActivations = buildPaidActivationIndex(payments, auditEvents);
  };
  const eventsFor = (paymentId: string): PaymentAuditEvent[] => auditEvents.filter((e) => e.paymentId === paymentId).map((e) => ({ ...e }));
  return {
    create: (record, initialEvents) => exclusive(() => {
      const duplicateIdempotency = [...payments.values()].find((p) => p.accountId === record.accountId && p.idempotencyKey === record.idempotencyKey);
      if (duplicateIdempotency !== undefined) {
        const samePayload = duplicateIdempotency.plan === record.plan && duplicateIdempotency.paymentMethod === record.paymentMethod && duplicateIdempotency.referenceKey === record.referenceKey && duplicateIdempotency.amountMinorUnits === record.amountMinorUnits && duplicateIdempotency.currency === record.currency;
        return samePayload ? { kind: 'IDEMPOTENT' as const, payment: { ...duplicateIdempotency } } : { kind: 'IDEMPOTENCY_MISMATCH' as const };
      }
      if ([...payments.values()].some((p) => p.referenceKey === record.referenceKey)) return { kind: 'DUPLICATE_REFERENCE' as const };
      if ([...payments.values()].some((p) => p.accountId === record.accountId && p.plan === record.plan && ACTIVE_STATUSES.has(p.status))) return { kind: 'ACTIVE_EXISTS' as const };
      const next = new Map(payments);
      next.set(record.paymentId, { ...record });
      commit(next, [...auditEvents, ...initialEvents.map((e) => ({ ...e }))]);
      return { kind: 'CREATED' as const, payment: { ...record } };
    }),
    get: (paymentId) => { const record = payments.get(paymentId); return record === undefined ? undefined : { ...record }; },
    findByIdempotency: (accountId, idempotencyKey) => {
      const record = [...payments.values()].find((p) => p.accountId === accountId && p.idempotencyKey === idempotencyKey);
      return record === undefined ? undefined : { ...record };
    },
    listForAccount: (accountId) => [...payments.values()].filter((p) => p.accountId === accountId).sort((a, b) => b.createdAt.localeCompare(a.createdAt) || a.paymentId.localeCompare(b.paymentId)).map((p) => ({ ...p })),
    listAll: () => [...payments.values()].sort((a, b) => b.createdAt.localeCompare(a.createdAt) || a.paymentId.localeCompare(b.paymentId)).map((p) => ({ ...p })),
    hasConfirmedProActivation: (accountId, subscriptionCreatedAt) => {
      if (subscriptionCreatedAt === null) return false;
      const created = Date.parse(subscriptionCreatedAt);
      return Number.isFinite(created) && (paidActivations.get(accountId)?.some(({ from, to }) => from <= created && created <= to) ?? false);
    },
    adminPage: (filters, page, pageSize) => {
      const offset = (page - 1) * pageSize;
      const retain = offset + pageSize;
      const candidates: PaymentRecord[] = [];
      let total = 0;
      for (const record of payments.values()) {
        if (filters.status !== undefined && record.status !== filters.status) continue;
        if (filters.paymentMethod !== undefined && record.paymentMethod !== filters.paymentMethod) continue;
        if (filters.accountId !== undefined && record.accountId !== filters.accountId) continue;
        if (filters.from !== undefined && record.createdAt < filters.from) continue;
        if (filters.to !== undefined && record.createdAt > filters.to) continue;
        total += 1;
        candidates.push(record);
        if (candidates.length >= retain + 1000) {
          candidates.sort((a, b) => b.createdAt.localeCompare(a.createdAt) || a.paymentId.localeCompare(b.paymentId));
          candidates.length = retain;
        }
      }
      candidates.sort((a, b) => b.createdAt.localeCompare(a.createdAt) || a.paymentId.localeCompare(b.paymentId));
      return { payments: candidates.slice(offset, offset + pageSize).map((record) => ({ ...record })), total };
    },
    adminCounts: () => {
      const byStatus: Record<PaymentStatus, number> = { PENDING: 0, UNDER_REVIEW: 0, APPROVING: 0, APPROVED: 0, REJECTED: 0, CANCELLED: 0 };
      let submittedAmountMinorUnits = 0;
      let approvedAmountMinorUnits = 0;
      for (const record of payments.values()) {
        byStatus[record.status] += 1;
        submittedAmountMinorUnits += record.amountMinorUnits;
        if (record.status === 'APPROVED') approvedAmountMinorUnits += record.amountMinorUnits;
      }
      return { total: payments.size, byStatus, submittedAmountMinorUnits, approvedAmountMinorUnits };
    },
    accountStats: (accountIds) => {
      const target = new Set(accountIds);
      const result = new Map<string, { requestCount: number; latestPaymentStatus: PaymentStatus | null }>();
      const paymentsForLatest = new Map<string, PaymentRecord>();
      for (const id of target) result.set(id, { requestCount: 0, latestPaymentStatus: null });
      for (const record of payments.values()) {
        if (!target.has(record.accountId)) continue;
        const current = result.get(record.accountId);
        if (current === undefined) continue;
        current.requestCount += 1;
        const latest = record.createdAt.localeCompare(paymentsForLatest.get(record.accountId)?.createdAt ?? '');
        if (latest >= 0) paymentsForLatest.set(record.accountId, record);
        const newest = paymentsForLatest.get(record.accountId);
        current.latestPaymentStatus = newest?.status ?? null;
      }
      return result;
    },
    listAudit: eventsFor,
    adminAuditPage: (filters, page, pageSize) => {
      const offset = (page - 1) * pageSize;
      const retain = offset + pageSize;
      const candidates: PaymentAuditEvent[] = [];
      let total = 0;
      for (const event of auditEvents) {
        if (filters.action !== undefined && event.action !== filters.action) continue;
        if (filters.accountId !== undefined && event.accountId !== filters.accountId) continue;
        if (filters.paymentId !== undefined && event.paymentId !== filters.paymentId) continue;
        if (filters.from !== undefined && event.timestamp < filters.from) continue;
        if (filters.to !== undefined && event.timestamp > filters.to) continue;
        total += 1;
        candidates.push(event);
        if (candidates.length >= retain + 1000) {
          candidates.sort((a, b) => b.timestamp.localeCompare(a.timestamp) || a.eventId.localeCompare(b.eventId));
          candidates.length = retain;
        }
      }
      candidates.sort((a, b) => b.timestamp.localeCompare(a.timestamp) || a.eventId.localeCompare(b.eventId));
      return { events: candidates.slice(offset, offset + pageSize).map((event) => ({ ...event })), total };
    },
    beginReview: (paymentId, reviewerId, at, event) => exclusive(() => {
      const current = payments.get(paymentId); if (current === undefined) return { kind: 'NOT_FOUND' as const };
      if (current.status === 'UNDER_REVIEW') return { kind: 'IDEMPOTENT' as const, payment: { ...current } };
      if (current.status !== 'PENDING') return { kind: 'INVALID_STATE' as const };
      const updated = { ...current, status: 'UNDER_REVIEW' as const, reviewerId, reviewedAt: at, updatedAt: at };
      const next = new Map(payments); next.set(paymentId, updated); commit(next, [...auditEvents, { ...event }]);
      return { kind: 'UPDATED' as const, payment: { ...updated } };
    }),
    beginApproval: (paymentId, reviewerId, at, event) => exclusive(() => {
      const current = payments.get(paymentId); if (current === undefined) return { kind: 'NOT_FOUND' as const };
      if (current.status === 'APPROVED') return { kind: 'IDEMPOTENT' as const, payment: { ...current } };
      if (current.status === 'APPROVING') return { kind: 'RESUME' as const, payment: { ...current } };
      if (current.status !== 'PENDING' && current.status !== 'UNDER_REVIEW') return { kind: 'INVALID_STATE' as const };
      const updated = { ...current, status: 'APPROVING' as const, reviewerId, reviewedAt: current.reviewedAt ?? at, updatedAt: at };
      const next = new Map(payments); next.set(paymentId, updated); commit(next, [...auditEvents, { ...event }]);
      return { kind: 'STARTED' as const, payment: { ...updated } };
    }),
    finishApproval: (paymentId, at, event) => exclusive(() => {
      const current = payments.get(paymentId); if (current === undefined) return { kind: 'NOT_FOUND' as const };
      if (current.status === 'APPROVED') return { kind: 'IDEMPOTENT' as const, payment: { ...current } };
      if (current.status !== 'APPROVING') return { kind: 'INVALID_STATE' as const };
      const updated = { ...current, status: 'APPROVED' as const, approvedAt: at, updatedAt: at };
      const next = new Map(payments); next.set(paymentId, updated); commit(next, [...auditEvents, { ...event }]);
      return { kind: 'UPDATED' as const, payment: { ...updated } };
    }),
    reject: (paymentId, reviewerId, reason, at, event) => exclusive(() => {
      const current = payments.get(paymentId); if (current === undefined) return { kind: 'NOT_FOUND' as const };
      if (current.status === 'REJECTED') return { kind: 'IDEMPOTENT' as const, payment: { ...current } };
      if (current.status !== 'PENDING' && current.status !== 'UNDER_REVIEW') return { kind: 'INVALID_STATE' as const };
      const updated = { ...current, status: 'REJECTED' as const, reviewerId, reviewedAt: current.reviewedAt ?? at, rejectedAt: at, updatedAt: at, rejectionReason: reason };
      const next = new Map(payments); next.set(paymentId, updated); commit(next, [...auditEvents, { ...event }]);
      return { kind: 'UPDATED' as const, payment: { ...updated } };
    }),
    cancel: (paymentId, accountId, at, event) => exclusive(() => {
      const current = payments.get(paymentId);
      if (current === undefined || current.accountId !== accountId) return { kind: 'NOT_FOUND' as const };
      if (current.status === 'CANCELLED') return { kind: 'IDEMPOTENT' as const, payment: { ...current } };
      if (current.status !== 'PENDING') return { kind: 'INVALID_STATE' as const };
      const updated = { ...current, status: 'CANCELLED' as const, updatedAt: at };
      const next = new Map(payments); next.set(paymentId, updated); commit(next, [...auditEvents, { ...event }]);
      return { kind: 'UPDATED' as const, payment: { ...updated } };
    }),
  };
}

/** Durable JSON-backed, atomic, single-process/single-writer payment + audit store. */
export function createJsonFilePaymentStore(path: string): PaymentStore {
  const persist = (document: StoreDocument): void => {
    writePrivateJson(path, `${JSON.stringify(document, null, 2)}\n`);
  };
  return createStore(loadDocument(path), persist);
}

/** Process-local store for tests/explicit ephemeral non-production deployments. */
export function createMemoryPaymentStore(): PaymentStore {
  return createStore({ version: 1, payments: [], auditEvents: [] }, () => undefined);
}
