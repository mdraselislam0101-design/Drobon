import { writePrivateJson } from '../lib/writePrivateJson.js';
import { readFileSync } from 'node:fs';
import type {
  CommissionStatus,
  CouponStatus,
  PartnerAuditEvent,
  PartnerStatus,
  Subscription,
} from '@drobon/shared';
import {
  COMMISSION_ID_PATTERN,
  COUPON_CODE_PATTERN,
  MAX_COMMISSION_PERCENT,
  MAX_COUPON_DISCOUNT_PERCENT,
  PARTNER_ID_PATTERN,
  isCommissionStatus,
  isCouponStatus,
  isPartnerAuditAction,
  isPartnerStatus,
  isPlan,
  isSubscriptionStatus,
} from '@drobon/shared';

/** Private partner record. Exactly one identity per user; the coupon is the attribution anchor. */
export interface PartnerRecord {
  partnerId: string;
  userId: string;
  email: string;
  status: PartnerStatus;
  coupon: {
    couponCode: string;
    status: CouponStatus;
    discountPercent: number;
    commissionPercent: number;
    expiresAt: string | null;
    createdAt: string;
    updatedAt: string;
  };
  complimentaryProGrantedAt: string;
  /** Legacy partner-store-only grant; startup recovery migrates it to the account. */
  grantModel?: 'PARTNER_STORE_V1';
  /** A pre-upgrade partial record awaiting an explicit matching admin retry. */
  activationRecovery?: 'INCOMPLETE';
  /** An inactive durable intent; no coupon is usable until finalization. */
  activationPending?: { initiatedAt: string; previousSubscription: Subscription | null };
  createdAt: string;
  updatedAt: string;
  deactivatedAt: string | null;
  audit: PartnerAuditEvent[];
}

export interface CommissionRecord {
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

export interface PartnerListFilters {
  status?: PartnerStatus;
}

export interface CommissionListFilters {
  partnerId?: string;
  status?: CommissionStatus;
}

export interface PartnerStore {
  /** One partner per user, one coupon globally unique. */
  createPartner(record: PartnerRecord): Promise<{ kind: 'CREATED'; partner: PartnerRecord } | { kind: 'USER_EXISTS' | 'COUPON_EXISTS' }>;
  prepareLegacyActivation(partnerId: string, at: string, previous: Subscription | null, event: PartnerAuditEvent): Promise<PartnerRecord | undefined>;
  refreshPendingActivation(partnerId: string, at: string, previous: Subscription | null): Promise<PartnerRecord | undefined>;
  finishActivation(partnerId: string, at: string, event: PartnerAuditEvent): Promise<PartnerRecord | undefined>;
  migrateAtomicGrant(partnerId: string, at: string, event: PartnerAuditEvent): Promise<void>;
  getPartnerById(partnerId: string): PartnerRecord | undefined;
  getPartnerByUserId(userId: string): PartnerRecord | undefined;
  getPartnerByCoupon(couponCode: string): PartnerRecord | undefined;
  listPartners(filters: PartnerListFilters, page: number, pageSize: number): { partners: PartnerRecord[]; total: number };
  listAllPartners(): PartnerRecord[];
  updatePartnerStatus(partnerId: string, status: 'ACTIVE' | 'DEACTIVATED', at: string, event: PartnerAuditEvent): Promise<
    { kind: 'UPDATED' | 'IDEMPOTENT'; partner: PartnerRecord } | { kind: 'NOT_FOUND' }
  >;
  updateCoupon(partnerId: string, patch: {
    status?: CouponStatus;
    discountPercent?: number;
    commissionPercent?: number;
    expiresAt?: string | null;
  }, at: string, auditEvents: PartnerAuditEvent[]): Promise<
    { kind: 'UPDATED'; partner: PartnerRecord } | { kind: 'NOT_FOUND' }
  >;
  appendAudit(partnerId: string, event: PartnerAuditEvent): Promise<void>;
  /** Idempotent by paymentId — settlement retries never duplicate a commission. */
  createCommission(record: CommissionRecord): Promise<{ kind: 'CREATED'; commission: CommissionRecord } | { kind: 'DUPLICATE'; commission: CommissionRecord }>;
  getCommission(commissionId: string): CommissionRecord | undefined;
  getCommissionByPayment(paymentId: string): CommissionRecord | undefined;
  listCommissions(filters: CommissionListFilters, page: number, pageSize: number): { commissions: CommissionRecord[]; total: number };
  listCommissionsForPartner(partnerId: string): CommissionRecord[];
  transitionCommission(commissionId: string, to: 'AVAILABLE' | 'PAID', at: string, event: PartnerAuditEvent): Promise<
    { kind: 'UPDATED' | 'IDEMPOTENT'; commission: CommissionRecord } | { kind: 'NOT_FOUND' | 'INVALID_STATE' }
  >;
}

interface StoreDocument {
  version: 1;
  partners: PartnerRecord[];
  commissions: CommissionRecord[];
}

const MAX_PARTNER_RECORDS = 10_000;
const MAX_COMMISSION_RECORDS = 200_000;
const MAX_AUDIT_EVENT_PER_PARTNER = 200;
const EMPTY_DOCUMENT: StoreDocument = { version: 1, partners: [], commissions: [] };

function validTimestamp(value: unknown): value is string {
  return typeof value === 'string' && !Number.isNaN(Date.parse(value));
}

function isNullableTimestamp(value: unknown): value is string | null {
  return value === null || validTimestamp(value);
}

function isPreviousSubscription(value: unknown): value is Subscription | null {
  if (value === null) return true;
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const s = value as Record<string, unknown>;
  return Object.keys(s).length === 4 && isPlan(s['plan']) && isSubscriptionStatus(s['status']) &&
    isNullableTimestamp(s['createdAt']) && isNullableTimestamp(s['updatedAt']);
}

function isPendingActivation(value: unknown): boolean {
  if (value === undefined) return true;
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const pending = value as Record<string, unknown>;
  return Object.keys(pending).length === 2 && validTimestamp(pending['initiatedAt']) &&
    isPreviousSubscription(pending['previousSubscription']);
}

function money(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function isAuditEvent(value: unknown): value is PartnerAuditEvent {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const r = value as Record<string, unknown>;
  return (
    typeof r['eventId'] === 'string' && /^evt_[0-9a-f-]{36}$/i.test(r['eventId']) &&
    isPartnerAuditAction(r['action']) &&
    typeof r['actorId'] === 'string' && r['actorId'].length > 0 &&
    validTimestamp(r['at']) &&
    (r['detail'] === null || (typeof r['detail'] === 'string' && r['detail'].length <= 200))
  );
}

function isPartnerRecord(value: unknown): value is PartnerRecord {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const r = value as Record<string, unknown>;
  const c = r['coupon'];
  if (typeof c !== 'object' || c === null || Array.isArray(c)) return false;
  const coupon = c as Record<string, unknown>;
  return (
    typeof r['partnerId'] === 'string' && PARTNER_ID_PATTERN.test(r['partnerId']) &&
    typeof r['userId'] === 'string' && r['userId'].length > 0 &&
    typeof r['email'] === 'string' && r['email'].length > 0 &&
    isPartnerStatus(r['status']) &&
    typeof coupon['couponCode'] === 'string' && COUPON_CODE_PATTERN.test(coupon['couponCode']) &&
    isCouponStatus(coupon['status']) &&
    money(coupon['discountPercent']) && (coupon['discountPercent'] as number) <= MAX_COUPON_DISCOUNT_PERCENT &&
    money(coupon['commissionPercent']) && (coupon['commissionPercent'] as number) <= MAX_COMMISSION_PERCENT &&
    isNullableTimestamp(coupon['expiresAt']) &&
    validTimestamp(coupon['createdAt']) && validTimestamp(coupon['updatedAt']) &&
    validTimestamp(r['complimentaryProGrantedAt']) &&
    (r['grantModel'] === undefined || r['grantModel'] === 'PARTNER_STORE_V1') &&
    (r['activationRecovery'] === undefined || (r['activationRecovery'] === 'INCOMPLETE' && r['grantModel'] === undefined && r['status'] === 'DEACTIVATED')) &&
    isPendingActivation(r['activationPending']) &&
    (r['activationPending'] === undefined || (r['status'] === 'DEACTIVATED' && r['grantModel'] === undefined && r['activationRecovery'] === undefined)) &&
    validTimestamp(r['createdAt']) && validTimestamp(r['updatedAt']) &&
    isNullableTimestamp(r['deactivatedAt']) &&
    Array.isArray(r['audit']) && (r['audit'] as unknown[]).length <= MAX_AUDIT_EVENT_PER_PARTNER &&
    (r['audit'] as unknown[]).every(isAuditEvent)
  );
}

function isCommissionRecord(value: unknown): value is CommissionRecord {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const r = value as Record<string, unknown>;
  return (
    typeof r['commissionId'] === 'string' && COMMISSION_ID_PATTERN.test(r['commissionId']) &&
    typeof r['partnerId'] === 'string' && PARTNER_ID_PATTERN.test(r['partnerId']) &&
    typeof r['paymentId'] === 'string' && /^pay_[0-9a-f-]{36}$/i.test(r['paymentId']) &&
    typeof r['couponCode'] === 'string' && COUPON_CODE_PATTERN.test(r['couponCode']) &&
    isCommissionStatus(r['status']) && r['currency'] === 'BDT' &&
    money(r['baseAmountMinorUnits']) && (r['baseAmountMinorUnits'] as number) > 0 &&
    money(r['discountAmountMinorUnits']) && money(r['collectedAmountMinorUnits']) &&
    (r['collectedAmountMinorUnits'] as number) === (r['baseAmountMinorUnits'] as number) - (r['discountAmountMinorUnits'] as number) &&
    money(r['commissionAmountMinorUnits']) && (r['commissionAmountMinorUnits'] as number) <= (r['collectedAmountMinorUnits'] as number) &&
    money(r['commissionPercent']) && (r['commissionPercent'] as number) <= MAX_COMMISSION_PERCENT &&
    validTimestamp(r['createdAt']) && validTimestamp(r['updatedAt']) &&
    isNullableTimestamp(r['availableAt']) && isNullableTimestamp(r['paidAt'])
  );
}

function loadDocument(path: string): StoreDocument {
  let raw: string;
  try {
    raw = readFileSync(path, 'utf8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { ...EMPTY_DOCUMENT, partners: [], commissions: [] };
    throw new Error(`Cannot read partner store at ${path}: ${(error as NodeJS.ErrnoException).code ?? 'I/O error'}`);
  }
  let parsed: unknown;
  try { parsed = JSON.parse(raw) as unknown; } catch {
    throw new Error(`Partner store at ${path} is not valid JSON — refusing to start with corrupt partner data.`);
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error(`Partner store at ${path} has an unexpected shape — refusing to start.`);
  }
  const doc = parsed as Record<string, unknown>;
  if (doc['version'] !== 1 || !Array.isArray(doc['partners']) || !Array.isArray(doc['commissions']) ||
      doc['partners'].length > MAX_PARTNER_RECORDS || doc['commissions'].length > MAX_COMMISSION_RECORDS ||
      !doc['partners'].every(isPartnerRecord) || !doc['commissions'].every(isCommissionRecord)) {
    throw new Error(`Partner store at ${path} has invalid records — refusing to start.`);
  }
  const partners = doc['partners'] as PartnerRecord[];
  const ids = new Set<string>();
  const userIds = new Set<string>();
  const couponCodes = new Set<string>();
  for (const partner of partners) {
    if (ids.has(partner.partnerId) || userIds.has(partner.userId) || couponCodes.has(partner.coupon.couponCode)) {
      throw new Error(`Partner store at ${path} contains duplicate partner/coupon identity data — refusing to start.`);
    }
    ids.add(partner.partnerId); userIds.add(partner.userId); couponCodes.add(partner.coupon.couponCode);
  }
  const commissions = doc['commissions'] as CommissionRecord[];
  const commissionIds = new Set<string>();
  const paymentIds = new Set<string>();
  for (const commission of commissions) {
    if (commissionIds.has(commission.commissionId) || paymentIds.has(commission.paymentId) || !ids.has(commission.partnerId)) {
      throw new Error(`Partner store at ${path} contains duplicate or orphan commission data — refusing to start.`);
    }
    commissionIds.add(commission.commissionId); paymentIds.add(commission.paymentId);
  }
  return {
    version: 1,
    partners: partners.map((partner) => ({ ...partner, coupon: { ...partner.coupon }, audit: partner.audit.map((event) => ({ ...event })) })),
    commissions: commissions.map((commission) => ({ ...commission })),
  };
}

function clone(record: PartnerRecord): PartnerRecord {
  return {
    ...record,
    coupon: { ...record.coupon },
    audit: record.audit.map((event) => ({ ...event })),
    ...(record.activationPending === undefined ? {} : { activationPending: {
      ...record.activationPending,
      previousSubscription: record.activationPending.previousSubscription === null
        ? null : { ...record.activationPending.previousSubscription },
    } }),
  };
}

function createStore(initial: StoreDocument, persist: (document: StoreDocument) => void): PartnerStore {
  let partners = new Map(initial.partners.map((partner) => [partner.partnerId, clone(partner)]));
  let commissions = new Map(initial.commissions.map((commission) => [commission.commissionId, { ...commission }]));
  let queue: Promise<unknown> = Promise.resolve();
  const exclusive = <T>(task: () => T): Promise<T> => {
    const run = queue.then(task, task);
    queue = run.catch(() => undefined);
    return run;
  };
  const commit = (nextPartners: Map<string, PartnerRecord>, nextCommissions: Map<string, CommissionRecord>): void => {
    if (nextPartners.size > MAX_PARTNER_RECORDS || nextCommissions.size > MAX_COMMISSION_RECORDS) {
      throw new Error('Partner store capacity reached.');
    }
    persist({ version: 1, partners: [...nextPartners.values()], commissions: [...nextCommissions.values()] });
    partners = nextPartners;
    commissions = nextCommissions;
  };
  return {
    createPartner: (record) => exclusive(() => {
      if (!isPartnerRecord(record)) throw new Error('Invalid partner record.');
      if ([...partners.values()].some((partner) => partner.userId === record.userId)) return { kind: 'USER_EXISTS' as const };
      if ([...partners.values()].some((partner) => partner.coupon.couponCode === record.coupon.couponCode)) return { kind: 'COUPON_EXISTS' as const };
      const draft = new Map([...partners.values()].map((partner) => [partner.partnerId, clone(partner)]));
      draft.set(record.partnerId, clone(record));
      commit(draft, commissions);
      return { kind: 'CREATED' as const, partner: clone(record) };
    }),
    prepareLegacyActivation: (partnerId, at, previous, event) => exclusive(() => {
      const record = partners.get(partnerId);
      if (record === undefined || record.grantModel !== undefined || record.activationPending !== undefined) return undefined;
      const draft = new Map([...partners.values()].map((partner) => [partner.partnerId, clone(partner)]));
      const next = draft.get(partnerId)!;
      delete next.activationRecovery;
      next.activationPending = { initiatedAt: at, previousSubscription: previous === null ? null : { ...previous } };
      next.status = 'DEACTIVATED'; next.deactivatedAt = at; next.updatedAt = at;
      next.audit = [...next.audit, { ...event }].slice(-MAX_AUDIT_EVENT_PER_PARTNER);
      commit(draft, commissions);
      return clone(next);
    }),
    refreshPendingActivation: (partnerId, at, previous) => exclusive(() => {
      const record = partners.get(partnerId);
      if (record?.activationPending === undefined) return undefined;
      const draft = new Map([...partners.values()].map((partner) => [partner.partnerId, clone(partner)]));
      const next = draft.get(partnerId)!;
      next.activationPending = { initiatedAt: at, previousSubscription: previous === null ? null : { ...previous } };
      next.updatedAt = at;
      commit(draft, commissions);
      return clone(next);
    }),
    finishActivation: (partnerId, at, event) => exclusive(() => {
      const record = partners.get(partnerId);
      if (record === undefined || record.activationPending === undefined) return undefined;
      const draft = new Map([...partners.values()].map((partner) => [partner.partnerId, clone(partner)]));
      const next = draft.get(partnerId)!;
      next.complimentaryProGrantedAt = next.activationPending!.initiatedAt;
      delete next.activationPending;
      next.status = 'ACTIVE'; next.deactivatedAt = null; next.updatedAt = at;
      next.audit = [...next.audit, { ...event }].slice(-MAX_AUDIT_EVENT_PER_PARTNER);
      commit(draft, commissions);
      return clone(next);
    }),
    migrateAtomicGrant: (partnerId, at, event) => exclusive(() => {
      const record = partners.get(partnerId);
      if (record?.grantModel !== 'PARTNER_STORE_V1') return;
      const draft = new Map([...partners.values()].map((partner) => [partner.partnerId, clone(partner)]));
      const next = draft.get(partnerId)!;
      delete next.grantModel; next.updatedAt = at;
      next.audit = [...next.audit, { ...event }].slice(-MAX_AUDIT_EVENT_PER_PARTNER);
      commit(draft, commissions);
    }),
    getPartnerById: (partnerId) => {
      const record = partners.get(partnerId);
      return record === undefined ? undefined : clone(record);
    },
    getPartnerByUserId: (userId) => {
      const record = [...partners.values()].find((partner) => partner.userId === userId);
      return record === undefined ? undefined : clone(record);
    },
    getPartnerByCoupon: (couponCode) => {
      const record = [...partners.values()].find((partner) => partner.coupon.couponCode === couponCode);
      return record === undefined ? undefined : clone(record);
    },
    listPartners: (filters, page, pageSize) => {
      const all = [...partners.values()]
        .filter((partner) => filters.status === undefined || partner.status === filters.status)
        .sort((a, b) => (a.createdAt > b.createdAt ? -1 : a.createdAt < b.createdAt ? 1 : a.partnerId.localeCompare(b.partnerId)))
        .map(clone);
      const offset = (page - 1) * pageSize;
      return { partners: all.slice(offset, offset + pageSize), total: all.length };
    },
    listAllPartners: () => [...partners.values()].map(clone),
    updatePartnerStatus: (partnerId, status, at, event) => exclusive(() => {
      const record = partners.get(partnerId);
      if (record === undefined) return { kind: 'NOT_FOUND' as const };
      if (record.status === status) return { kind: 'IDEMPOTENT' as const, partner: clone(record) };
      const draft = new Map([...partners.values()].map((partner) => [partner.partnerId, clone(partner)]));
      const next = draft.get(partnerId) as PartnerRecord;
      next.status = status;
      next.updatedAt = at;
      next.deactivatedAt = status === 'DEACTIVATED' ? at : null;
      next.audit = [...next.audit, { ...event }].slice(-MAX_AUDIT_EVENT_PER_PARTNER);
      commit(draft, commissions);
      return { kind: 'UPDATED' as const, partner: clone(next) };
    }),
    updateCoupon: (partnerId, patch, at, auditEvents) => exclusive(() => {
      const record = partners.get(partnerId);
      if (record === undefined) return { kind: 'NOT_FOUND' as const };
      const draft = new Map([...partners.values()].map((partner) => [partner.partnerId, clone(partner)]));
      const next = draft.get(partnerId) as PartnerRecord;
      if (patch.status !== undefined) next.coupon.status = patch.status;
      if (patch.discountPercent !== undefined) next.coupon.discountPercent = patch.discountPercent;
      if (patch.commissionPercent !== undefined) next.coupon.commissionPercent = patch.commissionPercent;
      if (patch.expiresAt !== undefined) next.coupon.expiresAt = patch.expiresAt;
      next.coupon.updatedAt = at;
      next.updatedAt = at;
      next.audit = [...next.audit, ...auditEvents.map((event) => ({ ...event }))].slice(-MAX_AUDIT_EVENT_PER_PARTNER);
      commit(draft, commissions);
      return { kind: 'UPDATED' as const, partner: clone(next) };
    }),
    appendAudit: (partnerId, event) => exclusive(() => {
      const record = partners.get(partnerId);
      if (record === undefined) return;
      const draft = new Map([...partners.values()].map((partner) => [partner.partnerId, clone(partner)]));
      const next = draft.get(partnerId) as PartnerRecord;
      next.audit = [...next.audit, { ...event }].slice(-MAX_AUDIT_EVENT_PER_PARTNER);
      commit(draft, commissions);
    }),
    createCommission: (record) => exclusive(() => {
      const existing = [...commissions.values()].find((commission) => commission.paymentId === record.paymentId);
      if (existing !== undefined) return { kind: 'DUPLICATE' as const, commission: { ...existing } };
      const draft = new Map([...commissions.values()].map((commission) => [commission.commissionId, { ...commission }]));
      draft.set(record.commissionId, { ...record });
      commit(partners, draft);
      return { kind: 'CREATED' as const, commission: { ...record } };
    }),
    getCommission: (commissionId) => {
      const record = commissions.get(commissionId);
      return record === undefined ? undefined : { ...record };
    },
    getCommissionByPayment: (paymentId) => {
      const record = [...commissions.values()].find((commission) => commission.paymentId === paymentId);
      return record === undefined ? undefined : { ...record };
    },
    listCommissions: (filters, page, pageSize) => {
      const all = [...commissions.values()]
        .filter((commission) => (filters.partnerId === undefined || commission.partnerId === filters.partnerId) && (filters.status === undefined || commission.status === filters.status))
        .sort((a, b) => (a.createdAt > b.createdAt ? -1 : a.createdAt < b.createdAt ? 1 : a.commissionId.localeCompare(b.commissionId)))
        .map((commission) => ({ ...commission }));
      const offset = (page - 1) * pageSize;
      return { commissions: all.slice(offset, offset + pageSize), total: all.length };
    },
    listCommissionsForPartner: (partnerId) => [...commissions.values()].filter((commission) => commission.partnerId === partnerId).map((commission) => ({ ...commission })),
    transitionCommission: (commissionId, to, at, event) => exclusive(() => {
      const record = commissions.get(commissionId);
      if (record === undefined) return { kind: 'NOT_FOUND' as const };
      if (record.status === to) return { kind: 'IDEMPOTENT' as const, commission: { ...record } };
      const allowed =
        (to === 'AVAILABLE' && record.status === 'PENDING') ||
        (to === 'PAID' && record.status === 'AVAILABLE');
      if (!allowed) return { kind: 'INVALID_STATE' as const };
      const draftCommissions = new Map([...commissions.values()].map((commission) => [commission.commissionId, { ...commission }]));
      const next = draftCommissions.get(commissionId) as CommissionRecord;
      next.status = to;
      next.updatedAt = at;
      if (to === 'AVAILABLE') next.availableAt = at;
      else next.paidAt = at;
      // Commission lifecycle events are audited on the owning partner record.
      const draftPartners = new Map([...partners.values()].map((partner) => [partner.partnerId, clone(partner)]));
      const owner = draftPartners.get(record.partnerId);
      if (owner !== undefined) owner.audit = [...owner.audit, { ...event }].slice(-MAX_AUDIT_EVENT_PER_PARTNER);
      commit(draftPartners, draftCommissions);
      return { kind: 'UPDATED' as const, commission: { ...next } };
    }),
  };
}

/** Durable JSON document: temp-file write (0600) + atomic rename, same discipline as the payment store. */
export function createJsonFilePartnerStore(path: string): PartnerStore {
  const document = loadDocument(path);
  const persist = (next: StoreDocument): void => {
    writePrivateJson(path, `${JSON.stringify(next, null, 2)}\n`);
  };
  return createStore(document, persist);
}

/** Explicitly ephemeral store for tests/development; production config forbids ':memory:' here. */
export function createMemoryPartnerStore(): PartnerStore {
  return createStore(EMPTY_DOCUMENT, () => undefined);
}
