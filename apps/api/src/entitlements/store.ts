import { writePrivateJson } from '../lib/writePrivateJson.js';
import { readFileSync } from 'node:fs';
import type {
  AdminProGrant,
  AdminProGrantAuditAction,
  AdminProGrantStatus,
  EntitlementAuditEvent,
} from '@drobon/shared';
import { isAdminProGrantAuditAction, isAdminProGrantStatus } from '@drobon/shared';

/**
 * Admin complimentary PRO entitlement store.
 *
 * ONE atomic JSON document holds grants + their append-only audit trail,
 * exactly mirroring the payment-store discipline: load-time validation
 * that refuses corrupt data (fail fast — these records grant commercial
 * entitlement), exclusive serialized mutations, and atomic temp-file
 * renames. The store is the ONLY writer of grant records; the payment
 * ledger and the account subscription are structurally out of its reach.
 *
 * Expiry is DERIVED at read time (`expiresAt` vs the passed clock) — no
 * background mutator exists, so a lapsed grant is never silently
 * rewritten; admins always see the honest stored lifecycle plus the
 * derived effective state.
 */

export interface EntitlementGrantFilters {
  accountId?: string;
  status?: AdminProGrantStatus;
}

export interface EntitlementAuditFilters {
  grantId?: string;
  accountId?: string;
  action?: AdminProGrantAuditAction;
}

export interface EntitlementStore {
  /** Create a grant. Rejects when the account already has an ACTIVE (unexpired) grant. */
  createGrant(
    record: AdminProGrant,
    events: readonly EntitlementAuditEvent[],
    nowMs: number,
  ): Promise<{ kind: 'CREATED'; grant: AdminProGrant } | { kind: 'ACTIVE_EXISTS'; grant: AdminProGrant }>;
  get(grantId: string): AdminProGrant | undefined;
  /** The account's currently-active grant (ACTIVE status AND unexpired), if any. */
  getActiveForAccount(accountId: string, nowMs: number): AdminProGrant | undefined;
  /** Active-grant lookup across a set of accounts (admin projection seam). */
  activeGrantsByAccount(accountIds: readonly string[], nowMs: number): ReadonlyMap<string, AdminProGrant>;
  list(filters: EntitlementGrantFilters, page: number, pageSize: number): { grants: AdminProGrant[]; total: number };
  revoke(
    grantId: string,
    patch: { revokedAt: string; revokedBy: string; reason: string | null; updatedAt: string },
    event: EntitlementAuditEvent,
  ): Promise<{ kind: 'UPDATED'; grant: AdminProGrant } | { kind: 'NOT_FOUND' | 'ALREADY_REVOKED' }>;
  listAudit(filters: EntitlementAuditFilters, page: number, pageSize: number): { events: EntitlementAuditEvent[]; total: number };
}

interface StoreDocument {
  version: 1;
  grants: AdminProGrant[];
  auditEvents: EntitlementAuditEvent[];
}

const MAX_GRANT_RECORDS = 100_000;
const MAX_AUDIT_EVENTS = 500_000;

function validTimestamp(value: unknown): value is string {
  return typeof value === 'string' && !Number.isNaN(Date.parse(value));
}

function isNullableTimestamp(value: unknown): value is string | null {
  return value === null || validTimestamp(value);
}

function isGrantRecord(value: unknown): value is AdminProGrant {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const r = value as Record<string, unknown>;
  return (
    typeof r['grantId'] === 'string' && /^apg_[0-9a-f-]{36}$/i.test(r['grantId']) &&
    typeof r['accountId'] === 'string' && r['accountId'].length > 0 &&
    r['source'] === 'ADMIN_GRANT' && r['plan'] === 'PRO' &&
    isAdminProGrantStatus(r['status']) && r['paymentRequired'] === false &&
    typeof r['grantedBy'] === 'string' && r['grantedBy'].length > 0 &&
    validTimestamp(r['grantedAt']) && isNullableTimestamp(r['expiresAt']) &&
    isNullableTimestamp(r['revokedAt']) &&
    (r['revokedBy'] === null || (typeof r['revokedBy'] === 'string' && r['revokedBy'].length > 0)) &&
    (r['reason'] === null || (typeof r['reason'] === 'string' && r['reason'].length <= 300)) &&
    validTimestamp(r['updatedAt'])
  );
}

function isAuditEvent(value: unknown): value is EntitlementAuditEvent {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const r = value as Record<string, unknown>;
  return (
    typeof r['eventId'] === 'string' && /^evt_[0-9a-f-]{36}$/i.test(r['eventId']) &&
    typeof r['grantId'] === 'string' && typeof r['accountId'] === 'string' &&
    typeof r['actorId'] === 'string' && isAdminProGrantAuditAction(r['action']) &&
    validTimestamp(r['timestamp']) &&
    (r['reason'] === null || (typeof r['reason'] === 'string' && r['reason'].length <= 300))
  );
}

/** Is the stored grant effectively active at `nowMs` (ACTIVE and unexpired)? */
export function isGrantEffectivelyActive(grant: AdminProGrant, nowMs: number): boolean {
  if (grant.status !== 'ACTIVE') return false;
  if (grant.expiresAt !== null && Date.parse(grant.expiresAt) <= nowMs) return false;
  return true;
}

function loadDocument(path: string): StoreDocument {
  let raw: string;
  try {
    raw = readFileSync(path, 'utf8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { version: 1, grants: [], auditEvents: [] };
    throw new Error(`Cannot read entitlement store at ${path}: ${(error as NodeJS.ErrnoException).code ?? 'I/O error'}`);
  }
  let parsed: unknown;
  try { parsed = JSON.parse(raw) as unknown; } catch {
    throw new Error(`Entitlement store at ${path} is not valid JSON — refusing to start with corrupt entitlement data.`);
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error(`Entitlement store at ${path} has an unexpected shape — refusing to start.`);
  }
  const doc = parsed as Record<string, unknown>;
  if (doc['version'] !== 1 || !Array.isArray(doc['grants']) || !Array.isArray(doc['auditEvents']) ||
      doc['grants'].length > MAX_GRANT_RECORDS || doc['auditEvents'].length > MAX_AUDIT_EVENTS ||
      !doc['grants'].every(isGrantRecord) || !doc['auditEvents'].every(isAuditEvent)) {
    throw new Error(`Entitlement store at ${path} has invalid records — refusing to start.`);
  }
  const grants = doc['grants'] as AdminProGrant[];
  const ids = new Set<string>();
  for (const grant of grants) {
    if (ids.has(grant.grantId)) {
      throw new Error(`Entitlement store at ${path} contains duplicate grant ids — refusing to start.`);
    }
    ids.add(grant.grantId);
  }
  const grantIds = new Set(ids);
  if ((doc['auditEvents'] as EntitlementAuditEvent[]).some((event) => !grantIds.has(event.grantId))) {
    throw new Error(`Entitlement store at ${path} contains an orphan audit event — refusing to start.`);
  }
  return { version: 1, grants: grants.map((g) => ({ ...g })), auditEvents: (doc['auditEvents'] as EntitlementAuditEvent[]).map((e) => ({ ...e })) };
}

function createStore(initial: StoreDocument, persist: (document: StoreDocument) => void): EntitlementStore {
  let grants = new Map(initial.grants.map((g) => [g.grantId, { ...g }]));
  let auditEvents = initial.auditEvents.map((e) => ({ ...e }));
  let queue: Promise<unknown> = Promise.resolve();
  const exclusive = <T>(task: () => T): Promise<T> => {
    const run = queue.then(task, task);
    queue = run.catch(() => undefined);
    return run;
  };
  const commit = (nextGrants: Map<string, AdminProGrant>, nextEvents: EntitlementAuditEvent[]): void => {
    if (nextGrants.size > MAX_GRANT_RECORDS || nextEvents.length > MAX_AUDIT_EVENTS) {
      throw new Error('Entitlement store capacity reached.');
    }
    const doc: StoreDocument = { version: 1, grants: [...nextGrants.values()], auditEvents: nextEvents };
    persist(doc);
    grants = nextGrants;
    auditEvents = nextEvents;
  };
  const sortByNewest = (a: AdminProGrant, b: AdminProGrant): number =>
    b.grantedAt.localeCompare(a.grantedAt) || a.grantId.localeCompare(b.grantId);
  return {
    createGrant: (record, events, nowMs) => exclusive(() => {
      const existingActive = [...grants.values()].find(
        (g) => g.accountId === record.accountId && isGrantEffectivelyActive(g, nowMs),
      );
      if (existingActive !== undefined) return { kind: 'ACTIVE_EXISTS' as const, grant: { ...existingActive } };
      const next = new Map(grants);
      next.set(record.grantId, { ...record });
      commit(next, [...auditEvents, ...events.map((e) => ({ ...e }))]);
      return { kind: 'CREATED' as const, grant: { ...record } };
    }),
    get: (grantId) => {
      const record = grants.get(grantId);
      return record === undefined ? undefined : { ...record };
    },
    getActiveForAccount: (accountId, nowMs) => {
      for (const grant of grants.values()) {
        if (grant.accountId === accountId && isGrantEffectivelyActive(grant, nowMs)) return { ...grant };
      }
      return undefined;
    },
    activeGrantsByAccount: (accountIds, nowMs) => {
      const wanted = new Set(accountIds);
      const result = new Map<string, AdminProGrant>();
      for (const grant of grants.values()) {
        if (!wanted.has(grant.accountId)) continue;
        if (!isGrantEffectivelyActive(grant, nowMs)) continue;
        const current = result.get(grant.accountId);
        if (current === undefined || grant.grantedAt > current.grantedAt) result.set(grant.accountId, { ...grant });
      }
      return result;
    },
    list: (filters, page, pageSize) => {
      const offset = (page - 1) * pageSize;
      const all = [...grants.values()]
        .filter((g) =>
          (filters.accountId === undefined || g.accountId === filters.accountId) &&
          (filters.status === undefined || g.status === filters.status))
        .sort(sortByNewest);
      return { grants: all.slice(offset, offset + pageSize).map((g) => ({ ...g })), total: all.length };
    },
    revoke: (grantId, patch, event) => exclusive(() => {
      const current = grants.get(grantId);
      if (current === undefined) return { kind: 'NOT_FOUND' as const };
      if (current.status === 'REVOKED') return { kind: 'ALREADY_REVOKED' as const };
      const updated: AdminProGrant = {
        ...current,
        status: 'REVOKED',
        revokedAt: patch.revokedAt,
        revokedBy: patch.revokedBy,
        reason: patch.reason ?? current.reason,
        updatedAt: patch.updatedAt,
      };
      const next = new Map(grants);
      next.set(grantId, updated);
      commit(next, [...auditEvents, { ...event }]);
      return { kind: 'UPDATED' as const, grant: { ...updated } };
    }),
    listAudit: (filters, page, pageSize) => {
      const offset = (page - 1) * pageSize;
      const all = auditEvents
        .filter((e) =>
          (filters.grantId === undefined || e.grantId === filters.grantId) &&
          (filters.accountId === undefined || e.accountId === filters.accountId) &&
          (filters.action === undefined || e.action === filters.action))
        .sort((a, b) => b.timestamp.localeCompare(a.timestamp) || a.eventId.localeCompare(b.eventId));
      return { events: all.slice(offset, offset + pageSize).map((e) => ({ ...e })), total: all.length };
    },
  };
}

/** Durable JSON-backed, atomic, single-process/single-writer grant + audit store. */
export function createJsonFileEntitlementStore(path: string): EntitlementStore {
  const persist = (document: StoreDocument): void => {
    writePrivateJson(path, `${JSON.stringify(document, null, 2)}\n`);
  };
  return createStore(loadDocument(path), persist);
}

/** Process-local store for tests/explicit ephemeral non-production deployments. */
export function createMemoryEntitlementStore(): EntitlementStore {
  return createStore({ version: 1, grants: [], auditEvents: [] }, () => undefined);
}
