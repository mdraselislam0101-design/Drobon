import { randomUUID } from 'node:crypto';
import type {
  AdminProGrant,
  AdminProGrantAuditAction,
  EntitlementAuditEvent,
  ProEntitlementSource,
  Subscription,
} from '@drobon/shared';
import {
  ADMIN_PRO_GRANT_MAX_EXPIRY_DAYS,
  ADMIN_PRO_GRANT_REASON_MAX_LENGTH,
} from '@drobon/shared';
import { conflict, notFound, validationError } from '../errors.js';
import { redactAssistantText } from '../assistant/redaction.js';
import type { UserRecord } from '../auth/repositories.js';
import { resolveSubscription } from '../auth/subscriptions.js';
import type { EntitlementAuditFilters, EntitlementGrantFilters, EntitlementStore } from './store.js';

/**
 * The entitlement service — the SINGLE authority for admin complimentary
 * PRO grants. Every mutation is server-authoritative:
 *
 * - the acting admin identity and the timestamps come from the server
 *   (session + clock), never from the request body;
 * - the client may choose ONLY the target account, an optional expiry
 *   and an optional reason — never a price, an amount, a plan level or a
 *   commission (those concepts do not exist here by construction);
 * - a grant NEVER writes a payment record, the payment ledger, revenue,
 *   commissions or coupon attribution (payment isolation, tested);
 * - a grant NEVER mutates the account's persisted subscription (the paid
 *   source), so paid PRO always survives a revoke/expiry (tested);
 * - idempotency: at most ONE effectively-active grant per account ever
 *   exists; duplicate submissions return the existing grant unchanged;
 * - every grant and revoke appends an immutable audit event with the
 *   server-side actor — the client cannot forge actor or time.
 */

export interface EntitlementService {
  /** Grant complimentary PRO. Idempotent while a grant is active. */
  grantPro(adminId: string, input: {
    accountId: string;
    expiresAt?: string | null;
    reason?: string | null;
  }): Promise<{ grant: AdminProGrant; created: boolean }>;
  /** Revoke an ACTIVE grant. Paid state is never touched. */
  revokePro(grantId: string, adminId: string, input: {
    reason?: string | null;
  }): Promise<{ grant: AdminProGrant }>;
  listGrants(filters: EntitlementGrantFilters, page: number, pageSize: number): {
    grants: AdminProGrant[];
    page: number;
    pageSize: number;
    total: number;
  };
  getGrant(grantId: string): AdminProGrant | undefined;
  listAudit(filters: EntitlementAuditFilters, page: number, pageSize: number): {
    events: EntitlementAuditEvent[];
    page: number;
    pageSize: number;
    total: number;
  };
  /** Is at least one ADMIN_GRANT currently active for the account? */
  hasActivePro(accountId: string): boolean;
  /** The account's currently-active grant record, if any. */
  getActiveGrant(accountId: string): AdminProGrant | undefined;
  /** Known source only: active admin grant or auditable paid activation. */
  proEntitlementSourceFor(record: UserRecord): ProEntitlementSource | undefined;
  /** Unknown/legacy/partner subscription provenance is deliberately omitted. */
  proEntitlementSourceForSubscription(accountId: string, subscription: Subscription): ProEntitlementSource | undefined;
}

/** Normalize the optional reason: sanitized, bounded, or `null`. */
function normalizeReason(raw: string | null | undefined): string | null {
  if (raw === undefined || raw === null) return null;
  const redacted = redactAssistantText(raw).text;
  let withoutControls = '';
  for (const character of redacted) {
    const code = character.charCodeAt(0);
    withoutControls += code < 32 || code === 127 ? ' ' : character;
  }
  const normalized = withoutControls.trim().replace(/\s+/g, ' ');
  if (normalized.length === 0) return null;
  if (normalized.length > ADMIN_PRO_GRANT_REASON_MAX_LENGTH) {
    throw validationError([{ path: 'reason', message: `Reason must be at most ${ADMIN_PRO_GRANT_REASON_MAX_LENGTH} characters.` }]);
  }
  return normalized;
}

/** Validate the optional expiry: ISO timestamp, strictly future, bounded horizon. */
function normalizeExpiry(raw: string | null | undefined, nowMs: number): string | null {
  if (raw === undefined || raw === null) return null;
  if (typeof raw !== 'string' || Number.isNaN(Date.parse(raw))) {
    throw validationError([{ path: 'expiresAt', message: 'Expiry must be an ISO 8601 timestamp or null.' }]);
  }
  const at = Date.parse(raw);
  if (at <= nowMs) {
    throw validationError([{ path: 'expiresAt', message: 'Expiry must be in the future.' }]);
  }
  const maxMs = nowMs + ADMIN_PRO_GRANT_MAX_EXPIRY_DAYS * 24 * 60 * 60 * 1000;
  if (at > maxMs) {
    throw validationError([{ path: 'expiresAt', message: `Expiry may be at most ${ADMIN_PRO_GRANT_MAX_EXPIRY_DAYS} days ahead.` }]);
  }
  return new Date(at).toISOString();
}

function auditEvent(input: {
  grantId: string;
  accountId: string;
  actorId: string;
  action: AdminProGrantAuditAction;
  timestamp: string;
  reason: string | null;
}): EntitlementAuditEvent {
  return {
    eventId: `evt_${randomUUID()}`,
    grantId: input.grantId,
    accountId: input.accountId,
    actorId: input.actorId,
    action: input.action,
    timestamp: input.timestamp,
    reason: input.reason,
  };
}

export function createEntitlementService(options: {
  store: EntitlementStore;
  users: import('../auth/repositories.js').UserRepository;
  /** Internal payment audit evidence, never a client claim. */
  hasPaidActivation?: (accountId: string, subscriptionCreatedAt: string | null) => boolean;
  now?: () => number;
}): EntitlementService {
  const { store, users } = options;
  const now = options.now ?? Date.now;
  const timestamp = (): string => new Date(now()).toISOString();
  const sourceFor = (accountId: string, subscription: Subscription): ProEntitlementSource | undefined => {
    if (store.getActiveForAccount(accountId, now()) !== undefined) return 'ADMIN_GRANT';
    if (subscription.plan === 'PRO' && subscription.status === 'ACTIVE' &&
        options.hasPaidActivation?.(accountId, subscription.createdAt) === true) return 'PAID';
    return undefined;
  };

  return {
    grantPro: async (adminId, input) => {
      if (typeof input.accountId !== 'string' || input.accountId.length === 0) {
        throw validationError([{ path: 'accountId', message: 'A target account is required.' }]);
      }
      const account = await users.findById(input.accountId);
      if (account === undefined) {
        // Uniform with the partner-activation surface: never an existence
        // oracle beyond the admin's need to pick a valid target.
        throw validationError([{ path: 'accountId', message: 'The selected account does not exist.' }]);
      }
      const expiresAt = normalizeExpiry(input.expiresAt, now());
      const reason = normalizeReason(input.reason);
      const at = timestamp();
      const grant: AdminProGrant = {
        grantId: `apg_${randomUUID()}`,
        accountId: account.id,
        source: 'ADMIN_GRANT',
        plan: 'PRO',
        status: 'ACTIVE',
        paymentRequired: false,
        grantedBy: adminId,
        grantedAt: at,
        expiresAt,
        revokedAt: null,
        revokedBy: null,
        reason,
        updatedAt: at,
      };
      const result = await store.createGrant(grant, [
        auditEvent({ grantId: grant.grantId, accountId: grant.accountId, actorId: adminId, action: 'ADMIN_PRO_GRANT', timestamp: at, reason }),
      ], now());
      // Idempotent replay: the SAME active grant, no second audit event,
      // no second entitlement record — duplicate submissions are safe.
      return { grant: result.grant, created: result.kind === 'CREATED' };
    },

    revokePro: async (grantId, adminId, input) => {
      const current = store.get(grantId);
      if (current === undefined) throw notFound();
      const reason = normalizeReason(input.reason);
      const at = timestamp();
      const result = await store.revoke(grantId, {
        revokedAt: at,
        revokedBy: adminId,
        reason,
        updatedAt: at,
      }, auditEvent({ grantId, accountId: current.accountId, actorId: adminId, action: 'ADMIN_PRO_REVOKE', timestamp: at, reason }));
      if (!('grant' in result)) {
        if (result.kind === 'NOT_FOUND') throw notFound();
        throw conflict('This grant has already been revoked.');
      }
      return { grant: result.grant };
    },

    listGrants: (filters, page, pageSize) => {
      const result = store.list(filters, page, pageSize);
      return { grants: result.grants, page, pageSize, total: result.total };
    },

    getGrant: (grantId) => store.get(grantId),

    listAudit: (filters, page, pageSize) => {
      const result = store.listAudit(filters, page, pageSize);
      return { events: result.events, page, pageSize, total: result.total };
    },

    hasActivePro: (accountId) => store.getActiveForAccount(accountId, now()) !== undefined,

    getActiveGrant: (accountId) => store.getActiveForAccount(accountId, now()),

    proEntitlementSourceFor: (record) => sourceFor(record.id, resolveSubscription(record)),
    proEntitlementSourceForSubscription: sourceFor,
  };
}
