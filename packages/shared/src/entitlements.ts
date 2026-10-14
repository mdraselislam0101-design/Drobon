import { isRecord } from './guards.js';
import type { Plan } from './plans.js';

/**
 * Admin Complimentary PRO entitlement contracts.
 *
 * BUSINESS RULE (deliberate, load-bearing): an admin-granted PRO
 * entitlement is NOT a payment. It never creates a payment record, never
 * touches the payment ledger, revenue, collected amounts, partner
 * commissions or coupon attribution. The ONLY thing it does is make the
 * account's EFFECTIVE plan PRO while the grant is ACTIVE.
 *
 * ENTITLEMENT SOURCES — deliberately kept separate:
 * - `PAID` — the account's own persisted subscription was set to
 *   PRO+ACTIVE by the payment approval saga (or the legacy partner
 *   complimentary activation, which shares that seam; see docs/ADMIN.md).
 *   This is the subscription on the account record.
 * - `ADMIN_GRANT` — a persistent grant record in the entitlement store,
 *   created by a platform admin, with its own grant/revoke/expiry
 *   lifecycle and its own audit trail. Never merged into the payment
 *   ledger and never written into the account's subscription.
 * - Partner complimentary PRO remains its own concept (partner store
 *   flag + activation seam). It is NOT re-labeled ADMIN_GRANT here.
 *
 * Effective plan derivation (the ONE rule, server-side only):
 *   effective = PRO  iff  (subscription is PRO+ACTIVE)  OR
 *                         (at least one ADMIN_GRANT is currently active)
 *   effective = FREE otherwise.
 *
 * Consequences (all tested):
 * - revoke/expire the grant with paid PRO underneath → still PRO (paid);
 * - revoke/expire the grant with nothing underneath → FREE;
 * - the grant can never corrupt, reset or replace paid state.
 */

/** How the caller's effective PRO is sourced (subscription vs explicit grant). */
export const PRO_ENTITLEMENT_SOURCES = ['PAID', 'ADMIN_GRANT'] as const;
export type ProEntitlementSource = (typeof PRO_ENTITLEMENT_SOURCES)[number];

/** Runtime guard for {@link ProEntitlementSource}. */
export function isProEntitlementSource(value: unknown): value is ProEntitlementSource {
  return typeof value === 'string' && (PRO_ENTITLEMENT_SOURCES as readonly string[]).includes(value);
}

/** Grant lifecycle states. `EXPIRED` is derived from `expiresAt` at read time. */
export const ADMIN_PRO_GRANT_STATUSES = ['ACTIVE', 'REVOKED'] as const;
export type AdminProGrantStatus = (typeof ADMIN_PRO_GRANT_STATUSES)[number];

/** Runtime guard for {@link AdminProGrantStatus}. */
export function isAdminProGrantStatus(value: unknown): value is AdminProGrantStatus {
  return typeof value === 'string' && (ADMIN_PRO_GRANT_STATUSES as readonly string[]).includes(value);
}

/** Audit actions of the entitlement domain (append-only trail). */
export const ADMIN_PRO_GRANT_AUDIT_ACTIONS = ['ADMIN_PRO_GRANT', 'ADMIN_PRO_REVOKE'] as const;
export type AdminProGrantAuditAction = (typeof ADMIN_PRO_GRANT_AUDIT_ACTIONS)[number];

/** Runtime guard for {@link AdminProGrantAuditAction}. */
export function isAdminProGrantAuditAction(value: unknown): value is AdminProGrantAuditAction {
  return (
    typeof value === 'string' &&
    (ADMIN_PRO_GRANT_AUDIT_ACTIONS as readonly string[]).includes(value)
  );
}

/** Pagination bounds for the admin grant surface. */
export const ADMIN_ENTITLEMENT_PAGE_SIZE_MAX = 100;
export const ADMIN_ENTITLEMENT_PAGE_MAX = 1_000;
/** Reason/note bound (audit redaction rules apply server-side). */
export const ADMIN_PRO_GRANT_REASON_MAX_LENGTH = 300;
/** Maximum grant horizon: 3660 days (~10 years) from grant time. */
export const ADMIN_PRO_GRANT_MAX_EXPIRY_DAYS = 3660;

/**
 * The public shape of an admin complimentary PRO grant (admin surface).
 * `paymentRequired` is a fixed `false` — the type itself documents that a
 * grant is never a payment.
 */
export interface AdminProGrant {
  grantId: string;
  accountId: string;
  source: 'ADMIN_GRANT';
  plan: 'PRO';
  status: AdminProGrantStatus;
  /** Always false: a grant never requires (and never records) a payment. */
  paymentRequired: false;
  grantedBy: string;
  grantedAt: string;
  /** Server-authoritative expiry, or `null` for an open-ended grant. */
  expiresAt: string | null;
  revokedAt: string | null;
  revokedBy: string | null;
  reason: string | null;
  updatedAt: string;
}

/** `POST /api/v1/admin/entitlements/pro` response. */
export interface AdminProGrantResponse {
  grant: AdminProGrant;
}

/** Paged grant list (`GET /api/v1/admin/entitlements/pro`). */
export interface AdminProGrantsResponse {
  grants: AdminProGrant[];
  page: number;
  pageSize: number;
  total: number;
}

/** Single append-only audit event of the entitlement domain. */
export interface EntitlementAuditEvent {
  eventId: string;
  grantId: string;
  accountId: string;
  actorId: string;
  action: AdminProGrantAuditAction;
  timestamp: string;
  reason: string | null;
}

/** Paged entitlement audit (`GET /api/v1/admin/entitlements/pro/audit`). */
export interface EntitlementAuditResponse {
  events: EntitlementAuditEvent[];
  page: number;
  pageSize: number;
  total: number;
  coverage: 'ENTITLEMENT_EVENTS_ONLY';
}

function isTimestampOrNull(value: unknown): value is string | null {
  return value === null || (typeof value === 'string' && !Number.isNaN(Date.parse(value)));
}

/** Structural guard for {@link AdminProGrant} at the admin client boundary. */
export function isAdminProGrant(value: unknown): value is AdminProGrant {
  return (
    isRecord(value) &&
    typeof value['grantId'] === 'string' && /^apg_[0-9a-f-]{36}$/i.test(value['grantId']) &&
    typeof value['accountId'] === 'string' && /^usr_[A-Za-z0-9_-]{1,128}$/.test(value['accountId']) &&
    value['source'] === 'ADMIN_GRANT' &&
    value['plan'] === 'PRO' &&
    isAdminProGrantStatus(value['status']) &&
    value['paymentRequired'] === false &&
    typeof value['grantedBy'] === 'string' && value['grantedBy'].length > 0 &&
    typeof value['grantedAt'] === 'string' && !Number.isNaN(Date.parse(value['grantedAt'])) &&
    isTimestampOrNull(value['expiresAt']) &&
    isTimestampOrNull(value['revokedAt']) &&
    (value['revokedBy'] === null || (typeof value['revokedBy'] === 'string' && value['revokedBy'].length > 0)) &&
    (value['reason'] === null || (typeof value['reason'] === 'string' && value['reason'].length <= ADMIN_PRO_GRANT_REASON_MAX_LENGTH)) &&
    typeof value['updatedAt'] === 'string' && !Number.isNaN(Date.parse(value['updatedAt']))
  );
}

/** Guard for {@link AdminProGrantResponse}. */
export function isAdminProGrantResponse(value: unknown): value is AdminProGrantResponse {
  return isRecord(value) && isAdminProGrant(value['grant']);
}

/** Guard for {@link AdminProGrantsResponse}. */
export function isAdminProGrantsResponse(value: unknown): value is AdminProGrantsResponse {
  return (
    isRecord(value) &&
    Array.isArray(value['grants']) &&
    value['grants'].every(isAdminProGrant) &&
    typeof value['page'] === 'number' && Number.isSafeInteger(value['page']) && value['page'] >= 1 &&
    typeof value['pageSize'] === 'number' && Number.isSafeInteger(value['pageSize']) && value['pageSize'] >= 1 &&
    value['pageSize'] <= ADMIN_ENTITLEMENT_PAGE_SIZE_MAX &&
    typeof value['total'] === 'number' && Number.isSafeInteger(value['total']) && value['total'] >= 0 &&
    value['grants'].length <= value['pageSize']
  );
}

/** Guard for {@link EntitlementAuditEvent}. */
export function isEntitlementAuditEvent(value: unknown): value is EntitlementAuditEvent {
  return (
    isRecord(value) &&
    typeof value['eventId'] === 'string' && /^evt_[0-9a-f-]{36}$/i.test(value['eventId']) &&
    typeof value['grantId'] === 'string' && /^apg_[0-9a-f-]{36}$/i.test(value['grantId']) &&
    typeof value['accountId'] === 'string' && value['accountId'].length > 0 &&
    typeof value['actorId'] === 'string' && value['actorId'].length > 0 &&
    isAdminProGrantAuditAction(value['action']) &&
    typeof value['timestamp'] === 'string' && !Number.isNaN(Date.parse(value['timestamp'])) &&
    (value['reason'] === null || (typeof value['reason'] === 'string' && value['reason'].length <= ADMIN_PRO_GRANT_REASON_MAX_LENGTH))
  );
}

/** Guard for {@link EntitlementAuditResponse}. */
export function isEntitlementAuditResponse(value: unknown): value is EntitlementAuditResponse {
  return (
    isRecord(value) &&
    Array.isArray(value['events']) &&
    value['events'].every(isEntitlementAuditEvent) &&
    typeof value['page'] === 'number' && Number.isSafeInteger(value['page']) && value['page'] >= 1 &&
    typeof value['pageSize'] === 'number' && Number.isSafeInteger(value['pageSize']) && value['pageSize'] >= 1 && value['pageSize'] <= ADMIN_ENTITLEMENT_PAGE_SIZE_MAX &&
    typeof value['total'] === 'number' && Number.isSafeInteger(value['total']) && value['total'] >= 0 &&
    value['events'].length <= value['pageSize'] &&
    value['coverage'] === 'ENTITLEMENT_EVENTS_ONLY'
  );
}

/**
 * Effective-plan contribution of one account's entitlement state — the
 * pure server-side rule shared by every consumer (usage, subscription,
 * payments, admin projections). `paidPro` is the account's own persisted
 * subscription verdict; `hasActiveGrant` says whether at least one
 * ADMIN_GRANT is currently active (status ACTIVE and unexpired).
 */
export function effectivePlanFor(paidPro: boolean, hasActiveGrant: boolean): Plan {
  return paidPro || hasActiveGrant ? 'PRO' : 'FREE';
}
