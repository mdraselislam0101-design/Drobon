import type { AuthUser } from './auth.js';
import { isRecord } from './guards.js';

/**
 * Authorization contracts (Pump 3) shared by the API and the Web client.
 *
 * Two INDEPENDENT concepts, deliberately never conflated:
 *
 * - `AccountRole` — authorization role: what the account is allowed to do
 *   (MEMBER < ADMIN < ACCOUNT_OWNER). The ONLY thing that may grant access.
 * - `UserType` — classification/visibility tag (how the user describes
 *   themselves). It never grants access, bypasses authentication, or
 *   substitutes for a role anywhere in the system.
 *
 * Access is declared per capability through the `PERMISSIONS` table below:
 * every protected capability names its required role explicitly, so future
 * systems (plans, scans, admin, partner) extend this table instead of
 * relying on hierarchy alone.
 */

/** Authorization roles, ordered from the built-in table's ranks. */
export const ACCOUNT_ROLES = ['MEMBER', 'ADMIN', 'ACCOUNT_OWNER'] as const;
export type AccountRole = (typeof ACCOUNT_ROLES)[number];

/**
 * Hierarchy ranks. Comparison against these numbers is only ever performed
 * via `roleAtLeast()` — callers never hand-roll rank math.
 */
export const ACCOUNT_ROLE_RANK: Readonly<Record<AccountRole, number>> = {
  MEMBER: 0,
  ADMIN: 10,
  ACCOUNT_OWNER: 20,
};

/** Runtime guard: value is exactly one of the known account roles. */
export function isAccountRole(value: unknown): value is AccountRole {
  return typeof value === 'string' && (ACCOUNT_ROLES as readonly string[]).includes(value);
}

/**
 * Hierarchy check (`role >= min`). Hierarchy alone NEVER grants access —
 * a capability must first declare its required role via `PERMISSIONS` or
 * an explicit `requireRole`.
 */
export function roleAtLeast(role: AccountRole, min: AccountRole): boolean {
  return ACCOUNT_ROLE_RANK[role] >= ACCOUNT_ROLE_RANK[min];
}

/** User classification/visibility tags — NOT authorization inputs. */
export const USER_TYPES = [
  'DEVELOPER',
  'STUDENT',
  'SECURITY_PROFESSIONAL',
  'PENTESTER',
] as const;
export type UserType = (typeof USER_TYPES)[number];

/** Runtime guard: value is exactly one of the known user types. */
export function isUserType(value: unknown): value is UserType {
  return typeof value === 'string' && (USER_TYPES as readonly string[]).includes(value);
}

/**
 * The capability table: permission → the MINIMUM account role that holds
 * it. This is the single place capabilities are declared; routes, guards
 * and UI all read from it — no scattered role strings.
 */
export const PERMISSIONS = {
  /** Authenticated access to the member-level capability probe. */
  'authz:capability:member': 'MEMBER',
  /** Admin-level capability probe. */
  'authz:capability:admin': 'ADMIN',
  /** Owner-level capability probe. */
  'authz:capability:owner': 'ACCOUNT_OWNER',
  /** Read your own account record. */
  'users:read:self': 'MEMBER',
  /** Read another user's account record (privileged; explicit). */
  'users:read:others': 'ADMIN',
} as const satisfies Record<string, AccountRole>;

export type Permission = keyof typeof PERMISSIONS;

/** Runtime guard: value is a permission declared in the table. */
export function isPermission(value: unknown): value is Permission {
  return typeof value === 'string' && Object.prototype.hasOwnProperty.call(PERMISSIONS, value);
}

/** The minimum role required for a declared permission. */
export function requiredRoleForPermission(permission: Permission): AccountRole {
  return PERMISSIONS[permission];
}

/** Does this role hold this permission (via the table + hierarchy)? */
export function hasPermission(role: AccountRole, permission: Permission): boolean {
  return roleAtLeast(role, requiredRoleForPermission(permission));
}

/**
 * The minimum authorization information the UI may hold about the
 * authenticated user. Derived exclusively from server-side state (the
 * session → account record); the client NEVER supplies it.
 *
 * Hiding UI is UX defense-in-depth only — the API remains the real
 * security boundary.
 */
export interface AuthzContext {
  readonly user: AuthUser;
  readonly role: AccountRole;
  readonly userType: UserType | null;
  hasRole(min: AccountRole): boolean;
  hasPermission(permission: Permission): boolean;
}

/** The three capability probes exposed by the API foundation. */
export const AUTHZ_CAPABILITY_LEVELS = ['member', 'admin', 'owner'] as const;
export type AuthzCapability = (typeof AUTHZ_CAPABILITY_LEVELS)[number];

/** Runtime guard for capability probe responses. */
export function isAuthzCapability(value: unknown): value is AuthzCapability {
  return typeof value === 'string' && (AUTHZ_CAPABILITY_LEVELS as readonly string[]).includes(value);
}

/**
 * `GET /api/v1/authz/capabilities/:level` response — confirms only that
 * the capability was granted. It never discloses role configuration,
 * required roles, or anything about other accounts.
 */
export interface CapabilityResponse {
  capability: AuthzCapability;
}

/** Guard for {@link CapabilityResponse} payloads. */
export function isCapabilityResponse(value: unknown): value is CapabilityResponse {
  return isRecord(value) && isAuthzCapability(value['capability']);
}
