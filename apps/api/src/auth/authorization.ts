import type { AccountRole, AuthzContext, AuthUser, Permission } from '@drobon/shared';
import { hasPermission, roleAtLeast } from '@drobon/shared';
import { forbidden, unauthorized } from '../errors.js';

/**
 * Authorization primitives (Pump 3).
 *
 * Every protected capability declares its requirement explicitly — either
 * a role (`Route.requireRole`) or a permission from the shared table
 * (`Route.requirePermission`) — enforced at the router choke point (the
 * same place `requireAuth` lives, so authentication → authorization keeps
 * one coherent boundary). Ownership-sensitive handlers additionally use
 * the `canReadUser`/`assertCanReadUser` helpers below.
 *
 * Design rules:
 * - authorization state is derived ONLY from server-side account state
 *   (session → repository record); client-supplied role/userType/headers
 *   are never consulted;
 * - denials are uniformly `403 FORBIDDEN` with {@link AUTHZ_DENIED_MESSAGE}
 *   — no role names, no required-role hints, no existence leaks;
 * - 401 stays reserved for missing/invalid authentication, so the two
 *   statuses keep their distinct meanings;
 * - future capabilities (plans, scans, admin, partner) add entries to the
 *   shared PERMISSIONS table and/or new routes — never a second system.
 */

/** One message for every authorization denial — nothing to enumerate. */
export const AUTHZ_DENIED_MESSAGE = 'You do not have access to this resource.';

/**
 * Build the per-request authorization context from the trusted server-side
 * user record. Called by session middleware right after `ctx.user` is set.
 */
export function createAuthzContext(user: AuthUser): AuthzContext {
  return {
    user,
    role: user.role,
    userType: user.userType,
    hasRole: (min: AccountRole): boolean => roleAtLeast(user.role, min),
    hasPermission: (permission: Permission): boolean => hasPermission(user.role, permission),
  };
}

/** Defensive: authentication first — anonymous callers are never authorized. */
export function assertAuthenticated(user: AuthUser | undefined): AuthUser {
  if (user === undefined) {
    throw unauthorized();
  }
  return user;
}

/** Throw 403 unless the (authenticated) user holds at least `min`. */
export function assertRole(user: AuthUser | undefined, min: AccountRole): void {
  const actor = assertAuthenticated(user);
  if (!roleAtLeast(actor.role, min)) {
    throw forbidden(AUTHZ_DENIED_MESSAGE);
  }
}

/** Throw 403 unless the (authenticated) user's role holds `permission`. */
export function assertPermission(user: AuthUser | undefined, permission: Permission): void {
  const actor = assertAuthenticated(user);
  if (!hasPermission(actor.role, permission)) {
    throw forbidden(AUTHZ_DENIED_MESSAGE);
  }
}

/**
 * Ownership check for a user record acting as a resource (the pattern
 * future resources copy: compare actor to owner, fall back to an
 * explicitly-declared privileged permission — never "role is high enough
 * somehow").
 *
 * - reading your own record → `users:read:self` (every account);
 * - reading someone else's → `users:read:others` (ADMIN+, explicit).
 *
 * Returns a boolean; callers decide the denial shape so it stays uniform.
 */
export function canReadUser(actor: AuthUser, targetId: string): boolean {
  if (actor.id === targetId) {
    return hasPermission(actor.role, 'users:read:self');
  }
  return hasPermission(actor.role, 'users:read:others');
}

/** {@link canReadUser} with a uniform 403 denial (no existence oracle). */
export function assertCanReadUser(actor: AuthUser | undefined, targetId: string): void {
  const user = assertAuthenticated(actor);
  if (!canReadUser(user, targetId)) {
    throw forbidden(AUTHZ_DENIED_MESSAGE);
  }
}
