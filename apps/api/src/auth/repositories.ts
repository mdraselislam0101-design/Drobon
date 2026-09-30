import type { AccountRole, AuthUser, Plan, Subscription, SubscriptionStatus, UserType } from '@drobon/shared';
import { normalizeSubscription } from './subscriptions.js';

/**
 * The minimum persistence boundary required by authentication (Pump 2),
 * extended by Pump 3 for authorization (role + user type live on the
 * account record) and by Pump 4 for the commercial foundation
 * (subscription state lives on the account record — no second store).
 *
 * Everything account-related goes through this interface — the HTTP layer,
 * session middleware and tests only ever see `UserRepository`. The later
 * database phase replaces the implementation (see
 * `jsonFileUserRepository.ts`) without touching routes, middleware or
 * shared contracts.
 */

/** Internal account record. `passwordHash` must never leave the process. */
export interface UserRecord {
  id: string;
  /** Normalized email (trim + lowercase) — the uniqueness key. */
  email: string;
  /** scrypt hash produced by `auth/passwords.ts`. */
  passwordHash: string;
  createdAt: string;
  /**
   * Authorization role. Assigned server-side ONLY (registration always
   * writes MEMBER; elevation is an operator/future-admin action).
   */
  role: AccountRole;
  /** Classification/visibility tag — never used for access decisions. */
  userType: UserType | null;
  /**
   * Commercial subscription state (Pump 4). `undefined` on records that
   * predate Pump 4 — those resolve to the documented legacy default
   * (FREE + ACTIVE) via `resolveSubscription`. When present it is ALWAYS
   * normalized fail-closed by `parseStoredUser`: corrupt subscription
   * data degrades the account to safe commercial defaults instead of
   * refusing the store (it can only lose entitlements, never grant them).
   */
  subscription?: Subscription;
}

export type AdminUserRecord = Omit<UserRecord, 'passwordHash'>;

export interface AdminAccountFilters {
  role?: AccountRole;
  userType?: UserType | 'NONE';
  plan?: Plan;
  search?: string;
}

export interface AdminAccountPage {
  accounts: AdminUserRecord[];
  total: number;
}

export interface AdminAccountCounts {
  total: number;
  byPlan: Record<Plan, number>;
  bySubscriptionStatus: Record<SubscriptionStatus, number>;
  byRole: Record<AccountRole, number>;
  byUserType: Record<UserType | 'NONE', number>;
}

export interface UserRepository {
  /**
   * Atomically check uniqueness and insert. Returns `true` when the account
   * was created, `false` when the email is already registered (the caller
   * maps that to 409 CONFLICT).
   */
  create(record: UserRecord): Promise<boolean>;
  findByEmail(email: string): Promise<UserRecord | undefined>;
  findById(id: string): Promise<UserRecord | undefined>;
  /** Server-only entitlement mutation used by the payment approval saga. */
  activatePro(id: string, at: string): Promise<'ACTIVATED' | 'ALREADY_ACTIVE' | 'NOT_FOUND'>;
  /**
   * Classification-only mutation (Phase 20): rewrites `userType` and nothing
   * else. Role, subscription and every other field are untouched by design —
   * switching user type never grants entitlements, resets quota or changes
   * ownership. Returns the updated record, or `undefined` when missing.
   */
  setUserType(id: string, userType: UserType): Promise<UserRecord | undefined>;
  /** Bounded safe account projection for platform-admin read-only operations. */
  adminPage(filters: AdminAccountFilters, page: number, pageSize: number): Promise<AdminAccountPage>;
  /** Aggregate counts from the existing account/subscription records. */
  adminCounts(): Promise<AdminAccountCounts>;
}

/** Project the internal record to the ONLY user shape allowed to leave. */
export function toAuthUser(record: UserRecord): AuthUser {
  return {
    id: record.id,
    email: record.email,
    createdAt: record.createdAt,
    role: record.role,
    userType: record.userType,
  };
}

/**
 * Parse + normalize a record loaded from durable storage.
 *
 * Migration rules:
 * - Pump 2→3: records without `role`/`userType` remain valid and are read
 *   as `MEMBER` / `null`. When the fields ARE present they are validated
 *   strictly — a corrupt authorization field refuses to load (fail fast,
 *   same posture as the rest of the store).
 * - Pump 3→4: records without `subscription` remain valid (the key stays
 *   absent and resolves to FREE + ACTIVE). When present it is normalized
 *   FAIL-CLOSED by `normalizeSubscription` — corrupt subscription data
 *   never refuses the store and can never grant PRO; it degrades to safe
 *   defaults (see `auth/subscriptions.ts` for the rationale).
 *
 * Returns `undefined` when the record is structurally invalid.
 */
export function parseStoredUser(value: unknown): UserRecord | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return undefined;
  }
  const record = value as Record<string, unknown>;
  if (
    typeof record['id'] !== 'string' ||
    record['id'].length === 0 ||
    typeof record['email'] !== 'string' ||
    record['email'].length === 0 ||
    record['email'] !== record['email'].trim().toLowerCase() ||
    typeof record['passwordHash'] !== 'string' ||
    !record['passwordHash'].startsWith('scrypt$') ||
    typeof record['createdAt'] !== 'string' ||
    Number.isNaN(Date.parse(record['createdAt']))
  ) {
    return undefined;
  }
  const roleValue = record['role'];
  const userTypeValue = record['userType'];
  let role: AccountRole;
  if (roleValue === undefined) {
    role = 'MEMBER'; // Pump 2-era record: default, never elevated.
  } else if (roleValue === 'MEMBER' || roleValue === 'ADMIN' || roleValue === 'ACCOUNT_OWNER') {
    role = roleValue;
  } else {
    return undefined;
  }
  let userType: UserType | null;
  if (userTypeValue === undefined || userTypeValue === null) {
    userType = null;
  } else if (
    userTypeValue === 'DEVELOPER' ||
    userTypeValue === 'STUDENT' ||
    userTypeValue === 'SECURITY_PROFESSIONAL' ||
    userTypeValue === 'PENTESTER'
  ) {
    userType = userTypeValue;
  } else {
    return undefined;
  }
  const subscriptionValue = record['subscription'];
  return {
    id: record['id'],
    email: record['email'],
    passwordHash: record['passwordHash'],
    createdAt: record['createdAt'],
    role,
    userType,
    // Absent on pre-Pump-4 records (key stays absent → legacy default);
    // present-but-corrupt degrades fail-closed instead of failing the store.
    ...(subscriptionValue === undefined || subscriptionValue === null
      ? {}
      : { subscription: normalizeSubscription(subscriptionValue) }),
  };
}

/** Structural validation for records loaded from durable storage. */
export function isValidStoredUser(value: unknown): value is UserRecord {
  return parseStoredUser(value) !== undefined;
}
