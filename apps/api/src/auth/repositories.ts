import type { AuthUser } from '@drobon/shared';

/**
 * The minimum persistence boundary required by authentication (Pump 2).
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
}

/** Project the internal record to the ONLY user shape allowed to leave. */
export function toAuthUser(record: UserRecord): AuthUser {
  return { id: record.id, email: record.email, createdAt: record.createdAt };
}

/** Structural validation for records loaded from durable storage. */
export function isValidStoredUser(value: unknown): value is UserRecord {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false;
  }
  const record = value as Record<string, unknown>;
  return (
    typeof record['id'] === 'string' &&
    record['id'].length > 0 &&
    typeof record['email'] === 'string' &&
    record['email'].length > 0 &&
    record['email'] === record['email'].trim().toLowerCase() &&
    typeof record['passwordHash'] === 'string' &&
    record['passwordHash'].startsWith('scrypt$') &&
    typeof record['createdAt'] === 'string' &&
    !Number.isNaN(Date.parse(record['createdAt']))
  );
}
