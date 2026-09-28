import { isRecord } from './guards.js';
import { isAccountRole, isUserType, type AccountRole, type UserType } from './authz.js';

/**
 * Authentication contracts shared by the API and the Web client.
 *
 * `AuthUser` is the ONLY user representation that may leave the API — it is
 * deliberately public-only: no password, no hash, no session token, no
 * internal security fields. Guards below are the client-side boundary that
 * rejects anything else at runtime.
 */

/** Public account representation. Safe to render and store client-side. */
export interface AuthUser {
  id: string;
  /** Normalized (trimmed, lowercased) email address. */
  email: string;
  /** Account creation time (ISO 8601). */
  createdAt: string;
  /**
   * Authorization role (server-assigned; NEVER accepted from clients).
   * Required by the UI for role-aware rendering — enforcement happens on
   * the API regardless.
   */
  role: AccountRole;
  /**
   * Classification/visibility tag. NOT an authorization input: it never
   * grants access, bypasses roles, or substitutes for a permission.
   * `null` when the account has not declared one.
   */
  userType: UserType | null;
}

/** `POST /api/v1/auth/register` request body. */
export interface RegisterRequest {
  email: string;
  password: string;
  /** Optional classification tag. `role` is NOT accepted, by design. */
  userType?: UserType;
}

/** `POST /api/v1/auth/login` request body. */
export interface LoginRequest {
  email: string;
  password: string;
}

/**
 * `POST /api/v1/auth/register` and `POST /api/v1/auth/login` response.
 * The session itself travels ONLY in an `httpOnly` cookie — tokens are
 * never part of a JSON body.
 */
export interface AuthResponse {
  user: AuthUser;
}

/** `GET /api/v1/me` response — the authenticated user, or 401. */
export interface CurrentUserResponse {
  user: AuthUser;
}

/**
 * `POST /api/v1/auth/logout` response. Idempotent: logging out without an
 * active session still succeeds, with `loggedOut: false`.
 */
export interface LogoutResponse {
  loggedOut: boolean;
}

/** Email policy: trimmed, lowercased, at most 254 characters (RFC 5321). */
export const EMAIL_MAX_LENGTH = 254;
/**
 * Pragmatic email shape check (not full RFC 5322): exactly one `@`, a
 * non-empty local part, and a dotted domain without consecutive dots.
 * Structural validation only — deliverability is out of scope.
 */
export const EMAIL_PATTERN =
  /^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/;

/** Password policy: length-first (NIST-style), no composition gimmicks. */
export const PASSWORD_MIN_LENGTH = 8;
export const PASSWORD_MAX_LENGTH = 128;

/** Normalize an email for storage and lookup (trim + lowercase). */
export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

/** Structural email check against {@link EMAIL_PATTERN}. */
export function isValidEmail(email: string): boolean {
  const normalized = normalizeEmail(email);
  return normalized.length > 0 && normalized.length <= EMAIL_MAX_LENGTH && EMAIL_PATTERN.test(normalized);
}

/**
 * Password policy check shared by the API (enforcement) and the Web form
 * (early feedback) so the two can never disagree. Returns a user-facing
 * issue message, or `undefined` when the password is acceptable.
 */
export function passwordPolicyIssue(password: string): string | undefined {
  if (typeof password !== 'string' || password.length < PASSWORD_MIN_LENGTH) {
    return `Password must be at least ${PASSWORD_MIN_LENGTH} characters.`;
  }
  if (password.length > PASSWORD_MAX_LENGTH) {
    return `Password must be at most ${PASSWORD_MAX_LENGTH} characters.`;
  }
  return undefined;
}

/**
 * Keys that must never appear inside an {@link AuthUser} payload. Since
 * Pump 4 this also blocks plan/subscription material: commercial state
 * has exactly ONE channel (`GET /api/v1/subscription`, validated by
 * `isSubscriptionResponse`) — user payloads must never carry a second,
 * forgeable copy of it.
 */
const FORBIDDEN_USER_KEYS = [
  'password',
  'passwordhash',
  'hash',
  'token',
  'session',
  'secret',
  'plan',
  'subscription',
] as const;

/** Structural guard for {@link AuthUser} at the client boundary. */
export function isAuthUser(value: unknown): value is AuthUser {
  if (
    !isRecord(value) ||
    typeof value['id'] !== 'string' ||
    value['id'].length === 0 ||
    typeof value['email'] !== 'string' ||
    !isValidEmail(value['email']) ||
    typeof value['createdAt'] !== 'string' ||
    Number.isNaN(Date.parse(value['createdAt'])) ||
    !isAccountRole(value['role']) ||
    !(value['userType'] === null || isUserType(value['userType']))
  ) {
    return false;
  }
  // Defense in depth: reject payloads that smuggle credential material even
  // when the public shape is otherwise valid (over-rejection is intentional).
  for (const key of Object.keys(value)) {
    const normalized = key.toLowerCase().replace(/[^a-z0-9]/g, '');
    if (FORBIDDEN_USER_KEYS.some((part) => normalized.includes(part))) {
      return false;
    }
  }
  return true;
}

/** Guard for {@link AuthResponse} payloads. */
export function isAuthResponse(value: unknown): value is AuthResponse {
  return isRecord(value) && isAuthUser(value['user']);
}

/** Guard for {@link CurrentUserResponse} payloads. */
export function isCurrentUserResponse(value: unknown): value is CurrentUserResponse {
  return isRecord(value) && isAuthUser(value['user']);
}

/** Guard for {@link LogoutResponse} payloads. */
export function isLogoutResponse(value: unknown): value is LogoutResponse {
  return isRecord(value) && typeof value['loggedOut'] === 'boolean';
}
