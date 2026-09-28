import { createHash, randomBytes } from 'node:crypto';
import { parseCookies } from '../auth/cookies.js';

/**
 * Device identity for usage anti-abuse (Pump 5).
 *
 * Model: an OPAQUE server-issued cookie (`drobon_device`) carrying a
 * cryptographically random token. The server only ever stores and logs
 * the SHA-256 hash of the token — the raw value exists solely inside the
 * cookie (mirroring the session-token posture). No account id, no user
 * data, no fingerprinting: two accounts on the same browser simply share
 * the same random device token, which is exactly the behavior the shared
 * device allowance needs.
 *
 * Honest boundary (documented in docs/USAGE.md): a client that discards
 * or rotates cookies appears as a new device. This control is
 * anti-abuse, NOT a hard identity guarantee — the account quota, rate
 * limits and the opaque+hashed cookie keep evasion expensive without
 * invasive fingerprinting or IP bans.
 */

export const DEVICE_COOKIE_NAME = 'drobon_device';

/** 32 random bytes → 43-char base64url (no padding). */
export const DEVICE_TOKEN_BYTES = 32;

/**
 * Cookie lifetime: 400 days (the browser cap). Anti-abuse recognition
 * should persist as long as the platform allows.
 */
export const DEVICE_COOKIE_MAX_AGE_SECONDS = 400 * 24 * 60 * 60;

/** base64url alphabet, exactly the encoding `randomBytes` + `toString` produce. */
const DEVICE_TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;

/** Generate a fresh device token (43-char base64url of 32 random bytes). */
export function generateDeviceToken(): string {
  return randomBytes(DEVICE_TOKEN_BYTES).toString('base64url');
}

/**
 * Accept a device token ONLY in the exact shape the server issues.
 * Malformed, wrong-length or foreign-encoding values are rejected → the
 * caller treats the request as deviceless and issues a fresh cookie
 * (fail closed: a garbage cookie never maps to someone else's device).
 */
export function isValidDeviceTokenShape(token: string | undefined): token is string {
  return typeof token === 'string' && DEVICE_TOKEN_PATTERN.test(token);
}

/**
 * The server-side device identity: SHA-256 hex of the token. Only this
 * hash is stored, compared or logged — never the raw token.
 */
export function deviceHashFor(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

/** Extract the device token from a request cookie header, if present. */
export function readDeviceToken(cookieHeader: string | undefined): string | undefined {
  const token = parseCookies(cookieHeader)[DEVICE_COOKIE_NAME];
  return token !== undefined && token.length > 0 ? token : undefined;
}

/** Build the `Set-Cookie` value for a freshly issued device token. */
export function deviceCookie(
  token: string,
  options: { secure: boolean; maxAgeSeconds: number },
): string {
  const parts = [
    `${DEVICE_COOKIE_NAME}=${token}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Strict',
    `Max-Age=${Math.max(0, Math.floor(options.maxAgeSeconds))}`,
  ];
  if (options.secure) {
    parts.push('Secure');
  }
  return parts.join('; ');
}
