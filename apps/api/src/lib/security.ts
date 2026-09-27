/**
 * Small, pure security predicates. Every function here is side-effect free
 * and covered by unit tests — see `test/security.test.ts`.
 */

/** Request IDs the server is willing to echo back (safe header token). */
const REQUEST_ID_PATTERN = /^[A-Za-z0-9\-_.~]{1,128}$/;

export function isValidRequestId(value: string): boolean {
  return REQUEST_ID_PATTERN.test(value);
}

/**
 * Normalize a candidate origin to `scheme://host[:port]`, or `undefined`
 * when it is not a plain http(s) origin. Rejects credentials, paths,
 * queries, fragments and whitespace.
 */
export function normalizeOrigin(value: string): string | undefined {
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.includes('@') || /[\s]/.test(trimmed)) {
    return undefined;
  }
  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    return undefined;
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return undefined;
  }
  if (url.username.length > 0 || url.password.length > 0) {
    return undefined;
  }
  if (url.search.length > 0 || url.hash.length > 0) {
    return undefined;
  }
  if (url.pathname.length > 0 && url.pathname !== '/') {
    return undefined;
  }
  return url.origin;
}

/**
 * Strict allowlist membership: both sides are normalized, then compared with
 * exact string equality. No wildcards, no suffix matching, no regex.
 */
export function isAllowedOrigin(
  originHeader: string,
  allowlist: readonly string[],
): boolean {
  const candidate = normalizeOrigin(originHeader);
  if (candidate === undefined) {
    return false;
  }
  return allowlist.some((entry) => normalizeOrigin(entry) === candidate);
}
