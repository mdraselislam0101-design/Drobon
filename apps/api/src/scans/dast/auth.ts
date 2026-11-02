/**
 * Active DAST — operator-configured authenticated probing (P2-12, second half).
 *
 * DELIBERATELY NARROW. Drobon never stores user credentials, never performs a
 * login flow and never sends a credential the operator did not configure on the
 * server itself:
 *
 * - The credential is a single static HTTP header supplied through the
 *   deployment environment (`DAST_AUTH_HEADER_NAME` + `DAST_AUTH_HEADER_VALUE`).
 *   It is read once at startup by `config.ts` (the only module allowed to read
 *   the process environment) and lives in memory only.
 * - It is never written to a scan record, an observation, a finding, a report,
 *   a metric or a log line. Results disclose only the MODE
 *   (`authMode: 'HEADER'`), never the name or value.
 * - The header is attached only to requests for the same resolved target the
 *   scan was authorized for; the transport never follows redirects, and every
 *   redirect hop is re-resolved and re-authorized by the target policy.
 * - Nothing here can widen the request class: probes stay `GET`-only.
 *
 * What this is NOT: session/login automation, cookie-jar management, CSRF or
 * MFA handling, per-user credential vaults, or multi-role scanning. Those need
 * a credential-storage design and an explicit operator decision; they are not
 * implemented (see docs/DAST.md).
 */

export const DAST_AUTH_MODES = ['NONE', 'HEADER'] as const;
export type DastAuthMode = (typeof DAST_AUTH_MODES)[number];

export interface DastAuthHeader {
  /** Validated header name (never surfaced in results). */
  headerName: string;
  /** Validated header value (never surfaced in results, logs or reports). */
  headerValue: string;
}

/**
 * Headers that would break the HTTP request itself or the security boundary of
 * the transport. `host` would defeat the pinned-address resolution, and the
 * hop-by-hop headers are owned by the client.
 */
export const DAST_FORBIDDEN_AUTH_HEADERS = [
  'host',
  'connection',
  'content-length',
  'transfer-encoding',
  'upgrade',
  'te',
  'trailer',
  'keep-alive',
  'expect',
] as const;

/** `^[A-Za-z0-9-]{1,48}$`, lowercase-insensitive, never a forbidden header. */
export function normalizeDastAuthHeaderName(raw: unknown): string | undefined {
  if (typeof raw !== 'string') return undefined;
  const trimmed = raw.trim();
  if (!/^[A-Za-z0-9-]{1,48}$/.test(trimmed)) return undefined;
  const lower = trimmed.toLowerCase();
  if ((DAST_FORBIDDEN_AUTH_HEADERS as readonly string[]).includes(lower)) return undefined;
  return lower;
}

/**
 * A header value is a single line of printable ASCII/UTF-8 text: no control
 * characters (a CR/LF would split the request), bounded to 4096 characters.
 * Empty values are refused — an empty credential is not authentication.
 */
export function isDastAuthHeaderValue(raw: unknown): raw is string {
  if (typeof raw !== 'string') return false;
  if (raw.length === 0 || raw.length > 4096) return false;
  if (raw.trim().length === 0) return false;
  for (const char of raw) {
    const code = char.codePointAt(0) ?? 0;
    if (code < 0x20 || code === 0x7f) return false;
  }
  return true;
}

/**
 * Resolve the optional credential. Both halves must be present and valid;
 * anything else yields `undefined` (unauthenticated) — a misconfiguration can
 * never produce a half-applied or malformed credential.
 */
export function resolveDastAuth(
  headerName: unknown,
  headerValue: unknown,
): DastAuthHeader | undefined {
  const name = normalizeDastAuthHeaderName(headerName);
  if (name === undefined) return undefined;
  if (!isDastAuthHeaderValue(headerValue)) return undefined;
  return { headerName: name, headerValue };
}

/** The mode a configured credential produces — the only thing results disclose. */
export function dastAuthMode(auth: DastAuthHeader | undefined): DastAuthMode {
  return auth === undefined ? 'NONE' : 'HEADER';
}
