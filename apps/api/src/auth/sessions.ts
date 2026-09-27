import { createHash, randomBytes } from 'node:crypto';

/**
 * Server-side session store (single process, explicitly non-durable —
 * a restart signs everyone out; accounts themselves live in the durable
 * user repository).
 *
 * Design points:
 * - the raw token exists only in the client's `httpOnly` cookie; the store
 *   keeps a SHA-256 hash, so a memory dump or future persistence of this
 *   store still does not expose usable tokens;
 * - absolute expiry (no sliding refresh) keeps the lifetime predictable;
 * - expired sessions are pruned during normal operation (bounded memory);
 * - revocation is immediate: logout deletes the entry, resolving a revoked
 *   or expired token returns `undefined` on the very next request.
 */

export interface SessionRecord {
  userId: string;
  expiresAtMs: number;
  issuedAtMs: number;
}

export interface SessionIssue {
  token: string;
  expiresAtMs: number;
}

export interface SessionStore {
  issue(userId: string): SessionIssue;
  resolve(token: string): SessionRecord | undefined;
  revoke(token: string): boolean;
  /** Test/diagnostic size, after opportunistic pruning. */
  size(): number;
}

const PRUNE_THRESHOLD = 10_000;
const TOKEN_BYTES = 32;

function hashToken(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

export function createSessionStore(options: {
  ttlSeconds: number;
  now?: () => number;
}): SessionStore {
  const now = options.now ?? Date.now;
  const ttlMs = options.ttlSeconds * 1000;
  const sessions = new Map<string, SessionRecord>();

  const prune = (nowMs: number): void => {
    if (sessions.size < PRUNE_THRESHOLD) {
      return;
    }
    for (const [key, record] of sessions) {
      if (record.expiresAtMs <= nowMs) {
        sessions.delete(key);
      }
    }
  };

  return {
    issue: (userId) => {
      const nowMs = now();
      prune(nowMs);
      const token = randomBytes(TOKEN_BYTES).toString('base64url');
      const expiresAtMs = nowMs + ttlMs;
      sessions.set(hashToken(token), { userId, expiresAtMs, issuedAtMs: nowMs });
      return { token, expiresAtMs };
    },
    resolve: (token) => {
      if (token.length === 0 || token.length > 512) {
        return undefined;
      }
      const key = hashToken(token);
      const record = sessions.get(key);
      if (record === undefined) {
        return undefined;
      }
      if (record.expiresAtMs <= now()) {
        sessions.delete(key);
        return undefined;
      }
      return record;
    },
    revoke: (token) => {
      if (token.length === 0 || token.length > 512) {
        return false;
      }
      return sessions.delete(hashToken(token));
    },
    size: () => sessions.size,
  };
}
