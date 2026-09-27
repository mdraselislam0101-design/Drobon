import { describe, expect, test } from 'vitest';
import { createSessionStore } from '../src/auth/sessions.js';

describe('session store', () => {
  test('issues opaque base64url tokens that resolve to the user', () => {
    const store = createSessionStore({ ttlSeconds: 3600 });
    const { token } = store.issue('usr_1');
    expect(token).toMatch(/^[A-Za-z0-9_-]+$/); // base64url, cookie-safe
    expect(token.length).toBeGreaterThanOrEqual(43); // 32 bytes
    expect(store.resolve(token)?.userId).toBe('usr_1');
    expect(store.size()).toBe(1);
  });

  test('unknown or malformed tokens resolve to nothing', () => {
    const store = createSessionStore({ ttlSeconds: 3600 });
    store.issue('usr_1');
    expect(store.resolve('not-a-real-token')).toBeUndefined();
    expect(store.resolve('')).toBeUndefined();
    expect(store.resolve('a'.repeat(513))).toBeUndefined();
  });

  test('revocation is immediate and idempotent', () => {
    const store = createSessionStore({ ttlSeconds: 3600 });
    const { token } = store.issue('usr_1');
    expect(store.revoke(token)).toBe(true);
    expect(store.resolve(token)).toBeUndefined();
    expect(store.revoke(token)).toBe(false);
    expect(store.size()).toBe(0);
  });

  test('sessions expire at absolute TTL and are pruned on resolve', () => {
    let nowMs = 1_000_000;
    const store = createSessionStore({ ttlSeconds: 60, now: () => nowMs });
    const { token, expiresAtMs } = store.issue('usr_1');
    expect(expiresAtMs).toBe(nowMs + 60_000);
    nowMs += 59_999;
    expect(store.resolve(token)).toBeDefined();
    nowMs += 2; // past expiry
    expect(store.resolve(token)).toBeUndefined();
    expect(store.size()).toBe(0);
  });

  test('different users get independent sessions', () => {
    const store = createSessionStore({ ttlSeconds: 3600 });
    const a = store.issue('usr_a');
    const b = store.issue('usr_b');
    expect(a.token).not.toBe(b.token);
    expect(store.resolve(a.token)?.userId).toBe('usr_a');
    expect(store.resolve(b.token)?.userId).toBe('usr_b');
    store.revoke(a.token);
    expect(store.resolve(a.token)).toBeUndefined();
    expect(store.resolve(b.token)?.userId).toBe('usr_b');
  });
});
