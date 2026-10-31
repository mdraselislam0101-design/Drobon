import { mkdirSync, mkdtempSync, readdirSync, renameSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, test } from 'vitest';
import { createUsageFileStore, type UsageStore } from '../src/usage/store.js';

const period = '2026-10';
const accountId = 'usr_synthetic';
const deviceHash = 'device-synthetic';

async function consume(store: UsageStore, kind: 'FREE' | 'EXEMPT'): Promise<void> {
  if (kind === 'FREE') {
    expect(await store.consumeFree({ accountId, deviceHash, period, accountLimit: 5, deviceLimit: 5 })).toBe('OK');
  } else {
    await store.consumeExempt({ accountId, period });
  }
}

describe('usage persistence failures', () => {
  test.each(['FREE', 'EXEMPT'] as const)(
    '%s failed rename keeps disk and memory unchanged and can be retried',
    async (kind) => {
      const dir = mkdtempSync(join(tmpdir(), 'drobon-usage-failure-'));
      const path = join(dir, 'usage.json');
      const backup = join(dir, 'original.json');
      try {
        const store = createUsageFileStore(path);
        await consume(store, kind);
        expect(store.getAccountUsed(accountId, period)).toBe(1);
        expect(store.getDeviceUsed(deviceHash, period)).toBe(kind === 'FREE' ? 1 : 0);

        // Replace the destination with a directory so the real temp-file
        // rename fails after the temp file has been written.
        renameSync(path, backup);
        mkdirSync(path);
        await expect(consume(store, kind)).rejects.toThrow();
        expect(store.getAccountUsed(accountId, period)).toBe(1);
        expect(store.getDeviceUsed(deviceHash, period)).toBe(kind === 'FREE' ? 1 : 0);
        expect(readdirSync(dir).filter((entry) => entry.endsWith('.tmp'))).toEqual([]);

        rmSync(path, { recursive: true });
        renameSync(backup, path);
        const fromDisk = createUsageFileStore(path);
        expect(fromDisk.getAccountUsed(accountId, period)).toBe(1);
        expect(fromDisk.getDeviceUsed(deviceHash, period)).toBe(kind === 'FREE' ? 1 : 0);

        // The mutation queue and the original instance remain usable.
        await consume(store, kind);
        expect(store.getAccountUsed(accountId, period)).toBe(2);
        const reloaded = createUsageFileStore(path);
        expect(reloaded.getAccountUsed(accountId, period)).toBe(2);
        expect(reloaded.getDeviceUsed(deviceHash, period)).toBe(kind === 'FREE' ? 2 : 0);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    },
  );

  test('special owner keys remain ordinary persisted data', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'drobon-usage-keys-'));
    const path = join(dir, 'usage.json');
    try {
      const store = createUsageFileStore(path);
      expect(await store.consumeFree({
        accountId: '__proto__', deviceHash: '__proto__', period, accountLimit: 3, deviceLimit: 3,
      })).toBe('OK');
      const reloaded = createUsageFileStore(path);
      expect(reloaded.getAccountUsed('__proto__', period)).toBe(1);
      expect(reloaded.getDeviceUsed('__proto__', period)).toBe(1);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
