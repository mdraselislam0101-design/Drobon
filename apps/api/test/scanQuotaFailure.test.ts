import { mkdirSync, mkdtempSync, readdirSync, renameSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, test } from 'vitest';
import type { UserRecord } from '../src/auth/repositories.js';
import { createJsonFileScanStore } from '../src/scans/store.js';
import { createUsageService, type ConsumeGranted } from '../src/usage/service.js';
import { createUsageFileStore } from '../src/usage/store.js';

const period = '2026-10';
const now = () => Date.parse('2026-10-15T00:00:00.000Z');
const device = 'synthetic-device';
const projectId = 'prj_00000000-0000-4000-8000-000000000001';

function account(plan: 'FREE' | 'PRO', id = 'usr_synthetic'): UserRecord {
  return {
    id, email: `${id}@example.test`, passwordHash: 'synthetic', role: 'MEMBER', userType: null,
    createdAt: '2026-01-01T00:00:00.000Z',
    subscription: { plan, status: 'ACTIVE', createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z' },
  };
}

describe('scan quota compensation for ordinary persistence errors', () => {
  test.each(['FREE', 'PRO'] as const)('%s failed scan rename compensates quota and allows a retry', async (plan) => {
    const dir = mkdtempSync(join(tmpdir(), 'drobon-scan-quota-'));
    const scanPath = join(dir, 'scans.json');
    const usagePath = join(dir, 'usage.json');
    try {
      const usageStore = createUsageFileStore(usagePath);
      const usage = createUsageService({ store: usageStore, now });
      const scans = createJsonFileScanStore(scanPath);
      const user = account(plan);
      const input = {
        ownerId: user.id, projectId, scanType: 'DAST' as const, targetUrl: 'https://example.test/',
        idempotencyKey: 'scan-quota-test', consume: () => usage.consumeScan(user, device),
      };
      // The scan destination becomes a directory after store initialization.
      mkdirSync(scanPath);
      await expect(scans.createScanWithQuota(input)).rejects.toThrow();
      expect(usageStore.getAccountUsed(user.id, period)).toBe(0);
      expect(usageStore.getDeviceUsed(device, period)).toBe(0);
      expect(createUsageFileStore(usagePath).getAccountUsed(user.id, period)).toBe(0);
      expect(await scans.listByProject(projectId)).toHaveLength(0);
      expect(readdirSync(dir).filter((entry) => entry.endsWith('.tmp'))).toEqual([]);

      rmSync(scanPath, { recursive: true });
      const created = await scans.createScanWithQuota(input);
      expect(created.outcome).toBe('created');
      const replay = await scans.createScanWithQuota(input);
      expect(replay.outcome).toBe('replayed');
      expect(usageStore.getAccountUsed(user.id, period)).toBe(1);
      expect(usageStore.getDeviceUsed(device, period)).toBe(plan === 'FREE' ? 1 : 0);
      expect(createUsageFileStore(usagePath).getAccountUsed(user.id, period)).toBe(1);
      expect(await createJsonFileScanStore(scanPath).listByProject(projectId)).toHaveLength(1);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('compensation is idempotent under concurrency and does not release another account’s shared-device usage', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'drobon-quota-once-'));
    try {
      const store = createUsageFileStore(join(dir, 'usage.json'));
      const usage = createUsageService({ store, now });
      const first = await usage.consumeScan(account('FREE', 'usr_first'), device);
      const second = await usage.consumeScan(account('FREE', 'usr_second'), device);
      expect(first.ok).toBe(true);
      expect(second.ok).toBe(true);
      if (!first.ok) throw new Error('Expected a granted fixture.');
      await Promise.all([first.rollback(), first.rollback(), first.rollback()]);
      await first.rollback();
      expect(store.getAccountUsed('usr_first', period)).toBe(0);
      expect(store.getAccountUsed('usr_second', period)).toBe(1);
      expect(store.getDeviceUsed(device, period)).toBe(1);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('if both scan persistence and compensation fail, both errors surface and compensation remains retryable', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'drobon-quota-double-failure-'));
    const scanPath = join(dir, 'scans.json');
    const usagePath = join(dir, 'usage.json');
    const backup = join(dir, 'usage-backup.json');
    let grant: ConsumeGranted | undefined;
    try {
      const store = createUsageFileStore(usagePath);
      const usage = createUsageService({ store, now });
      const scans = createJsonFileScanStore(scanPath);
      const user = account('FREE');
      mkdirSync(scanPath);
      await expect(scans.createScanWithQuota({
        ownerId: user.id, projectId, scanType: 'DAST', targetUrl: 'https://example.test/',
        consume: async () => {
          const outcome = await usage.consumeScan(user, device);
          if (!outcome.ok) throw new Error('Expected a granted fixture.');
          grant = outcome;
          renameSync(usagePath, backup);
          mkdirSync(usagePath);
          return outcome;
        },
      })).rejects.toThrow('Scan persistence and usage compensation both failed.');
      expect(store.getAccountUsed(user.id, period)).toBe(1);
      expect(store.getDeviceUsed(device, period)).toBe(1);
      expect(await scans.listByProject(projectId)).toHaveLength(0);
      expect(readdirSync(dir).filter((entry) => entry.endsWith('.tmp'))).toEqual([]);
      rmSync(usagePath, { recursive: true });
      renameSync(backup, usagePath);
      if (grant === undefined) throw new Error('Expected a captured grant.');
      await grant.rollback();
      expect(store.getAccountUsed(user.id, period)).toBe(0);
      expect(store.getDeviceUsed(device, period)).toBe(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
