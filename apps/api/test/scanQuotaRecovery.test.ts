import { spawn } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { describe, expect, test } from 'vitest';
import type { UserRecord } from '../src/auth/repositories.js';
import { createJsonFileScanStore } from '../src/scans/store.js';
import { createUsageService, recoverScanUsageReservations } from '../src/usage/service.js';
import { createUsageFileStore } from '../src/usage/store.js';
import { startTestServer } from './helpers.js';

const projectId = 'prj_00000000-0000-4000-8000-000000000001';
const device = 'test-device-hash';
const at = () => Date.parse('2026-10-15T00:00:00.000Z');
const user: UserRecord = {
  id: 'usr_recovery', email: 'recovery@example.test', passwordHash: 'fixture', role: 'MEMBER', userType: null,
  createdAt: '2026-01-01T00:00:00.000Z',
  subscription: { plan: 'FREE', status: 'ACTIVE', createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z' },
};

async function killAtWriteBoundary(dir: string, phase: 'after-reserve' | 'after-scan', plan: 'FREE' | 'PRO' = 'FREE'): Promise<void> {
  const usageModule = pathToFileURL(resolve('src/usage/store.ts')).href;
  const serviceModule = pathToFileURL(resolve('src/usage/service.ts')).href;
  const scanModule = pathToFileURL(resolve('src/scans/store.ts')).href;
  const script = `
    import { createUsageFileStore } from ${JSON.stringify(usageModule)};
    import { createUsageService } from ${JSON.stringify(serviceModule)};
    import { createJsonFileScanStore } from ${JSON.stringify(scanModule)};
    const user = ${JSON.stringify({ ...user, subscription: { ...user.subscription!, plan } })}, projectId = ${JSON.stringify(projectId)}, device = ${JSON.stringify(device)};
    const store = createUsageFileStore(${JSON.stringify(join(dir, 'usage.json'))});
    const scans = createJsonFileScanStore(${JSON.stringify(join(dir, 'scans.json'))});
    const usage = createUsageService({store, now: () => ${at()}});
    const pause = () => new Promise(() => { console.log('CRASH_POINT'); setInterval(() => {}, 1000); });
    await scans.createScanWithQuota({ownerId: user.id, projectId, scanType: 'SAST', idempotencyKey: 'crash-replay', consume: async (id) => {
      const grant = await usage.reserveScan(user, device, projectId, id);
      if (!grant.ok) throw new Error('unexpected quota denial');
      if (${JSON.stringify(phase)} === 'after-reserve') await pause();
      return {...grant, commit: async () => pause()};
    }});
  `;
  await new Promise<void>((resolvePromise, reject) => {
    const child = spawn(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', script], { cwd: process.cwd(), stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = ''; let stderr = ''; let killed = false;
    const timeout = setTimeout(() => { child.kill('SIGKILL'); reject(new Error(`child did not reach crash point: ${stderr}`)); }, 15_000);
    child.stdout.on('data', (data: Buffer) => {
      stdout += data.toString();
      if (!killed && stdout.includes('CRASH_POINT')) { killed = true; child.kill('SIGKILL'); }
    });
    child.stderr.on('data', (data: Buffer) => { stderr += data.toString(); });
    child.on('error', (error) => { clearTimeout(timeout); reject(error); });
    child.on('exit', (_code, signal) => {
      clearTimeout(timeout);
      if (killed && signal === 'SIGKILL') resolvePromise();
      else reject(new Error(`child exited before crash point (${String(signal)}): ${stderr}`));
    });
  });
}

describe('durable scan quota reservations', () => {
  test.each(['after-reserve', 'after-scan'] as const)('SIGKILL %s is reconciled once after restart', async (phase) => {
    const dir = mkdtempSync(join(tmpdir(), 'drobon-reservation-crash-'));
    try {
      await killAtWriteBoundary(dir, phase);
      const usagePath = join(dir, 'usage.json');
      const scanPath = join(dir, 'scans.json');
      const usage = createUsageFileStore(usagePath);
      const scans = createJsonFileScanStore(scanPath);
      expect(usage.getAccountUsed(user.id, '2026-10')).toBe(1);
      expect(usage.pendingScanReservations()).toHaveLength(1);
      expect(await scans.listByProject(projectId)).toHaveLength(phase === 'after-scan' ? 1 : 0);
      await recoverScanUsageReservations(usage, scans, at);
      await recoverScanUsageReservations(usage, scans, at);
      const reopened = createUsageFileStore(usagePath);
      expect(reopened.pendingScanReservations()).toHaveLength(0);
      expect(reopened.getAccountUsed(user.id, '2026-10')).toBe(phase === 'after-scan' ? 1 : 0);
      expect(reopened.getDeviceUsed(device, '2026-10')).toBe(phase === 'after-scan' ? 1 : 0);
      const audit = JSON.parse(readFileSync(usagePath, 'utf8')) as { reservations: Array<{ status: string; reason: string; scanId: string }> };
      expect(audit.reservations).toHaveLength(1);
      expect(audit.reservations[0]).toMatchObject(phase === 'after-scan'
        ? { status: 'COMMITTED', reason: 'RECOVERED_SCAN_PRESENT' }
        : { status: 'RELEASED', reason: 'RECOVERED_SCAN_ABSENT' });
      if (phase === 'after-scan') {
        const service = createUsageService({ store: reopened, now: at });
        const replay = await scans.createScanWithQuota({ ownerId: user.id, projectId, scanType: 'SAST', idempotencyKey: 'crash-replay', consume: (scanId) => service.reserveScan(user, device, projectId, scanId) });
        expect(replay.outcome).toBe('replayed');
        expect(reopened.getAccountUsed(user.id, '2026-10')).toBe(1);
        expect((await scans.listByProject(projectId))[0]?.id).toBe(audit.reservations[0]?.scanId);
      }
    } finally { rmSync(dir, { recursive: true, force: true }); }
  }, 20_000);

  test.each(['after-reserve', 'after-scan'] as const)('PRO SIGKILL %s recovers account usage without consuming device quota', async (phase) => {
    const dir = mkdtempSync(join(tmpdir(), 'drobon-pro-reservation-crash-'));
    try {
      await killAtWriteBoundary(dir, phase, 'PRO');
      const usagePath = join(dir, 'usage.json');
      const scanPath = join(dir, 'scans.json');
      const usage = createUsageFileStore(usagePath);
      const scans = createJsonFileScanStore(scanPath);
      expect(usage.getAccountUsed(user.id, '2026-10')).toBe(1);
      expect(usage.getDeviceUsed(device, '2026-10')).toBe(0);
      expect(usage.pendingScanReservations()).toHaveLength(1);
      expect(usage.pendingScanReservations()[0]?.deviceHash).toBeUndefined();
      await recoverScanUsageReservations(usage, scans, at);
      await recoverScanUsageReservations(usage, scans, at);
      const reopened = createUsageFileStore(usagePath);
      expect(reopened.getAccountUsed(user.id, '2026-10')).toBe(phase === 'after-scan' ? 1 : 0);
      expect(reopened.getDeviceUsed(device, '2026-10')).toBe(0);
      expect(reopened.pendingScanReservations()).toHaveLength(0);
      const audit = JSON.parse(readFileSync(usagePath, 'utf8')) as { reservations: Array<{ status: string; reason: string; deviceHash?: string }> };
      expect(audit.reservations).toHaveLength(1);
      expect(audit.reservations[0]).toMatchObject(phase === 'after-scan'
        ? { status: 'COMMITTED', reason: 'RECOVERED_SCAN_PRESENT' }
        : { status: 'RELEASED', reason: 'RECOVERED_SCAN_ABSENT' });
      expect(audit.reservations[0]?.deviceHash).toBeUndefined();
      if (phase === 'after-scan') {
        const retry = await scans.createScanWithQuota({ ownerId: user.id, projectId, scanType: 'SAST', idempotencyKey: 'crash-replay', consume: () => { throw new Error('PRO replay consumed quota'); } });
        expect(retry.outcome).toBe('replayed');
        expect(reopened.getAccountUsed(user.id, '2026-10')).toBe(1);
      }
    } finally { rmSync(dir, { recursive: true, force: true }); }
  }, 20_000);

  test('real server startup reconciles before accepting traffic', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'drobon-reservation-startup-'));
    try {
      await killAtWriteBoundary(dir, 'after-reserve');
      expect(createUsageFileStore(join(dir, 'usage.json')).pendingScanReservations()).toHaveLength(1);
      const server = await startTestServer({ usageStoreDir: dir, scanStoreDir: dir, usageNow: at });
      try {
        expect((await fetch(`${server.baseUrl}/api/v1/status`)).status).not.toBe(500);
        const reloaded = createUsageFileStore(join(dir, 'usage.json'));
        expect(reloaded.pendingScanReservations()).toHaveLength(0);
        expect(reloaded.getAccountUsed(user.id, '2026-10')).toBe(0);
      } finally { await server.stop(); }
    } finally { rmSync(dir, { recursive: true, force: true }); }
  }, 20_000);

  test('scan-write failure leaves a released audit record; quota-write failure creates no scan', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'drobon-reservation-fail-'));
    try {
      const usagePath = join(dir, 'usage.json'); const scanPath = join(dir, 'scans.json');
      const store = createUsageFileStore(usagePath); const scans = createJsonFileScanStore(scanPath);
      const service = createUsageService({ store, now: at });
      const input = { ownerId: user.id, projectId, scanType: 'SAST' as const, consume: (scanId: string) => service.reserveScan(user, device, projectId, scanId) };
      mkdirSync(scanPath);
      await expect(scans.createScanWithQuota(input)).rejects.toThrow();
      expect(store.getAccountUsed(user.id, '2026-10')).toBe(0);
      expect(store.pendingScanReservations()).toHaveLength(0);
      const audit = JSON.parse(readFileSync(usagePath, 'utf8')) as { reservations: Array<{ status: string; reason: string }> };
      expect(audit.reservations[0]).toMatchObject({ status: 'RELEASED', reason: 'SCAN_WRITE_FAILED' });
      rmSync(scanPath, { recursive: true });
      renameSync(usagePath, `${usagePath}.backup`); mkdirSync(usagePath);
      await expect(scans.createScanWithQuota(input)).rejects.toThrow();
      expect(await scans.listByProject(projectId)).toHaveLength(0);
      expect(store.getAccountUsed(user.id, '2026-10')).toBe(0);
      rmSync(usagePath, { recursive: true }); renameSync(`${usagePath}.backup`, usagePath);
      await recoverScanUsageReservations(createUsageFileStore(usagePath), createJsonFileScanStore(scanPath), at);
      expect(createUsageFileStore(usagePath).getAccountUsed(user.id, '2026-10')).toBe(0);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  test('quota-finalization failure returns the durable scan and restart commits its pending reservation', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'drobon-reservation-commit-fail-'));
    try {
      const usagePath = join(dir, 'usage.json'); const scanPath = join(dir, 'scans.json');
      const store = createUsageFileStore(usagePath); const scans = createJsonFileScanStore(scanPath);
      const service = createUsageService({ store, now: at });
      const created = await scans.createScanWithQuota({
        ownerId: user.id, projectId, scanType: 'SAST', idempotencyKey: 'commit-retry',
        consume: async (scanId) => {
          const grant = await service.reserveScan(user, device, projectId, scanId);
          if (!grant.ok) throw new Error('unexpected denial');
          renameSync(usagePath, `${usagePath}.backup`); mkdirSync(usagePath);
          return grant;
        },
      });
      expect(created.outcome).toBe('created');
      if (created.outcome !== 'created') throw new Error('scan missing');
      expect(created.quotaCommitPending).toBe(true);
      expect(await scans.listByProject(projectId)).toHaveLength(1);
      rmSync(usagePath, { recursive: true }); renameSync(`${usagePath}.backup`, usagePath);
      const reopened = createUsageFileStore(usagePath);
      await recoverScanUsageReservations(reopened, createJsonFileScanStore(scanPath), at);
      expect(reopened.getAccountUsed(user.id, '2026-10')).toBe(1);
      expect(reopened.pendingScanReservations()).toHaveLength(0);
      const retry = await scans.createScanWithQuota({ ownerId: user.id, projectId, scanType: 'SAST', idempotencyKey: 'commit-retry', consume: () => { throw new Error('replay consumed quota'); } });
      expect(retry.outcome).toBe('replayed');
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
});
