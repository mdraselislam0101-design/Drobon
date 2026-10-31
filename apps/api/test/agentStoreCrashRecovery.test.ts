import { execFile, spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, readdirSync, rmSync, rmdirSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { promisify } from 'node:util';
import { pathToFileURL } from 'node:url';
import { describe, expect, test } from 'vitest';
import { createJsonFileScanStore } from '../src/scans/store.js';

const projectId = 'prj_00000000-0000-4000-8000-000000000001';
const assessmentId = 'asm_00000000-0000-4000-8000-000000000001';
const ownerId = 'usr_synthetic';
const agent = { version: 1 as const, datasetDigest: 'a'.repeat(64), sourceDigest: 'b'.repeat(64),
  engagementId: 'eng_00000000-0000-4000-8000-000000000001' };
const moduleUrl = pathToFileURL(resolve('src/scans/store.ts')).href;
const input = { ownerId, projectId, assessmentId, scanType: 'SAST' as const, agent };
const execFileAsync = promisify(execFile);

describe.skipIf(process.platform === 'win32')('synthetic scan-store crash and ownership recovery', () => {
  test.each(['before', 'after'] as const)('SIGKILL %s rename preserves a valid old/new snapshot and leaves the lock for review', async (stage) => {
    const dir = mkdtempSync(join(tmpdir(), 'drobon-agent-store-crash-'));
    const path = join(dir, 'scans.json');
    const lock = join(dir, '.scans.json.drobon-write-lock');
    const initial = createJsonFileScanStore(path);
    try {
      expect((await initial.createScanWithQuota({ ...input, consume: async () => ({ ok: true }) })).outcome).toBe('created');
      const original = readFileSync(path);
      const script = `
        import fs from 'node:fs'; import { syncBuiltinESMExports } from 'node:module';
        const rename = fs.renameSync;
        fs.renameSync = (from, to) => {
          if (String(to) === ${JSON.stringify(path)} && String(from).endsWith('.tmp')) {
            if (${JSON.stringify(stage)} === 'after') rename(from, to);
            fs.writeSync(1, 'RENAME_BOUNDARY\\n');
            Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0);
          }
          return rename(from, to);
        };
        syncBuiltinESMExports();
        const { createJsonFileScanStore } = await import(${JSON.stringify(moduleUrl)});
        await createJsonFileScanStore(${JSON.stringify(path)}).createScanWithQuota({ ...${JSON.stringify(input)}, consume: async () => ({ ok: true }) });
      `;
      const child = spawn(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', script], { stdio: ['ignore', 'pipe', 'pipe'] });
      let stderr = '';
      try {
        await new Promise<void>((resolveReady, reject) => {
          const timer = setTimeout(() => reject(new Error(`Synthetic crash fixture timed out: ${stderr}`)), 15_000);
          child.stderr.on('data', (chunk: Buffer) => { stderr += chunk.toString(); });
          child.stdout.on('data', (chunk: Buffer) => { if (chunk.toString().includes('RENAME_BOUNDARY')) { clearTimeout(timer); resolveReady(); } });
          child.once('error', (error) => { clearTimeout(timer); reject(error); });
          child.once('exit', () => { clearTimeout(timer); reject(new Error(`Synthetic crash fixture exited: ${stderr}`)); });
        });
        const exited = new Promise<void>((resolveExit) => child.once('exit', () => resolveExit()));
        child.kill('SIGKILL');
        await exited;
      } finally { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); }
      const bytes = readFileSync(path);
      if (stage === 'before') expect(bytes).toEqual(original);
      else expect(bytes).not.toEqual(original);
      expect(statSync(lock).isDirectory()).toBe(true);
      expect(statSync(lock).mode & 0o777).toBe(0o700);
      const orphans = readdirSync(dir).filter((name) => name.endsWith('.tmp'));
      expect(orphans).toHaveLength(stage === 'before' ? 1 : 0);
      const reopened = createJsonFileScanStore(path);
      expect(await reopened.listByProject(projectId)).toHaveLength(stage === 'before' ? 1 : 2);
      await expect(reopened.claimNextQueued()).rejects.toThrow(/lock/i);
      expect(readFileSync(path)).toEqual(bytes);
      // Only this test-owned empty lock is removed after the test process is
      // known dead; production requires independently reviewed recovery.
      rmdirSync(lock);
      expect(await reopened.claimNextQueued()).toBeDefined();
      expect(await createJsonFileScanStore(path).listByProject(projectId)).toHaveLength(stage === 'before' ? 1 : 2);
      expect(readdirSync(dir).filter((name) => name.endsWith('.tmp'))).toEqual(orphans);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  }, 30_000);

  test('lock cleanup failure after publication does not compensate quota for the published job', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'drobon-agent-cleanup-fault-'));
    const path = join(dir, 'scans.json');
    const lock = join(dir, '.scans.json.drobon-write-lock');
    try {
      const store = createJsonFileScanStore(path);
      expect((await store.createScanWithQuota({ ...input, consume: async () => ({ ok: true }) })).outcome).toBe('created');
      const script = `
        import fs from 'node:fs'; import { syncBuiltinESMExports } from 'node:module';
        const rmdir = fs.rmdirSync;
        fs.rmdirSync = (path, options) => {
          if (String(path) === ${JSON.stringify(lock)}) throw new Error('synthetic cleanup failure');
          return rmdir(path, options);
        };
        syncBuiltinESMExports();
        const { createJsonFileScanStore } = await import(${JSON.stringify(moduleUrl)});
        const store = createJsonFileScanStore(${JSON.stringify(path)}); let rollbacks = 0; let commits = 0; let fenced = false;
        const result = await store.createScanWithQuota({ ...${JSON.stringify(input)}, consume: async () => ({ ok: true,
          rollback: async () => { rollbacks += 1; }, commit: async () => { commits += 1; } }) });
        try { await store.claimNextQueued(); } catch { fenced = true; }
        fs.writeSync(1, JSON.stringify({ outcome: result.outcome, rollbacks, commits, fenced }));
      `;
      const { stdout } = await execFileAsync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', script], { timeout: 15_000 });
      expect(JSON.parse(stdout)).toEqual({ outcome: 'created', rollbacks: 0, commits: 1, fenced: true });
      expect(statSync(lock).isDirectory()).toBe(true);
      expect((await createJsonFileScanStore(path).listByProject(projectId))).toHaveLength(2);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  }, 30_000);

  test('a replaced lock is detected before rename without deleting the replacement', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'drobon-agent-stolen-lock-'));
    const path = join(dir, 'scans.json');
    const lock = join(dir, '.scans.json.drobon-write-lock');
    const displaced = `${lock}.displaced`;
    try {
      const store = createJsonFileScanStore(path);
      expect((await store.createScanWithQuota({ ...input, consume: async () => ({ ok: true }) })).outcome).toBe('created');
      const original = readFileSync(path);
      const script = `
        import fs from 'node:fs'; import { syncBuiltinESMExports } from 'node:module';
        const fsync = fs.fsyncSync; let replaced = false;
        fs.fsyncSync = (fd) => {
          const result = fsync(fd);
          if (!replaced) { replaced = true; fs.renameSync(${JSON.stringify(lock)}, ${JSON.stringify(displaced)}); fs.mkdirSync(${JSON.stringify(lock)}, { mode: 0o700 }); }
          return result;
        };
        syncBuiltinESMExports();
        const { createJsonFileScanStore } = await import(${JSON.stringify(moduleUrl)});
        const store = createJsonFileScanStore(${JSON.stringify(path)}); let rollbacks = 0; let first = false; let second = false;
        try { await store.createScanWithQuota({ ...${JSON.stringify(input)}, consume: async () => ({ ok: true, rollback: async () => { rollbacks += 1; } }) }); } catch { first = true; }
        try { await store.claimNextQueued(); } catch { second = true; }
        fs.writeSync(1, JSON.stringify({ first, second, rollbacks }));
      `;
      const { stdout } = await execFileAsync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', script], { timeout: 15_000 });
      expect(JSON.parse(stdout)).toEqual({ first: true, second: true, rollbacks: 1 });
      expect(readFileSync(path)).toEqual(original);
      expect(statSync(lock).isDirectory()).toBe(true);
      expect(statSync(displaced).isDirectory()).toBe(true);
      expect(readdirSync(dir).filter((name) => name.endsWith('.tmp'))).toHaveLength(0);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  }, 30_000);
});
