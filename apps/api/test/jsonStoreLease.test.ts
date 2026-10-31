import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { createServer as createTcpServer } from 'node:net';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { describe, expect, test } from 'vitest';
import { loadConfig, type ApiConfig } from '../src/config.js';
import { acquireJsonStoreLeases } from '../src/lib/jsonStoreLease.js';
import { createLogger } from '../src/logger.js';
import { startServer } from '../src/server.js';
import { createJsonFileScanStore, createMemoryScanStore } from '../src/scans/store.js';
import { createJsonFileAssessmentStore } from '../src/assessments/store.js';
import type { ScanEngine } from '../src/scans/engines.js';

const linux = process.platform === 'linux';
const logger = createLogger({ out: () => undefined });
function config(projectStorePath: string): ApiConfig {
  return { ...loadConfig({ NODE_ENV: 'test' }), host: '127.0.0.1', port: 0,
    authStorePath: ':memory:', usageStorePath: ':memory:', projectStorePath,
    scanStorePath: ':memory:', assessmentStorePath: ':memory:', studentStorePath: ':memory:',
    sourceStorePath: ':memory:', paymentStorePath: ':memory:', entitlementStorePath: ':memory:',
    partnerStorePath: ':memory:', paymentConfigStorePath: ':memory:' };
}
async function withDir(run: (dir: string) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), 'drobon-store-lease-'));
  try { await run(dir); } finally { rmSync(dir, { recursive: true, force: true }); }
}

describe.skipIf(!linux)('Linux same-network-namespace default JSON store guard', () => {
  test('overlapping default paths fail before loading; independent paths and restart work', () => withDir(async (dir) => {
    const path = join(dir, 'one', 'projects.json');
    const a = await startServer({ config: config(path), logger, scanProcessorAutoStart: false });
    try {
      await expect(startServer({ config: config(path), logger, scanProcessorAutoStart: false })).rejects.toThrow(/already owned/);
      const b = await startServer({ config: config(join(dir, 'two', 'projects.json')), logger, scanProcessorAutoStart: false });
      await b.stop();
    } finally { await a.stop(); }
    await a.stop(); // idempotent stop
    const restarted = await startServer({ config: config(path), logger, scanProcessorAutoStart: false });
    await restarted.stop();
  }));

  test.each(['scan', 'assessment'] as const)('known injected %s file stores are leased by their actual path', (kind) => withDir(async (dir) => {
    const path = join(dir, `${kind}.json`);
    const cfg = config(':memory:'); // deliberately differs from the injected file path
    const firstDeps = kind === 'scan' ? { scanStore: createJsonFileScanStore(path) }
      : { assessmentStore: createJsonFileAssessmentStore(path) };
    const secondDeps = kind === 'scan' ? { scanStore: createJsonFileScanStore(path) }
      : { assessmentStore: createJsonFileAssessmentStore(path) };
    const first = await startServer({ config: cfg, logger, ...firstDeps, scanProcessorAutoStart: false });
    let second: Awaited<ReturnType<typeof startServer>> | undefined;
    let failure: unknown;
    try {
      try { second = await startServer({ config: cfg, logger, ...secondDeps, scanProcessorAutoStart: false }); }
      catch (error) { failure = error; }
      expect(second).toBeUndefined();
      expect(failure).toBeInstanceOf(Error);
      expect((failure as Error).message).toMatch(/already owned/i);
    } finally { if (second !== undefined) await second.stop(); await first.stop(); }
  }));

  test('directory symlink aliases and duplicate default store paths fail closed', () => withDir(async (dir) => {
    const alias = join(tmpdir(), `drobon-lease-alias-${process.pid}-${Date.now()}`);
    symlinkSync(dir, alias, 'dir');
    const first = await acquireJsonStoreLeases([join(dir, 'sub', 'store.json')]);
    try {
      await expect(acquireJsonStoreLeases([join(alias, 'sub', 'store.json')])).rejects.toThrow(/already owned/);
      await expect(acquireJsonStoreLeases([join(dir, 'same.json'), join(dir, '.', 'same.json')])).rejects.toThrow(/must not share/);
    } finally { await first.release(); rmSync(alias, { force: true }); }
  }));

  test('partial acquisition is released on collision; a failed startup releases all leases', () => withDir(async (dir) => {
    const firstPath = join(dir, 'a.json');
    const secondPath = join(dir, 'b.json');
    const held = await acquireJsonStoreLeases([secondPath]);
    try {
      await expect(acquireJsonStoreLeases([firstPath, secondPath])).rejects.toThrow(/already owned/);
      const first = await acquireJsonStoreLeases([firstPath]);
      await first.release();
    } finally { await held.release(); }
    const corrupt = join(dir, 'corrupt.json');
    writeFileSync(corrupt, 'synthetic invalid json');
    await expect(startServer({ config: config(corrupt), logger, scanProcessorAutoStart: false })).rejects.toThrow(/refusing to start/);
    expect(readFileSync(corrupt, 'utf8')).toBe('synthetic invalid json');
    const freed = await acquireJsonStoreLeases([corrupt]);
    await freed.release();
  }));

  test('HTTP listen failure releases the already-acquired JSON lease', () => withDir(async (dir) => {
    const blocker = createTcpServer();
    await new Promise<void>((resolveListen) => blocker.listen(0, '127.0.0.1', resolveListen));
    try {
      const address = blocker.address();
      if (typeof address !== 'object' || address === null) throw new Error('fixture address missing');
      const path = join(dir, 'projects.json');
      await expect(startServer({ config: { ...config(path), port: address.port }, logger, scanProcessorAutoStart: false })).rejects.toThrow();
      const lease = await acquireJsonStoreLeases([path]);
      await lease.release();
    } finally { await new Promise<void>((resolveClose) => blocker.close(() => resolveClose())); }
  }));

  test('SIGKILL releases an acquired lease without an on-disk lockfile', () => withDir(async (dir) => {
    const path = join(dir, 'project.json');
    const serverUrl = pathToFileURL(resolve('src/server.ts')).href;
    const loggerUrl = pathToFileURL(resolve('src/logger.ts')).href;
    const script = `import { startServer } from ${JSON.stringify(serverUrl)}; import { createLogger } from ${JSON.stringify(loggerUrl)};\n` +
      `await startServer({ config: ${JSON.stringify(config(path))}, logger: createLogger({ out: () => {} }), scanProcessorAutoStart: false }); console.log('LEASE_HELD');`;
    const child = spawn(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', script], { stdio: ['ignore', 'pipe', 'pipe'] });
    let stderr = '';
    try {
      await new Promise<void>((resolveReady, reject) => {
        const timer = setTimeout(() => reject(new Error(`fixture startup timed out: ${stderr}`)), 10_000);
        child.stderr.on('data', (chunk: Buffer) => { stderr += chunk.toString(); });
        child.stdout.on('data', (chunk: Buffer) => { if (chunk.toString().includes('LEASE_HELD')) { clearTimeout(timer); resolveReady(); } });
        child.once('error', (error) => { clearTimeout(timer); reject(error); });
        child.once('exit', () => { clearTimeout(timer); reject(new Error(`fixture exited: ${stderr}`)); });
      });
      await expect(startServer({ config: config(path), logger, scanProcessorAutoStart: false })).rejects.toThrow(/already owned/);
      expect(readdirSync(dir)).toEqual([]); // abstract socket, not a persistent lockfile
      const exited = new Promise<void>((resolveExit) => child.once('exit', () => resolveExit()));
      child.kill('SIGKILL');
      await exited;
      const restarted = await startServer({ config: config(path), logger, scanProcessorAutoStart: false });
      await restarted.stop();
    } finally { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); }
  }));

  test('shutdown also waits for startup recovery before releasing its lease', () => withDir(async (dir) => {
    const path = join(dir, 'projects.json');
    const base = createMemoryScanStore();
    let release!: () => void; let entered!: () => void;
    const gate = new Promise<void>((resolveGate) => { release = resolveGate; });
    const recoveryStarted = new Promise<void>((resolveStarted) => { entered = resolveStarted; });
    const scans = { ...base, failAllRunning: async (...args: Parameters<typeof base.failAllRunning>) => {
      entered(); await gate; return base.failAllRunning(...args);
    } };
    const server = await startServer({ config: config(path), logger, scanStore: scans, scanEngines: [] });
    await recoveryStarted;
    const stopping = server.stop();
    try { await expect(acquireJsonStoreLeases([path])).rejects.toThrow(/already owned/); }
    finally { release(); await stopping; }
    const next = await acquireJsonStoreLeases([path]);
    await next.release();
  }));

  test('graceful shutdown keeps the lease until an active processor write settles', () => withDir(async (dir) => {
    const path = join(dir, 'projects.json');
    const scans = createMemoryScanStore();
    const projectId = 'prj_00000000-0000-4000-8000-000000000001';
    await scans.createScanWithQuota({ ownerId: 'usr_fixture', projectId, scanType: 'SAST', consume: async () => ({ ok: true }) });
    let release!: () => void; let entered!: () => void;
    const gate = new Promise<void>((resolveGate) => { release = resolveGate; });
    const started = new Promise<void>((resolveStarted) => { entered = resolveStarted; });
    const engine: ScanEngine = { scanType: 'SAST', execute: async () => {
      entered(); await gate;
      return { kind: 'completed', resultSummary: { findingsTotal: 0 }, findings: [] };
    } };
    const server = await startServer({ config: config(path), logger, scanStore: scans, scanEngines: [engine], scanProcessorAutoStart: false });
    const drain = server.app.scanProcessor.drain();
    await started;
    const stopping = server.stop();
    try {
      await expect(acquireJsonStoreLeases([path])).rejects.toThrow(/already owned/);
    } finally { release(); await Promise.all([drain, stopping]); }
    expect((await scans.listByProject(projectId))[0]?.status).toBe('COMPLETED');
    const next = await acquireJsonStoreLeases([path]);
    await next.release();
  }));
});
