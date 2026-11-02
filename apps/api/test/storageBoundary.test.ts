import { chmodSync, linkSync, mkdirSync, mkdtempSync, openSync, closeSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { spawn, type ChildProcess } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, test } from 'vitest';
import { loadConfig, type ApiConfig } from '../src/config.js';
import { createLogger } from '../src/logger.js';
import { startServer } from '../src/server.js';
import { createJsonFileScanStore, createMemoryScanStore } from '../src/scans/store.js';
import {
  attestAgentStorage, findForeignWriters, inspectStorePath, STORAGE_BLOCKED, STORAGE_READY,
} from '../src/lib/storageBoundary.js';

const linux = process.platform === 'linux';
const logger = createLogger({ out: () => undefined });
const children: ChildProcess[] = [];
const roots: string[] = [];

function root(): string {
  const dir = mkdtempSync(join(tmpdir(), 'drobon-storage-boundary-'));
  roots.push(dir);
  return dir;
}
function storeWithDocument(directory: string): string {
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  chmodSync(directory, 0o700);
  const path = join(directory, 'scans.json');
  writeFileSync(path, '{"version":2,"scans":[],"idempotency":[]}\n', { mode: 0o600 });
  chmodSync(path, 0o600);
  return path;
}
function agentConfig(scanStorePath: string, agentEnabled: boolean): ApiConfig {
  return {
    ...loadConfig({ NODE_ENV: 'test', ...(agentEnabled ? { AGENT_EXPERIMENTAL_ENABLED: 'true' } : {}) }),
    host: '127.0.0.1', port: 0,
    authStorePath: ':memory:', usageStorePath: ':memory:', projectStorePath: ':memory:',
    scanStorePath, assessmentStorePath: ':memory:', studentStorePath: ':memory:',
    sourceStorePath: ':memory:', paymentStorePath: ':memory:', entitlementStorePath: ':memory:',
    partnerStorePath: ':memory:', paymentConfigStorePath: ':memory:',
  };
}

afterEach(async () => {
  for (const child of children.splice(0)) child.kill('SIGKILL');
  for (const dir of roots.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe('Agent storage boundary attestation (synthetic files only)', () => {
  test('attests an owner-only document inside an owner-only directory', () => {
    const directory = join(root(), 'protected');
    const path = storeWithDocument(directory);
    expect(inspectStorePath(path)).toEqual([]);
    const verdict = attestAgentStorage([path]);
    expect(verdict).toMatchObject({ code: STORAGE_READY, ok: true, issues: [], foreignWriterCount: 0 });
  });

  test('allows the first write when the document does not exist yet', () => {
    const directory = join(root(), 'fresh');
    mkdirSync(directory, { mode: 0o700 });
    chmodSync(directory, 0o700);
    expect(attestAgentStorage([join(directory, 'scans.json')]).ok).toBe(true);
  });

  test('memory stores carry no filesystem boundary to attest', () => {
    expect(attestAgentStorage([':memory:']).code).toBe(STORAGE_READY);
  });

  test.each([0o0777, 0o0770, 0o0775])('blocks a store directory with mode %s', (mode) => {
    const directory = join(root(), `dir-${mode.toString(8)}`);
    const path = storeWithDocument(directory);
    chmodSync(directory, mode);
    const issues = inspectStorePath(path);
    if ((mode & 0o020) !== 0) expect(issues).toContain('directory-group-writable');
    if ((mode & 0o002) !== 0) expect(issues).toContain('directory-world-writable');
    expect(attestAgentStorage([path]).code).toBe(STORAGE_BLOCKED);
  });

  test('blocks a document another identity could read or write', () => {
    const path = storeWithDocument(join(root(), 'readable'));
    chmodSync(path, 0o0640);
    expect(inspectStorePath(path)).toContain('store-group-accessible');
    expect(attestAgentStorage([path]).ok).toBe(false);
  });

  test('blocks a hard-linked document and a symlinked document', () => {
    const directory = join(root(), 'linked');
    const linkedPath = storeWithDocument(directory);
    linkSync(linkedPath, join(directory, 'alias.json'));
    expect(inspectStorePath(linkedPath)).toContain('store-hard-linked');

    const other = join(root(), 'symlinked');
    mkdirSync(other, { mode: 0o700 });
    chmodSync(other, 0o700);
    symlinkSync(linkedPath, join(other, 'scans.json'));
    expect(inspectStorePath(join(other, 'scans.json'))).toContain('store-symlink');
  });

  test('blocks a symlinked parent and a non-sticky writable ancestor', () => {
    const directory = join(root(), 'real');
    storeWithDocument(directory);
    const alias = join(root(), 'alias-dir');
    symlinkSync(directory, alias);
    expect(inspectStorePath(join(alias, 'scans.json'))).toContain('ancestor-symlink');

    // A world-writable, non-sticky parent can displace the private directory.
    const loose = join(root(), 'loose');
    mkdirSync(loose, { mode: 0o777 });
    chmodSync(loose, 0o777);
    const nested = join(loose, 'protected');
    const nestedPath = storeWithDocument(nested);
    expect(inspectStorePath(nestedPath)).toContain('ancestor-world-writable');
    expect(attestAgentStorage([nestedPath]).ok).toBe(false);
  });

  test('blocks a non-regular document path', () => {
    const directory = join(root(), 'obstructed');
    mkdirSync(directory, { mode: 0o700 });
    chmodSync(directory, 0o700);
    mkdirSync(join(directory, 'scans.json'));
    expect(inspectStorePath(join(directory, 'scans.json'))).toContain('store-not-regular');
  });

  test.skipIf(!linux)('detects a separate process that write-holds the document', async () => {
    const path = storeWithDocument(join(root(), 'foreign'));
    expect(findForeignWriters([path]).pids).toEqual([]);
    const child = spawn(process.execPath, ['--input-type=module', '-e', `
      import { openSync, closeSync } from 'node:fs';
      const descriptor = openSync(${JSON.stringify(path)}, 'r+');
      console.log('HELD');
      setInterval(() => { closeSync; void descriptor; }, 1000);
    `], { stdio: ['ignore', 'pipe', 'pipe'] });
    children.push(child);
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('synthetic writer did not start')), 10_000);
      child.stdout?.on('data', (chunk: Buffer) => {
        if (chunk.toString().includes('HELD')) { clearTimeout(timer); resolve(); }
      });
      child.once('exit', () => { clearTimeout(timer); reject(new Error('synthetic writer exited early')); });
    });
    const found = findForeignWriters([path]);
    expect(found.pids).toContain(child.pid);
    const verdict = attestAgentStorage([path]);
    expect(verdict.code).toBe(STORAGE_BLOCKED);
    expect(verdict.issues).toContain('foreign-writer-process');
    expect(verdict.foreignWriterCount).toBeGreaterThan(0);
  });

  test.skipIf(!linux)('refuses startup while a legacy writer still holds the otherwise-private store', async () => {
    const directory = join(root(), 'concurrent-legacy');
    const path = storeWithDocument(directory); // 0700 directory, 0600 document
    expect(attestAgentStorage([path]).ok).toBe(true);
    const child = spawn(process.execPath, ['--input-type=module', '-e', `
      import { openSync } from 'node:fs';
      const descriptor = openSync(${JSON.stringify(path)}, 'r+');
      console.log('LEGACY_HELD');
      setInterval(() => { void descriptor; }, 1000);
    `], { stdio: ['ignore', 'pipe', 'pipe'] });
    children.push(child);
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('synthetic legacy writer did not start')), 10_000);
      child.stdout?.on('data', (chunk: Buffer) => {
        if (chunk.toString().includes('LEGACY_HELD')) { clearTimeout(timer); resolve(); }
      });
      child.once('exit', () => { clearTimeout(timer); reject(new Error('synthetic legacy writer exited early')); });
    });
    await expect(startServer({ config: agentConfig(path, true), logger, scanProcessorAutoStart: false }))
      .rejects.toMatchObject({ issues: expect.arrayContaining(['foreign-writer-process']) });
    child.kill('SIGKILL');
    await new Promise<void>((resolve) => child.once('exit', resolve));
    children.splice(children.indexOf(child), 1);
    const server = await startServer({ config: agentConfig(path, true), logger, scanProcessorAutoStart: false });
    try { expect(server.port).toBeGreaterThan(0); } finally { await server.stop(); }
  });

  test.skipIf(!linux)('refuses startup with STORAGE BLOCKED when the Agent is enabled on an unsafe path', async () => {
    const directory = join(root(), 'unsafe');
    const path = storeWithDocument(directory);
    chmodSync(directory, 0o0777);
    await expect(startServer({ config: agentConfig(path, true), logger, scanProcessorAutoStart: false }))
      .rejects.toThrow(/STORAGE BLOCKED/);
    await expect(startServer({ config: agentConfig(path, true), logger, scanProcessorAutoStart: false }))
      .rejects.toMatchObject({ issues: expect.arrayContaining(['directory-world-writable']) });
  });

  test.skipIf(!linux)('keeps the same unsafe path usable while the Agent is disabled', async () => {
    const directory = join(root(), 'legacy-safe');
    const path = storeWithDocument(directory);
    chmodSync(directory, 0o0777);
    const server = await startServer({ config: agentConfig(path, false), logger, scanProcessorAutoStart: false });
    try {
      expect(server.port).toBeGreaterThan(0);
    } finally {
      await server.stop();
    }
  });

  test.skipIf(!linux)('starts with the Agent enabled when the boundary is attested', async () => {
    const path = storeWithDocument(join(root(), 'ready'));
    const server = await startServer({ config: agentConfig(path, true), logger, scanProcessorAutoStart: false });
    try {
      expect(server.port).toBeGreaterThan(0);
    } finally {
      await server.stop();
    }
  });

  test('per-write guard refuses a directory widened after the store was opened', async () => {
    const directory = join(root(), 'per-write');
    const path = storeWithDocument(directory);
    let guardRuns = 0;
    const store = createJsonFileScanStore(path, { beforePersist: () => {
      guardRuns += 1;
      const verdict = attestAgentStorage([path], { scanForeignWriters: false });
      if (!verdict.ok) throw new Error(`STORAGE BLOCKED: ${verdict.issues.join(',')}`);
    } });
    const input = {
      ownerId: 'usr_synthetic', projectId: 'prj_00000000-0000-4000-8000-000000000001', scanType: 'SAST' as const,
      consume: async () => ({ ok: true as const }),
    };
    expect((await store.createScanWithQuota(input)).outcome).toBe('created');
    const before = Buffer.from(readFileSync(path));
    chmodSync(directory, 0o0777);
    try {
      await expect(store.createScanWithQuota(input)).rejects.toThrow(/STORAGE BLOCKED/);
    } finally {
      chmodSync(directory, 0o700);
    }
    // The refused write must not have published anything.
    expect(Buffer.from(readFileSync(path)).equals(before)).toBe(true);
    expect(guardRuns).toBe(2);
    expect((await store.createScanWithQuota(input)).outcome).toBe('created');
  });

  test.skipIf(!linux)('refuses an opaque injected store when the Agent is enabled on a durable path', async () => {
    const path = storeWithDocument(join(root(), 'opaque'));
    const opaque = { ...createMemoryScanStore() }; // wrapper: real path unknown
    await expect(startServer({ config: agentConfig(path, true), logger, scanStore: opaque, scanProcessorAutoStart: false }))
      .rejects.toMatchObject({ issues: expect.arrayContaining(['opaque-injected-adapter']) });
  });

  test.skipIf(!linux)('still accepts the same injected store when the Agent is disabled', async () => {
    const path = storeWithDocument(join(root(), 'opaque-legacy'));
    const opaque = { ...createMemoryScanStore() };
    const server = await startServer({ config: agentConfig(path, false), logger, scanStore: opaque, scanProcessorAutoStart: false });
    try { expect(server.port).toBeGreaterThan(0); } finally { await server.stop(); }
  });

  test('does not create or modify the document it inspects', () => {
    const directory = join(root(), 'inspect-only');
    mkdirSync(directory, { mode: 0o700 });
    chmodSync(directory, 0o700);
    const path = join(directory, 'absent.json');
    const descriptor = (): number | undefined => {
      try { const fd = openSync(path, 'r'); closeSync(fd); return fd; } catch { return undefined; }
    };
    expect(descriptor()).toBeUndefined();
    expect(attestAgentStorage([path]).ok).toBe(true);
    expect(descriptor()).toBeUndefined();
  });
});
