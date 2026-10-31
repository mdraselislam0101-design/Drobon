import { spawn, type ChildProcess } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { afterEach, describe, expect, test } from 'vitest';
import { createJsonFileScanStore } from '../src/scans/store.js';

const dirs: string[] = [];
const projectId = 'prj_00000000-0000-4000-8000-000000000001';
const assessmentId = 'asm_00000000-0000-4000-8000-000000000001';
const ownerId = 'usr_synthetic';
const agent = { version: 1 as const, datasetDigest: 'a'.repeat(64), sourceDigest: 'b'.repeat(64),
  engagementId: 'eng_00000000-0000-4000-8000-000000000001' };
const consume = async () => ({ ok: true as const, rollback: async () => {} });
function location(): string {
  const dir = mkdtempSync(join(tmpdir(), 'drobon-agent-writer-race-'));
  dirs.push(dir);
  return join(dir, 'scans.json');
}
function create(store: ReturnType<typeof createJsonFileScanStore>) {
  return store.createScanWithQuota({ ownerId, projectId, assessmentId, scanType: 'SAST', agent, consume });
}
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });

function message(child: ChildProcess, type: string): Promise<Record<string, unknown>> {
  return new Promise((resolveMessage, reject) => {
    const timer = setTimeout(() => { cleanup(); reject(new Error(`Synthetic child timed out waiting for ${type}.`)); }, 15_000);
    const onMessage = (data: unknown): void => {
      if (typeof data !== 'object' || data === null || (data as { type?: unknown }).type !== type) return;
      cleanup(); resolveMessage(data as Record<string, unknown>);
    };
    const onExit = (): void => { cleanup(); reject(new Error(`Synthetic child exited before ${type}.`)); };
    const cleanup = (): void => { clearTimeout(timer); child.off('message', onMessage); child.off('exit', onExit); };
    child.on('message', onMessage);
    child.once('exit', onExit);
  });
}
function childWriter(path: string): ChildProcess {
  const moduleUrl = pathToFileURL(resolve('src/scans/store.ts')).href;
  const script = `
    import { createJsonFileScanStore } from ${JSON.stringify(moduleUrl)};
    const store = createJsonFileScanStore(${JSON.stringify(path)});
    process.send({ type: 'ready' });
    process.on('message', async (msg) => {
      if (msg !== 'write') return;
      try {
        const result = await store.createScanWithQuota({ ownerId: ${JSON.stringify(ownerId)}, projectId: ${JSON.stringify(projectId)},
          assessmentId: ${JSON.stringify(assessmentId)}, scanType: 'SAST', agent: ${JSON.stringify(agent)},
          consume: async () => ({ ok: true, rollback: async () => {} }) });
        process.send({ type: 'result', outcome: result.outcome }, () => process.exit(0));
      } catch { process.send({ type: 'result', outcome: 'refused' }, () => process.exit(0)); }
    });
  `;
  return spawn(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', script], { stdio: ['ignore', 'ignore', 'pipe', 'ipc'] });
}

describe('synthetic scan-store writer isolation', () => {
  test('a stale in-process store cannot overwrite a newer record', async () => {
    const path = location();
    const original = createJsonFileScanStore(path);
    expect((await create(original)).outcome).toBe('created');
    const stale = createJsonFileScanStore(path);
    const newer = createJsonFileScanStore(path);
    expect((await create(newer)).outcome).toBe('created');
    const expectedBytes = readFileSync(path);
    await expect(stale.claimNextQueued()).rejects.toThrow(/changed|fenced|ownership/i);
    expect(readFileSync(path)).toEqual(expectedBytes);
    expect(await createJsonFileScanStore(path).listByProject(projectId)).toHaveLength(2);
  });

  test('a previously opened writer refuses a future version before quota and preserves its bytes', async () => {
    const path = location();
    const store = createJsonFileScanStore(path);
    expect((await create(store)).outcome).toBe('created');
    const current = JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>;
    writeFileSync(path, JSON.stringify({ ...current, version: 3 })); // isolated synthetic fixture only
    const bytes = readFileSync(path);
    let charged = 0;
    await expect(store.createScanWithQuota({ ownerId, projectId, assessmentId, scanType: 'SAST', agent,
      consume: async () => { charged += 1; return consume(); } })).rejects.toThrow(/changed|version|fenced|ownership/i);
    expect(charged).toBe(0);
    expect(readFileSync(path)).toEqual(bytes);
  });

  test('a previously opened store refuses a deleted file without recreating it or charging quota', async () => {
    const path = location();
    const store = createJsonFileScanStore(path);
    expect((await create(store)).outcome).toBe('created');
    unlinkSync(path); // test-owned synthetic file only
    let charged = 0;
    await expect(store.createScanWithQuota({ ownerId, projectId, assessmentId, scanType: 'SAST', agent,
      consume: async () => { charged += 1; return consume(); } })).rejects.toThrow(/changed|fenced/i);
    expect(charged).toBe(0);
    expect(existsSync(path)).toBe(false);
  });

  test('known limitation: a fresh process cannot distinguish a deleted store from a never-created path', async () => {
    const path = location();
    const store = createJsonFileScanStore(path);
    expect((await create(store)).outcome).toBe('created');
    const backup = readFileSync(path);
    unlinkSync(path); // synthetic fixture only
    const reopened = createJsonFileScanStore(path);
    expect(await reopened.listByProject(projectId)).toHaveLength(0); // risk, not successful recovery
    expect(existsSync(path)).toBe(false);
    expect(backup.length).toBeGreaterThan(0);
  });

  test('corrupt records refuse restart; a verified backup is rehearsed only on a separate copy', async () => {
    const path = location();
    const store = createJsonFileScanStore(path);
    expect((await create(store)).outcome).toBe('created');
    const backup = readFileSync(path);
    const document = JSON.parse(backup.toString('utf8')) as { scans: Array<{ agent: { engagementId: string } }> };
    document.scans[0]!.agent.engagementId = 'invalid synthetic engagement';
    writeFileSync(path, JSON.stringify(document));
    const corrupt = readFileSync(path);
    expect(() => createJsonFileScanStore(path)).toThrow(/invalid/i);
    const recoveryCopy = `${path}.verified-copy`;
    writeFileSync(recoveryCopy, backup); // isolated fixture; never overwrite the corrupt original
    expect((await createJsonFileScanStore(recoveryCopy).listByProject(projectId))).toHaveLength(1);
    expect(readFileSync(path)).toEqual(corrupt);
    expect(readFileSync(recoveryCopy)).toEqual(backup);
  });

  test('Agent quota is not reserved for a directory obstruction; restoring the original inode permits a checked retry', async () => {
    const path = location();
    const store = createJsonFileScanStore(path);
    expect((await create(store)).outcome).toBe('created');
    const backup = `${path}.fixture-backup`;
    const original = readFileSync(path);
    renameSync(path, backup); mkdirSync(path);
    let charged = 0;
    await expect(store.createScanWithQuota({ ownerId, projectId, assessmentId, scanType: 'SAST', agent,
      consume: async () => { charged += 1; return consume(); } })).rejects.toThrow(/regular file/i);
    expect(charged).toBe(0);
    expect(readFileSync(backup)).toEqual(original);
    rmSync(path, { recursive: true }); renameSync(backup, path); // fixture-owned obstruction only
    expect((await create(store)).outcome).toBe('created');
    expect((await createJsonFileScanStore(path).listByProject(projectId))).toHaveLength(2);
  });

  test('a byte-identical replacement inode still fences the cached writer', async () => {
    const path = location();
    const store = createJsonFileScanStore(path);
    expect((await create(store)).outcome).toBe('created');
    const bytes = readFileSync(path);
    const replacement = `${path}.replacement`;
    writeFileSync(replacement, bytes);
    renameSync(replacement, path); // isolated fixture simulates another writer's rename
    await expect(store.claimNextQueued()).rejects.toThrow(/changed|fenced/i);
    expect(readFileSync(path)).toEqual(bytes);
  });

  test('a detected stale instance stays fenced even if the original synthetic bytes return', async () => {
    const path = location();
    const store = createJsonFileScanStore(path);
    expect((await create(store)).outcome).toBe('created');
    const original = readFileSync(path);
    writeFileSync(path, '{"synthetic":"changed"}');
    await expect(store.claimNextQueued()).rejects.toThrow(/changed|fenced/i);
    writeFileSync(path, original); // fixture-owned file; an operator would need a reviewed recovery
    await expect(store.claimNextQueued()).rejects.toThrow(/fenced/i);
    expect(readFileSync(path)).toEqual(original);
    expect((await createJsonFileScanStore(path).listByProject(projectId))).toHaveLength(1);
  });

  test('a changed file during quota reservation rolls back the reservation without overwriting', async () => {
    const path = location();
    const waiting = createJsonFileScanStore(path);
    expect((await create(waiting)).outcome).toBe('created');
    const newer = createJsonFileScanStore(path);
    let entered!: () => void; let release!: () => void;
    const reserved = new Promise<void>((resolveReserved) => { entered = resolveReserved; });
    const gate = new Promise<void>((resolveGate) => { release = resolveGate; });
    let rollbacks = 0;
    const pending = waiting.createScanWithQuota({ ownerId, projectId, assessmentId, scanType: 'SAST', agent,
      consume: async () => { entered(); await gate; return { ok: true as const, rollback: async () => { rollbacks += 1; } }; } });
    await reserved;
    expect((await create(newer)).outcome).toBe('created');
    const newerBytes = readFileSync(path);
    release();
    await expect(pending).rejects.toThrow(/changed|fenced/i);
    expect(rollbacks).toBe(1);
    expect(readFileSync(path)).toEqual(newerBytes);
    expect((await createJsonFileScanStore(path).listByProject(projectId))).toHaveLength(2);
  });

  test('an existing synthetic write lock is refused before quota and is not removed', async () => {
    const path = location();
    const store = createJsonFileScanStore(path);
    expect((await create(store)).outcome).toBe('created');
    const before = readFileSync(path);
    const lock = join(dirname(path), '.scans.json.drobon-write-lock');
    mkdirSync(lock);
    let charged = 0;
    await expect(store.createScanWithQuota({ ownerId, projectId, assessmentId, scanType: 'SAST', agent,
      consume: async () => { charged += 1; return consume(); } })).rejects.toThrow(/lock/i);
    expect(charged).toBe(0);
    expect(readFileSync(path)).toEqual(before);
    expect(() => mkdirSync(lock)).toThrow(); // the other writer's lock was not removed
  });

  test('a cancellation saved by a cooperating instance prevents a stale instance from starting a DAST probe', async () => {
    const path = location();
    const first = createJsonFileScanStore(path);
    const created = await first.createScanWithQuota({ ownerId, projectId, assessmentId, scanType: 'DAST', agent,
      targetUrl: 'https://fixture.example.org/', consume });
    if (created.outcome !== 'created') throw new Error('Expected synthetic DAST job.');
    expect((await first.claimNextQueued())?.id).toBe(created.scan.id);
    const other = createJsonFileScanStore(path);
    expect((await other.requestAgentCancellation({ ownerId, projectId, assessmentId, scanId: created.scan.id })).outcome).toBe('requested');
    const cancelledBytes = readFileSync(path);
    let probes = 0;
    await expect(first.beginAgentProbe({ ownerId, projectId, assessmentId, scanId: created.scan.id,
      engagementId: agent.engagementId }, () => { probes += 1; })).rejects.toThrow(/changed|fenced/i);
    expect(probes).toBe(0);
    expect(readFileSync(path)).toEqual(cancelledBytes);
  });

  test('two fresh processes cannot both publish from the same cached empty state', async () => {
    const path = location();
    const children = [childWriter(path), childWriter(path)];
    try {
      await Promise.all(children.map((child) => message(child, 'ready')));
      const results = children.map((child) => message(child, 'result'));
      for (const child of children) child.send('write');
      const outcomes = (await Promise.all(results)).map((item) => item['outcome']).sort();
      expect(outcomes).toEqual(['created', 'refused']);
      const saved = await createJsonFileScanStore(path).listByProject(projectId);
      expect(saved).toHaveLength(1);
      expect(saved[0]?.agent).toEqual(agent);
    } finally { for (const child of children) if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); }
  }, 30_000);
});
