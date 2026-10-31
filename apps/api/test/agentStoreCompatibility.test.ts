import { afterEach, describe, expect, test } from 'vitest';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createJsonFileScanStore } from '../src/scans/store.js';

const dirs: string[] = [];
const projectId = 'prj_00000000-0000-4000-8000-000000000001';
const assessmentId = 'asm_00000000-0000-4000-8000-000000000001';
const ownerId = 'usr_synthetic';
const agent = { version: 1 as const, datasetDigest: 'a'.repeat(64), sourceDigest: 'b'.repeat(64),
  engagementId: 'eng_00000000-0000-4000-8000-000000000001' };
const granted = async () => ({ ok: true as const, rollback: async () => {} });
function location(): string {
  const directory = mkdtempSync(join(tmpdir(), 'drobon-agent-version-fixture-'));
  dirs.push(directory);
  return join(directory, 'scans.json');
}
function json(path: string): Record<string, unknown> { return JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>; }
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });

describe('agent scan-store compatibility (isolated synthetic files)', () => {
  test('a newly created agent-bearing store is versioned and can reopen without losing metadata', async () => {
    const path = location();
    const store = createJsonFileScanStore(path);
    const created = await store.createScanWithQuota({ ownerId, projectId, assessmentId, scanType: 'SAST', agent, consume: granted });
    expect(created.outcome).toBe('created');
    expect(json(path)['version']).toBe(2);
    const reopened = createJsonFileScanStore(path);
    const records = await reopened.listByProject(projectId);
    expect(records).toHaveLength(1);
    expect(records[0]?.agent).toEqual(agent);
  });

  test('an existing v1 legacy store is never silently upgraded or charged for an agent job', async () => {
    const path = location();
    const store = createJsonFileScanStore(path);
    expect((await store.createScanWithQuota({ ownerId, projectId, scanType: 'SAST', consume: granted })).outcome).toBe('created');
    const original = readFileSync(path);
    expect(json(path)['version']).toBe(1);
    let charged = 0;
    const outcome = await store.createScanWithQuota({ ownerId, projectId, assessmentId, scanType: 'SAST', agent,
      consume: async () => { charged += 1; return granted(); } });
    expect(outcome.outcome).toBe('compatibility-required');
    expect(charged).toBe(0);
    expect(readFileSync(path)).toEqual(original);
    expect(await createJsonFileScanStore(path).listByProject(projectId)).toHaveLength(1);
  });

  test.each(['legacy-first', 'agent-first'] as const)('concurrent initial writes preserve the %s version boundary', async (order) => {
    const path = location();
    const store = createJsonFileScanStore(path);
    let charges = 0;
    const consume = async () => { charges += 1; return granted(); };
    const legacy = () => store.createScanWithQuota({ ownerId, projectId, scanType: 'SAST', consume });
    const agentJob = () => store.createScanWithQuota({ ownerId, projectId, assessmentId, scanType: 'SAST', agent, consume });
    if (order === 'legacy-first') {
      const [first, second] = await Promise.all([legacy(), agentJob()]);
      expect(first.outcome).toBe('created');
      expect(second.outcome).toBe('compatibility-required');
      expect(charges).toBe(1);
      expect(json(path)['version']).toBe(1);
      expect(await createJsonFileScanStore(path).listByProject(projectId)).toHaveLength(1);
    } else {
      const [first, second] = await Promise.all([agentJob(), legacy()]);
      expect(first.outcome).toBe('created');
      expect(second.outcome).toBe('created');
      expect(charges).toBe(2);
      expect(json(path)['version']).toBe(2);
      expect(await createJsonFileScanStore(path).listByProject(projectId)).toHaveLength(2);
    }
  });

  test('an unsafe v1 file already containing agent metadata fails closed without a write', async () => {
    const path = location();
    const store = createJsonFileScanStore(path);
    expect((await store.createScanWithQuota({ ownerId, projectId, assessmentId, scanType: 'SAST', agent, consume: granted })).outcome).toBe('created');
    const v1 = { ...json(path), version: 1 };
    writeFileSync(path, JSON.stringify(v1)); // fixture-owned temporary file only
    const before = readFileSync(path);
    expect(() => createJsonFileScanStore(path)).toThrow(/agent.*version 1|version 1.*agent/i);
    expect(readFileSync(path)).toEqual(before);
  });

  test.each([null, {}, 'forged'])('any v1 agent property, including %s, is refused without a write', (value) => {
    const path = location();
    const document = { version: 1, scans: [{ agent: value }], idempotency: [], reports: [] };
    writeFileSync(path, JSON.stringify(document));
    const before = readFileSync(path);
    expect(() => createJsonFileScanStore(path)).toThrow(/agent.*version 1|version 1.*agent/i);
    expect(readFileSync(path)).toEqual(before);
  });

  test('v2 Agent records missing their exact authorizing engagement fail closed unchanged', async () => {
    const path = location();
    const store = createJsonFileScanStore(path);
    expect((await store.createScanWithQuota({ ownerId, projectId, assessmentId, scanType: 'SAST', agent, consume: granted })).outcome).toBe('created');
    const document = json(path) as { scans: Array<{ agent: { engagementId?: string } }> };
    delete document.scans[0]!.agent.engagementId;
    writeFileSync(path, JSON.stringify(document));
    const before = readFileSync(path);
    expect(() => createJsonFileScanStore(path)).toThrow(/invalid.*scan|scan.*invalid/i);
    expect(readFileSync(path)).toEqual(before);
  });

  test('a v2 completed job falsely marked cancelled fails closed unchanged', async () => {
    const path = location();
    const store = createJsonFileScanStore(path);
    const created = await store.createScanWithQuota({ ownerId, projectId, assessmentId, scanType: 'SAST', agent, consume: granted });
    if (created.outcome !== 'created') throw new Error('Expected a synthetic job.');
    await store.claimNextQueued();
    expect((await store.completeScan(created.scan.id, { findingsTotal: 0 }, []))?.status).toBe('COMPLETED');
    const document = json(path) as { scans: Array<{ agent: { cancelRequestedAt?: string } }> };
    document.scans[0]!.agent.cancelRequestedAt = new Date().toISOString();
    writeFileSync(path, JSON.stringify(document));
    const before = readFileSync(path);
    expect(() => createJsonFileScanStore(path)).toThrow(/invalid.*scan|scan.*invalid/i);
    expect(readFileSync(path)).toEqual(before);
  });

  test.each(['document', 'scan', 'idempotency'] as const)('v2 refuses an unsupported %s field without silently dropping it', async (placement) => {
    const path = location();
    const store = createJsonFileScanStore(path);
    const created = await store.createScanWithQuota({ ownerId, projectId, assessmentId, scanType: 'SAST', agent,
      idempotencyKey: 'synthetic_key', consume: granted });
    expect(created.outcome).toBe('created');
    const document = json(path) as { scans: Record<string, unknown>[]; idempotency: Record<string, unknown>[]; [key: string]: unknown };
    const target = placement === 'document' ? document : placement === 'scan' ? document.scans[0]! : document.idempotency[0]!;
    target['futureUnsupportedField'] = 'synthetic future data';
    writeFileSync(path, JSON.stringify(document));
    const bytes = readFileSync(path);
    expect(() => createJsonFileScanStore(path)).toThrow(/unsupported|unknown/i);
    expect(readFileSync(path)).toEqual(bytes);
  });

  test('unsupported future versions refuse startup without rewriting the document', () => {
    const path = location();
    writeFileSync(path, JSON.stringify({ version: 3, scans: [], idempotency: [], reports: [] }));
    const before = readFileSync(path);
    expect(() => createJsonFileScanStore(path)).toThrow(/refusing to start/);
    expect(readFileSync(path)).toEqual(before);
  });

  test('a copy-only legacy upgrade rehearsal preserves the original and record identities', async () => {
    const path = location();
    const store = createJsonFileScanStore(path);
    const created = await store.createScanWithQuota({ ownerId, projectId, scanType: 'SAST', consume: granted });
    expect(created.outcome).toBe('created');
    const originalBytes = readFileSync(path);
    const before = json(path);
    const copyPath = `${path}.isolated-copy`;
    writeFileSync(copyPath, JSON.stringify({ ...before, version: 2 })); // rehearsal, never the source path
    expect(readFileSync(path)).toEqual(originalBytes);
    const migrated = json(copyPath);
    expect({ ...migrated, version: 1 }).toEqual(before);
    const reopened = createJsonFileScanStore(copyPath);
    expect(await reopened.listByProject(projectId)).toHaveLength(1);
    expect((await reopened.claimNextQueued())?.id).toBe(created.outcome === 'created' ? created.scan.id : '');
    expect(readFileSync(path)).toEqual(originalBytes);
    expect(json(copyPath)['version']).toBe(2);
  });

  test('synthetic rollback rehearsal retains both the v1 backup and divergent v2 copy', async () => {
    const originalPath = location();
    const legacy = createJsonFileScanStore(originalPath);
    expect((await legacy.createScanWithQuota({ ownerId, projectId, scanType: 'SAST', consume: granted })).outcome).toBe('created');
    const backupBytes = readFileSync(originalPath);
    const backupDocument = json(originalPath);
    const upgradedPath = `${originalPath}.upgraded-copy`;
    const rollbackPath = `${originalPath}.rollback-copy`;
    writeFileSync(upgradedPath, JSON.stringify({ ...backupDocument, version: 2 }));
    const upgraded = createJsonFileScanStore(upgradedPath);
    expect((await upgraded.createScanWithQuota({ ownerId, projectId, assessmentId, scanType: 'SAST', agent, consume: granted })).outcome).toBe('created');
    const divergentV2Bytes = readFileSync(upgradedPath);
    // Restore the old snapshot only as another fixture-owned copy; keeping
    // the v2 bytes makes divergence and the new job's absence explicit.
    writeFileSync(rollbackPath, backupBytes);
    expect(readFileSync(originalPath)).toEqual(backupBytes);
    expect(readFileSync(rollbackPath)).toEqual(backupBytes);
    expect(readFileSync(upgradedPath)).toEqual(divergentV2Bytes);
    expect((await createJsonFileScanStore(rollbackPath).listByProject(projectId))).toHaveLength(1);
    expect((await createJsonFileScanStore(upgradedPath).listByProject(projectId))).toHaveLength(2);
  });
});
