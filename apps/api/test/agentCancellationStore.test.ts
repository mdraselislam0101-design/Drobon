import { describe, expect, test } from 'vitest';
import { createMemoryScanStore } from '../src/scans/store.js';

const ownerId = 'usr_fixture';
const projectId = 'prj_00000000-0000-4000-8000-000000000001';
const assessmentId = 'asm_00000000-0000-4000-8000-000000000001';
const agent = { version: 1 as const, datasetDigest: 'a'.repeat(64), sourceDigest: 'b'.repeat(64),
  engagementId: 'eng_00000000-0000-4000-8000-000000000001' };

async function running(scanType: 'SAST' | 'DAST' = 'SAST') {
  const store = createMemoryScanStore();
  const created = await store.createScanWithQuota({ ownerId, projectId, assessmentId, agent, scanType,
    ...(scanType === 'DAST' ? { targetUrl: 'https://fixture.example.org/' } : {}), consume: async () => ({ ok: true }) });
  if (created.outcome !== 'created') throw new Error('Could not create synthetic agent job.');
  expect((await store.claimNextQueued())?.id).toBe(created.scan.id);
  return { store, scanId: created.scan.id };
}

describe('agent cancellation store serialization', () => {
  test('a committed cancellation wins a concurrent completion and leaves no findings', async () => {
    const { store, scanId } = await running();
    const [cancelled, completed] = await Promise.all([
      store.requestAgentCancellation({ ownerId, projectId, assessmentId, scanId }),
      store.completeScan(scanId, { findingsTotal: 0 }, []),
    ]);
    expect(cancelled.outcome).toBe('requested');
    expect(completed).toBeUndefined();
    const failed = await store.failScan(scanId, 'SCAN_ENGINE_ERROR', 'A generic engine result.');
    expect(failed?.status).toBe('FAILED');
    expect(failed?.failureMessage).toMatch(/cancel/i);
    expect(failed?.findings).toBeUndefined();
    expect((await store.requestAgentCancellation({ ownerId, projectId, assessmentId, scanId })).outcome).toBe('already-requested');
  });

  test('a committed completion wins cancellation and is not falsely labelled cancelled', async () => {
    const { store, scanId } = await running();
    const [completed, cancelled] = await Promise.all([
      store.completeScan(scanId, { findingsTotal: 0 }, []),
      store.requestAgentCancellation({ ownerId, projectId, assessmentId, scanId }),
    ]);
    expect(completed?.status).toBe('COMPLETED');
    expect(cancelled.outcome).toBe('terminal');
    expect((await store.findByProjectAndId(projectId, scanId))?.agent?.cancelRequestedAt).toBeUndefined();
  });

  test('cancellation and the synchronous start of a network probe have a deterministic order', async () => {
    const { store, scanId } = await running('DAST');
    let starts = 0;
    const scope = { ownerId, projectId, assessmentId, scanId, engagementId: agent.engagementId };
    const [cancelled, started] = await Promise.all([
      store.requestAgentCancellation({ ownerId, projectId, assessmentId, scanId }),
      store.beginAgentProbe(scope, () => { starts += 1; return Promise.resolve('fixture'); }),
    ]);
    expect(cancelled.outcome).toBe('requested');
    expect(started).toBeUndefined();
    expect(starts).toBe(0);
  });

  test('a started network promise does not hold the cancellation mutation queue', async () => {
    const { store, scanId } = await running('DAST');
    let release!: () => void;
    const probe = new Promise<void>((resolve) => { release = resolve; });
    const started = await store.beginAgentProbe({ ownerId, projectId, assessmentId, scanId, engagementId: agent.engagementId }, () => probe);
    expect(started).toBeDefined();
    expect((await store.requestAgentCancellation({ ownerId, projectId, assessmentId, scanId })).outcome).toBe('requested');
    release();
    await started!.value;
  });

  test('repeated concurrent requests persist one intent and reject mismatched authority', async () => {
    const { store, scanId } = await running();
    expect((await store.requestAgentCancellation({ ownerId: 'usr_other', projectId, assessmentId, scanId })).outcome).toBe('not-found');
    expect((await store.requestAgentCancellation({ ownerId, projectId, assessmentId: 'asm_00000000-0000-4000-8000-000000000002', scanId })).outcome).toBe('not-found');
    const results = await Promise.all(Array.from({ length: 5 }, () => store.requestAgentCancellation({ ownerId, projectId, assessmentId, scanId })));
    expect(results.filter((item) => item.outcome === 'requested')).toHaveLength(1);
    expect(results.filter((item) => item.outcome === 'already-requested')).toHaveLength(4);
  });
});
