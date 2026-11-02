import { describe, expect, test } from 'vitest';
import { createEngineRegistry, type ScanEngine } from '../src/scans/engines.js';
import { createLogger } from '../src/logger.js';
import { createMemoryScanStore } from '../src/scans/store.js';
import { createScanProcessor, MAX_SCAN_CONCURRENCY } from '../src/scans/processor.js';

/**
 * Bounded parallel scan lanes (audit finding P1-9).
 *
 * The durable store is still the single writer, so the guarantees under test
 * are exactly the ones that must survive a throughput change:
 * - a scan is claimed and executed at most once, even with several lanes;
 * - lanes never run more than the configured number of scans at once;
 * - the default stays fully serialized (no behaviour change unless asked);
 * - one failing scan does not stop the others.
 */

const OWNER = 'usr_concurrency';
const quiet = (): ReturnType<typeof createLogger> => createLogger({ out: () => undefined });

interface Harness {
  store: ReturnType<typeof createMemoryScanStore>;
  projectIds: string[];
  scanIds: string[];
}

async function seed(store: Harness['store'], count: number): Promise<Harness> {
  const projectIds: string[] = [];
  const scanIds: string[] = [];
  for (let index = 0; index < count; index += 1) {
    const projectId = `prj_00000000-0000-4000-8000-${String(index).padStart(12, '0')}`;
    const created = await store.createScanWithQuota({
      ownerId: OWNER, projectId, scanType: 'SAST', consume: async () => ({ ok: true }),
    });
    if (created.outcome !== 'created') throw new Error('Expected a created scan.');
    projectIds.push(projectId);
    scanIds.push(created.scan.id);
  }
  return { store, projectIds, scanIds };
}

/** Tracks how many engines run at the same moment, and the peak. */
function trackingEngine(onRun?: (id: string) => void): {
  engine: ScanEngine; peak: () => number;
  /** Release every currently parked engine execution. */
  release: () => void;
  waitForEntered: (n: number) => Promise<void>;
} {
  let active = 0;
  let peak = 0;
  const gates: Array<() => void> = [];
  const entered: Array<() => void> = [];
  let enteredCount = 0;
  const engine: ScanEngine = {
    scanType: 'SAST',
    execute: async (scan) => {
      active += 1;
      peak = Math.max(peak, active);
      onRun?.(scan.id);
      enteredCount += 1;
      entered.splice(0).forEach((resolve) => { resolve(); });
      await new Promise<void>((resolve) => { gates.push(resolve); });
      active -= 1;
      return { kind: 'completed', resultSummary: { findingsTotal: 0 } as never, findings: [] };
    },
  };
  return {
    engine,
    peak: () => peak,
    release: () => { gates.splice(0).forEach((resolve) => { resolve(); }); },
    waitForEntered: async (n: number) => {
      while (enteredCount < n) {
        await new Promise<void>((resolve) => { entered.push(resolve); });
      }
    },
  };
}

describe('bounded scan concurrency (P1-9)', () => {
  test('the default is one lane: scans still run strictly one at a time', async () => {
    const base = createMemoryScanStore();
    const harness = await seed(base, 3);
    const tracking = trackingEngine();
    const processor = createScanProcessor({
      store: harness.store, engines: createEngineRegistry([tracking.engine]), logger: quiet(),
    });
    const drain = processor.drain();
    await tracking.waitForEntered(1);
    // Give the lane loop every chance to start a second engine.
    await new Promise((resolve) => { setTimeout(resolve, 30); });
    expect(tracking.peak()).toBe(1);
    tracking.release();
    await Promise.race([drain, new Promise((resolve) => { setTimeout(resolve, 20); })]);
    // Finish the rest of the queue.
    for (let index = 0; index < 5; index += 1) {
      tracking.release();
      await new Promise((resolve) => { setTimeout(resolve, 10); });
    }
    await drain;
    const scans = await harness.store.listByProject(harness.projectIds[0]!);
    expect(scans[0]?.status).toBe('COMPLETED');
    expect(tracking.peak()).toBe(1);
  });

  test('configured lanes run independent scans in parallel but never exceed the bound', async () => {
    const base = createMemoryScanStore();
    const harness = await seed(base, 4);
    const executions = new Map<string, number>();
    const tracking = trackingEngine((id) => { executions.set(id, (executions.get(id) ?? 0) + 1); });
    const processor = createScanProcessor({
      store: harness.store, engines: createEngineRegistry([tracking.engine]), logger: quiet(), concurrency: 2,
    });
    const drain = processor.drain();
    await tracking.waitForEntered(2);
    // Two lanes are busy; a third engine must not start.
    await new Promise((resolve) => { setTimeout(resolve, 30); });
    expect(tracking.peak()).toBe(2);
    for (let index = 0; index < 12; index += 1) {
      tracking.release();
      await new Promise((resolve) => { setTimeout(resolve, 10); });
    }
    await drain;
    expect(tracking.peak()).toBe(2);
    expect(tracking.peak()).toBeLessThanOrEqual(MAX_SCAN_CONCURRENCY);
    // Every scan ran exactly once.
    for (const scanId of harness.scanIds) {
      expect(executions.get(scanId)).toBe(1);
    }
    for (const projectId of harness.projectIds) {
      const scans = await harness.store.listByProject(projectId);
      expect(scans).toHaveLength(1);
      expect(scans[0]?.status).toBe('COMPLETED');
    }
  });

  test('one failing scan does not block the other lane', async () => {
    const base = createMemoryScanStore();
    const harness = await seed(base, 2);
    let calls = 0;
    const engine: ScanEngine = {
      scanType: 'SAST',
      execute: async () => {
        calls += 1;
        if (calls === 1) return { kind: 'failed', failureCode: 'SAST_INPUT_INVALID', failureMessage: 'bad input' };
        return { kind: 'completed', resultSummary: { findingsTotal: 0 } as never, findings: [] };
      },
    };
    const processor = createScanProcessor({
      store: harness.store, engines: createEngineRegistry([engine]), logger: quiet(), concurrency: 2,
    });
    await processor.drain();
    const statuses = await Promise.all(harness.projectIds.map(async (projectId) => {
      const [scan] = await harness.store.listByProject(projectId);
      return scan?.status;
    }));
    expect(statuses.sort()).toEqual(['COMPLETED', 'FAILED']);
  });
});
