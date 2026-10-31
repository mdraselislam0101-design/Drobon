import { describe, expect, test } from 'vitest';
import { createLogger } from '../src/logger.js';
import { createEngineRegistry, type ScanEngine } from '../src/scans/engines.js';
import { createScanProcessor } from '../src/scans/processor.js';
import { createMemoryScanStore } from '../src/scans/store.js';

describe('scan processor process-local resource bounds', () => {
  test('coalesces concurrent drains and executes cooperative engines one at a time', async () => {
    const store = createMemoryScanStore();
    const projectId = 'prj_00000000-0000-4000-8000-000000000001';
    for (let index = 0; index < 3; index += 1) {
      const created = await store.createScanWithQuota({ ownerId: 'usr_fixture', projectId, scanType: 'SAST', consume: async () => ({ ok: true }) });
      expect(created.outcome).toBe('created');
    }
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    let firstEntered!: () => void;
    const entered = new Promise<void>((resolve) => { firstEntered = resolve; });
    let running = 0;
    let maxRunning = 0;
    let executions = 0;
    const engine: ScanEngine = {
      scanType: 'SAST',
      execute: async () => {
        running += 1;
        maxRunning = Math.max(maxRunning, running);
        executions += 1;
        if (executions === 1) { firstEntered(); await gate; }
        running -= 1;
        return { kind: 'completed', resultSummary: { findingsTotal: 0 }, findings: [] };
      },
    };
    const processor = createScanProcessor({ store, engines: createEngineRegistry([engine]), logger: createLogger({ out: () => undefined }) });
    const first = processor.drain();
    await entered;
    const second = processor.drain();
    const third = processor.drain();
    await new Promise<void>((resolve) => setImmediate(resolve));
    expect(executions).toBe(1);
    expect(maxRunning).toBe(1);
    release();
    await Promise.all([first, second, third]);
    expect(executions).toBe(3);
    expect(maxRunning).toBe(1);
    expect((await store.listByProject(projectId)).every((scan) => scan.status === 'COMPLETED')).toBe(true);
    await processor.drain();
    expect(executions).toBe(3);
  });

  test('shutdown waits for all startup recovery, cancels scheduled kicks and prevents new drains', async () => {
    const base = createMemoryScanStore();
    let entered!: () => void; let release!: () => void;
    const started = new Promise<void>((resolve) => { entered = resolve; });
    const gate = new Promise<void>((resolve) => { release = resolve; });
    let claims = 0;
    const store = { ...base,
      failAllRunning: async (...args: Parameters<typeof base.failAllRunning>) => { entered(); await gate; return base.failAllRunning(...args); },
      claimNextQueued: async () => { claims += 1; return base.claimNextQueued(); },
    };
    const processor = createScanProcessor({ store, engines: createEngineRegistry([]), logger: createLogger({ out: () => undefined }) });
    const starting = processor.start();
    await started;
    processor.kick();
    let shutDown = false;
    const shutdown = processor.shutdown().then(() => { shutDown = true; });
    await new Promise<void>((resolve) => setImmediate(resolve));
    expect(shutDown).toBe(false);
    release();
    await Promise.all([starting, shutdown]);
    await processor.start();
    await processor.drain();
    await new Promise<void>((resolve) => setImmediate(resolve));
    expect(claims).toBe(0);
    expect(processor.started).toBe(false);
  });
});
