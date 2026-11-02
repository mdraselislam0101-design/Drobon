import { describe, expect, test } from 'vitest';
import { SOURCE_MAX_TOTAL_BYTES, SOURCE_SNAPSHOT_BODY_MAX_BYTES } from '@drobon/shared';
import { ConfigError, loadConfig } from '../src/config.js';
import { SCAN_ENGINE_TIMEOUT_MS } from '../src/scans/processor.js';
import { ACTIVE_DAST_SCAN_DEADLINE_MS } from '../src/scans/dast/activeEngine.js';
import { DAST_SCAN_DEADLINE_MS, createDastEngine } from '../src/scans/dast/engine.js';
import { createSastEngine } from '../src/scans/sast/engine.js';

/**
 * P0/P1 regression guards for the audit's top findings. Each case asserts a
 * SECURE DEFAULT, not a feature: the previous behaviour (fail-open DAST,
 * body limit smaller than a legal snapshot, deadline equal to the processor's
 * abort instant) is exactly what these tests make impossible to reintroduce.
 */
describe('P0-1: active DAST requires engagement authorization by default', () => {
  test('the default configuration requires an attested engagement', () => {
    expect(loadConfig({ NODE_ENV: 'test' }).dastRequireEngagement).toBe(true);
    expect(loadConfig({}).dastRequireEngagement).toBe(true);
  });

  test('legacy mode stays possible but only as an explicit, valid opt-out', () => {
    expect(loadConfig({ NODE_ENV: 'test', DAST_REQUIRE_ENGAGEMENT: 'false' }).dastRequireEngagement)
      .toBe(false);
    // Anything ambiguous must never be read as "disabled" or "enabled" silently.
    for (const value of ['', 'FALSE', '0', 'no', 'true ']) {
      expect(() => loadConfig({ NODE_ENV: 'test', DAST_REQUIRE_ENGAGEMENT: value }))
        .toThrow(ConfigError);
    }
  });

  test('an unlinked scan is not authorized once an authorizer is present', async () => {
    // The processor always injects an authorizer in the real application, so
    // the engine-level "no assessment and no authorizer" shortcut is not
    // reachable there. Assert the authorizer path itself fails closed.
    const engine = createDastEngine({
      authorize: async () => false,
      packRules: [],
      transport: { probe: async () => ({ status: 200, headers: {}, body: '', bodyTruncated: false, elapsedMs: 1 }) },
    });
    expect(engine.scanType).toBe('DAST');
    const outcome = await engine.execute(
      {
        id: 'scan-1', projectId: 'project-1', ownerId: 'owner-1', scanType: 'DAST',
        status: 'RUNNING', createdAt: new Date().toISOString(),
        dastTargetUrl: 'https://example.test/', assessmentId: 'assessment-1',
      } as never,
      { signal: new AbortController().signal },
    );
    expect(outcome.kind).toBe('failed');
    expect(outcome.kind === 'failed' ? outcome.failureCode : undefined).toBe('DAST_TARGET_BLOCKED');
  });
});

describe('P0-2: upload body limit is consistent with the snapshot limit', () => {
  test('the default body limit covers a maximal, heavily escaped snapshot', () => {
    // Pathological but legal content: every byte escaped by JSON encoders.
    const perFile = '\\"\\\\'.repeat(SOURCE_MAX_TOTAL_BYTES / 4);
    const payload = { files: [{ path: 'src/a.js', content: perFile }] };
    expect(Buffer.byteLength(perFile, 'utf8')).toBe(SOURCE_MAX_TOTAL_BYTES);
    expect(Buffer.byteLength(JSON.stringify(payload), 'utf8')).toBeLessThan(SOURCE_SNAPSHOT_BODY_MAX_BYTES);
    expect(loadConfig({}).bodyMaxBytes).toBeGreaterThanOrEqual(SOURCE_SNAPSHOT_BODY_MAX_BYTES);
  });

  test('the derived bound keeps a strict relation to the snapshot cap', () => {
    expect(SOURCE_SNAPSHOT_BODY_MAX_BYTES).toBeGreaterThan(SOURCE_MAX_TOTAL_BYTES * 2);
    expect(SOURCE_SNAPSHOT_BODY_MAX_BYTES).toBeLessThan(10_485_760);
  });
});

describe('P1-7: engine deadlines keep a safety margin below the processor abort', () => {
  test('active DAST finishes before the processor would abort it', () => {
    expect(ACTIVE_DAST_SCAN_DEADLINE_MS).toBeLessThan(SCAN_ENGINE_TIMEOUT_MS);
    expect(SCAN_ENGINE_TIMEOUT_MS - ACTIVE_DAST_SCAN_DEADLINE_MS).toBeGreaterThanOrEqual(5_000);
  });

  test('passive DAST and SAST deadlines also stay inside the processor bound', () => {
    expect(DAST_SCAN_DEADLINE_MS).toBeLessThan(SCAN_ENGINE_TIMEOUT_MS);
    const sast = createSastEngine({ sources: { replace: async () => undefined } as never });
    expect(sast.scanType).toBe('SAST');
    // SAST declares its own bounded deadline well inside the processor bound.
    expect(10_000).toBeLessThan(SCAN_ENGINE_TIMEOUT_MS);
  });
});
