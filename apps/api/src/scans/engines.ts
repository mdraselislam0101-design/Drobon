import type { ScanResultSummary, ScanType } from '@drobon/shared';
import type { ScanRecord } from './store.js';

/**
 * The scanner-engine boundary (Pump 7).
 *
 * A {@link ScanEngine} is the ONLY thing that may produce a scan
 * result. The registry is populated exclusively server-side at process
 * composition time (app.ts); nothing client-facing can register,
 * discover or influence engines.
 *
 * PUMP 7 SHIPS ZERO ENGINES — deliberately. `SAST`, `SCA`, `SECRETS`
 * and `DAST` are SUPPORTED job types of the orchestration layer; the
 * engines themselves arrive in later pumps. Until then the processor
 * deterministically fails every scan with `SCAN_ENGINE_NOT_IMPLEMENTED`
 * — it NEVER fabricates findings, never pretends a scan happened, and
 * never touches vulnerability datasets (the dataset lock: no
 * CVE/NVD/GHSA/OSV/KEV/EPSS data, ever, in this repository).
 *
 * Engines are hand-written code in later pumps, NOT dataset loaders.
 */

/** Execution context handed to an engine. */
export interface ScanEngineContext {
  /** Cooperative cancellation — engines SHOULD observe it. */
  signal: AbortSignal;
}

export type EngineOutcome =
  | { kind: 'completed'; resultSummary: ScanResultSummary }
  | { kind: 'failed'; failureCode: 'SCAN_ENGINE_ERROR'; failureMessage: string };

/**
 * One scanner engine for one scan type. `execute` must be side-effect
 * bounded: it receives the durable record and returns a summary; it
 * never mutates job state directly (the processor owns transitions).
 */
export interface ScanEngine {
  readonly scanType: ScanType;
  execute(record: ScanRecord, ctx: ScanEngineContext): Promise<EngineOutcome>;
}

export interface ScanEngineRegistry {
  /** The engine for a type, or `undefined` when none is available. */
  get(scanType: ScanType): ScanEngine | undefined;
  /** Types with an actually-available engine (diagnostics/logging only). */
  availableTypes(): readonly ScanType[];
}

/**
 * Build the server-side engine registry. Duplicate registration for one
 * scan type is a composition error and throws at startup (fail fast).
 */
export function createEngineRegistry(engines: readonly ScanEngine[]): ScanEngineRegistry {
  const byType = new Map<ScanType, ScanEngine>();
  for (const engine of engines) {
    if (byType.has(engine.scanType)) {
      throw new Error(`Duplicate scan engine registered for ${engine.scanType}.`);
    }
    byType.set(engine.scanType, engine);
  }
  return {
    get: (scanType) => byType.get(scanType),
    availableTypes: () => [...byType.keys()],
  };
}
