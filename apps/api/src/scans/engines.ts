import type { DastResult, Finding, ScaResult, ScanFailureCode, ScanResultSummary, ScanType } from '@drobon/shared';
import type { ScanRecord } from './store.js';

/**
 * The scanner-engine boundary (Pump 7; SAST became REAL in Pump 8).
 *
 * A {@link ScanEngine} is the ONLY thing that may produce a scan
 * result. The registry is populated exclusively server-side at process
 * composition time (app.ts); nothing client-facing can register,
 * discover or influence engines.
 *
 * Pumps 8–11 register real engines: SAST (`sast/`), SCA (`sca/`),
 * SECRETS (`secrets/`), and limited passive DAST (`dast/`). Unavailable
 * engine types fail deterministically with `SCAN_ENGINE_NOT_IMPLEMENTED`;
 * the processor NEVER fabricates findings or pretends a scan happened.
 * No scanner loads vulnerability datasets (the dataset lock: no
 * CVE/NVD/GHSA/OSV/KEV/EPSS data, ever, in this repository).
 *
 * Engines are hand-written code, NOT dataset loaders.
 */

/** Execution context handed to an engine. */
export interface ScanEngineContext {
  /** Cooperative cancellation — engines SHOULD observe it. */
  signal: AbortSignal;
}

/**
 * A completed outcome carries the summary AND the real findings the
 * engine produced (bounded by MAX_FINDINGS_PER_SCAN; the processor
 * persists them with the terminal transition). A failed outcome uses a
 * closed-vocabulary failure code with a safe, bounded message.
 */
export type EngineOutcome =
  | {
      kind: 'completed';
      resultSummary: ScanResultSummary;
      /** Real findings (SAST, Pump 8) — bounded, persisted atomically. */
      findings?: Finding[];
      /**
       * The SCA payload (Pump 9): inventory, manifest results, SBOM
       * and the honest assessment. Persisted atomically with the
       * terminal transition — COMPLETED SCA scans only.
       */
      sca?: ScaResult;
      /** Bounded observed HTTP responses for DAST only. */
      dast?: DastResult;
    }
  | { kind: 'failed'; failureCode: ScanFailureCode; failureMessage: string }
  | { kind: 'timed-out'; failureCode: ScanFailureCode; failureMessage: string };

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
