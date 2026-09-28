import type { Logger } from '../logger.js';
import type { EngineOutcome, ScanEngineRegistry } from './engines.js';
import type { ScanStore } from './store.js';

/**
 * The scan processor (Pump 7) — the durable worker loop of the scan
 * orchestration foundation.
 *
 * The durable {@link ScanStore} IS the queue: claiming is a serialized
 * QUEUED→RUNNING transition, so a job can be executed at most once per
 * lifecycle and duplicate delivery is structurally impossible
 * (RUNNING/COMPLETED/FAILED scans are never claimable again). This
 * complements the Pump 1 worker package (`apps/worker` — in-memory
 * runner/queue/retry, unchanged and still the future out-of-process
 * engine host): scan state must survive restarts, so the durable store
 * drives processing here.
 *
 * Lifecycle (the ONLY transition path — there is no client-facing
 * mutation endpoint):
 *
 *   QUEUED → RUNNING → COMPLETED   (engine produced a real summary)
 *   QUEUED → RUNNING → FAILED      (deterministic failure, incl.
 *                                   SCAN_ENGINE_NOT_IMPLEMENTED)
 *   RUNNING → FAILED               (startup recovery: SCAN_INTERRUPTED)
 *
 * Startup recovery (`start`): every RUNNING scan — a crash interrupted
 * it — deterministically becomes FAILED/SCAN_INTERRUPTED, then all
 * QUEUED scans drain. The process NEVER boots with an ambiguous scan.
 */

export interface ScanProcessor {
  /**
   * Begin processing: recover interrupted scans, drain the queue, start
   * the periodic sweep. Idempotent. Called once by the server runtime
   * (NOT by tests, which drive {@link ScanProcessor.drain} explicitly
   * for determinism).
   */
  start(): Promise<void>;
  /**
   * Process queued scans until none remain (bounded per call). Exposed
   * for deterministic tests and startup recovery.
   */
  drain(): Promise<void>;
  /** Schedule an async drain without awaiting (used after creation). */
  kick(): void;
  /** Stop the periodic sweep (in-flight work still settles). */
  stop(): void;
  /** Whether `start` has been called. */
  readonly started: boolean;
}

export interface ScanProcessorOptions {
  store: ScanStore;
  engines: ScanEngineRegistry;
  logger: Logger;
  /** Periodic sweep interval (default 5s; injectable for tests). */
  intervalMs?: number;
}

/** Safety bound: one drain call never spins forever. */
const MAX_DRAIN_ITERATIONS = 1000;

export function createScanProcessor(options: ScanProcessorOptions): ScanProcessor {
  const { store, engines, logger } = options;
  const intervalMs = options.intervalMs ?? 5000;
  let started = false;
  let timer: ReturnType<typeof setInterval> | undefined;
  let kicking = false;

  const processOne = async (): Promise<boolean> => {
    const scan = await store.claimNextQueued();
    if (scan === undefined) {
      return false;
    }
    const engine = engines.get(scan.scanType);
    if (engine === undefined) {
      // The honest Pump 7 state for every scan type: the orchestration
      // layer supports the job type, but no real scanner engine exists
      // yet. Deterministic failure — NEVER a fabricated completion.
      const failed = await store.failScan(
        scan.id,
        'SCAN_ENGINE_NOT_IMPLEMENTED',
        `The ${scan.scanType} scanner engine is not implemented yet.`,
      );
      if (failed === undefined) {
        logger.error('Scan finalize failed after engine-unavailable', { scanId: scan.id });
        return true;
      }
      logger.info('Scan failed', {
        scanId: failed.id,
        projectId: failed.projectId,
        failureCode: failed.failureCode,
      });
      return true;
    }
    const controller = new AbortController();
    // Defensive per-engine bound (mirrors the Pump 1 runner's timeout
    // posture): a hung engine fails the scan deterministically instead
    // of blocking the sweep. The attempt may still be running in the
    // background — the durable store already moved on, exactly like the
    // worker runner's documented at-most-once caveat.
    const engineTimeoutMs = 30_000;
    const timer = setTimeout(() => controller.abort(), engineTimeoutMs);
    timer.unref?.();
    let timedOut = false;
    controller.signal.addEventListener('abort', () => {
      timedOut = true;
    }, { once: true });
    try {
      let outcome: EngineOutcome;
      try {
        outcome = await Promise.race([
          engine.execute(scan, { signal: controller.signal }),
          new Promise<never>((_resolve, reject) => {
            if (controller.signal.aborted) {
              reject(new Error('Engine attempt aborted.'));
              return;
            }
            controller.signal.addEventListener(
              'abort',
              () => {
                reject(new Error('Engine attempt aborted.'));
              },
              { once: true },
            );
          }),
        ]);
      } catch (error: unknown) {
        if (timedOut) {
          const failed = await store.failScan(
            scan.id,
            'SCAN_ENGINE_ERROR',
            'The scanner engine timed out.',
          );
          if (failed === undefined) {
            logger.error('Scan finalize failed after engine timeout', { scanId: scan.id });
            return true;
          }
          logger.info('Scan failed', {
            scanId: failed.id,
            projectId: failed.projectId,
            failureCode: failed.failureCode,
          });
          return true;
        }
        throw error;
      }
      if (outcome.kind === 'completed') {
        // Pump 8: real findings (when the engine produced any) persist
        // atomically with the terminal transition. Pump 9: the SCA
        // payload (inventory + manifest results + SBOM + assessment)
        // persists the same way — one linearized terminal write.
        const completed = await store.completeScan(
          scan.id,
          outcome.resultSummary,
          outcome.findings,
          outcome.sca,
        );
        if (completed === undefined) {
          logger.error('Scan finalize failed after completion', { scanId: scan.id });
          return true;
        }
        logger.info('Scan completed', {
          scanId: completed.id,
          projectId: completed.projectId,
          findingsTotal: completed.resultSummary?.findingsTotal,
        });
        return true;
      }
      const failed = await store.failScan(scan.id, outcome.failureCode, outcome.failureMessage);
      if (failed === undefined) {
        logger.error('Scan finalize failed after engine failure', { scanId: scan.id });
        return true;
      }
      logger.info('Scan failed', {
        scanId: failed.id,
        projectId: failed.projectId,
        failureCode: failed.failureCode,
      });
      return true;
    } catch (error: unknown) {
      // An engine crash must never hang a scan in RUNNING and never
      // leak internals: bounded, generic, closed-vocabulary failure.
      void error;
      const failed = await store.failScan(
        scan.id,
        'SCAN_ENGINE_ERROR',
        'The scanner engine failed to run.',
      );
      if (failed === undefined) {
        logger.error('Scan finalize failed after engine crash', { scanId: scan.id });
        return true;
      }
      logger.info('Scan failed', {
        scanId: failed.id,
        projectId: failed.projectId,
        failureCode: failed.failureCode,
      });
      return true;
    } finally {
      clearTimeout(timer);
      controller.abort();
    }
  };

  const drain = async (): Promise<void> => {
    for (let index = 0; index < MAX_DRAIN_ITERATIONS; index += 1) {
      const progressed = await processOne();
      if (!progressed) {
        return;
      }
    }
    logger.error('Scan processor drain hit its iteration bound');
  };

  return {
    start: async () => {
      if (started) {
        return;
      }
      started = true;
      // Recover first: a RUNNING scan at boot was interrupted by the
      // restart — deterministically FAILED, never resurrected, never
      // executed twice (COMPLETED/FAILED → RUNNING does not exist).
      const recovered = await store.failAllRunning(
        'SCAN_INTERRUPTED',
        'Processing was interrupted before the scan could finish.',
      );
      if (recovered > 0) {
        logger.info('Scan processor recovered interrupted scans', { count: recovered });
      }
      await drain();
      timer = setInterval(() => {
        void drain().catch((error: unknown) => {
          logger.error('Scan processor sweep failed', { err: error });
        });
      }, intervalMs);
      timer.unref?.();
    },
    drain,
    kick: () => {
      if (!started || kicking) {
        return;
      }
      kicking = true;
      setTimeout(() => {
        kicking = false;
        void drain().catch((error: unknown) => {
          logger.error('Scan processor kick failed', { err: error });
        });
      }, 0).unref?.();
    },
    stop: () => {
      if (timer !== undefined) {
        clearInterval(timer);
        timer = undefined;
      }
      started = false;
    },
    get started(): boolean {
      return started;
    },
  };
}
