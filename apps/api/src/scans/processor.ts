import type { Logger } from '../logger.js';
import type { EngineOutcome, ScanEngineRegistry } from './engines.js';
import type { ScanRecord, ScanStore } from './store.js';

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
 * Lifecycle (Agent cancellation is a durable intent; it never creates a
 * fabricated completed scan):
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
  /** Signal the one owned in-process agent attempt after cancellation commits. */
  abortAgentJob(scanId: string): void;
  /**
   * Signal an in-flight attempt for ANY scan type. The durable cancellation
   * intent is written by the store first; this only stops the work, and the
   * terminal transition becomes FAILED/`SCAN_CANCELLED` because of that intent.
   */
  cancelScan(scanId: string): void;
  /** Signal only attempts bound to the exact withdrawn authorization. */
  abortAgentEngagement(ownerId: string, projectId: string, assessmentId: string, engagementId: string): void;
  /** Stop the periodic sweep (in-flight work still settles). */
  stop(): void;
  /** Permanently stop scheduling and wait for owned startup/drain writes to settle. */
  shutdown(): Promise<void>;
  /** Whether `start` has been called. */
  readonly started: boolean;
}

export interface ScanProcessorOptions {
  store: ScanStore;
  engines: ScanEngineRegistry;
  logger: Logger;
  /** Periodic sweep interval (default 5s; injectable for tests). */
  intervalMs?: number;
  /** Serialize Agent completion with its exact engagement's withdrawal. */
  finalizeAgent?: (scan: ScanRecord, complete: () => Promise<ScanRecord | undefined>) => Promise<ScanRecord | undefined>;
  /** Total attempts per scan (1 disables retry). Default 2. */
  maxAttempts?: number;
  /** Base backoff for attempt N: base * 2^(N-1). Default 5s. */
  retryBaseDelayMs?: number;
  /** Clock for the backoff instant (tests). */
  now?: () => number;
  /**
   * How many scans one drain may execute at the same time (P1-9).
   *
   * Default 1 — the historical, fully serialized behaviour. Values above 1
   * run independent scans in parallel lanes; the durable store still serializes
   * every state transition, so a claim can never hand the same scan to two
   * lanes, and cancellation/shutdown semantics are unchanged.
   */
  concurrency?: number;
}

/**
 * Which failure codes are worth another attempt.
 *
 * Only a transient ENGINE crash qualifies: the process failed to run the
 * scanner, so a second run can plausibly succeed. Everything else is a
 * deterministic statement about the input, the configured target, the limits
 * or a deadline — retrying those would burn quota to reproduce the same answer.
 */
export function isRetryableFailure(code: string | undefined): boolean {
  return code === 'SCAN_ENGINE_ERROR';
}

/**
 * Hard per-engine bound enforced by the processor. Every engine's OWN deadline
 * must be strictly smaller than this so it can return a deterministic
 * `*_TIMEOUT` outcome instead of being aborted mid-flight (see
 * `test/engineDeadlineMargin.test.ts`).
 */
export const SCAN_ENGINE_TIMEOUT_MS = 30_000;

/** Safety bound: one drain call never spins forever. */
const MAX_DRAIN_ITERATIONS = 1000;

/** Upper bound for parallel scan lanes in one drain (operator-tunable below it). */
export const MAX_SCAN_CONCURRENCY = 8;

export function createScanProcessor(options: ScanProcessorOptions): ScanProcessor {
  const maxAttempts = Math.min(5, Math.max(1, options.maxAttempts ?? 2));
  const retryBaseDelayMs = Math.max(100, options.retryBaseDelayMs ?? 5_000);
  const clock = options.now ?? (() => Date.now());
  // Lanes are a throughput knob, never an unbounded fan-out.
  const concurrency = Math.min(MAX_SCAN_CONCURRENCY, Math.max(1, options.concurrency ?? 1));

  /**
   * Requeue a failed attempt with exponential backoff, or answer `false` when
   * the scan must stay FAILED (attempts exhausted / non-retryable outcome).
   */
  const scheduleRetry = async (scan: ScanRecord, failureCode: string | undefined): Promise<boolean> => {
    // Agent jobs are never retried: their authorization, engagement and
    // Dataset/source digests were checked for THIS attempt. A withdrawn or
    // expired authorization must fail closed, not re-run later.
    if (scan.agent !== undefined) return false;
    // Never re-queue while shutting down: the runtime is releasing its lease.
    if (closed) return false;
    if (!isRetryableFailure(failureCode)) return false;
    const attempt = scan.attempt ?? 1;
    if (attempt >= maxAttempts) return false;
    const delay = retryBaseDelayMs * 2 ** (attempt - 1);
    const retryAt = new Date(clock() + delay).toISOString();
    const requeued = await store.requeueScan(scan.id, retryAt);
    if (requeued === undefined) return false;
    logger.warn('Scan requeued for retry', {
      scanId: requeued.id, projectId: requeued.projectId, attempt: requeued.attempt, retryAt,
    });
    return true;
  };
  const { store, engines, logger } = options;
  const intervalMs = options.intervalMs ?? 5000;
  let started = false;
  let closed = false;
  let generation = 0;
  let starting: Promise<void> | undefined;
  const pendingStarts = new Set<Promise<void>>();
  let timer: ReturnType<typeof setInterval> | undefined;
  let kickTimer: ReturnType<typeof setTimeout> | undefined;
  // A sweep, startup and concurrent kicks must share one drain. Without
  // this guard different queued scans could execute concurrently without a
  // process-wide bound, despite each individual claim being serialized.
  let activeDrain: Promise<void> | undefined;
  let drainAgain = false;
  const activeAgents = new Map<string, { scan: ScanRecord; controller: AbortController }>();

  const processOne = async (): Promise<boolean> => {
    const scan = await store.claimNextQueued();
    if (scan === undefined) {
      return false;
    }
    // Shutdown may have committed while an injected or durable claim was
    // awaiting I/O. Do not start the engine after that boundary; record a
    // recoverable interruption rather than leaving the claimed job running.
    if (closed) {
      await store.failScan(scan.id, 'SCAN_INTERRUPTED', 'Processing stopped before the scan could start.');
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
    // Register immediately after claim, before any asynchronous recheck, so a
    // cancellation that lands during the recheck can still signal this attempt.
    activeAgents.set(scan.id, { scan, controller });
    // Defensive per-engine bound (mirrors the Pump 1 runner's timeout
    // posture): a hung engine fails the scan deterministically instead
    // of blocking the sweep. The attempt may still be running in the
    // background — the durable store already moved on, exactly like the
    // worker runner's documented at-most-once caveat.
    const engineTimeoutMs = SCAN_ENGINE_TIMEOUT_MS;
    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; controller.abort(); }, engineTimeoutMs);
    timer.unref?.();
    try {
      if (scan.agent === undefined) {
        // A user cancellation can commit between claim and registration.
        const latest = await store.findByProjectAndId(scan.projectId, scan.id);
        if (latest === undefined || latest.cancelRequestedAt !== undefined || controller.signal.aborted) {
          await store.failScan(scan.id, closed ? 'SCAN_INTERRUPTED' : 'SCAN_ENGINE_ERROR',
            'The scan was cancelled before it started.');
          return true;
        }
      }
      if (scan.agent !== undefined) {
        // Cancellation can commit between claim and controller registration.
        // Reread the durable intent before invoking any scanner.
        const latest = await store.findByProjectAndId(scan.projectId, scan.id);
        if (latest?.agent === undefined || latest.agent.cancelRequestedAt !== undefined || controller.signal.aborted) {
          await store.failScan(scan.id, closed ? 'SCAN_INTERRUPTED' : 'SCAN_ENGINE_ERROR', closed
            ? 'Agent processing stopped before completion.' : 'Agent execution was cancelled or its authorization was withdrawn.');
          return true;
        }
      }
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
        if (controller.signal.aborted && scan.agent !== undefined) {
          await store.failScan(scan.id, closed ? 'SCAN_INTERRUPTED' : 'SCAN_ENGINE_ERROR', closed
            ? 'Agent processing stopped before completion.' : 'Agent execution was cancelled or its authorization was withdrawn.');
          return true;
        }
        throw error;
      }
      if (outcome.kind === 'completed') {
        // A cancellation that landed while the engine was finishing wins: the
        // owner asked to stop, so the run must not be presented as a result.
        const latest = scan.agent === undefined
          ? await store.findByProjectAndId(scan.projectId, scan.id)
          : undefined;
        if (latest?.cancelRequestedAt !== undefined) {
          await store.failScan(scan.id, 'SCAN_ENGINE_ERROR', 'The scan was cancelled on request.');
          return true;
        }
        // Pump 8: real findings (when the engine produced any) persist
        // atomically with the terminal transition. Pump 9: the SCA
        // payload (inventory + manifest results + SBOM + assessment)
        // persists the same way — one linearized terminal write.
        const complete = (): Promise<ScanRecord | undefined> => store.completeScan(
          scan.id, outcome.resultSummary, outcome.findings, outcome.sca, outcome.dast,
        );
        // A withdrawal and result commit share the assessment mutation
        // lock. Cancellation additionally races in the scan-store queue.
        const completed = scan.agent === undefined ? await complete()
          : options.finalizeAgent === undefined ? undefined : await options.finalizeAgent(scan, complete);
        if (completed === undefined) {
          // FAIL CLOSED (Pump 3): the durable store rejected the engine
          // outcome (it failed the shared closed-shape/invariant
          // guards). A scan must NEVER strand in RUNNING — claim the
          // deterministic terminal FAILED state so the lifecycle always
          // ends, whatever an engine produced.
          logger.error('Scan finalize failed after completion', { scanId: scan.id });
          const recovered = await store.failScan(
            scan.id,
            'SCAN_ENGINE_ERROR',
            'The scan result could not be recorded safely.',
          );
          if (recovered === undefined) {
            logger.error('Scan recovery after rejected completion did not apply', {
              scanId: scan.id,
            });
          }
          return true;
        }
        logger.info('Scan completed', {
          scanId: completed.id,
          projectId: completed.projectId,
          findingsTotal: completed.resultSummary?.findingsTotal,
        });
        return true;
      }
      if (outcome.kind === 'timed-out') {
        const timedOut = await store.timeoutScan(scan.id, outcome.failureCode, outcome.failureMessage);
        if (timedOut === undefined) {
          // FAIL CLOSED (Pump 3): the store refused the timeout
          // transition (e.g. a non-DAST scan type claimed a DAST
          // timeout code). Never leave the scan stranded in RUNNING.
          logger.error('Scan finalize failed after engine timeout outcome', {
            scanId: scan.id,
          });
          const recovered = await store.failScan(
            scan.id,
            'SCAN_ENGINE_ERROR',
            'The scan timeout could not be recorded safely.',
          );
          if (recovered === undefined) {
            logger.error('Scan recovery after rejected timeout did not apply', {
              scanId: scan.id,
            });
          }
          return true;
        }
        logger.info('Scan timed out', {
          scanId: timedOut.id,
          projectId: timedOut.projectId,
          failureCode: timedOut.failureCode,
        });
        return true;
      }
      // Transient engine crash: requeue with backoff instead of a terminal
      // failure, so a flaky scanner does not consume the user's scan.
      if (await scheduleRetry(scan, outcome.failureCode)) return true;
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
      // A cancellation is never retried; a crash is.
      const latest = await store.findByProjectAndId(scan.projectId, scan.id);
      if (latest?.cancelRequestedAt === undefined && await scheduleRetry(scan, 'SCAN_ENGINE_ERROR')) {
        return true;
      }
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
      activeAgents.delete(scan.id);
      controller.abort();
    }
  };

  const drain = (): Promise<void> => {
    if (closed) return Promise.resolve();
    if (activeDrain !== undefined) {
      // A job can arrive while the current drain is checking for an empty
      // queue. Remember the request instead of starting a parallel engine.
      drainAgain = true;
      return activeDrain;
    }
    activeDrain = (async () => {
      let processed = 0;
      try {
        do {
          drainAgain = false;
          // Concurrency lanes: each lane independently claims the next queued
          // scan. Claiming is a serialized store transition, so a scan is
          // still executed at most once — two lanes can never get the same
          // record, they only move to the next one when a lane finds work.
          await Promise.all(Array.from({ length: concurrency }, async () => {
            while (!closed && processed < MAX_DRAIN_ITERATIONS) {
              if (!(await processOne())) break;
              processed += 1;
            }
          }));
          if (processed >= MAX_DRAIN_ITERATIONS) {
            logger.error('Scan processor drain hit its iteration bound');
            return;
          }
        } while (drainAgain);
      } finally {
        // Clear before resolving the promise, so a request arriving at the
        // completion boundary starts a fresh drain rather than being lost.
        activeDrain = undefined;
        drainAgain = false;
      }
    })();
    return activeDrain;
  };

  const stop = (): void => {
    started = false;
    generation += 1;
    if (timer !== undefined) { clearInterval(timer); timer = undefined; }
    if (kickTimer !== undefined) { clearTimeout(kickTimer); kickTimer = undefined; }
  };

  return {
    start: () => {
      if (closed) return Promise.resolve();
      if (started) return starting ?? Promise.resolve();
      started = true;
      const current = ++generation;
      const startup = (async () => {
        // Recovery must settle before a runtime lease can be released.
        const recovered = await store.failAllRunning(
          'SCAN_INTERRUPTED',
          'Processing was interrupted before the scan could finish.',
        );
        if (!started || closed || generation !== current) return;
        if (recovered > 0) logger.info('Scan processor recovered interrupted scans', { count: recovered });
        await drain();
        if (!started || closed || generation !== current) return;
        timer = setInterval(() => {
          void drain().catch((error: unknown) => {
            logger.error('Scan processor sweep failed', { err: error });
          });
        }, intervalMs);
        timer.unref?.();
      })();
      starting = startup;
      pendingStarts.add(startup);
      void startup.then(
        () => { pendingStarts.delete(startup); if (starting === startup) starting = undefined; },
        () => { pendingStarts.delete(startup); if (starting === startup) { starting = undefined; if (generation === current) started = false; } },
      );
      return startup;
    },
    drain,
    abortAgentJob: (scanId) => { activeAgents.get(scanId)?.controller.abort(); },
    cancelScan: (scanId) => { activeAgents.get(scanId)?.controller.abort(); },
    abortAgentEngagement: (ownerId, projectId, assessmentId, engagementId) => {
      for (const { scan, controller } of activeAgents.values()) {
        if (scan.ownerId === ownerId && scan.projectId === projectId && scan.assessmentId === assessmentId &&
            scan.agent?.engagementId === engagementId) controller.abort();
      }
    },
    kick: () => {
      if (!started || closed || kickTimer !== undefined) return;
      const current = generation;
      kickTimer = setTimeout(() => {
        kickTimer = undefined;
        if (!started || closed || generation !== current) return;
        void drain().catch((error: unknown) => {
          logger.error('Scan processor kick failed', { err: error });
        });
      }, 0);
      kickTimer.unref?.();
    },
    stop,
    shutdown: async () => {
      closed = true;
      stop();
      // Signal owned Agent attempts immediately, before waiting for drain.
      // A cooperative network transport closes; a transport/CPU loop that
      // ignores the signal can still outlive the processor and cannot have
      // already-sent requests recalled.
      //
      // Normal scans are deliberately NOT aborted here: shutdown waits for the
      // active drain to settle, and a scan that finishes in that window should
      // record its real result. A hard kill is covered by startup recovery
      // (RUNNING → FAILED/SCAN_INTERRUPTED).
      for (const { scan, controller } of activeAgents.values()) {
        if (scan.agent !== undefined) controller.abort();
      }
      // Both promises may fail; either way they have settled before the
      // runtime releases its lease. Engine code that ignores abort can
      // still outlive its timeout and is not covered by this guarantee.
      await Promise.allSettled([...pendingStarts]);
      if (activeDrain !== undefined) await activeDrain.catch(() => undefined);
    },
    get started(): boolean {
      return started;
    },
  };
}
