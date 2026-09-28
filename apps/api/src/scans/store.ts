import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { randomBytes, randomUUID } from 'node:crypto';
import {
  IDEMPOTENCY_KEY_PATTERN,
  MAX_FINDINGS_PER_SCAN,
  PROJECT_ID_PATTERN,
  SCAN_ID_PATTERN,
  isFinding,
  isScanFailureCode,
  isScanResultSummary,
  isScanStatus,
  isScanType,
  type Finding,
  compareFindings,
  isScaResult,
  type Scan,
  type ScanDetail,
  type ScanFailureCode,
  type ScanResultSummary,
  type ScanType,
  type ScaResult,
} from '@drobon/shared';

/**
 * Durable scan-job store (Pump 7) — the minimum persistence boundary for
 * the secure scan orchestration foundation, following the exact
 * architecture of the account (Pump 2), usage (Pump 5) and project
 * (Pump 6) stores:
 *
 * - one JSON document (`{ version: 1, scans: [...], idempotency: [...] }`),
 *   one writer, isolated behind the `ScanStore` interface so the future
 *   database phase swaps this module with zero changes elsewhere;
 * - scans survive process restarts (loaded at startup, fail fast on a
 *   corrupt document or an invalid record — security state is never
 *   silently repaired);
 * - writes are atomic (temp file + rename in the same directory, mode
 *   0600), so a crash mid-write cannot tear the store;
 * - every mutation runs inside the serialized in-process queue and
 *   persists BEFORE it is observable;
 * - ids are `scan_` + `crypto.randomUUID()` — cryptographically strong,
 *   never counters, never client-supplied.
 *
 * THE ATOMIC CREATION OPERATION ({@link ScanStore.createScanWithQuota}):
 * quota consumption and job creation are ONE linearized operation —
 * idempotency lookup, quota consumption (via the Pump 5 UsageService,
 * the single quota authority) and the durable append all run inside the
 * same serialized section, then persist once. Concurrent or replayed
 * requests therefore cannot create a scan without consuming quota, and
 * cannot consume twice for one logical request. The only possible
 * failure direction is fail-closed: a crash between consumption and
 * persistence can lose a paid slot, NEVER grant a free scan.
 *
 * Honest limits: single-process/single-writer, foundation-scale data.
 * That is the documented pre-database posture of this repository.
 */

/** The stored record — includes the owner; the API response never does. */
export interface ScanRecord {
  id: string;
  ownerId: string;
  projectId: string;
  scanType: ScanType;
  status: 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED';
  createdAt: string;
  updatedAt: string;
  startedAt?: string;
  completedAt?: string;
  failureCode?: ScanFailureCode;
  failureMessage?: string;
  resultSummary?: ScanResultSummary;
  /**
   * The engine's real findings (Pump 8) — COMPLETED scans only, bounded
   * by MAX_FINDINGS_PER_SCAN, persisted with the terminal transition.
   * Present only when the engine actually produced findings.
   */
  findings?: Finding[];
  /**
   * The SCA payload (Pump 9) — COMPLETED SCA scans only, validated by
   * the shared closed-shape guard, persisted with the terminal
   * transition. Inventory + manifest results + SBOM + assessment.
   */
  sca?: ScaResult;
}

/**
 * One remembered idempotency key: (accountId, key) → the scan it
 * created, with the request fingerprint (projectId + scanType) so a
 * reused key with a DIFFERENT request is a conflict, not a silent
 * replay of an unrelated scan.
 */
export interface IdempotencyEntry {
  accountId: string;
  key: string;
  projectId: string;
  scanType: ScanType;
  scanId: string;
  createdAt: string;
}

/** Quota verdict relayed from the UsageService callback. */
export interface QuotaDenied {
  ok: false;
  retryAfterSec: number;
}

export interface QuotaGranted {
  ok: true;
}

export type QuotaOutcome = QuotaGranted | QuotaDenied;

export interface CreateScanInput {
  ownerId: string;
  projectId: string;
  scanType: ScanType;
  /**
   * Optional idempotency key (already format-validated by the route).
   * Scoped to (ownerId, key) inside the store — cross-account key
   * reuse is impossible by construction.
   */
  idempotencyKey?: string;
  /**
   * The single quota authority call (UsageService.consumeScan). Runs
   * INSIDE the serialized creation section so check-then-create cannot
   * interleave. Must be awaited to completion before any append.
   */
  consume: () => Promise<QuotaOutcome>;
}

export type CreateScanOutcome =
  | { outcome: 'created'; scan: ScanRecord }
  | { outcome: 'replayed'; scan: ScanRecord }
  | { outcome: 'conflict' }
  | { outcome: 'quota-denied'; retryAfterSec: number };

export interface ScanStore {
  /**
   * THE atomic creation operation (see the module doc). Linearizes
   * idempotency, quota consumption and the durable append.
   */
  createScanWithQuota(input: CreateScanInput): Promise<CreateScanOutcome>;
  /**
   * All scans of one project, deterministically ordered:
   * `createdAt` DESC, then `id` ASC (the shared documented contract).
   */
  listByProject(projectId: string): Promise<ScanRecord[]>;
  /** One scan of one project (ownership is resolved by the caller). */
  findByProjectAndId(projectId: string, scanId: string): Promise<ScanRecord | undefined>;
  /**
   * Claim the oldest QUEUED scan for processing: QUEUED → RUNNING with
   * `startedAt`, persisted before it is observable. Returns `undefined`
   * when nothing is claimable. A scan can be claimed EXACTLY ONCE per
   * lifecycle — RUNNING/COMPLETED/FAILED scans are never returned, so
   * duplicate worker delivery cannot execute a job twice.
   */
  claimNextQueued(): Promise<ScanRecord | undefined>;
  /**
   * RUNNING → COMPLETED with the engine-produced summary and its real
   * findings (Pump 8: bounded, validated, persisted atomically with the
   * terminal transition). Returns `undefined` when the scan is missing
   * or not RUNNING (a terminal scan can never be re-finalized —
   * COMPLETED → RUNNING does not exist).
   */
  completeScan(
    id: string,
    resultSummary: ScanResultSummary,
    findings?: Finding[],
    sca?: ScaResult,
  ): Promise<ScanRecord | undefined>;
  /**
   * RUNNING → FAILED with a closed-vocabulary failure code and a safe,
   * bounded message. Same single-transition guard as
   * {@link completeScan}.
   */
  failScan(
    id: string,
    failureCode: ScanFailureCode,
    failureMessage: string,
  ): Promise<ScanRecord | undefined>;
  /**
   * Startup recovery: every RUNNING scan (a crash interrupted it)
   * deterministically → FAILED with `SCAN_INTERRUPTED`. Persisted before
   * the process serves traffic. Returns the recovered count.
   */
  failAllRunning(failureCode: ScanFailureCode, failureMessage: string): Promise<number>;
}

interface StoreDocument {
  version: 1;
  scans: ScanRecord[];
  idempotency: IdempotencyEntry[];
}

/** Bounded per-account idempotency memory (oldest evicted first). */
const IDEMPOTENCY_ENTRIES_PER_ACCOUNT = 20;

/** Safe stored text: bounded, no control characters (server-authored). */
function isSafeScanText(value: unknown, maxLength: number): value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > maxLength) {
    return false;
  }
  for (const char of value) {
    const code = char.codePointAt(0) ?? 0;
    if (code < 0x20 || code === 0x7f) {
      return false;
    }
  }
  return true;
}

const SCAN_FAILURE_MESSAGE_MAX_LENGTH = 200;

/**
 * Fail-fast record validation — mirrors the server-side state machine
 * EXACTLY (see the shared `isScan` invariants): the store must always
 * accept back what the API legitimately wrote, and must refuse to boot
 * on anything else (a mismatch would brick startup after a legitimate
 * write — that exact class of bug was found and fixed in Pump 6).
 */
function parseStoredScan(value: unknown): ScanRecord | undefined {
  if (typeof value !== 'object' || value === null) {
    return undefined;
  }
  const record = value as Record<string, unknown>;
  const status = record['status'];
  if (
    typeof record['id'] !== 'string' ||
    !SCAN_ID_PATTERN.test(record['id']) ||
    typeof record['ownerId'] !== 'string' ||
    record['ownerId'].length === 0 ||
    typeof record['projectId'] !== 'string' ||
    !PROJECT_ID_PATTERN.test(record['projectId']) ||
    !isScanType(record['scanType']) ||
    !isScanStatus(status) ||
    typeof record['createdAt'] !== 'string' ||
    Number.isNaN(Date.parse(record['createdAt'])) ||
    typeof record['updatedAt'] !== 'string' ||
    Number.isNaN(Date.parse(record['updatedAt']))
  ) {
    return undefined;
  }
  if (record['startedAt'] !== undefined && typeof record['startedAt'] !== 'string') {
    return undefined;
  }
  if (record['completedAt'] !== undefined && typeof record['completedAt'] !== 'string') {
    return undefined;
  }
  if (record['failureCode'] !== undefined && !isScanFailureCode(record['failureCode'])) {
    return undefined;
  }
  if (
    record['failureMessage'] !== undefined &&
    !isSafeScanText(record['failureMessage'], SCAN_FAILURE_MESSAGE_MAX_LENGTH)
  ) {
    return undefined;
  }
  if (record['resultSummary'] !== undefined && !isScanResultSummary(record['resultSummary'])) {
    return undefined;
  }
  // Findings (Pump 8): COMPLETED scans only, bounded, individually
  // guarded, and each finding must belong to THIS scan (a cross-scan
  // finding would mean corrupted or transplanted state — refuse).
  if (record['findings'] !== undefined) {
    if (!Array.isArray(record['findings']) || record['findings'].length > MAX_FINDINGS_PER_SCAN) {
      return undefined;
    }
    if (!record['findings'].every((finding) => isFinding(finding))) {
      return undefined;
    }
    const scanId = record['id'];
    if (!record['findings'].every((finding) => finding.scanId === scanId)) {
      return undefined;
    }
    // The summary must agree with the persisted findings.
    const summary = record['resultSummary'];
    if (
      summary === undefined ||
      summary.findingsTotal !== record['findings'].length
    ) {
      return undefined;
    }
  }
  // State-machine invariants (identical to the shared isScan guard).
  const hasStartedAt = record['startedAt'] !== undefined;
  const hasCompletedAt = record['completedAt'] !== undefined;
  const hasFailureCode = record['failureCode'] !== undefined;
  const hasFailureMessage = record['failureMessage'] !== undefined;
  const hasResult = record['resultSummary'] !== undefined;
  const hasFindings = record['findings'] !== undefined;
  if (status === 'QUEUED') {
    if (hasStartedAt || hasCompletedAt || hasFailureCode || hasFailureMessage || hasResult) {
      return undefined;
    }
  } else {
    if (!hasStartedAt) {
      return undefined;
    }
    if (status === 'RUNNING') {
      if (hasCompletedAt || hasFailureCode || hasFailureMessage || hasResult) {
        return undefined;
      }
    } else {
      if (!hasCompletedAt) {
        return undefined;
      }
      if (status === 'COMPLETED') {
        if (!hasResult || hasFailureCode || hasFailureMessage) {
          return undefined;
        }
      } else if (!hasFailureCode || hasResult) {
        return undefined;
      }
    }
  }
  // Findings exist ONLY on COMPLETED scans (the engine produces them;
  // QUEUED/RUNNING/FAILED scans can never carry findings).
  if (hasFindings && status !== 'COMPLETED') {
    return undefined;
  }
  // SCA payload (Pump 9): closed-shape + bounded + cross-field-checked
  // by the shared guard, and it exists ONLY on COMPLETED SCA scans —
  // a payload on any other record (SAST scan, non-terminal state) is
  // corruption or a transplant attempt and refuses to boot.
  if (record['sca'] !== undefined) {
    if (!isScaResult(record['sca'])) {
      return undefined;
    }
    if (status !== 'COMPLETED' || record['scanType'] !== 'SCA') {
      return undefined;
    }
  }
  // Rebuild explicitly from the validated fields (no casts — the
  // optional fields exist exactly when the state machine allows).
  const built: ScanRecord = {
    id: record['id'],
    ownerId: record['ownerId'],
    projectId: record['projectId'],
    scanType: record['scanType'],
    status,
    createdAt: record['createdAt'],
    updatedAt: record['updatedAt'],
  };
  if (typeof record['startedAt'] === 'string') {
    built.startedAt = record['startedAt'];
  }
  if (typeof record['completedAt'] === 'string') {
    built.completedAt = record['completedAt'];
  }
  if (isScanFailureCode(record['failureCode'])) {
    built.failureCode = record['failureCode'];
  }
  if (typeof record['failureMessage'] === 'string') {
    built.failureMessage = record['failureMessage'];
  }
  if (record['resultSummary'] !== undefined) {
    built.resultSummary = record['resultSummary'] as ScanResultSummary;
  }
  if (Array.isArray(record['findings'])) {
    built.findings = record['findings'];
  }
  if (record['sca'] !== undefined && isScaResult(record['sca'])) {
    built.sca = record['sca'];
  }
  return built;
}

function parseStoredIdempotencyEntry(
  value: unknown,
  scanIds: ReadonlySet<string>,
): IdempotencyEntry | undefined {
  if (typeof value !== 'object' || value === null) {
    return undefined;
  }
  const record = value as Record<string, unknown>;
  if (
    typeof record['accountId'] !== 'string' ||
    record['accountId'].length === 0 ||
    typeof record['key'] !== 'string' ||
    !IDEMPOTENCY_KEY_PATTERN.test(record['key']) ||
    typeof record['projectId'] !== 'string' ||
    !PROJECT_ID_PATTERN.test(record['projectId']) ||
    !isScanType(record['scanType']) ||
    typeof record['scanId'] !== 'string' ||
    !SCAN_ID_PATTERN.test(record['scanId']) ||
    typeof record['createdAt'] !== 'string' ||
    Number.isNaN(Date.parse(record['createdAt']))
  ) {
    return undefined;
  }
  // An entry pointing at a missing scan is inconsistent state — refuse
  // to start rather than silently repairing (scan records are never
  // deleted, so this cannot arise from legitimate operation).
  if (!scanIds.has(record['scanId'])) {
    return undefined;
  }
  const entry: IdempotencyEntry = {
    accountId: record['accountId'],
    key: record['key'],
    projectId: record['projectId'],
    scanType: record['scanType'],
    scanId: record['scanId'],
    createdAt: record['createdAt'],
  };
  return entry;
}

function loadDocument(path: string): StoreDocument {
  let raw: string;
  try {
    raw = readFileSync(path, 'utf8');
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') {
      return { version: 1, scans: [], idempotency: [] };
    }
    throw new Error(`Cannot read scan store at ${path}: ${String(code ?? error)}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw) as unknown;
  } catch {
    throw new Error(
      `Scan store at ${path} is not valid JSON — refusing to start with corrupt scan data.`,
    );
  }
  if (
    typeof parsed !== 'object' ||
    parsed === null ||
    (parsed as Record<string, unknown>)['version'] !== 1 ||
    !Array.isArray((parsed as Record<string, unknown>)['scans']) ||
    !Array.isArray((parsed as Record<string, unknown>)['idempotency'])
  ) {
    throw new Error(`Scan store at ${path} has an unexpected shape — refusing to start.`);
  }
  const rawScans = (parsed as StoreDocument).scans;
  const seenIds = new Set<string>();
  const scans: ScanRecord[] = [];
  rawScans.forEach((entry, index) => {
    const record = parseStoredScan(entry);
    if (record === undefined) {
      throw new Error(
        `Scan store at ${path} has an invalid record at index ${index} — refusing to start.`,
      );
    }
    if (seenIds.has(record.id)) {
      throw new Error(`Scan store at ${path} contains duplicate ids — refusing to start.`);
    }
    seenIds.add(record.id);
    scans.push(record);
  });
  const rawEntries = (parsed as StoreDocument).idempotency;
  const seenKeys = new Set<string>();
  const idempotency: IdempotencyEntry[] = [];
  rawEntries.forEach((entry, index) => {
    const record = parseStoredIdempotencyEntry(entry, seenIds);
    if (record === undefined) {
      throw new Error(
        `Scan store at ${path} has an invalid idempotency entry at index ${index} — refusing to start.`,
      );
    }
    const composite = `${record.accountId}:${record.key}`;
    if (seenKeys.has(composite)) {
      throw new Error(
        `Scan store at ${path} contains duplicate idempotency keys — refusing to start.`,
      );
    }
    seenKeys.add(composite);
    idempotency.push(record);
  });
  return { version: 1, scans, idempotency };
}

interface StoreInternals {
  scans: ScanRecord[];
  idempotency: IdempotencyEntry[];
  /** Persist the full next state atomically (called inside the queue). */
  persistWith(scans: ScanRecord[], idempotency: IdempotencyEntry[]): void;
}

function createScanStoreFrom(internals: StoreInternals): ScanStore {
  // The single mutation queue — every change is linearized here,
  // exactly like the account, usage and project stores.
  let queue: Promise<unknown> = Promise.resolve();
  const runExclusive = <T>(task: () => T | Promise<T>): Promise<T> => {
    const run = queue.then(task, task);
    queue = run.catch(() => undefined);
    return run;
  };

  const scansById = new Map<string, ScanRecord>();
  for (const record of internals.scans) {
    scansById.set(record.id, record);
  }
  // (accountId, key) → entry. One key resolves to at most one scan per
  // account, for the key's whole bounded lifetime.
  const idempotencyByKey = new Map<string, IdempotencyEntry>();
  for (const entry of internals.idempotency) {
    idempotencyByKey.set(`${entry.accountId}:${entry.key}`, entry);
  }

  const toPublic = (record: ScanRecord): ScanRecord => ({ ...record });

  const applyClaimPersist = (
    record: ScanRecord,
    mutate: (record: ScanRecord) => ScanRecord,
  ): ScanRecord | undefined => {
    const current = scansById.get(record.id);
    if (current === undefined) {
      return undefined;
    }
    const updated = mutate(current);
    const nextScans = [...scansById.values()].map((scan) =>
      scan.id === updated.id ? updated : scan,
    );
    internals.persistWith(nextScans, [...idempotencyByKey.values()]);
    scansById.set(updated.id, updated);
    return toPublic(updated);
  };

  return {
    createScanWithQuota: (input) =>
      runExclusive(async () => {
        // 1. Idempotency replay — BEFORE consuming anything. Scoped to
        //    (ownerId, key); another account's key is simply absent.
        if (input.idempotencyKey !== undefined) {
          const existing = idempotencyByKey.get(`${input.ownerId}:${input.idempotencyKey}`);
          if (existing !== undefined) {
            if (existing.projectId !== input.projectId || existing.scanType !== input.scanType) {
              return { outcome: 'conflict' };
            }
            const scan = scansById.get(existing.scanId);
            if (scan !== undefined) {
              return { outcome: 'replayed', scan: toPublic(scan) };
            }
            // Unreachable in consistent state (entries always point at
            // existing scans — enforced at load). Fail closed: treat as
            // a fresh request rather than trusting the dangling entry.
          }
        }
        // 2. Quota — the single authority (UsageService). Denied means
        //    NOTHING was appended and nothing was incremented.
        const quota = await input.consume();
        if (!quota.ok) {
          return { outcome: 'quota-denied', retryAfterSec: quota.retryAfterSec };
        }
        // 3. Durable append + idempotency entry, persisted together.
        const now = new Date().toISOString();
        let id = `scan_${randomUUID()}`;
        if (scansById.has(id)) {
          id = `scan_${randomUUID()}`; // Astronomically unlikely collision.
        }
        const record: ScanRecord = {
          id,
          ownerId: input.ownerId,
          projectId: input.projectId,
          scanType: input.scanType,
          status: 'QUEUED',
          createdAt: now,
          updatedAt: now,
        };
        const nextScans = [...scansById.values(), record];
        let nextIdempotency = [...idempotencyByKey.values()];
        if (input.idempotencyKey !== undefined) {
          const entry: IdempotencyEntry = {
            accountId: input.ownerId,
            key: input.idempotencyKey,
            projectId: input.projectId,
            scanType: input.scanType,
            scanId: record.id,
            createdAt: now,
          };
          nextIdempotency = [...nextIdempotency, entry];
          // Bound the per-account memory (oldest first). Deterministic:
          // sort by createdAt then key, keep the newest N.
          const byAccount = nextIdempotency
            .filter((item) => item.accountId === input.ownerId)
            .sort((a, b) =>
              a.createdAt === b.createdAt
                ? a.key < b.key
                  ? -1
                  : 1
                : a.createdAt < b.createdAt
                  ? -1
                  : 1,
            );
          if (byAccount.length > IDEMPOTENCY_ENTRIES_PER_ACCOUNT) {
            const evict = new Set(
              byAccount
                .slice(0, byAccount.length - IDEMPOTENCY_ENTRIES_PER_ACCOUNT)
                .map((item) => `${item.accountId}:${item.key}`),
            );
            nextIdempotency = nextIdempotency.filter(
              (item) => !evict.has(`${item.accountId}:${item.key}`),
            );
          }
        }
        internals.persistWith(nextScans, nextIdempotency);
        scansById.set(record.id, record);
        const nextKeys = new Set(
          nextIdempotency.map((item) => `${item.accountId}:${item.key}`),
        );
        for (const key of [...idempotencyByKey.keys()]) {
          if (!nextKeys.has(key)) {
            idempotencyByKey.delete(key);
          }
        }
        for (const entry of nextIdempotency) {
          idempotencyByKey.set(`${entry.accountId}:${entry.key}`, entry);
        }
        return { outcome: 'created', scan: toPublic(record) };
      }),

    listByProject: (projectId) =>
      Promise.resolve(
        [...scansById.values()]
          .filter((record) => record.projectId === projectId)
          .sort(
            (a, b) =>
              (a.createdAt < b.createdAt ? 1 : a.createdAt > b.createdAt ? -1 : a.id < b.id ? -1 : 1),
          )
          .map(toPublic),
      ),

    findByProjectAndId: (projectId, scanId) => {
      const record = scansById.get(scanId);
      if (record === undefined || record.projectId !== projectId) {
        return Promise.resolve(undefined);
      }
      return Promise.resolve(toPublic(record));
    },

    claimNextQueued: () =>
      runExclusive(() => {
        const candidate = [...scansById.values()]
          .filter((record) => record.status === 'QUEUED')
          .sort(
            (a, b) =>
              (a.createdAt < b.createdAt ? -1 : a.createdAt > b.createdAt ? 1 : a.id < b.id ? -1 : 1),
          )[0];
        if (candidate === undefined) {
          return undefined;
        }
        const claimed = applyClaimPersist(candidate, (current) => ({
          ...current,
          status: 'RUNNING',
          startedAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        }));
        return claimed === undefined ? undefined : toPublic(claimed);
      }),

    completeScan: (id, resultSummary, findings, sca) =>
      runExclusive(() => {
        const current = scansById.get(id);
        if (current === undefined || current.status !== 'RUNNING') {
          return undefined;
        }
        // Defense in depth (Pump 9): the SCA payload is a closed-shape,
        // bounded, cross-field-checked contract AND may only exist on
        // an SCA scan. A SAST scan completing with an SCA payload (or
        // a malformed payload) is inconsistent state — refused.
        if (sca !== undefined && !(isScaResult(sca) && current.scanType === 'SCA')) {
          return undefined;
        }
        // Defense in depth: findings are bounded and must belong to
        // this scan, and the summary must agree with them (the engine
        // already guarantees this; the store never trusts blindly).
        const safeFindings =
          findings === undefined || findings.length === 0
            ? undefined
            : findings.slice(0, MAX_FINDINGS_PER_SCAN);
        if (safeFindings !== undefined) {
          if (
            safeFindings.length !== findings?.length ||
            !safeFindings.every((finding) => isFinding(finding) && finding.scanId === id)
          ) {
            return undefined;
          }
          if (resultSummary.findingsTotal !== safeFindings.length) {
            return undefined;
          }
        }
        const updated = applyClaimPersist(current, (record) => ({
          ...record,
          status: 'COMPLETED',
          completedAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
          resultSummary,
          ...(safeFindings === undefined ? {} : { findings: safeFindings }),
          ...(sca === undefined ? {} : { sca }),
        }));
        return updated === undefined ? undefined : toPublic(updated);
      }),

    failScan: (id, failureCode, failureMessage) =>
      runExclusive(() => {
        const current = scansById.get(id);
        if (current === undefined || current.status !== 'RUNNING') {
          return undefined;
        }
        const updated = applyClaimPersist(current, (record) => ({
          ...record,
          status: 'FAILED',
          completedAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
          failureCode,
          failureMessage: failureMessage.slice(0, SCAN_FAILURE_MESSAGE_MAX_LENGTH),
        }));
        return updated === undefined ? undefined : toPublic(updated);
      }),

    failAllRunning: (failureCode, failureMessage) =>
      runExclusive(() => {
        const running = [...scansById.values()].filter((record) => record.status === 'RUNNING');
        if (running.length === 0) {
          return 0;
        }
        const now = new Date().toISOString();
        const updatedById = new Map<string, ScanRecord>();
        for (const record of running) {
          updatedById.set(record.id, {
            ...record,
            status: 'FAILED',
            completedAt: now,
            updatedAt: now,
            failureCode,
            failureMessage: failureMessage.slice(0, SCAN_FAILURE_MESSAGE_MAX_LENGTH),
          });
        }
        const nextScans = [...scansById.values()].map((record) => updatedById.get(record.id) ?? record);
        internals.persistWith(nextScans, [...idempotencyByKey.values()]);
        for (const updated of updatedById.values()) {
          scansById.set(updated.id, updated);
        }
        return running.length;
      }),
  };
}

/** Durable scan store: one JSON document, atomic writes. */
export function createJsonFileScanStore(path: string): ScanStore {
  const document = loadDocument(path);
  const persistWith = (scans: ScanRecord[], idempotency: IdempotencyEntry[]): void => {
    mkdirSync(dirname(path), { recursive: true });
    const payload: StoreDocument = { version: 1, scans, idempotency };
    const tempPath = join(dirname(path), `.${randomBytes(6).toString('hex')}.tmp`);
    writeFileSync(tempPath, `${JSON.stringify(payload, null, 2)}\n`, { mode: 0o600 });
    renameSync(tempPath, path);
  };
  return createScanStoreFrom({
    scans: document.scans,
    idempotency: document.idempotency,
    persistWith,
  });
}

/** In-memory scan store (tests and explicit `:memory:` setups). */
export function createMemoryScanStore(): ScanStore {
  return createScanStoreFrom({ scans: [], idempotency: [], persistWith: () => undefined });
}

/**
 * The public scan DETAIL shape (Pump 8): the scan plus its findings,
 * deterministically ordered (severity rank, then file, then line, then
 * rule). Findings are only in the detail response — list responses
 * stay lean and carry only the summary counts.
 */
export function toScanDetailResponse(record: ScanRecord): ScanDetail {
  const findings = [...(record.findings ?? [])].sort(compareFindings);
  return {
    ...toScanResponse(record),
    findings,
    // The SCA payload rides ONLY the detail route (the list stays
    // lean — counts live in resultSummary).
    ...(record.sca === undefined ? {} : { sca: record.sca }),
  };
}

/** The public scan shape (no ownerId, no internals) for API responses. */
export function toScanResponse(record: ScanRecord): Scan {
  return {
    id: record.id,
    projectId: record.projectId,
    scanType: record.scanType,
    status: record.status,
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
    ...(record.startedAt === undefined ? {} : { startedAt: record.startedAt }),
    ...(record.completedAt === undefined ? {} : { completedAt: record.completedAt }),
    ...(record.failureCode === undefined ? {} : { failureCode: record.failureCode }),
    ...(record.failureMessage === undefined ? {} : { failureMessage: record.failureMessage }),
    ...(record.resultSummary === undefined ? {} : { resultSummary: record.resultSummary }),
  };
}
