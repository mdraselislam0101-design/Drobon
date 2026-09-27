/**
 * Scan job contracts (Pump 7) — the secure orchestration boundary future
 * scanner engines (SAST/SCA/SECRETS/DAST) plug into.
 *
 * IMPORTANT — what this module is NOT:
 * - it is NOT a vulnerability database and carries no CVE/NVD/GHSA/OSV/
 *   KEV/EPSS data (the dataset lock forbids that, forever separately);
 * - it does NOT claim any scanner engine exists. `SCAN_TYPES` are the
 *   SUPPORTED job types of the orchestration layer; whether an engine
 *   is actually available is a separate, server-side registry — an
 *   unavailable engine fails a scan deterministically with
 *   `SCAN_ENGINE_NOT_IMPLEMENTED` (never a fabricated result).
 *
 * Security posture (mirrors `projects.ts`):
 * - the public {@link Scan} shape carries NO `ownerId` (self-only API —
 *   the caller is by construction the owner of everything it can see),
 *   no filesystem paths, no worker internals, no stack traces;
 * - ids are `scan_` + a lowercase UUID v4 (server-generated only);
 * - every status/lifecycle field is server-authoritative; clients can
 *   submit ONLY the scan type.
 */

/** Supported scan job types of the orchestration layer (closed union). */
export const SCAN_TYPES = ['SAST', 'SCA', 'SECRETS', 'DAST'] as const;

export type ScanType = (typeof SCAN_TYPES)[number];

export function isScanType(value: unknown): value is ScanType {
  return typeof value === 'string' && (SCAN_TYPES as readonly string[]).includes(value);
}

/**
 * Server-authoritative scan lifecycle. Exactly one forward path
 * QUEUED → RUNNING → COMPLETED, with deterministic failure exits from
 * QUEUED/RUNNING. There is NO client-facing transition endpoint.
 */
export const SCAN_STATUSES = ['QUEUED', 'RUNNING', 'COMPLETED', 'FAILED'] as const;

export type ScanStatus = (typeof SCAN_STATUSES)[number];

export function isScanStatus(value: unknown): value is ScanStatus {
  return typeof value === 'string' && (SCAN_STATUSES as readonly string[]).includes(value);
}

/**
 * Closed vocabulary of scan-level failure codes (the scan domain's
 * equivalent of the shared `ErrorCode` transport vocabulary — these are
 * stable, machine-readable, safe to expose, and never leak internals).
 *
 * - `SCAN_ENGINE_NOT_IMPLEMENTED` — the requested job type is supported
 *   by the orchestration layer but no real scanner engine for it exists
 *   yet (the honest Pump 7 state for every type);
 * - `SCAN_INTERRUPTED` — processing was interrupted (e.g. process
 *   restart mid-run); the scan deterministically FAILED, never hung;
 * - `SCAN_ENGINE_ERROR` — an engine crashed/timed out while running.
 */
export const SCAN_FAILURE_CODES = [
  'SCAN_ENGINE_NOT_IMPLEMENTED',
  'SCAN_INTERRUPTED',
  'SCAN_ENGINE_ERROR',
] as const;

export type ScanFailureCode = (typeof SCAN_FAILURE_CODES)[number];

export function isScanFailureCode(value: unknown): value is ScanFailureCode {
  return (
    typeof value === 'string' && (SCAN_FAILURE_CODES as readonly string[]).includes(value)
  );
}

/**
 * Scan ids: `scan_` + a lowercase UUID v4 — the same convention as
 * account (`usr_`) and project (`prj_`) ids, generated with
 * `crypto.randomUUID()`. Never counters; never client-supplied.
 */
export const SCAN_ID_PATTERN =
  /^scan_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/**
 * Optional `Idempotency-Key` request header for scan creation: 8–64
 * URL-safe characters. Scoped to the authenticated account by the
 * server; a replayed key returns the ORIGINAL scan instead of creating
 * (and charging) a new one.
 */
export const IDEMPOTENCY_KEY_PATTERN = /^[A-Za-z0-9_-]{8,64}$/;

/**
 * Engine-produced result summary (only present on COMPLETED scans, and
 * only ever produced by a real engine — never fabricated). Deliberately
 * minimal; later engine pumps extend it behind the same guard.
 */
export interface ScanResultSummary {
  /** Total number of findings the engine reported (0 = clean scan). */
  findingsTotal: number;
}

export function isScanResultSummary(value: unknown): value is ScanResultSummary {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const record = value as Record<string, unknown>;
  return (
    Object.keys(record).length === 1 &&
    typeof record['findingsTotal'] === 'number' &&
    Number.isInteger(record['findingsTotal']) &&
    record['findingsTotal'] >= 0
  );
}

/**
 * The scan as the API returns it (the caller's own). Deliberately
 * carries NO `ownerId`, no engine/worker internals, no filesystem
 * paths. Optional fields are exactly the lifecycle fields the server
 * sets as the scan progresses (see the status invariants below).
 */
export interface Scan {
  id: string;
  projectId: string;
  scanType: ScanType;
  status: ScanStatus;
  createdAt: string;
  updatedAt: string;
  /** Set once the processor claims the scan (status ≠ QUEUED). */
  startedAt?: string;
  /** Set on a terminal status (COMPLETED or FAILED). */
  completedAt?: string;
  /** Terminal failure classification (FAILED only). */
  failureCode?: ScanFailureCode;
  /** Safe, bounded, human-readable failure detail (FAILED only). */
  failureMessage?: string;
  /** Engine-produced summary (COMPLETED only, never fabricated). */
  resultSummary?: ScanResultSummary;
}

/** `GET /api/v1/projects/:projectId/scans` — one project's scans, ordered. */
export interface ScansResponse {
  scans: Scan[];
}

/** Scan creation/read responses. */
export interface ScanResponse {
  scan: Scan;
}

/** Closed-shape guard for `GET …/scans` responses. */
export function isScansResponse(value: unknown): value is ScansResponse {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const record = value as Record<string, unknown>;
  if (Object.keys(record).length !== 1 || !Array.isArray(record['scans'])) {
    return false;
  }
  return record['scans'].every((scan) => isScan(scan));
}

/** Closed-shape guard for scan creation/read responses. */
export function isScanResponse(value: unknown): value is ScanResponse {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const record = value as Record<string, unknown>;
  return Object.keys(record).length === 1 && isScan(record['scan']);
}

/**
 * Deterministic list ordering (documented contract): `createdAt` DESC
 * (newest first), then `id` ASC as the stable tie-breaker. Identical on
 * every request for identical data.
 */
export function compareScansDesc(a: Scan, b: Scan): number {
  if (a.createdAt !== b.createdAt) {
    return a.createdAt < b.createdAt ? 1 : -1;
  }
  return a.id < b.id ? -1 : 1;
}

/** Closed-shape + cross-field-invariant guard for a public scan. */
export function isScan(value: unknown): value is Scan {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  const allowed: readonly string[] = [
    'id',
    'projectId',
    'scanType',
    'status',
    'createdAt',
    'updatedAt',
    'startedAt',
    'completedAt',
    'failureCode',
    'failureMessage',
    'resultSummary',
  ];
  if (keys.some((key) => !allowed.includes(key))) {
    return false;
  }
  if (
    typeof record['id'] !== 'string' ||
    !SCAN_ID_PATTERN.test(record['id']) ||
    typeof record['projectId'] !== 'string' ||
    record['projectId'].length === 0 ||
    !isScanType(record['scanType']) ||
    !isScanStatus(record['status']) ||
    typeof record['createdAt'] !== 'string' ||
    typeof record['updatedAt'] !== 'string'
  ) {
    return false;
  }
  if (record['failureMessage'] !== undefined && typeof record['failureMessage'] !== 'string') {
    return false;
  }
  if (record['resultSummary'] !== undefined && !isScanResultSummary(record['resultSummary'])) {
    return false;
  }
  // Lifecycle invariants — the server-side state machine, enforced on
  // every untrusted payload (a client must never be able to conjure a
  // COMPLETED scan without timestamps, or a failure without a code).
  const status = record['status'];
  const hasStartedAt = record['startedAt'] !== undefined;
  const hasCompletedAt = record['completedAt'] !== undefined;
  const hasFailureCode = record['failureCode'] !== undefined;
  const hasFailureMessage = record['failureMessage'] !== undefined;
  const hasResult = record['resultSummary'] !== undefined;
  if (hasFailureCode && !isScanFailureCode(record['failureCode'])) {
    return false;
  }
  if (status === 'QUEUED') {
    return !(hasStartedAt || hasCompletedAt || hasFailureCode || hasFailureMessage || hasResult);
  }
  if (!hasStartedAt) {
    return false; // RUNNING/COMPLETED/FAILED must have startedAt.
  }
  if (status === 'RUNNING') {
    return !(hasCompletedAt || hasFailureCode || hasFailureMessage || hasResult);
  }
  // Terminal statuses need completedAt.
  if (!hasCompletedAt) {
    return false;
  }
  if (status === 'COMPLETED') {
    return hasResult && !hasFailureCode && !hasFailureMessage;
  }
  return hasFailureCode && !hasResult; // FAILED
}
