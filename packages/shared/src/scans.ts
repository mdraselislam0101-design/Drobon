import { isValidSourcePath } from './sources.js';

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
 *   (the honest state for SCA/SECRETS/DAST until their pumps; SAST has
 *   a real engine since Pump 8);
 * - `SCAN_INTERRUPTED` — processing was interrupted (e.g. process
 *   restart mid-run); the scan deterministically FAILED, never hung;
 * - `SCAN_ENGINE_ERROR` — an engine crashed/timed out while running;
 * - `SAST_TARGET_NOT_FOUND` — (Pump 8) a SAST scan found no source
 *   snapshot attached to the project (the API pre-flights this, so via
 *   HTTP this arises only from a race — the engine still fails closed);
 * - `SAST_TARGET_TOO_LARGE` — the snapshot exceeds the engine's total
 *   scan-byte budget (fail closed; the snapshot caps make this a
 *   defense-in-depth path);
 * - `SAST_FILE_LIMIT_EXCEEDED` — the snapshot has more scannable files
 *   than the engine's hard file cap (same defense-in-depth posture);
 * - `SAST_SCAN_TIMEOUT` — the engine's own processing deadline was
 *   exhausted before the scan finished (deterministic, never reported
 *   as COMPLETED; distinct from the processor-level
 *   `SCAN_ENGINE_ERROR` timeout);
 * - `SAST_INPUT_INVALID` — the stored snapshot failed the engine's
 *   re-validation (fail closed; durable state is corrupt);
 * - `SAST_UNSUPPORTED_LANGUAGE` — RESERVED (defined for stability, not
 *   emitted in v1): a snapshot containing no supported-language files
 *   completes honestly with `filesScanned: 0` rather than failing —
 *   unsupported files are skipped and counted, never claimed as
 *   scanned.
 */
import { isScaResult, type ScaResult } from './sca.js';

/**
 * Failure codes (scan-domain, stable, safe to expose). Pump 8 added
 * the closed SAST engine set; Pump 9 adds the SCA engine's mirror
 * set (target/size/manifest-limit/timeout/input). Closed vocabulary:
 * internals never leak through failure messages.
 */
export const SCAN_FAILURE_CODES = [
  'SCAN_ENGINE_NOT_IMPLEMENTED',
  'SCAN_INTERRUPTED',
  'SCAN_ENGINE_ERROR',
  'SAST_TARGET_NOT_FOUND',
  'SAST_TARGET_TOO_LARGE',
  'SAST_FILE_LIMIT_EXCEEDED',
  'SAST_SCAN_TIMEOUT',
  'SAST_INPUT_INVALID',
  'SAST_UNSUPPORTED_LANGUAGE',
  'SCA_TARGET_NOT_FOUND',
  'SCA_TARGET_TOO_LARGE',
  'SCA_MANIFEST_LIMIT_EXCEEDED',
  'SCA_SCAN_TIMEOUT',
  'SCA_INPUT_INVALID',
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
 * only ever produced by a real engine — never fabricated). The base
 * `findingsTotal` is the Pump 7 contract; the optional SAST fields
 * (Pump 8) extend the same shape behind one guard. NO CVSS or
 * exploitability claims — an engine may only report what it actually
 * measured.
 */
export interface ScanResultSummary {
  /** Total number of findings the engine reported (0 = clean scan). */
  findingsTotal: number;
  /**
   * Findings per severity (SAST, Pump 8). Present only when the engine
   * actually classified findings; all five severities are keys.
   */
  findingsBySeverity?: Record<FindingSeverity, number>;
  /** Source files the engine actually analyzed (SAST). */
  filesScanned?: number;
  /** Source files present but skipped (unsupported/ignored) (SAST). */
  filesSkipped?: number;
  /**
   * True when the per-scan findings cap truncated the finding list —
   * the honest signal that more findings may exist (SAST).
   */
  truncated?: boolean;
  /** Unique dependencies discovered (SCA, Pump 9) — lean list metric. */
  dependenciesTotal?: number;
  /** Direct dependencies (SCA, Pump 9) — lean list metric. */
  directDependencies?: number;
}

const SUMMARY_ALLOWED_KEYS = [
  'findingsTotal',
  'findingsBySeverity',
  'filesScanned',
  'filesSkipped',
  'truncated',
  // SCA (Pump 9): lean metrics so the LIST route can show dependency
  // counts without shipping the inventory. The full payload (manifest
  // results, SBOM, advisories) lives in the scan-detail response only.
  'dependenciesTotal',
  'directDependencies',
] as const;

function isCount(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0;
}

export function isScanResultSummary(value: unknown): value is ScanResultSummary {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  if (keys.length === 0 || keys.length > SUMMARY_ALLOWED_KEYS.length) {
    return false;
  }
  if (keys.some((key) => !(SUMMARY_ALLOWED_KEYS as readonly string[]).includes(key))) {
    return false;
  }
  if (!isCount(record['findingsTotal'])) {
    return false;
  }
  if (record['findingsBySeverity'] !== undefined) {
    const bySeverity = record['findingsBySeverity'];
    if (typeof bySeverity !== 'object' || bySeverity === null) {
      return false;
    }
    const severityKeys = Object.keys(bySeverity);
    if (severityKeys.length !== FINDING_SEVERITIES.length) {
      return false;
    }
    if (severityKeys.some((key) => !isFindingSeverity(key))) {
      return false;
    }
    if (severityKeys.some((key) => !isCount((bySeverity as Record<string, unknown>)[key]))) {
      return false;
    }
  }
  if (record['filesScanned'] !== undefined && !isCount(record['filesScanned'])) {
    return false;
  }
  if (record['filesSkipped'] !== undefined && !isCount(record['filesSkipped'])) {
    return false;
  }
  if (record['truncated'] !== undefined && typeof record['truncated'] !== 'boolean') {
    return false;
  }
  if (record['dependenciesTotal'] !== undefined && !isCount(record['dependenciesTotal'])) {
    return false;
  }
  if (record['directDependencies'] !== undefined && !isCount(record['directDependencies'])) {
    return false;
  }
  return true;
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

// ---------------------------------------------------------------------------
// Findings (Pump 8 — the real SAST engine's output)
// ---------------------------------------------------------------------------

/**
 * The documented severity scale. Determined by the RULE definition —
 * never by user input, never client-modifiable, never inflated. A
 * severity describes the rule's worst realistic class, not proven
 * exploitability (no dataflow → conservative, e.g. raw-HTML sinks are
 * MEDIUM, not HIGH).
 */
export const FINDING_SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const;

export type FindingSeverity = (typeof FINDING_SEVERITIES)[number];

export function isFindingSeverity(value: unknown): value is FindingSeverity {
  return (
    typeof value === 'string' && (FINDING_SEVERITIES as readonly string[]).includes(value)
  );
}

/**
 * Rule identifiers: `DG-SAST-###` — stable, documented in docs/SAST.md,
 * never reused. `DG` is the product prefix (Drobon).
 */
export const SAST_RULE_ID_PATTERN = /^DG-SAST-[0-9]{3}$/;

/**
 * Finding ids: `fnd_` + the first 24 hex chars of the finding's
 * fingerprint — DETERMINISTIC (derived from rule + file + line +
 * evidence), so repeated scans of unchanged source reproduce identical
 * finding ids. Never random.
 */
export const FINDING_ID_PATTERN = /^fnd_[0-9a-f]{24}$/;

/** Finding fingerprints: a full lowercase SHA-256 hex digest. */
export const FINDING_FINGERPRINT_PATTERN = /^[0-9a-f]{64}$/;

/** CWE references, only where a rule has a defensible mapping. */
export const FINDING_CWE_PATTERN = /^CWE-[1-9][0-9]{0,5}$/;

/** Hard cap on findings persisted per scan (engine + store agree). */
export const MAX_FINDINGS_PER_SCAN = 200;

/** Bound on a finding's evidence snippet (characters). */
export const FINDING_EVIDENCE_MAX_LENGTH = 200;

/** Bound on a finding's text fields (characters). */
export const FINDING_TEXT_MAX_LENGTH = 400;

/** Bound on a finding's title (characters). */
export const FINDING_TITLE_MAX_LENGTH = 80;

/** Bound on the finding's file path — the shared source-path policy. */
export const FINDING_FILE_PATH_MAX_LENGTH = 160;

function isSafeFindingText(value: unknown, maxLength: number): value is string {
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

/**
 * One real, engine-produced finding. Every field is server-authored:
 * the client can never create, mutate or delete findings (there is no
 * findings mutation endpoint, and evidence/text guards reject injected
 * control characters — evidence renders as text everywhere).
 *
 * NO CVSS score is present — none is calculated, so none may be shown.
 */
export interface Finding {
  /** Deterministic id derived from the fingerprint (stable across rescans). */
  id: string;
  /** The scan this finding belongs to (server-set, cross-checked at load). */
  scanId: string;
  /** The stable rule identifier (e.g. `DG-SAST-001`). */
  ruleId: string;
  /** Rule-fixed severity — never client-influenced. */
  severity: FindingSeverity;
  /** Short human title. */
  title: string;
  /** What matched and why it matters (bounded). */
  description: string;
  /** CWE mapping, only when defensible (omitted rather than guessed). */
  cwe?: string;
  /** Relative path inside the project's source snapshot. */
  file: string;
  /** 1-based line number of the match. */
  line: number;
  /** 1-based column of the match (reliable: regex match index). */
  column: number;
  /** Bounded, sanitized source evidence (credential values redacted). */
  evidence: string;
  /** Rule-specific remediation guidance (separate from evidence). */
  remediation: string;
  /** Deterministic identity: sha256(ruleId|file|line|evidence digest). */
  fingerprint: string;
}

/** Closed-shape + invariant guard for a finding. */
export function isFinding(value: unknown): value is Finding {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  const allowed: readonly string[] = [
    'id',
    'scanId',
    'ruleId',
    'severity',
    'title',
    'description',
    'cwe',
    'file',
    'line',
    'column',
    'evidence',
    'remediation',
    'fingerprint',
  ];
  if (keys.some((key) => !allowed.includes(key))) {
    return false;
  }
  if (
    typeof record['id'] !== 'string' ||
    !FINDING_ID_PATTERN.test(record['id']) ||
    typeof record['scanId'] !== 'string' ||
    !SCAN_ID_PATTERN.test(record['scanId']) ||
    typeof record['ruleId'] !== 'string' ||
    !SAST_RULE_ID_PATTERN.test(record['ruleId']) ||
    !isFindingSeverity(record['severity']) ||
    !isSafeFindingText(record['title'], FINDING_TITLE_MAX_LENGTH) ||
    !isSafeFindingText(record['description'], FINDING_TEXT_MAX_LENGTH) ||
    !isSafeFindingText(record['evidence'], FINDING_EVIDENCE_MAX_LENGTH) ||
    !isSafeFindingText(record['remediation'], FINDING_TEXT_MAX_LENGTH) ||
    typeof record['file'] !== 'string' ||
    !isValidSourcePath(record['file']) ||
    typeof record['fingerprint'] !== 'string' ||
    !FINDING_FINGERPRINT_PATTERN.test(record['fingerprint'])
  ) {
    return false;
  }
  if (
    typeof record['line'] !== 'number' ||
    !Number.isInteger(record['line']) ||
    record['line'] < 1 ||
    typeof record['column'] !== 'number' ||
    !Number.isInteger(record['column']) ||
    record['column'] < 1
  ) {
    return false;
  }
  if (typeof record['cwe'] === 'string' && !FINDING_CWE_PATTERN.test(record['cwe'])) {
    return false;
  }
  return true;
}

/**
 * Deterministic finding order (documented contract): severity rank
 * (CRITICAL first), then file path ASC, then line ASC, then ruleId ASC
 * — identical on every request for identical data.
 */
export function compareFindings(a: Finding, b: Finding): number {
  const rank = (severity: FindingSeverity): number =>
    FINDING_SEVERITIES.indexOf(severity);
  const rankDiff = rank(a.severity) - rank(b.severity);
  if (rankDiff !== 0) {
    return rankDiff;
  }
  if (a.file !== b.file) {
    return a.file < b.file ? -1 : 1;
  }
  if (a.line !== b.line) {
    return a.line - b.line;
  }
  return a.ruleId < b.ruleId ? -1 : a.ruleId > b.ruleId ? 1 : 0;
}

/**
 * `GET /api/v1/projects/:projectId/scans/:scanId` (Pump 8): the scan
 * plus its findings (bounded by {@link MAX_FINDINGS_PER_SCAN} by
 * construction — the engine truncates and flags `truncated` in the
 * summary). Findings are a DETAIL-response field: list responses stay
 * lean and carry only the summary counts.
 */
export interface ScanDetail extends Scan {
  findings: Finding[];
  /**
   * The SCA payload (Pump 9): dependency inventory, manifest results,
   * the deterministic SBOM and the honest assessment state. Present
   * ONLY on COMPLETED SCA scans; never on SAST scans, never in list
   * responses (the list stays lean — counts live in resultSummary).
   */
  sca?: ScaResult;
}

export interface ScanDetailResponse {
  scan: ScanDetail;
}

/**
 * Closed-shape guard for the scan-detail response: the envelope is
 * exactly `{ scan }`, and `scan` is a public Scan PLUS a bounded
 * `findings` array (validated by stripping it and re-checking the
 * Scan shape — no hardcoded key counts).
 */
export function isScanDetailResponse(value: unknown): value is ScanDetailResponse {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const record = value as Record<string, unknown>;
  if (Object.keys(record).length !== 1) {
    return false;
  }
  const scan = record['scan'];
  if (typeof scan !== 'object' || scan === null) {
    return false;
  }
  const scanRecord = scan as Record<string, unknown>;
  const { findings, sca, ...scanWithoutPayload } = scanRecord;
  if (!Array.isArray(findings)) {
    return false;
  }
  if (findings.length > MAX_FINDINGS_PER_SCAN) {
    return false;
  }
  if (!isScan(scanWithoutPayload)) {
    return false;
  }
  // The optional SCA payload is validated as a whole (closed shape,
  // bounded arrays, cross-field honesty — see sca.ts). A malformed or
  // forged payload fails the entire response as invalid.
  if (sca !== undefined && !isScaResult(sca)) {
    return false;
  }
  return findings.every((finding) => isFinding(finding));
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
