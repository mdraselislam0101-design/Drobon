import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { randomBytes, randomUUID } from 'node:crypto';
import {
  ASSESSMENT_ID_PATTERN,
  IDEMPOTENCY_KEY_PATTERN,
  MAX_FINDINGS_PER_SCAN,
  PROJECT_ID_PATTERN,
  SCAN_ID_PATTERN,
  isFinding,
  isScanFailureCode,
  isScanResultSummary,
  isAstSupplementForScanType,
  isScanStatus,
  isScanType,
  isDastResult,
  isSafeDastUrl,
  type DastResult,
  type AdminFindingSummary,
  type AdminScanSummary,
  type SecurityReport,
  FINDING_HISTORY_EVENTS_MAX,
  FINDING_SEVERITIES,
  FINDING_NOTES_MAX_COUNT,
  FINDING_HISTORY_PAGE_MAX,
  FINDING_HISTORY_PAGE_SIZE_MAX,
  FINDING_WORKFLOWS_MAX,
  isFindingLifecycleEvent,
  isFindingWorkflow,
  type FindingHistoryResponse,
  type FindingLifecycleEvent,
  type FindingLifecycleState,
  type FindingWorkflow,
  REPORT_MAX_BYTES,
  REPORT_PERSISTED_MAX_COUNT,
  WORKSPACE_FINDINGS_MAX,
  WORKSPACE_REPORTS_MAX,
  WORKSPACE_SCANS_MAX,
  emptyWorkspaceFindingsSummary,
  emptyWorkspaceScansSummary,
  type WorkspaceFindingCard,
  type WorkspaceFindingsSummary,
  type WorkspaceReportCard,
  type WorkspaceReportsSummary,
  type WorkspaceScansSummary,
  type WorkspaceScanCard,
  type Finding,
  compareFindings,
  findingScanner,
  isScaResult,
  type Scan,
  type ScanDetail,
  type ScanFailureCode,
  type ScanResultSummary,
  type ScanStatus,
  type ScanType,
  type ScaResult,
} from '@drobon/shared';
import { canonicalJson, verifySecurityReportIntegrity } from '../reports/build.js';
import {
  appendUserNote,
  appendUserStateEvent,
  canTransitionFinding,
  createInitialFindingWorkflow,
  findingWorkflowKey,
  markFindingNotObserved,
  observeFindingInScan,
  prepareFindingNote,
  type FindingWorkflowRecord,
  type PreparedFindingNote,
} from './findingWorkflow.js';

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

/** DAST mode: passive (default) or active with safe payloads (opt-in). */
export const DAST_MODES = ['PASSIVE', 'ACTIVE_SAFE'] as const;
export type DastMode = (typeof DAST_MODES)[number];
export function isDastMode(v: unknown): v is DastMode { return typeof v === 'string' && (DAST_MODES as readonly string[]).includes(v); }

/** The stored record — includes the owner; the API response never does. */
export interface ScanRecord {
  id: string;
  ownerId: string;
  projectId: string;
  scanType: ScanType;
  /** Assessment association is metadata/control context, never scan permission. */
  assessmentId?: string;
  status: ScanStatus;
  /** Canonical target URL, only for DAST scans; never contains credentials/query/fragment. */
  dastTargetUrl?: string;
  /** DAST mode — PASSIVE (default) or ACTIVE_SAFE (crawl+injection, consent required). */
  dastMode?: DastMode;
  /** Explicit user consent for active probing (timestamp of declaration). */
  dastActiveConsent?: boolean;
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
  /** Bounded, redacted HTTP observations for completed DAST scans only. */
  dast?: DastResult;
}

/**
 * One remembered idempotency key: (accountId, key) → the scan it
 * created, with the request identity (projectId + scanType + optional
 * assessment association + DAST target) so a reused key with a DIFFERENT
 * request is a conflict, not a silent
 * replay of an unrelated scan.
 */
export interface IdempotencyEntry {
  accountId: string;
  key: string;
  projectId: string;
  scanType: ScanType;
  /** Optional linked assessment; absent on legacy records. */
  assessmentId?: string;
  /** Included in the request identity for DAST; optional on older records. */
  targetUrl?: string;
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
  /** Assessment association validated against this owner's project-bound active record. */
  assessmentId?: string;
  /** Preflight-validated canonical target, required for new DAST scans. */
  targetUrl?: string;
  /** DAST mode for this scan (PASSIVE default). */
  dastMode?: DastMode;
  dastActiveConsent?: boolean;
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
  | { outcome: 'invalid-target' }
  | { outcome: 'quota-denied'; retryAfterSec: number };

export interface AdminScanFilters {
  status?: ScanStatus;
  scanType?: ScanType;
  accountId?: string;
  projectId?: string;
  from?: string;
  to?: string;
}

export interface AdminFindingFilters {
  severity?: (typeof FINDING_SEVERITIES)[number];
  scanner?: ScanType;
  lifecycleState?: FindingLifecycleState;
  projectId?: string;
  from?: string;
  to?: string;
}

export interface ScanAdminSummary {
  total: number;
  byStatus: Record<ScanStatus, number>;
  byType: Record<ScanType, number>;
  recentlyCompleted: number;
  findingsBySeverity: Record<(typeof FINDING_SEVERITIES)[number], number>;
  findingsByLifecycleState: Record<FindingLifecycleState, number>;
  unresolvedFindings: number;
  dastObservations: number;
  scaNotAssessed: number;
}

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
  /** Bounded, account-scoped scan/finding/report projections for the workspace overview. */
  workspaceSummary(ownerId: string, projectId?: string): Promise<{
    scans: WorkspaceScansSummary;
    findings: WorkspaceFindingsSummary;
    reports: WorkspaceReportsSummary;
  }>;
  /** Aggregate-only platform summary; never returns source content or all scan rows. */
  adminSummary(now: number): Promise<ScanAdminSummary>;
  /** Bounded metadata-only platform scan page. */
  adminScanPage(filters: AdminScanFilters, page: number, pageSize: number): Promise<{ scans: AdminScanSummary[]; total: number }>;
  /** Bounded redacted finding index; excludes evidence, file paths, and hashes. */
  adminFindingPage(filters: AdminFindingFilters, page: number, pageSize: number): Promise<{ findings: AdminFindingSummary[]; total: number }>;
  /** At most one latest completed scan per scanner type (bounded assistant context query). */
  listLatestCompletedByScannerForAssistant(projectId: string): Promise<ScanRecord[]>;
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
    dast?: DastResult,
  ): Promise<ScanRecord | undefined>;
  /** RUNNING → TIMED_OUT for bounded DAST request/scan deadlines. */
  timeoutScan(
    id: string,
    failureCode: ScanFailureCode,
    failureMessage: string,
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
  /** Retrieve a report snapshot scoped to its project and source scan. */
  findReportByProjectAndScan(projectId: string, scanId: string): Promise<SecurityReport | undefined>;
  /** Persist or refresh the single report snapshot for a completed scan. */
  createReport(report: SecurityReport): Promise<
    | { outcome: 'created'; report: SecurityReport }
    | { outcome: 'existing'; report: SecurityReport }
    | { outcome: 'updated'; report: SecurityReport }
    | { outcome: 'invalid-report' }
    | { outcome: 'scan-unavailable' }
    | { outcome: 'capacity-exceeded' }
    | { outcome: 'workflow-changed' }
  >;
  /** Lifecycle is keyed by project + full fingerprint, never client identity. */
  getFindingWorkflow(projectId: string, fingerprint: string): Promise<FindingWorkflow | undefined>;
  getFindingWorkflowsForFindings(projectId: string, findings: readonly Finding[]): Promise<FindingWorkflow[]>;
  transitionFindingLifecycle(
    projectId: string, fingerprint: string, next: FindingLifecycleState, actorId: string, at: string,
  ): Promise<{ outcome: 'updated'; workflow: FindingWorkflow } | { outcome: 'not-found' | 'invalid-transition' | 'history-limit' }>;
  addFindingRemediationNote(
    projectId: string, fingerprint: string, prepared: Extract<PreparedFindingNote, { ok: true }>, actorId: string, at: string,
  ): Promise<{ outcome: 'updated'; workflow: FindingWorkflow } | { outcome: 'not-found' | 'notes-limit' | 'history-limit' | 'invalid-note' }>;
  getFindingHistory(
    projectId: string, fingerprint: string, page: number, pageSize: number,
  ): Promise<FindingHistoryResponse | undefined>;
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
  /** Added in Pump 12; missing on Pump 7–11 documents is an empty report set. */
  reports: SecurityReport[];
  /** Added in Pump 13; old documents are migrated from persisted scan findings. */
  findingWorkflows?: FindingWorkflowRecord[];
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
    (record['assessmentId'] !== undefined && (typeof record['assessmentId'] !== 'string' || !ASSESSMENT_ID_PATTERN.test(record['assessmentId']))) ||
    typeof record['createdAt'] !== 'string' ||
    Number.isNaN(Date.parse(record['createdAt'])) ||
    typeof record['updatedAt'] !== 'string' ||
    Number.isNaN(Date.parse(record['updatedAt']))
  ) {
    return undefined;
  }
  if (record['dastTargetUrl'] !== undefined && (record['scanType'] !== 'DAST' || !isSafeDastUrl(record['dastTargetUrl']))) {
    return undefined;
  }
  if (
    record['scanType'] === 'DAST' &&
    (status === 'QUEUED' || status === 'RUNNING' || status === 'COMPLETED') &&
    record['dastTargetUrl'] === undefined
  ) return undefined;
  if (record['dastMode'] !== undefined && record['dastMode'] !== 'PASSIVE' && record['dastMode'] !== 'ACTIVE_SAFE') return undefined;
  if (record['dastActiveConsent'] !== undefined && typeof record['dastActiveConsent'] !== 'boolean') return undefined;
  if (record['dastMode'] === 'ACTIVE_SAFE' && record['dastActiveConsent'] !== true) return undefined;
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
  if (isScanResultSummary(record['resultSummary'])) {
    if ((record['resultSummary'].astParser !== undefined || record['resultSummary'].astCoverage !== undefined) && record['scanType'] !== 'SAST') return undefined;
    if (!isAstSupplementForScanType(record['resultSummary'], record['scanType'])) return undefined;
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
    if (record['findings'].some((finding) => {
      if (typeof finding !== 'object' || finding === null) return true;
      const item = finding as unknown as Record<string, unknown>;
      const isDastFinding = item['scanner'] === 'DAST';
      if (findingScanner(finding as Finding) !== record['scanType']) return true;
      if (item['projectId'] !== undefined && item['projectId'] !== record['projectId']) return true;
      return isDastFinding && item['targetUrl'] !== record['dastTargetUrl'];
    })) return undefined;
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
      } else if (!hasFailureCode || !hasFailureMessage || hasResult) {
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
  if (record['dast'] !== undefined) {
    if (!isDastResult(record['dast']) || status !== 'COMPLETED' || record['scanType'] !== 'DAST') {
      return undefined;
    }
    if (record['dast'].targetUrl !== record['dastTargetUrl']) return undefined;
  }
  if (status === 'COMPLETED' && record['scanType'] === 'DAST' && record['dast'] === undefined) {
    return undefined;
  }
  if (status === 'TIMED_OUT' && record['failureCode'] !== 'DAST_REQUEST_TIMEOUT' && record['failureCode'] !== 'DAST_SCAN_TIMEOUT') {
    return undefined;
  }
  // Rebuild explicitly from the validated fields (no casts — the
  // optional fields exist exactly when the state machine allows).
  const built: ScanRecord = {
    id: record['id'],
    ownerId: record['ownerId'],
    projectId: record['projectId'],
    scanType: record['scanType'],
    ...(typeof record['assessmentId'] === 'string' ? { assessmentId: record['assessmentId'] } : {}),
    status,
    createdAt: record['createdAt'],
    ...(typeof record['dastTargetUrl'] === 'string' ? { dastTargetUrl: record['dastTargetUrl'] } : {}),
    ...(record['dastMode'] === 'ACTIVE_SAFE' ? { dastMode: 'ACTIVE_SAFE' as const } : record['dastMode'] === 'PASSIVE' ? { dastMode: 'PASSIVE' as const } : {}),
    ...(record['dastActiveConsent'] === true ? { dastActiveConsent: true as const } : {}),
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
    // Pump 11 source findings could derive their project only through the
    // scan link. Hydrate that context from the server-owned scan record on
    // load; never accept a client/row-supplied cross-project value.
    built.findings = (record['findings'] as Finding[]).map((finding) =>
      finding.projectId === undefined ? { ...finding, projectId: record['projectId'] as string } : finding,
    );
  }
  if (record['sca'] !== undefined && isScaResult(record['sca'])) {
    built.sca = record['sca'];
  }
  if (record['dast'] !== undefined && isDastResult(record['dast'])) {
    built.dast = record['dast'];
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
    (record['assessmentId'] !== undefined && (typeof record['assessmentId'] !== 'string' || !ASSESSMENT_ID_PATTERN.test(record['assessmentId']))) ||
    (record['targetUrl'] !== undefined && (record['scanType'] !== 'DAST' || !isSafeDastUrl(record['targetUrl']))) ||
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
    ...(typeof record['assessmentId'] === 'string' ? { assessmentId: record['assessmentId'] } : {}),
    ...(typeof record['targetUrl'] === 'string' ? { targetUrl: record['targetUrl'] } : {}),
    scanId: record['scanId'],
    createdAt: record['createdAt'],
  };
  return entry;
}

function workflowMatchesFinding(record: FindingWorkflow, finding: Finding, projectId: string): boolean {
  return record.projectId === projectId && record.findingId === finding.id &&
    record.fingerprint === finding.fingerprint && record.scanner === findingScanner(finding) &&
    record.ruleId === finding.ruleId;
}

function parseStoredFindingWorkflow(value: unknown, scansById: ReadonlyMap<string, ScanRecord>): FindingWorkflowRecord | undefined {
  if (typeof value !== 'object' || value === null) return undefined;
  const record = value as Record<string, unknown>;
  if (Object.keys(record).length !== 18 || !Object.prototype.hasOwnProperty.call(record, 'history') || !Array.isArray(record['history']) ||
      !isFindingWorkflow(Object.fromEntries(Object.entries(record).filter(([key]) => key !== 'history')))) return undefined;
  const publicWorkflow = Object.fromEntries(Object.entries(record).filter(([key]) => key !== 'history')) as unknown as FindingWorkflow;
  if (record['history'].length !== publicWorkflow.historyTotal || record['history'].length > FINDING_HISTORY_EVENTS_MAX ||
      !record['history'].every(isFindingLifecycleEvent)) return undefined;
  const history = record['history'] as FindingLifecycleEvent[];
  const noteIds = new Set(publicWorkflow.notes.map((note) => note.id));
  const linkedNotes = new Set(history.flatMap((event) => event.action === 'NOTE_ADDED' && event.noteId !== undefined ? [event.noteId] : []));
  if (noteIds.size !== publicWorkflow.notes.length || linkedNotes.size !== publicWorkflow.notes.length ||
      [...noteIds].some((id) => !linkedNotes.has(id)) || history.some((event) =>
        event.findingId !== publicWorkflow.findingId || (event.action === 'NOTE_ADDED') !== (event.noteId !== undefined)) ||
      new Set(history.map((event) => event.id)).size !== history.length) return undefined;
  let state: FindingLifecycleState = 'OPEN';
  for (const [index, event] of history.entries()) {
    if (index === 0) {
      if (event.previousState !== null || event.newState !== 'OPEN' || event.action !== 'FINDING_OBSERVED') return undefined;
      state = 'OPEN';
      continue;
    }
    if (event.previousState !== state) return undefined;
    if (event.action === 'STATE_CHANGED') {
      if (event.actorType !== 'USER' || !canTransitionFinding(state, event.newState)) return undefined;
      state = event.newState;
    } else if (event.action === 'FINDING_REOBSERVED') {
      if (state === 'RESOLVED' || state === 'FALSE_POSITIVE') {
        if (event.newState !== 'REOPENED' || event.actorType !== 'SYSTEM') return undefined;
        state = 'REOPENED';
      } else if (event.newState !== state || event.actorType !== 'SYSTEM') return undefined;
    } else if (event.action === 'NOT_OBSERVED' || event.action === 'NOTE_ADDED') {
      if (event.newState !== state || (event.action === 'NOTE_ADDED' ? event.actorType !== 'USER' : event.actorType !== 'SYSTEM')) return undefined;
    } else return undefined;
  }
  if (state !== publicWorkflow.state || history[0]?.at !== publicWorkflow.firstObservedAt ||
      history[0]?.actorId !== 'system:scanner' || history[0]?.actorType !== 'SYSTEM') return undefined;
  const firstScan = scansById.get(publicWorkflow.firstObservedScanId);
  const lastObservedScan = scansById.get(publicWorkflow.lastObservedScanId);
  const verificationScan = scansById.get(publicWorkflow.lastVerificationScanId);
  const contains = (scan: ScanRecord | undefined): boolean =>
    scan !== undefined && scan.projectId === publicWorkflow.projectId && scan.scanType === publicWorkflow.scanner &&
    scan.status === 'COMPLETED' && (scan.findings ?? []).some((finding) => workflowMatchesFinding(publicWorkflow, finding, scan.projectId));
  if (!contains(firstScan) || !contains(lastObservedScan) || firstScan?.completedAt !== publicWorkflow.firstObservedAt ||
      lastObservedScan?.completedAt !== publicWorkflow.lastObservedAt || verificationScan === undefined ||
      verificationScan.projectId !== publicWorkflow.projectId || verificationScan.scanType !== publicWorkflow.scanner ||
      verificationScan.status !== 'COMPLETED' || verificationScan.completedAt !== publicWorkflow.lastVerificationAt ||
      verificationScan.resultSummary?.findingsTotal !== (verificationScan.findings ?? []).length) return undefined;
  const observedInVerification = (verificationScan.findings ?? []).some((finding) => workflowMatchesFinding(publicWorkflow, finding, verificationScan.projectId));
  if ((publicWorkflow.verificationState === 'OBSERVED') !== observedInVerification ||
      (publicWorkflow.verificationState === 'OBSERVED' && publicWorkflow.lastObservedScanId !== publicWorkflow.lastVerificationScanId)) return undefined;
  return { ...publicWorkflow, history };
}

// An incomplete scan can still positively observe a finding, but its lack
// of a finding is not reliable verification evidence. Older scans without
// coverage fields retain their historical interpretation.
function canVerifyAbsence(summary: ScanResultSummary, dast?: DastResult): boolean {
  return summary.partial !== true && summary.truncated !== true &&
    summary.astSupplement?.status !== 'PARTIAL' && dast?.partial !== true;
}

function migrateFindingWorkflows(scans: readonly ScanRecord[]): FindingWorkflowRecord[] {
  const workflows = new Map<string, FindingWorkflowRecord>();
  const completed = scans.filter((scan) => scan.status === 'COMPLETED' && scan.completedAt !== undefined &&
    scan.resultSummary?.findingsTotal === (scan.findings ?? []).length)
    .sort((a, b) => {
      const byTime = (a.completedAt ?? '') < (b.completedAt ?? '') ? -1 : (a.completedAt ?? '') > (b.completedAt ?? '') ? 1 : 0;
      return byTime || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
    });
  for (const scan of completed) {
    const scanContext = { id: scan.id, projectId: scan.projectId, scanType: scan.scanType, completedAt: scan.completedAt! };
    const currentFindings = scan.findings ?? [];
    const current = new Set(currentFindings.map((finding) => finding.fingerprint));
    if (scan.resultSummary !== undefined && canVerifyAbsence(scan.resultSummary, scan.dast)) {
      for (const [key, prior] of workflows) {
        if (prior.projectId === scan.projectId && prior.scanner === scan.scanType && !current.has(prior.fingerprint)) {
          workflows.set(key, markFindingNotObserved(prior, scanContext));
        }
      }
    }
    for (const finding of currentFindings) {
      const key = findingWorkflowKey(scan.projectId, finding.fingerprint);
      const existing = workflows.get(key);
      workflows.set(key, existing === undefined
        ? createInitialFindingWorkflow(finding, scanContext)
        : observeFindingInScan(existing, finding, scanContext));
      if (workflows.size > FINDING_WORKFLOWS_MAX) throw new Error('Finding workflow migration exceeded the configured record limit.');
    }
  }
  return [...workflows.values()].sort((a, b) => {
    const left = findingWorkflowKey(a.projectId, a.fingerprint);
    const right = findingWorkflowKey(b.projectId, b.fingerprint);
    return left < right ? -1 : left > right ? 1 : 0;
  });
}

function reportMatchesScan(report: SecurityReport, scan: ScanRecord): boolean {
  if (
    scan.status !== 'COMPLETED' || scan.completedAt === undefined || scan.resultSummary === undefined ||
    report.project.id !== scan.projectId || report.scan.id !== scan.id ||
    report.scan.projectId !== scan.projectId || report.scan.scanType !== scan.scanType ||
    report.scan.assessmentId !== scan.assessmentId ||
    report.scan.status !== 'COMPLETED' || report.scan.createdAt !== scan.createdAt ||
    report.scan.updatedAt !== scan.updatedAt || report.scan.startedAt !== scan.startedAt ||
    report.scan.completedAt !== scan.completedAt || report.scan.targetUrl !== scan.dastTargetUrl ||
    (report.scan.dastMode !== undefined && report.scan.dastMode !== scan.dastMode) ||
    canonicalJson(report.scan.resultSummary) !== canonicalJson(scan.resultSummary) ||
    canonicalJson(report.findings) !== canonicalJson(scan.findings ?? []) ||
    report.findingSummary.total !== scan.resultSummary.findingsTotal ||
    canonicalJson(report.dast ?? null) !== canonicalJson(scan.dast ?? null)
  ) return false;
  return scan.sca === undefined
    ? report.inventory.status === 'NOT_INCLUDED'
    : report.inventory.status === 'INCLUDED' && canonicalJson(report.inventory.sca) === canonicalJson(scan.sca);
}

function loadDocument(path: string): StoreDocument {
  let raw: string;
  try {
    raw = readFileSync(path, 'utf8');
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') {
      return { version: 1, scans: [], idempotency: [], reports: [] };
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
    !Array.isArray((parsed as Record<string, unknown>)['idempotency']) ||
    ((parsed as Record<string, unknown>)['reports'] !== undefined &&
      !Array.isArray((parsed as Record<string, unknown>)['reports'])) ||
    (((parsed as Record<string, unknown>)['reports'] as unknown[] | undefined)?.length ?? 0) > REPORT_PERSISTED_MAX_COUNT ||
    ((parsed as Record<string, unknown>)['findingWorkflows'] !== undefined && !Array.isArray((parsed as Record<string, unknown>)['findingWorkflows'])) ||
    (((parsed as Record<string, unknown>)['findingWorkflows'] as unknown[] | undefined)?.length ?? 0) > FINDING_WORKFLOWS_MAX
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
    const linkedScan = scans.find((scan) => scan.id === record.scanId);
    if (linkedScan === undefined || linkedScan.ownerId !== record.accountId || linkedScan.projectId !== record.projectId ||
        linkedScan.scanType !== record.scanType || record.targetUrl !== linkedScan.dastTargetUrl || record.assessmentId !== linkedScan.assessmentId) {
      throw new Error(`Scan store at ${path} has a mismatched idempotency association at index ${index} — refusing to start.`);
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
  const rawReports = ((parsed as Record<string, unknown>)['reports'] ?? []) as unknown[];
  const seenReportScans = new Set<string>();
  const seenReportIds = new Set<string>();
  const reports: SecurityReport[] = [];
  rawReports.forEach((entry, index) => {
    if (!verifySecurityReportIntegrity(entry) ||
        Buffer.byteLength(canonicalJson(entry), 'utf8') > REPORT_MAX_BYTES ||
        seenReportScans.has(entry.scan.id) || seenReportIds.has(entry.reportId)) {
      throw new Error(`Scan store at ${path} has an invalid report at index ${index} — refusing to start.`);
    }
    const scan = scans.find((candidate) => candidate.id === entry.scan.id);
    if (scan === undefined || !reportMatchesScan(entry, scan)) {
      throw new Error(`Scan store at ${path} has a report detached from its completed scan at index ${index} — refusing to start.`);
    }
    seenReportScans.add(entry.scan.id);
    seenReportIds.add(entry.reportId);
    reports.push(entry);
  });
  const workflowField = (parsed as Record<string, unknown>)['findingWorkflows'];
  let findingWorkflows: FindingWorkflowRecord[];
  if (workflowField === undefined) {
    // Pump 12 findings predate workflow rows. Reconstruct only from durable
    // completed scans, without changing any scanner evidence or reports.
    findingWorkflows = migrateFindingWorkflows(scans);
  } else {
    const seenIds = new Set<string>();
    const seenKeys = new Set<string>();
    const scansById = new Map(scans.map((scan) => [scan.id, scan]));
    findingWorkflows = [];
    (workflowField as unknown[]).forEach((entry, index) => {
      const workflow = parseStoredFindingWorkflow(entry, scansById);
      if (workflow === undefined || seenIds.has(workflow.id) || seenKeys.has(findingWorkflowKey(workflow.projectId, workflow.fingerprint))) {
        throw new Error(`Scan store at ${path} has an invalid finding workflow at index ${index} — refusing to start.`);
      }
      seenIds.add(workflow.id);
      seenKeys.add(findingWorkflowKey(workflow.projectId, workflow.fingerprint));
      findingWorkflows.push(workflow);
    });
  }
  return { version: 1, scans, idempotency, reports, findingWorkflows };
}

interface StoreInternals {
  scans: ScanRecord[];
  idempotency: IdempotencyEntry[];
  reports: SecurityReport[];
  findingWorkflows: FindingWorkflowRecord[];
  /** Persist the full next state atomically (called inside the queue). */
  persistWith(scans: ScanRecord[], idempotency: IdempotencyEntry[], reports: SecurityReport[], findingWorkflows: FindingWorkflowRecord[]): void;
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
  const reportsByScan = new Map<string, SecurityReport>();
  for (const report of internals.reports) reportsByScan.set(report.scan.id, report);
  const findingWorkflowsByKey = new Map<string, FindingWorkflowRecord>();
  for (const workflow of internals.findingWorkflows) {
    findingWorkflowsByKey.set(findingWorkflowKey(workflow.projectId, workflow.fingerprint), workflow);
  }
  const workflowValues = (source: ReadonlyMap<string, FindingWorkflowRecord> = findingWorkflowsByKey): FindingWorkflowRecord[] =>
    [...source.values()].sort((a, b) => {
      const left = findingWorkflowKey(a.projectId, a.fingerprint);
      const right = findingWorkflowKey(b.projectId, b.fingerprint);
      return left < right ? -1 : left > right ? 1 : 0;
    });
  const copyWorkflow = (workflow: FindingWorkflowRecord): FindingWorkflow => {
    const { history: _history, ...publicWorkflow } = workflow;
    void _history;
    return JSON.parse(JSON.stringify(publicWorkflow)) as FindingWorkflow;
  };

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
    internals.persistWith(nextScans, [...idempotencyByKey.values()], [...reportsByScan.values()], workflowValues());
    scansById.set(updated.id, updated);
    return toPublic(updated);
  };

  return {
    createScanWithQuota: (input) =>
      runExclusive(async () => {
        // Defense in depth: malformed/missing DAST targets and stray
        // target claims on other scan types never reach quota consumption.
        if (
          (input.scanType === 'DAST' && !isSafeDastUrl(input.targetUrl)) ||
          (input.scanType !== 'DAST' && input.targetUrl !== undefined)
        ) return { outcome: 'invalid-target' };
        // 1. Idempotency replay — BEFORE consuming anything. Scoped to
        //    (ownerId, key); another account's key is simply absent.
        if (input.idempotencyKey !== undefined) {
          const existing = idempotencyByKey.get(`${input.ownerId}:${input.idempotencyKey}`);
          if (existing !== undefined) {
            if (
              existing.projectId !== input.projectId ||
              existing.scanType !== input.scanType ||
              existing.targetUrl !== input.targetUrl ||
              existing.assessmentId !== input.assessmentId
            ) {
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
          ...(input.assessmentId === undefined ? {} : { assessmentId: input.assessmentId }),
          ...(input.targetUrl === undefined ? {} : { dastTargetUrl: input.targetUrl }),
          ...(input.dastMode === undefined ? {} : { dastMode: input.dastMode }),
          ...(input.dastActiveConsent === true ? { dastActiveConsent: true as const } : {}),
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
            ...(input.assessmentId === undefined ? {} : { assessmentId: input.assessmentId }),
            ...(input.targetUrl === undefined ? {} : { targetUrl: input.targetUrl }),
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
        internals.persistWith(nextScans, nextIdempotency, [...reportsByScan.values()], workflowValues());
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

    workspaceSummary: (ownerId, projectId) => {
      const scansSummary = emptyWorkspaceScansSummary();
      const findingsSummary = emptyWorkspaceFindingsSummary();
      const reportsSummary: WorkspaceReportsSummary = { availableCount: 0, recent: [] };
      const latestFindingByIdentity = new Map<string, {
        finding: Finding;
        projectId: string;
        scanId: string;
        observedAt: string;
      }>();
      const scanOrder = (a: WorkspaceScanCard, b: WorkspaceScanCard): number =>
        b.createdAt.localeCompare(a.createdAt) || a.scanId.localeCompare(b.scanId);
      const findingOrder = (a: WorkspaceFindingCard, b: WorkspaceFindingCard): number =>
        b.workflowUpdatedAt.localeCompare(a.workflowUpdatedAt) || b.observedAt.localeCompare(a.observedAt) || a.projectId.localeCompare(b.projectId) ||
        a.scanId.localeCompare(b.scanId) || a.findingId.localeCompare(b.findingId);
      const reportOrder = (a: WorkspaceReportCard, b: WorkspaceReportCard): number =>
        b.generatedAt.localeCompare(a.generatedAt) || a.reportId.localeCompare(b.reportId);

      for (const scan of scansById.values()) {
        if (scan.ownerId !== ownerId || (projectId !== undefined && scan.projectId !== projectId)) continue;
        scansSummary.total += 1;
        scansSummary.byStatus[scan.status] += 1;
        scansSummary.recent.push({
          scanId: scan.id,
          projectId: scan.projectId,
          scanType: scan.scanType,
          status: scan.status,
          createdAt: scan.createdAt,
          completedAt: scan.completedAt ?? null,
          findingsTotal: scan.resultSummary?.findingsTotal ?? null,
          partial: scan.resultSummary?.partial ?? null,
          reportAvailable: reportsByScan.get(scan.id)?.project.id === scan.projectId,
          dastObservationsCount: scan.status === 'COMPLETED' && scan.scanType === 'DAST' ? scan.dast?.observations.length ?? null : null,
          scaAssessmentState: scan.status === 'COMPLETED' && scan.scanType === 'SCA' ? scan.sca?.summary.assessmentState ?? null : null,
          scaDatasetStatus: scan.status === 'COMPLETED' && scan.scanType === 'SCA' ? scan.sca?.summary.datasetStatus ?? null : null,
        });
        scansSummary.recent.sort(scanOrder);
        if (scansSummary.recent.length > WORKSPACE_SCANS_MAX) scansSummary.recent.pop();

        if (scan.status !== 'COMPLETED') continue;
        const observedAt = scan.completedAt ?? scan.createdAt;
        for (const finding of scan.findings ?? []) {
          const key = findingWorkflowKey(scan.projectId, finding.fingerprint);
          const previous = latestFindingByIdentity.get(key);
          if (previous === undefined || observedAt > previous.observedAt ||
              (observedAt === previous.observedAt && scan.id < previous.scanId)) {
            latestFindingByIdentity.set(key, { finding, projectId: scan.projectId, scanId: scan.id, observedAt });
          }
        }
      }

      findingsSummary.currentObserved = latestFindingByIdentity.size;
      for (const [key, entry] of latestFindingByIdentity) {
        const workflow = findingWorkflowsByKey.get(key);
        const lifecycleState = workflow?.state ?? 'OPEN';
        const verificationState = workflow?.verificationState ?? 'OBSERVED';
        findingsSummary.byLifecycleState[lifecycleState] += 1;
        findingsSummary.byVerificationState[verificationState] += 1;
        if (lifecycleState !== 'RESOLVED' && lifecycleState !== 'FALSE_POSITIVE') {
          findingsSummary.unresolved += 1;
          findingsSummary.unresolvedBySeverity[entry.finding.severity] += 1;
        }
        const observedScan = scansById.get(entry.scanId);
        if (observedScan === undefined) continue;
        findingsSummary.recent.push({
          findingId: entry.finding.id,
          projectId: entry.projectId,
          scanId: entry.scanId,
          scanner: findingScanner(entry.finding) ?? observedScan.scanType,
          ruleId: entry.finding.ruleId,
          severity: entry.finding.severity,
          lifecycleState,
          verificationState,
          observedAt: entry.observedAt,
          workflowUpdatedAt: workflow?.updatedAt ?? entry.observedAt,
        });
      }
      findingsSummary.recent.sort(findingOrder);
      findingsSummary.recent.length = Math.min(findingsSummary.recent.length, WORKSPACE_FINDINGS_MAX);

      for (const report of reportsByScan.values()) {
        const scan = scansById.get(report.scan.id);
        if (scan === undefined || scan.ownerId !== ownerId || scan.projectId !== report.project.id ||
            (projectId !== undefined && scan.projectId !== projectId)) continue;
        reportsSummary.availableCount += 1;
        reportsSummary.recent.push({
          reportId: report.reportId,
          projectId: report.project.id,
          scanId: report.scan.id,
          generatedAt: report.generatedAt,
        });
        reportsSummary.recent.sort(reportOrder);
        if (reportsSummary.recent.length > WORKSPACE_REPORTS_MAX) reportsSummary.recent.pop();
      }

      return Promise.resolve({ scans: scansSummary, findings: findingsSummary, reports: reportsSummary });
    },

    adminSummary: (now) => {
      const byStatus: Record<ScanStatus, number> = { QUEUED: 0, RUNNING: 0, COMPLETED: 0, FAILED: 0, TIMED_OUT: 0 };
      const byType: Record<ScanType, number> = { SAST: 0, SCA: 0, SECRETS: 0, DAST: 0 };
      const findingsBySeverity: Record<(typeof FINDING_SEVERITIES)[number], number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
      const findingsByLifecycleState: Record<FindingLifecycleState, number> = { OPEN: 0, ACKNOWLEDGED: 0, IN_PROGRESS: 0, RESOLVED: 0, FALSE_POSITIVE: 0, REOPENED: 0 };
      const latestFindingByIdentity = new Map<string, { finding: Finding; completedAt: string }>();
      let recentlyCompleted = 0;
      let dastObservations = 0;
      let scaNotAssessed = 0;
      const recentBoundary = now - 30 * 24 * 60 * 60 * 1000;
      for (const scan of scansById.values()) {
        byStatus[scan.status] += 1;
        byType[scan.scanType] += 1;
        if (scan.status !== 'COMPLETED') continue;
        const completedAt = scan.completedAt ?? '';
        if (completedAt !== '' && Date.parse(completedAt) >= recentBoundary) recentlyCompleted += 1;
        if (scan.scanType === 'DAST') dastObservations += scan.dast?.observations.length ?? 0;
        if (scan.scanType === 'SCA' && scan.sca?.summary.assessmentState === 'NOT_ASSESSED') scaNotAssessed += 1;
        for (const finding of scan.findings ?? []) {
          const key = findingWorkflowKey(scan.projectId, finding.fingerprint);
          const prior = latestFindingByIdentity.get(key);
          if (prior === undefined || completedAt > prior.completedAt) latestFindingByIdentity.set(key, { finding, completedAt });
        }
      }
      let unresolvedFindings = 0;
      for (const workflow of findingWorkflowsByKey.values()) {
        findingsByLifecycleState[workflow.state] += 1;
        if (workflow.state !== 'RESOLVED' && workflow.state !== 'FALSE_POSITIVE') unresolvedFindings += 1;
      }
      for (const [key, entry] of latestFindingByIdentity) {
        const workflow = findingWorkflowsByKey.get(key);
        if (workflow?.state === 'RESOLVED' || workflow?.state === 'FALSE_POSITIVE') continue;
        findingsBySeverity[entry.finding.severity] += 1;
      }
      return Promise.resolve({ total: scansById.size, byStatus, byType, recentlyCompleted, findingsBySeverity, findingsByLifecycleState, unresolvedFindings, dastObservations, scaNotAssessed });
    },

    adminScanPage: (filters, page, pageSize) => {
      const offset = (page - 1) * pageSize;
      const retain = offset + pageSize;
      const candidates: AdminScanSummary[] = [];
      let total = 0;
      const compare = (a: AdminScanSummary, b: AdminScanSummary): number =>
        b.createdAt.localeCompare(a.createdAt) || a.scanId.localeCompare(b.scanId);
      for (const scan of scansById.values()) {
        const observedAt = scan.completedAt ?? scan.createdAt;
        if (filters.status !== undefined && scan.status !== filters.status) continue;
        if (filters.scanType !== undefined && scan.scanType !== filters.scanType) continue;
        if (filters.accountId !== undefined && scan.ownerId !== filters.accountId) continue;
        if (filters.projectId !== undefined && scan.projectId !== filters.projectId) continue;
        if (filters.from !== undefined && observedAt < filters.from) continue;
        if (filters.to !== undefined && observedAt > filters.to) continue;
        total += 1;
        candidates.push({
          scanId: scan.id, projectId: scan.projectId, accountId: scan.ownerId,
          scanType: scan.scanType, status: scan.status, createdAt: scan.createdAt,
          completedAt: scan.completedAt ?? null, findingsTotal: scan.resultSummary?.findingsTotal ?? 0,
        });
        if (candidates.length >= retain + 1000) {
          candidates.sort(compare);
          candidates.length = retain;
        }
      }
      candidates.sort(compare);
      return Promise.resolve({ scans: candidates.slice(offset, offset + pageSize), total });
    },

    adminFindingPage: (filters, page, pageSize) => {
      const offset = (page - 1) * pageSize;
      const retain = offset + pageSize;
      const candidates: AdminFindingSummary[] = [];
      let total = 0;
      const compare = (a: AdminFindingSummary, b: AdminFindingSummary): number =>
        b.observedAt.localeCompare(a.observedAt) || a.scanId.localeCompare(b.scanId) || a.findingNumber - b.findingNumber;
      for (const scan of scansById.values()) {
        if (scan.status !== 'COMPLETED' || (filters.projectId !== undefined && scan.projectId !== filters.projectId)) continue;
        const observedAt = scan.completedAt ?? scan.createdAt;
        if (filters.from !== undefined && observedAt < filters.from) continue;
        if (filters.to !== undefined && observedAt > filters.to) continue;
        for (const [findingIndex, finding] of (scan.findings ?? []).entries()) {
          const scanner = findingScanner(finding) ?? scan.scanType;
          const workflow = findingWorkflowsByKey.get(findingWorkflowKey(scan.projectId, finding.fingerprint));
          const lifecycleState = workflow?.state ?? 'OPEN';
          if (filters.severity !== undefined && finding.severity !== filters.severity) continue;
          if (filters.scanner !== undefined && scanner !== filters.scanner) continue;
          if (filters.lifecycleState !== undefined && lifecycleState !== filters.lifecycleState) continue;
          total += 1;
          candidates.push({
            findingNumber: findingIndex + 1, scanId: scan.id, projectId: scan.projectId, scanner,
            ruleId: finding.ruleId, severity: finding.severity, lifecycleState, observedAt,
          });
          if (candidates.length >= retain + 1000) {
            candidates.sort(compare);
            candidates.length = retain;
          }
        }
      }
      candidates.sort(compare);
      return Promise.resolve({ findings: candidates.slice(offset, offset + pageSize), total });
    },

    listLatestCompletedByScannerForAssistant: (projectId) => {
      const latest = new Map<ScanType, ScanRecord>();
      for (const record of scansById.values()) {
        if (record.projectId !== projectId || record.status !== 'COMPLETED') continue;
        const current = latest.get(record.scanType);
        const recordTime = record.completedAt ?? '';
        const currentTime = current?.completedAt ?? '';
        if (current === undefined || recordTime > currentTime || (recordTime === currentTime && record.id < current.id)) {
          latest.set(record.scanType, record);
        }
      }
      return Promise.resolve([...latest.values()].sort((a, b) =>
        (a.completedAt ?? '') > (b.completedAt ?? '') ? -1 :
          (a.completedAt ?? '') < (b.completedAt ?? '') ? 1 : a.id < b.id ? -1 : 1,
      ).map(toPublic));
    },

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

    completeScan: (id, resultSummary, findings, sca, dast) =>
      runExclusive(() => {
        const current = scansById.get(id);
        if (current === undefined || current.status !== 'RUNNING') return undefined;
        if (!isScanResultSummary(resultSummary)) return undefined;
        if ((resultSummary.astParser !== undefined || resultSummary.astCoverage !== undefined) && current.scanType !== 'SAST') return undefined;
        if (!isAstSupplementForScanType(resultSummary, current.scanType)) return undefined;
        if (sca !== undefined && !(isScaResult(sca) && current.scanType === 'SCA')) return undefined;
        if (dast !== undefined && !(isDastResult(dast) && current.scanType === 'DAST' && dast.targetUrl === current.dastTargetUrl)) return undefined;
        if ((current.scanType === 'DAST') !== (dast !== undefined)) return undefined;
        const contextualFindings = findings?.map((finding) =>
          finding.scanner === 'DAST' || finding.ruleId.startsWith('DG-DAST-')
            ? finding
            : { ...finding, projectId: current.projectId },
        );
        const safeFindings = contextualFindings === undefined || contextualFindings.length === 0
          ? undefined
          : contextualFindings.slice(0, MAX_FINDINGS_PER_SCAN);
        const actualFindings = safeFindings ?? [];
        if (contextualFindings !== undefined && contextualFindings.length !== actualFindings.length) return undefined;
        if (!actualFindings.every((finding) =>
          isFinding(finding) && finding.scanId === id && finding.projectId === current.projectId &&
          findingScanner(finding) === current.scanType,
        )) return undefined;
        if (new Set(actualFindings.map((finding) => finding.fingerprint)).size !== actualFindings.length ||
            (safeFindings !== undefined && resultSummary.findingsTotal !== safeFindings.length)) return undefined;
        if (actualFindings.some((finding) => finding.scanner === 'DAST' && finding.targetUrl !== current.dastTargetUrl)) return undefined;

        const completedAt = new Date().toISOString();
        const updated: ScanRecord = {
          ...current,
          status: 'COMPLETED',
          completedAt,
          updatedAt: completedAt,
          resultSummary,
          ...(safeFindings === undefined ? {} : { findings: safeFindings }),
          ...(sca === undefined ? {} : { sca }),
          ...(dast === undefined ? {} : { dast }),
        };
        const scanContext = { id, projectId: current.projectId, scanType: current.scanType, completedAt };
        const findingsAreAuthoritative = resultSummary.findingsTotal === actualFindings.length;
        const nextWorkflows = new Map(findingWorkflowsByKey);
        if (findingsAreAuthoritative) {
          const observed = new Set(actualFindings.map((finding) => finding.fingerprint));
          if (canVerifyAbsence(resultSummary, dast)) {
            for (const [key, workflow] of nextWorkflows) {
              if (workflow.projectId === current.projectId && workflow.scanner === current.scanType && !observed.has(workflow.fingerprint)) {
                nextWorkflows.set(key, markFindingNotObserved(workflow, scanContext));
              }
            }
          }
          for (const finding of actualFindings) {
            const key = findingWorkflowKey(current.projectId, finding.fingerprint);
            const workflow = nextWorkflows.get(key);
            if (workflow === undefined) {
              if (nextWorkflows.size >= FINDING_WORKFLOWS_MAX) return undefined;
              nextWorkflows.set(key, createInitialFindingWorkflow(finding, scanContext));
            } else {
              if (!workflowMatchesFinding(workflow, finding, current.projectId)) return undefined;
              nextWorkflows.set(key, observeFindingInScan(workflow, finding, scanContext));
            }
          }
        }
        const nextScans = [...scansById.values()].map((scan) => scan.id === id ? updated : scan);
        const nextWorkflowValues = workflowValues(nextWorkflows);
        internals.persistWith(nextScans, [...idempotencyByKey.values()], [...reportsByScan.values()], nextWorkflowValues);
        scansById.set(id, updated);
        findingWorkflowsByKey.clear();
        for (const workflow of nextWorkflowValues) findingWorkflowsByKey.set(findingWorkflowKey(workflow.projectId, workflow.fingerprint), workflow);
        return toPublic(updated);
      }),

    timeoutScan: (id, failureCode, failureMessage) =>
      runExclusive(() => {
        const current = scansById.get(id);
        if (
          current === undefined || current.status !== 'RUNNING' || current.scanType !== 'DAST' ||
          (failureCode !== 'DAST_REQUEST_TIMEOUT' && failureCode !== 'DAST_SCAN_TIMEOUT')
        ) return undefined;
        const updated = applyClaimPersist(current, (record) => ({
          ...record,
          status: 'TIMED_OUT',
          completedAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
          failureCode,
          failureMessage: failureMessage.slice(0, SCAN_FAILURE_MESSAGE_MAX_LENGTH),
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

    findReportByProjectAndScan: async (projectId, scanId) => {
      const report = reportsByScan.get(scanId);
      return report === undefined || report.project.id !== projectId
        ? undefined
        : JSON.parse(JSON.stringify(report)) as SecurityReport;
    },

    createReport: (report) =>
      runExclusive(() => {
        if (!verifySecurityReportIntegrity(report) ||
            Buffer.byteLength(canonicalJson(report), 'utf8') > REPORT_MAX_BYTES) {
          return { outcome: 'invalid-report' as const };
        }
        const scan = scansById.get(report.scan.id);
        if (scan === undefined || !reportMatchesScan(report, scan)) {
          return { outcome: 'scan-unavailable' as const };
        }
        if (report.findingWorkflows !== undefined) {
          const currentSnapshots = report.findings.flatMap((finding) => {
            const workflow = findingWorkflowsByKey.get(findingWorkflowKey(report.project.id, finding.fingerprint));
            return workflow !== undefined && workflowMatchesFinding(workflow, finding, report.project.id) ? [copyWorkflow(workflow)] : [];
          });
          if (currentSnapshots.length !== report.findings.length || canonicalJson(currentSnapshots) !== canonicalJson(report.findingWorkflows)) {
            return { outcome: 'workflow-changed' as const };
          }
        }
        const existing = reportsByScan.get(scan.id);
        if (existing !== undefined) {
          if (existing.contentDigest === report.contentDigest) {
            return { outcome: 'existing' as const, report: JSON.parse(JSON.stringify(existing)) as SecurityReport };
          }
          const nextReports = [...reportsByScan.values()].map((item) => item.scan.id === scan.id ? report : item)
            .sort((a, b) => a.reportId.localeCompare(b.reportId));
          internals.persistWith([...scansById.values()], [...idempotencyByKey.values()], nextReports, workflowValues());
          reportsByScan.set(scan.id, report);
          return { outcome: 'updated' as const, report: JSON.parse(JSON.stringify(report)) as SecurityReport };
        }
        if (reportsByScan.size >= REPORT_PERSISTED_MAX_COUNT) {
          return { outcome: 'capacity-exceeded' as const };
        }
        const nextReports = [...reportsByScan.values(), report].sort((a, b) => a.reportId.localeCompare(b.reportId));
        internals.persistWith([...scansById.values()], [...idempotencyByKey.values()], nextReports, workflowValues());
        reportsByScan.set(scan.id, report);
        return { outcome: 'created' as const, report: JSON.parse(JSON.stringify(report)) as SecurityReport };
      }),

    getFindingWorkflow: (projectId, fingerprint) => {
      const workflow = findingWorkflowsByKey.get(findingWorkflowKey(projectId, fingerprint));
      return Promise.resolve(workflow === undefined ? undefined : copyWorkflow(workflow));
    },

    getFindingWorkflowsForFindings: (projectId, findings) => Promise.resolve(
      findings.flatMap((finding) => {
        const workflow = findingWorkflowsByKey.get(findingWorkflowKey(projectId, finding.fingerprint));
        return workflow !== undefined && workflowMatchesFinding(workflow, finding, projectId) ? [copyWorkflow(workflow)] : [];
      }),
    ),

    transitionFindingLifecycle: (projectId, fingerprint, next, actorId, at) => runExclusive(() => {
      const key = findingWorkflowKey(projectId, fingerprint);
      const current = findingWorkflowsByKey.get(key);
      if (current === undefined) return { outcome: 'not-found' as const };
      if (!canTransitionFinding(current.state, next)) return { outcome: 'invalid-transition' as const };
      if (current.history.length >= FINDING_HISTORY_EVENTS_MAX - 1) return { outcome: 'history-limit' as const };
      const updated = appendUserStateEvent(current, next, actorId, at);
      if (updated === undefined) return { outcome: 'history-limit' as const };
      const { history: _history, ...publicUpdated } = updated;
      void _history;
      if (!isFindingWorkflow(publicUpdated) || !updated.history.every(isFindingLifecycleEvent)) return { outcome: 'history-limit' as const };
      const nextWorkflows = new Map(findingWorkflowsByKey);
      nextWorkflows.set(key, updated);
      internals.persistWith([...scansById.values()], [...idempotencyByKey.values()], [...reportsByScan.values()], workflowValues(nextWorkflows));
      findingWorkflowsByKey.set(key, updated);
      return { outcome: 'updated' as const, workflow: copyWorkflow(updated) };
    }),

    addFindingRemediationNote: (projectId, fingerprint, prepared, actorId, at) => runExclusive(() => {
      const key = findingWorkflowKey(projectId, fingerprint);
      const current = findingWorkflowsByKey.get(key);
      if (current === undefined) return { outcome: 'not-found' as const };
      if (current.notes.length >= FINDING_NOTES_MAX_COUNT) return { outcome: 'notes-limit' as const };
      if (current.history.length >= FINDING_HISTORY_EVENTS_MAX - 1) return { outcome: 'history-limit' as const };
      const normalized = prepareFindingNote(prepared.text);
      if (!normalized.ok) return { outcome: 'invalid-note' as const };
      const safePrepared = { ...normalized, redacted: normalized.redacted || prepared.redacted };
      const updated = appendUserNote(current, safePrepared, actorId, at);
      if (updated === undefined) return { outcome: 'history-limit' as const };
      const { history: _history, ...publicUpdated } = updated;
      void _history;
      if (!isFindingWorkflow(publicUpdated) || !updated.history.every(isFindingLifecycleEvent)) return { outcome: 'invalid-note' as const };
      const nextWorkflows = new Map(findingWorkflowsByKey);
      nextWorkflows.set(key, updated);
      internals.persistWith([...scansById.values()], [...idempotencyByKey.values()], [...reportsByScan.values()], workflowValues(nextWorkflows));
      findingWorkflowsByKey.set(key, updated);
      return { outcome: 'updated' as const, workflow: copyWorkflow(updated) };
    }),

    getFindingHistory: (projectId, fingerprint, page, pageSize) => {
      if (!Number.isInteger(page) || page < 1 || page > FINDING_HISTORY_PAGE_MAX ||
          !Number.isInteger(pageSize) || pageSize < 1 || pageSize > FINDING_HISTORY_PAGE_SIZE_MAX) return Promise.resolve(undefined);
      const workflow = findingWorkflowsByKey.get(findingWorkflowKey(projectId, fingerprint));
      if (workflow === undefined) return Promise.resolve(undefined);
      const events = [...workflow.history].reverse();
      const total = events.length;
      return Promise.resolve({
        events: events.slice((page - 1) * pageSize, page * pageSize),
        page, pageSize, total, totalPages: Math.ceil(total / pageSize),
      });
    },

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
        internals.persistWith(nextScans, [...idempotencyByKey.values()], [...reportsByScan.values()], workflowValues());
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
  const persistWith = (
    scans: ScanRecord[], idempotency: IdempotencyEntry[], reports: SecurityReport[], findingWorkflows: FindingWorkflowRecord[],
  ): void => {
    mkdirSync(dirname(path), { recursive: true });
    const payload: StoreDocument = { version: 1, scans, idempotency, reports, findingWorkflows };
    const tempPath = join(dirname(path), `.${randomBytes(6).toString('hex')}.tmp`);
    writeFileSync(tempPath, `${JSON.stringify(payload, null, 2)}\n`, { mode: 0o600 });
    renameSync(tempPath, path);
  };
  return createScanStoreFrom({
    scans: document.scans,
    idempotency: document.idempotency,
    reports: document.reports,
    findingWorkflows: document.findingWorkflows ?? [],
    persistWith,
  });
}

/** In-memory scan store (tests and explicit `:memory:` setups). */
export function createMemoryScanStore(): ScanStore {
  return createScanStoreFrom({ scans: [], idempotency: [], reports: [], findingWorkflows: [], persistWith: () => undefined });
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
    ...(record.dast === undefined ? {} : { dast: record.dast }),
  };
}

/** The public scan shape (no ownerId, no internals) for API responses. */
export function toScanResponse(record: ScanRecord): Scan {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- legacy untyped boundary; new modules use unknown.
  const sharedScan: any = {
    id: record.id,
    projectId: record.projectId,
    scanType: record.scanType,
    status: record.status,
    ...(record.assessmentId === undefined ? {} : { assessmentId: record.assessmentId }),
    ...(record.dastTargetUrl === undefined ? {} : { targetUrl: record.dastTargetUrl }),
    ...(record.dastMode === undefined ? {} : { dastMode: record.dastMode }),
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
    ...(record.startedAt === undefined ? {} : { startedAt: record.startedAt }),
    ...(record.completedAt === undefined ? {} : { completedAt: record.completedAt }),
    ...(record.failureCode === undefined ? {} : { failureCode: record.failureCode }),
    ...(record.failureMessage === undefined ? {} : { failureMessage: record.failureMessage }),
    ...(record.resultSummary === undefined ? {} : { resultSummary: record.resultSummary }),
  };
  return sharedScan as Scan;
}
