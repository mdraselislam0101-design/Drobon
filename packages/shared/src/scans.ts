import { isDastResult, isSafeDastUrl, type DastResult } from './dast.js';
import { PROJECT_ID_PATTERN } from './projects.js';
import { ASSESSMENT_ID_PATTERN } from './assessmentIds.js';
import { isValidSourcePath } from './sources.js';

/**
 * Scan job contracts (Pump 7) — the secure orchestration boundary future
 * scanner engines (SAST/SCA/SECRETS/DAST) plug into.
 *
 * IMPORTANT — what this module is NOT:
 * - it is NOT a vulnerability database and carries no CVE/NVD/GHSA/OSV/
 *   KEV/EPSS data (the dataset lock forbids that, forever separately);
 * - this module defines scan contracts, not scanner implementations.
 *   `SCAN_TYPES` are supported job types; the API's server-side registry
 *   decides which engines run. An unavailable engine fails with
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
export const SCAN_STATUSES = ['QUEUED', 'RUNNING', 'COMPLETED', 'FAILED', 'TIMED_OUT'] as const;

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
 *   (used only when a real engine is unavailable; DAST is now limited
 *   passive HTTP in Pump 11);
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
  'SECRETS_TARGET_NOT_FOUND',
  'SECRETS_TARGET_TOO_LARGE',
  'SECRETS_FILE_LIMIT_EXCEEDED',
  'SECRETS_SCAN_TIMEOUT',
  'SECRETS_INPUT_INVALID',
  'DAST_TARGET_NOT_FOUND',
  'DAST_TARGET_INVALID',
  'DAST_TARGET_BLOCKED',
  'DAST_DNS_FAILED',
  'DAST_REQUEST_FAILED',
  'DAST_REQUEST_TIMEOUT',
  'DAST_SCAN_TIMEOUT',
  'DAST_ACTIVE_CONSENT_REQUIRED',
  'DAST_ACTIVE_NOT_ALLOWED',
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
  /** Bounded number of HTTP requests actually made by DAST. */
  requestsMade?: number;
  /** Same-host redirects actually followed by DAST. */
  redirectsFollowed?: number;
  /**
   * True when the engine analyzed only PART of the snapshot because a
   * configured limit was hit (e.g. an oversize file was skipped, or
   * the findings cap truncated the sweep). A PARTIAL scan with 0
   * findings is NOT "no secrets" — it is "no secrets in what was
   * inspected". Required honesty for the secrets engine (Pump 10);
   * rendered explicitly in the UI.
   */
  partial?: boolean;
  /** Bounded reason for `partial` (never source content). */
  partialReason?: string;
  /** SCA declaration rules actually evaluated against a parsed artifact in this scan. */
  declarationRulesEvaluated?: number;
  /** SCA declaration rules not evaluated (artifact absent or parser not readable yet). */
  declarationRulesNotEvaluated?: number;
  /** Files analyzed by the bounded AST/dataflow pass (Pump 16). */
  astFilesAnalyzed?: number;
  /** Findings produced by the bounded AST/dataflow pass. */
  astFlowsFound?: number;
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
  'requestsMade',
  'redirectsFollowed',
  // Secrets engine (Pump 10): explicit partial-scan honesty.
  'partial',
  'partialReason',
  // SCA declaration evaluator (Pump 14): honest per-scan coverage.
  'declarationRulesEvaluated',
  'declarationRulesNotEvaluated',
  // Bounded AST/dataflow pass (Pump 16): honest coverage counters.
  'astFilesAnalyzed',
  'astFlowsFound',
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
  if (record['requestsMade'] !== undefined && (!isCount(record['requestsMade']) || record['requestsMade'] > 20)) {
    return false;
  }
  if (record['redirectsFollowed'] !== undefined && (!isCount(record['redirectsFollowed']) || record['redirectsFollowed'] > 5)) {
    return false;
  }
  if (record['partial'] !== undefined && typeof record['partial'] !== 'boolean') {
    return false;
  }
  // partialReason: bounded, control-character-free text — and it may
  // only exist when partial is actually true (never a dangling reason).
  if (record['partialReason'] !== undefined) {
    if (record['partial'] !== true || typeof record['partialReason'] !== 'string') {
      return false;
    }
    if (record['partialReason'].length === 0 || record['partialReason'].length > 200) {
      return false;
    }
    for (const char of record['partialReason']) {
      const code = char.codePointAt(0) ?? 0;
      if (code < 0x20 || code === 0x7f) {
        return false;
      }
    }
  }
  if (record['declarationRulesEvaluated'] !== undefined && !isCount(record['declarationRulesEvaluated'])) {
    return false;
  }
  if (record['declarationRulesNotEvaluated'] !== undefined && !isCount(record['declarationRulesNotEvaluated'])) {
    return false;
  }
  if (record['astFilesAnalyzed'] !== undefined && !isCount(record['astFilesAnalyzed'])) {
    return false;
  }
  if (record['astFlowsFound'] !== undefined && !isCount(record['astFlowsFound'])) {
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
  /** Project/owner-scoped assessment relation, when a scan is explicitly linked. */
  assessmentId?: string;
  /** Canonical target, present only for DAST scans. */
  targetUrl?: string;
  /** DAST mode: PASSIVE (default, ≤3 req) or ACTIVE_SAFE (crawl+injection, ≤20 req, consent required). */
  dastMode?: 'PASSIVE' | 'ACTIVE_SAFE';
  /** Set on a terminal status (COMPLETED, FAILED, or TIMED_OUT). */
  completedAt?: string;
  /** Terminal failure classification (FAILED or TIMED_OUT only). */
  failureCode?: ScanFailureCode;
  /** Safe, bounded, human-readable failure detail (FAILED or TIMED_OUT only). */
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
export const SAST_RULE_ID_PATTERN = /^(?:DG|DPK)-SAST-[0-9]{3}$/;

/**
 * The finding rule-id family pattern (Pump 10): every engine's rules
 * share the `DG-<ENGINE>-###` shape so a finding always identifies its
 * scanner family by id alone (`DG-SAST-###` static analysis,
 * `DG-SEC-###` secrets). Closed — no free-form rule ids.
 */
// Dataset packs legitimately ship 4-digit ids (DPK-SAST-1000 …). The
// scanner family is still closed: no free-form rule ids, no client input.
export const FINDING_RULE_ID_PATTERN = /^(?:(?:DG|DPK)-(?:SAST|SEC|DAST)-[0-9]{3,6}|DPK-SCA-[0-9]{3,6}|ADV-[0-9]{4,})$/;

/**
 * Detection confidence (Pump 10, secrets): how certain the RULE is
 * that the match is real credential material — deterministic,
 * rule-defined, never guessed by the UI. HIGH = structural/known
 * format (e.g. a private-key header, a known service-key prefix);
 * MEDIUM = strong shape + context (assignment + length + character
 * mix); LOW = deliberate residual uncertainty (documented per rule).
 * This is DETECTION confidence, never "the credential is live".
 */
export const FINDING_CONFIDENCES = ['LOW', 'MEDIUM', 'HIGH'] as const;
export type FindingConfidence = (typeof FINDING_CONFIDENCES)[number];

export function isFindingConfidence(value: unknown): value is FindingConfidence {
  return (
    typeof value === 'string' && (FINDING_CONFIDENCES as readonly string[]).includes(value)
  );
}

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
interface FindingBase {
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
  /** Bounded, sanitized evidence. Credential and cookie values are redacted. */
  evidence: string;
  /** Rule-specific remediation guidance (separate from evidence). */
  remediation: string;
  /** Detection confidence (Pump 10, secrets only); never credential validity. */
  confidence?: FindingConfidence;
  /** Deterministic SHA-256 identity. */
  fingerprint: string;
}

/**
 * Source/manifest finding produced by SAST, Secrets, or the SCA
 * declaration evaluator (Pump 14). Declaration findings carry a manifest
 * path and a 1-based line just like source findings; their evidence never
 * contains a declared VALUE (registry tokens are withheld).
 */
export interface SourceFinding extends FindingBase {
  scanner?: 'SAST' | 'SECRETS' | 'SCA';
  /** Relative path inside the project's source snapshot. */
  file: string;
  /** 1-based source location. */
  line: number;
  column: number;
  /** Project context is explicit on new findings; optional for legacy stored rows. */
  projectId?: string;
  targetUrl?: never;
  endpoint?: never;
  method?: never;
  responseStatus?: never;
  responseTimeMs?: never;
  contentType?: never;
  observedAt?: never;
  observedHeaders?: never;
}

/** HTTP observation finding produced by the passive DAST engine. */
export interface DastFinding extends FindingBase {
  scanner: 'DAST';
  projectId: string;
  targetUrl: string;
  endpoint: string;
  method: 'GET';
  responseStatus: number;
  responseTimeMs: number;
  contentType?: string;
  observedAt: string;
  /** Allowlisted summaries only; raw Set-Cookie and arbitrary header values are excluded. */
  observedHeaders: string[];
  file?: never;
  line?: never;
  column?: never;
}

export type Finding = SourceFinding | DastFinding;

/** Closed-shape + invariant guard for source and DAST findings. */
export function isFinding(value: unknown): value is Finding {
  if (typeof value !== 'object' || value === null) return false;
  const record = value as Record<string, unknown>;
  const allowed = [
    'id', 'scanId', 'ruleId', 'scanner', 'severity', 'title', 'description', 'cwe',
    'file', 'line', 'column', 'evidence', 'remediation', 'confidence', 'fingerprint',
    'projectId', 'targetUrl', 'endpoint', 'method', 'responseStatus', 'responseTimeMs',
    'contentType', 'observedAt', 'observedHeaders',
  ];
  if (Object.keys(record).some((key) => !allowed.includes(key))) return false;
  if (
    typeof record['id'] !== 'string' || !FINDING_ID_PATTERN.test(record['id']) ||
    typeof record['scanId'] !== 'string' || !SCAN_ID_PATTERN.test(record['scanId']) ||
    typeof record['ruleId'] !== 'string' || !FINDING_RULE_ID_PATTERN.test(record['ruleId']) ||
    !isFindingSeverity(record['severity']) ||
    !isSafeFindingText(record['title'], FINDING_TITLE_MAX_LENGTH) ||
    !isSafeFindingText(record['description'], FINDING_TEXT_MAX_LENGTH) ||
    !isSafeFindingText(record['evidence'], FINDING_EVIDENCE_MAX_LENGTH) ||
    !isSafeFindingText(record['remediation'], FINDING_TEXT_MAX_LENGTH) ||
    typeof record['fingerprint'] !== 'string' || !FINDING_FINGERPRINT_PATTERN.test(record['fingerprint'])
  ) return false;
  if (record['cwe'] !== undefined && (typeof record['cwe'] !== 'string' || !FINDING_CWE_PATTERN.test(record['cwe']))) return false;

  const dast = record['scanner'] === 'DAST' || record['ruleId'].startsWith('DG-DAST-') || record['ruleId'].startsWith('DPK-DAST-');
  if (dast) {
    if (
      record['scanner'] !== 'DAST' || !/^(?:(?:DG|DPK)-DAST-[0-9]{3,}|ADV-[0-9]{4,})$/.test(record['ruleId']) ||
      typeof record['projectId'] !== 'string' || !PROJECT_ID_PATTERN.test(record['projectId']) ||
      !isSafeDastUrl(record['targetUrl']) || !isSafeDastUrl(record['endpoint']) ||
      record['method'] !== 'GET' ||
      typeof record['responseStatus'] !== 'number' || !Number.isInteger(record['responseStatus']) ||
      record['responseStatus'] < 100 || record['responseStatus'] > 599 ||
      typeof record['responseTimeMs'] !== 'number' || !Number.isInteger(record['responseTimeMs']) ||
      record['responseTimeMs'] < 0 || record['responseTimeMs'] > 15_000 ||
      typeof record['observedAt'] !== 'string' || Number.isNaN(Date.parse(record['observedAt'])) ||
      !Array.isArray(record['observedHeaders']) || record['observedHeaders'].length > 12 ||
      !record['observedHeaders'].every((header) => isSafeFindingText(header, 120)) ||
      record['file'] !== undefined || record['line'] !== undefined || record['column'] !== undefined ||
      record['confidence'] !== undefined
    ) return false;
    if (record['contentType'] !== undefined && !isSafeFindingText(record['contentType'], 120)) return false;
    const target = new URL(record['targetUrl']);
    const endpoint = new URL(record['endpoint']);
    if (
      target.hostname !== endpoint.hostname ||
      (target.protocol === 'https:' && endpoint.protocol !== 'https:')
    ) return false;
    return true;
  }

  if (
    record['scanner'] !== undefined && record['scanner'] !== 'SAST' && record['scanner'] !== 'SECRETS' && record['scanner'] !== 'SCA' ||
    (record['ruleId'].startsWith('DG-DAST-') || record['ruleId'].startsWith('DPK-DAST-')) ||
    typeof record['file'] !== 'string' || !isValidSourcePath(record['file']) ||
    typeof record['line'] !== 'number' || !Number.isInteger(record['line']) || record['line'] < 1 ||
    typeof record['column'] !== 'number' || !Number.isInteger(record['column']) || record['column'] < 1 ||
    (record['projectId'] !== undefined && (typeof record['projectId'] !== 'string' || !PROJECT_ID_PATTERN.test(record['projectId']))) ||
    record['targetUrl'] !== undefined || record['endpoint'] !== undefined ||
    record['method'] !== undefined || record['responseStatus'] !== undefined || record['responseTimeMs'] !== undefined ||
    record['contentType'] !== undefined || record['observedAt'] !== undefined || record['observedHeaders'] !== undefined
  ) return false;
  if (record['confidence'] !== undefined && !isFindingConfidence(record['confidence'])) return false;
  return true;
}

/**
 * Deterministic finding order (documented contract): severity rank
 * (CRITICAL first), then file path ASC, then line ASC, then ruleId ASC
 * — identical on every request for identical data.
 */
export function findingScanner(finding: Finding): ScanType | undefined {
  if (finding.scanner !== undefined) return finding.scanner;
  if (finding.ruleId.startsWith('DG-SAST-') || finding.ruleId.startsWith('DPK-SAST-')) return 'SAST';
  if (finding.ruleId.startsWith('DG-SEC-') || finding.ruleId.startsWith('DPK-SEC-')) return 'SECRETS';
  if (finding.ruleId.startsWith('DPK-SCA-')) return 'SCA';
  return undefined;
}

export function compareFindings(a: Finding, b: Finding): number {
  const rank = (severity: FindingSeverity): number => FINDING_SEVERITIES.indexOf(severity);
  const rankDiff = rank(a.severity) - rank(b.severity);
  if (rankDiff !== 0) return rankDiff;
  const locationA = a.scanner === 'DAST' ? a.endpoint : a.file;
  const locationB = b.scanner === 'DAST' ? b.endpoint : b.file;
  if (locationA !== locationB) return locationA < locationB ? -1 : 1;
  const lineA = a.scanner === 'DAST' ? 0 : a.line;
  const lineB = b.scanner === 'DAST' ? 0 : b.line;
  if (lineA !== lineB) return lineA - lineB;
  if (a.ruleId !== b.ruleId) return a.ruleId < b.ruleId ? -1 : 1;
  return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
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
  /** Bounded, redacted HTTP observations, present only on completed DAST scans. */
  dast?: DastResult;
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
  const rawScan = record['scan'];
  if (typeof rawScan !== 'object' || rawScan === null) {
    return false;
  }
  const scanRecord = rawScan as Record<string, unknown>;
  const { findings, sca, dast, ...scanWithoutPayload } = scanRecord;
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
  if (sca !== undefined && (
    !isScaResult(sca) || scanWithoutPayload['scanType'] !== 'SCA' || scanWithoutPayload['status'] !== 'COMPLETED'
  )) return false;
  if (dast !== undefined && (
    !isDastResult(dast) || scanWithoutPayload['scanType'] !== 'DAST' || scanWithoutPayload['status'] !== 'COMPLETED'
  )) return false;
  if (scanWithoutPayload['status'] !== 'COMPLETED' && findings.length > 0) return false;
  const dastResult = dast as DastResult | undefined;
  if (scanWithoutPayload['status'] === 'COMPLETED' && scanWithoutPayload['scanType'] === 'DAST') {
    if (dastResult === undefined || scanWithoutPayload['targetUrl'] !== dastResult.targetUrl) return false;
    const summary = scanWithoutPayload['resultSummary'] as ScanResultSummary;
    if (summary.requestsMade !== dastResult.requestCount || summary.redirectsFollowed !== dastResult.redirectsFollowed) return false;
  }
  const detailScan = scanWithoutPayload as unknown as Scan;
  return findings.every((finding) => {
    if (!isFinding(finding) || finding.scanId !== detailScan.id) return false;
    if (detailScan.scanType === 'DAST') {
      return finding.scanner === 'DAST' &&
        finding.projectId === detailScan.projectId &&
        finding.targetUrl === detailScan.targetUrl &&
        dastResult?.observations.some((observation) =>
          observation.endpoint === finding.endpoint &&
          observation.status === finding.responseStatus &&
          observation.responseTimeMs === finding.responseTimeMs &&
          observation.observedAt === finding.observedAt &&
          observation.contentType === finding.contentType,
        ) === true;
    }
    return finding.scanner !== 'DAST';
  });
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
    'assessmentId',
    'targetUrl',
    'dastMode',
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
    (record['assessmentId'] !== undefined && (typeof record['assessmentId'] !== 'string' || !ASSESSMENT_ID_PATTERN.test(record['assessmentId']))) ||
    typeof record['createdAt'] !== 'string' ||
    typeof record['updatedAt'] !== 'string'
  ) {
    return false;
  }
  if (record['targetUrl'] !== undefined && (record['scanType'] !== 'DAST' || !isSafeDastUrl(record['targetUrl']))) {
    return false;
  }
  if (record['dastMode'] !== undefined && (record['scanType'] !== 'DAST' || (record['dastMode'] !== 'PASSIVE' && record['dastMode'] !== 'ACTIVE_SAFE'))) return false;
  if (
    record['scanType'] === 'DAST' &&
    (record['status'] === 'QUEUED' || record['status'] === 'RUNNING' || record['status'] === 'COMPLETED') &&
    record['targetUrl'] === undefined
  ) return false;
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
  if (!hasFailureCode || hasResult || !hasFailureMessage) return false;
  if (status === 'TIMED_OUT') {
    return record['failureCode'] === 'DAST_REQUEST_TIMEOUT' || record['failureCode'] === 'DAST_SCAN_TIMEOUT';
  }
  return true; // FAILED
}

/**
 * Scan-to-scan regression comparison (Phase 22 Pump 3). Both scans must
 * belong to the SAME owned project and share the scan type. Identity is
 * the finding fingerprint (deterministic across rescans), so this is a
 * PRESENCE/SEVERITY comparison over engine-produced findings — never a
 * second finding engine and never a correlation guess.
 *
 * Honesty contract of the states:
 * - NEW       — observed in the current scan, absent from the baseline scan.
 * - UNCHANGED — observed in both, same rule-fixed severity.
 * - CHANGED   — observed in both, different rule-fixed severity.
 * - RESOLVED  — observed in the baseline, NOT observed in the current scan.
 *               Absence in one scan is the same evidence class as the
 *               existing `NOT_OBSERVED_IN_LATEST_SCAN` workflow state: it
 *               is retest evidence, never proof the code was repaired.
 * - REOPENED  — observed in both while the persisted finding workflow is
 *               currently REOPENED (a closed finding was re-observed).
 * No historical workflow state is invented: REOPENED only reflects the
 * store's real current workflow state.
 */
export const SCAN_COMPARISON_ENTRY_STATES = ['NEW', 'UNCHANGED', 'RESOLVED', 'REOPENED', 'CHANGED'] as const;
export type ScanComparisonEntryState = (typeof SCAN_COMPARISON_ENTRY_STATES)[number];

export function isScanComparisonEntryState(value: unknown): value is ScanComparisonEntryState {
  return typeof value === 'string' && (SCAN_COMPARISON_ENTRY_STATES as readonly string[]).includes(value);
}

export interface ScanComparisonEntry {
  /** Deterministic finding identity (stable across rescans). */
  fingerprint: string;
  /** The finding id both scans share for this fingerprint. */
  findingId: string;
  ruleId: string;
  /** The comparison location: source file (SAST/SECRETS) or endpoint (DAST). */
  location: string;
  state: ScanComparisonEntryState;
  /** Severity on the baseline side (present when observed there). */
  baselineSeverity?: FindingSeverity;
  /** Severity on the current side (present when observed there). */
  currentSeverity?: FindingSeverity;
}

export interface ScanComparisonResponse {
  projectId: string;
  scanType: ScanType;
  baselineScanId: string;
  currentScanId: string;
  generatedAt: string;
  counts: {
    new: number;
    unchanged: number;
    resolved: number;
    reopened: number;
    changed: number;
  };
  /** Bounded by construction: at most 2 × MAX_FINDINGS_PER_SCAN entries. */
  entries: ScanComparisonEntry[];
}

const FINGERPRINT_PATTERN = /^[0-9a-f]{64}$/;

/** Closed-shape guard for `GET …/scans/:scanId/compare/:baselineScanId`. */
export function isScanComparisonResponse(value: unknown): value is ScanComparisonResponse {
  if (typeof value !== 'object' || value === null) return false;
  const record = value as Record<string, unknown>;
  if (Object.keys(record).length !== 7) return false;
  const { projectId, scanType, baselineScanId, currentScanId, generatedAt, counts, entries } = record as Record<string, unknown>;
  if (
    typeof projectId !== 'string' || !PROJECT_ID_PATTERN.test(projectId) ||
    !isScanType(scanType) ||
    typeof baselineScanId !== 'string' || !SCAN_ID_PATTERN.test(baselineScanId) ||
    typeof currentScanId !== 'string' || !SCAN_ID_PATTERN.test(currentScanId) ||
    typeof generatedAt !== 'string' || Number.isNaN(Date.parse(generatedAt)) ||
    typeof counts !== 'object' || counts === null ||
    !Array.isArray(entries) || entries.length > 2 * MAX_FINDINGS_PER_SCAN
  ) {
    return false;
  }
  const countRecord = counts as Record<string, unknown>;
  if (Object.keys(countRecord).length !== 5) return false;
  let total = 0;
  for (const key of ['new', 'unchanged', 'resolved', 'reopened', 'changed']) {
    const count = countRecord[key];
    if (typeof count !== 'number' || !Number.isInteger(count) || count < 0) return false;
    total += count;
  }
  if (total !== entries.length) return false;
  return entries.every((entry) => {
    if (typeof entry !== 'object' || entry === null) return false;
    const item = entry as Record<string, unknown>;
    const keys = Object.keys(item);
    if (keys.length !== 6 && keys.length !== 7) return false;
    const hasBaseline = item['baselineSeverity'] !== undefined;
    const hasCurrent = item['currentSeverity'] !== undefined;
    if (!hasBaseline && !hasCurrent) return false;
    if (
      typeof item['fingerprint'] !== 'string' || !FINGERPRINT_PATTERN.test(item['fingerprint']) ||
      typeof item['findingId'] !== 'string' || !FINDING_ID_PATTERN.test(item['findingId']) ||
      typeof item['ruleId'] !== 'string' || !FINDING_RULE_ID_PATTERN.test(item['ruleId']) ||
      typeof item['location'] !== 'string' || item['location'].length === 0 || item['location'].length > 500 ||
      !isScanComparisonEntryState(item['state']) ||
      (hasBaseline && !isFindingSeverity(item['baselineSeverity'])) ||
      (hasCurrent && !isFindingSeverity(item['currentSeverity']))
    ) {
      return false;
    }
    // RESOLVED entries exist only on the baseline side; NEW only on the current side.
    if (item['state'] === 'RESOLVED' && !hasBaseline) return false;
    if (item['state'] === 'NEW' && !hasCurrent) return false;
    return true;
  });
}
