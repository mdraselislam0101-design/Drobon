/**
 * Project operations and bounded-assessment contracts.
 *
 * SOC here means a read-only triage view of this app's saved scan records.
 * SAC means Security Assessment & Compliance, implemented here as a coverage ledger, not a compliance
 * certification. Neither is an additional scan type or a live SIEM.
 */
import { PROJECT_ID_PATTERN } from './projects.js';
import { ASSESSMENT_ID_PATTERN } from './assessmentIds.js';
import { isSafeDastUrl } from './dast.js';
import {
  FINDING_ID_PATTERN,
  FINDING_SEVERITIES,
  SCAN_ID_PATTERN,
  SCAN_TYPES,
  type FindingSeverity,
  type ScanType,
} from './scans.js';

export const SOC_MAX_SCANS = 100;
export const SOC_MAX_ALERTS = 100;
export const SOC_RECENT_SCAN_DAYS = 30;
export const SOC_WATCH_RULES = [
  'SCAN_FAILED',
  'SCAN_PARTIAL',
  'HIGH_SEVERITY_FINDING',
  'HIGH_SEVERITY_ADVISORY',
  'SCA_NOT_ASSESSED',
  'MISSING_RECENT_SCANS',
  'DATASET_UNAVAILABLE',
  'ADVISORY_UNAVAILABLE',
  'ADVISORY_STALE',
] as const;
export type SocWatchRuleId = (typeof SOC_WATCH_RULES)[number];
export type SocSourceStatus = 'AVAILABLE' | 'NOT_CONFIGURED' | 'UNAVAILABLE' | 'STALE';

/** A derived observation, not a confirmed intrusion or a persisted incident. */
export interface SocAlert {
  id: string;
  ruleId: SocWatchRuleId;
  severity: FindingSeverity;
  title: string;
  detail: string;
  observedAt: string;
  scanId?: string;
  findingId?: string;
}

export interface SocPosture {
  schemaVersion: '1.0';
  projectId: string;
  generatedAt: string;
  /** Only the most recent SOC_MAX_SCANS saved scans are reviewed. */
  scansReviewed: number;
  scansOmitted: number;
  scannerCoverage: Array<{ scanner: ScanType; lastCompletedAt: string | null }>;
  /** Current app configuration, not the rule set historically used by each scan. */
  sources: { dataset: SocSourceStatus; advisory: SocSourceStatus };
  alerts: SocAlert[];
  limitations: string[];
  truncated: boolean;
}
export interface SocPostureResponse { posture: SocPosture }

export const SAC_ASSESSMENT_LEVEL = 'AUTOMATED_BOUNDED_ASSESSMENT' as const;
export type SacVerdict = 'FINDINGS_PRESENT' | 'NO_FINDINGS_RECORDED';
export type SacCoverageStatus = 'RAN' | 'PARTIAL' | 'NOT_RUN';

/** Null means the original scan did not record a value; it does not mean zero. */
export interface SacMetrics {
  filesScanned: number | null;
  filesSkipped: number | null;
  requestsMade: number | null;
  redirectsFollowed: number | null;
  declarationRulesEvaluated: number | null;
  declarationRulesNotEvaluated: number | null;
  astFilesAnalyzed: number | null;
  astFlowsFound: number | null;
  partial: boolean | null;
  truncated: boolean | null;
  partialReason: string | null;
}

/** This is evidence about one completed scan, not a whole-site safety verdict. */
export interface SacAssessment {
  schemaVersion: '1.0';
  assessmentLevel: typeof SAC_ASSESSMENT_LEVEL;
  verdict: SacVerdict;
  verdictStatement: string;
  scope: {
    projectId: string;
    scanId: string;
    scanType: ScanType;
    completedAt: string;
    targetUrl?: string;
    assessmentId?: string;
  };
  scannerCoverage: Array<{ scanner: ScanType; status: SacCoverageStatus; reason: string }>;
  metrics: SacMetrics;
  findings: { total: number; bySeverity: Record<FindingSeverity, number> };
  ruleProvenance: 'NOT_RECORDED_AT_SCAN' | 'SAST_EFFECTIVE_RULES_RECORDED';
  limitations: string[];
  residualRisk: { status: 'UNKNOWN'; statement: string };
  compliance: { status: 'NOT_ASSESSED'; statement: string };
  nextSteps: string[];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}

function safeText(value: unknown, max: number): value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > max) return false;
  for (const char of value) {
    const code = char.codePointAt(0) ?? 0;
    if (code < 0x20 || code === 0x7f) return false;
  }
  return true;
}

function validDate(value: unknown): value is string {
  return typeof value === 'string' && Number.isFinite(Date.parse(value));
}

function validCount(value: unknown, max = 1_000_000): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0 && value <= max;
}

function severityCounts(value: unknown): value is Record<FindingSeverity, number> {
  return isRecord(value) && exactKeys(value, FINDING_SEVERITIES) && FINDING_SEVERITIES.every((key) => validCount(value[key], 200));
}

function safeList(value: unknown, maxItems: number, maxLength: number): value is string[] {
  return Array.isArray(value) && value.length <= maxItems && value.every((item) => safeText(item, maxLength));
}

export function isSocAlert(value: unknown): value is SocAlert {
  if (!isRecord(value)) return false;
  const allowed = ['id', 'ruleId', 'severity', 'title', 'detail', 'observedAt', 'scanId', 'findingId'];
  return Object.keys(value).every((key) => allowed.includes(key)) &&
    typeof value['id'] === 'string' && /^soca_[a-f0-9]{24}$/.test(value['id']) &&
    (SOC_WATCH_RULES as readonly unknown[]).includes(value['ruleId']) &&
    (FINDING_SEVERITIES as readonly unknown[]).includes(value['severity']) &&
    safeText(value['title'], 160) && safeText(value['detail'], 300) && validDate(value['observedAt']) &&
    (value['scanId'] === undefined || (typeof value['scanId'] === 'string' && SCAN_ID_PATTERN.test(value['scanId']))) &&
    (value['findingId'] === undefined || (typeof value['findingId'] === 'string' && FINDING_ID_PATTERN.test(value['findingId'])));
}

export function isSocPosture(value: unknown): value is SocPosture {
  if (!isRecord(value) || !exactKeys(value, ['schemaVersion', 'projectId', 'generatedAt', 'scansReviewed', 'scansOmitted', 'scannerCoverage', 'sources', 'alerts', 'limitations', 'truncated'])) return false;
  if (value['schemaVersion'] !== '1.0' || typeof value['projectId'] !== 'string' || !PROJECT_ID_PATTERN.test(value['projectId']) ||
      !validDate(value['generatedAt']) || !validCount(value['scansReviewed'], SOC_MAX_SCANS) || !validCount(value['scansOmitted']) ||
      !Array.isArray(value['alerts']) || value['alerts'].length > SOC_MAX_ALERTS || !value['alerts'].every(isSocAlert) ||
      !safeList(value['limitations'], 12, 300) || typeof value['truncated'] !== 'boolean') return false;
  const coverage = value['scannerCoverage'];
  if (!Array.isArray(coverage) || coverage.length !== SCAN_TYPES.length || !coverage.every((entry) =>
    isRecord(entry) && exactKeys(entry, ['scanner', 'lastCompletedAt']) && (SCAN_TYPES as readonly unknown[]).includes(entry['scanner']) &&
    (entry['lastCompletedAt'] === null || validDate(entry['lastCompletedAt'])))) return false;
  if (new Set(coverage.map((entry: { scanner: ScanType }) => entry.scanner)).size !== SCAN_TYPES.length) return false;
  const sources = value['sources'];
  const states: readonly SocSourceStatus[] = ['AVAILABLE', 'NOT_CONFIGURED', 'UNAVAILABLE', 'STALE'];
  return isRecord(sources) && exactKeys(sources, ['dataset', 'advisory']) &&
    (states as readonly unknown[]).includes(sources['dataset']) && (states as readonly unknown[]).includes(sources['advisory']);
}

export function isSocPostureResponse(value: unknown): value is SocPostureResponse {
  return isRecord(value) && exactKeys(value, ['posture']) && isSocPosture(value['posture']);
}

const SAC_METRIC_KEYS = [
  'filesScanned', 'filesSkipped', 'requestsMade', 'redirectsFollowed',
  'declarationRulesEvaluated', 'declarationRulesNotEvaluated', 'astFilesAnalyzed', 'astFlowsFound',
  'partial', 'truncated', 'partialReason',
] as const;

export function isSacAssessment(value: unknown): value is SacAssessment {
  if (!isRecord(value) || !exactKeys(value, ['schemaVersion', 'assessmentLevel', 'verdict', 'verdictStatement', 'scope', 'scannerCoverage', 'metrics', 'findings', 'ruleProvenance', 'limitations', 'residualRisk', 'compliance', 'nextSteps'])) return false;
  if (value['schemaVersion'] !== '1.0' || value['assessmentLevel'] !== SAC_ASSESSMENT_LEVEL ||
      !(['FINDINGS_PRESENT', 'NO_FINDINGS_RECORDED'] as readonly unknown[]).includes(value['verdict']) ||
      !safeText(value['verdictStatement'], 500) ||
      !(['NOT_RECORDED_AT_SCAN', 'SAST_EFFECTIVE_RULES_RECORDED'] as readonly unknown[]).includes(value['ruleProvenance'])) return false;
  const scope = value['scope'];
  if (!isRecord(scope) || Object.keys(scope).some((key) => !['projectId', 'scanId', 'scanType', 'completedAt', 'targetUrl', 'assessmentId'].includes(key)) ||
      typeof scope['projectId'] !== 'string' || !PROJECT_ID_PATTERN.test(scope['projectId']) ||
      typeof scope['scanId'] !== 'string' || !SCAN_ID_PATTERN.test(scope['scanId']) ||
      !(SCAN_TYPES as readonly unknown[]).includes(scope['scanType']) || !validDate(scope['completedAt']) ||
      (scope['targetUrl'] !== undefined && !isSafeDastUrl(scope['targetUrl'])) ||
      (scope['assessmentId'] !== undefined && (typeof scope['assessmentId'] !== 'string' || !ASSESSMENT_ID_PATTERN.test(scope['assessmentId'])))) return false;
  const coverage = value['scannerCoverage'];
  if (!Array.isArray(coverage) || coverage.length !== SCAN_TYPES.length || !coverage.every((entry) =>
    isRecord(entry) && exactKeys(entry, ['scanner', 'status', 'reason']) &&
    (SCAN_TYPES as readonly unknown[]).includes(entry['scanner']) &&
    (['RAN', 'PARTIAL', 'NOT_RUN'] as readonly unknown[]).includes(entry['status']) && safeText(entry['reason'], 240))) return false;
  if (new Set(coverage.map((entry: { scanner: ScanType }) => entry.scanner)).size !== SCAN_TYPES.length) return false;
  const metrics = value['metrics'];
  if (!isRecord(metrics) || !exactKeys(metrics, SAC_METRIC_KEYS)) return false;
  for (const key of SAC_METRIC_KEYS.slice(0, 8)) {
    if (metrics[key] !== null && !validCount(metrics[key])) return false;
  }
  if (!(metrics['partial'] === null || typeof metrics['partial'] === 'boolean') ||
      !(metrics['truncated'] === null || typeof metrics['truncated'] === 'boolean') ||
      !(metrics['partialReason'] === null || safeText(metrics['partialReason'], 200))) return false;
  const findings = value['findings'];
  if (!isRecord(findings) || !exactKeys(findings, ['total', 'bySeverity']) || !validCount(findings['total'], 200) || !severityCounts(findings['bySeverity'])) return false;
  if (FINDING_SEVERITIES.reduce((sum, key) => sum + (findings['bySeverity'] as Record<FindingSeverity, number>)[key], 0) !== findings['total']) return false;
  if ((findings['total'] === 0) !== (value['verdict'] === 'NO_FINDINGS_RECORDED')) return false;
  const risk = value['residualRisk'];
  const compliance = value['compliance'];
  return safeList(value['limitations'], 20, 300) && safeList(value['nextSteps'], 10, 300) &&
    isRecord(risk) && exactKeys(risk, ['status', 'statement']) && risk['status'] === 'UNKNOWN' && safeText(risk['statement'], 400) &&
    isRecord(compliance) && exactKeys(compliance, ['status', 'statement']) && compliance['status'] === 'NOT_ASSESSED' && safeText(compliance['statement'], 400);
}
