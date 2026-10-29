import { isSafeDastUrl } from './dast.js';
import { PROJECT_ID_PATTERN } from './projects.js';
import { ASSESSMENT_ID_PATTERN } from './assessmentIds.js';
import { SCAN_ID_PATTERN, isScanStatus, isScanType, type FindingSeverity, type ScanStatus, type ScanType } from './scans.js';

export { ASSESSMENT_ID_PATTERN } from './assessmentIds.js';
export const ASSESSMENT_EVENT_ID_PATTERN = /^ase_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
export const ASSESSMENT_TITLE_MAX_LENGTH = 120;
export const ASSESSMENT_OBJECTIVES_MAX_COUNT = 10;
export const ASSESSMENT_OBJECTIVE_MAX_LENGTH = 240;
export const ASSESSMENT_HOSTS_MAX_COUNT = 20;
export const ASSESSMENT_SCOPE_NOTES_MAX_LENGTH = 1000;
export const ASSESSMENT_EVENTS_MAX_COUNT = 100;
export const ASSESSMENT_DECLARATIONS_MAX_COUNT = 50;
export const ASSESSMENT_LIST_MAX_COUNT = 30;
/** Pump 17 — bounded third-party engagement/authorization records. */
export const ASSESSMENT_ENGAGEMENTS_MAX_COUNT = 20;
export const ENGAGEMENT_ID_PATTERN = /^eng_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
export const ENGAGEMENT_CLIENT_MAX_LENGTH = 120;
export const ENGAGEMENT_STATEMENT_MAX_LENGTH = 2000;
export const ENGAGEMENT_PATHS_MAX_COUNT = 20;
export const ENGAGEMENT_PATH_MAX_LENGTH = 200;
export const ENGAGEMENT_ACTOR_MAX_LENGTH = 64;

export const ASSESSMENT_STATUSES = ['PLANNED', 'ACTIVE', 'COMPLETED', 'CANCELLED'] as const;
export type AssessmentStatus = (typeof ASSESSMENT_STATUSES)[number];
export const AUTHORIZATION_DECLARATION_STATES = ['USER_DECLARED', 'WITHDRAWN'] as const;
export type AuthorizationDeclarationState = (typeof AUTHORIZATION_DECLARATION_STATES)[number];
export const ASSESSMENT_EVENT_TYPES = [
  'CREATED', 'DETAILS_UPDATED', 'STATUS_CHANGED', 'AUTHORIZATION_DECLARED', 'AUTHORIZATION_WITHDRAWN',
] as const;
export type AssessmentEventType = (typeof ASSESSMENT_EVENT_TYPES)[number];

export interface AssessmentScope {
  /** Exact DNS hostnames. Subdomains are not implicitly included. */
  inScopeHosts: string[];
  /** Explicit exclusions, which take precedence over inclusion. */
  outOfScopeHosts: string[];
  notes?: string;
}

export interface AssessmentAuthorizationDeclaration {
  targetUrl: string;
  state: AuthorizationDeclarationState;
  declaredAt: string;
}

/**
 * Pump 17 — an OWNER-ATTESTED engagement record for assessing a
 * third-party target. This is an auditable workspace record, NOT legal
 * verification: Drobon cannot confirm a client's signature, authority or
 * permission. `statement` is the operator's own written assertion.
 */
export type EngagementState = 'DECLARED' | 'WITHDRAWN';
export type EngagementStatus = 'ACTIVE' | 'NOT_YET_VALID' | 'EXPIRED' | 'WITHDRAWN';

export interface AssessmentEngagement {
  id: string;
  clientName: string;
  targetUrl: string;
  /** Exact hostnames; subdomains are never inherited. */
  inScopeHosts: string[];
  /** Optional URL path prefixes (e.g. `/api/`); empty means all paths. */
  scopePaths: string[];
  allowedScanTypes: ScanType[];
  validFrom: string;
  validUntil: string;
  statement: string;
  declaredBy: string;
  declaredAt: string;
  state: EngagementState;
  withdrawnAt?: string;
}

export interface EngagementView extends AssessmentEngagement {
  status: EngagementStatus;
}

export interface EngagementsResponse { engagements: EngagementView[] }
export interface EngagementResponse { engagement: EngagementView }

export interface AssessmentEvent {
  id: string;
  type: AssessmentEventType;
  at: string;
  status?: AssessmentStatus;
  targetUrl?: string;
}

export interface Assessment {
  id: string;
  projectId: string;
  title: string;
  objectives: string[];
  scope: AssessmentScope;
  status: AssessmentStatus;
  createdAt: string;
  updatedAt: string;
  startedAt?: string;
  completedAt?: string;
  cancelledAt?: string;
  authorizationDeclarations: AssessmentAuthorizationDeclaration[];
  /** Optional, additive: absent on all pre-Pump-17 records. */
  engagements?: AssessmentEngagement[];
  history: AssessmentEvent[];
}

export interface AssessmentScanSummary {
  id: string;
  scanType: ScanType;
  status: ScanStatus;
  createdAt: string;
  completedAt?: string;
  targetUrl?: string;
  findingsTotal?: number;
  reportAvailable: boolean;
}

export interface AssessmentProgress {
  totalScans: number;
  completedScans: number;
  failedScans: number;
  activeScans: number;
  findingsTotal: number;
  recentScans: AssessmentScanSummary[];
}

export interface AssessmentsResponse { assessments: Assessment[] }
export interface AssessmentResponse { assessment: Assessment }
export interface AssessmentDetailResponse { assessment: Assessment; progress: AssessmentProgress }

function exactKeys(record: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Object.keys(record);
  return keys.length === expected.length && expected.every((key) => Object.prototype.hasOwnProperty.call(record, key));
}

function boundedText(value: unknown, max: number): value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > max) return false;
  for (const char of value) {
    const code = char.codePointAt(0) ?? 0;
    if (code < 0x20 || code === 0x7f) return false;
  }
  return true;
}

export function isAssessmentHostname(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > 253 || value.length < 4 || value !== value.toLowerCase()) return false;
  if (value.endsWith('.') || value.includes('..') || value.includes('*') || value.includes(':')) return false;
  const labels = value.split('.');
  if (labels.length < 2) return false;
  if (labels.some((label) => label.length < 1 || label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label))) return false;
  // Hostnames are scope metadata, not IP literals or local single-label names.
  return !/^\d+(?:\.\d+){3}$/.test(value);
}

export function isAssessmentScope(value: unknown): value is AssessmentScope {
  if (typeof value !== 'object' || value === null) return false;
  const record = value as Record<string, unknown>;
  if (Object.keys(record).some((key) => !['inScopeHosts', 'outOfScopeHosts', 'notes'].includes(key)) ||
      !Array.isArray(record['inScopeHosts']) || !Array.isArray(record['outOfScopeHosts']) ||
      record['inScopeHosts'].length > ASSESSMENT_HOSTS_MAX_COUNT || record['outOfScopeHosts'].length > ASSESSMENT_HOSTS_MAX_COUNT ||
      !record['inScopeHosts'].every(isAssessmentHostname) || !record['outOfScopeHosts'].every(isAssessmentHostname)) return false;
  const included = record['inScopeHosts'] as string[];
  const excluded = record['outOfScopeHosts'] as string[];
  if (new Set(included).size !== included.length || new Set(excluded).size !== excluded.length || included.some((host) => excluded.includes(host))) return false;
  return record['notes'] === undefined || boundedText(record['notes'], ASSESSMENT_SCOPE_NOTES_MAX_LENGTH);
}

export function isAssessment(value: unknown): value is Assessment {
  if (typeof value !== 'object' || value === null) return false;
  const record = value as Record<string, unknown>;
  const allowed = ['id', 'projectId', 'title', 'objectives', 'scope', 'status', 'createdAt', 'updatedAt', 'startedAt', 'completedAt', 'cancelledAt', 'authorizationDeclarations', 'engagements', 'history'];
  if (Object.keys(record).some((key) => !allowed.includes(key)) ||
      typeof record['id'] !== 'string' || !ASSESSMENT_ID_PATTERN.test(record['id']) ||
      typeof record['projectId'] !== 'string' || !PROJECT_ID_PATTERN.test(record['projectId']) ||
      !boundedText(record['title'], ASSESSMENT_TITLE_MAX_LENGTH) ||
      !Array.isArray(record['objectives']) || record['objectives'].length < 1 || record['objectives'].length > ASSESSMENT_OBJECTIVES_MAX_COUNT ||
      !record['objectives'].every((objective) => boundedText(objective, ASSESSMENT_OBJECTIVE_MAX_LENGTH)) ||
      !isAssessmentScope(record['scope']) || !isAssessmentStatus(record['status']) ||
      !validDate(record['createdAt']) || !validDate(record['updatedAt']) ||
      !Array.isArray(record['authorizationDeclarations']) || record['authorizationDeclarations'].length > ASSESSMENT_DECLARATIONS_MAX_COUNT ||
      !record['authorizationDeclarations'].every(isAssessmentAuthorizationDeclaration) ||
      (record['engagements'] !== undefined && (!Array.isArray(record['engagements']) || record['engagements'].length > ASSESSMENT_ENGAGEMENTS_MAX_COUNT || !record['engagements'].every(isAssessmentEngagement))) ||
      !Array.isArray(record['history']) || record['history'].length < 1 || record['history'].length > ASSESSMENT_EVENTS_MAX_COUNT ||
      !record['history'].every(isAssessmentEvent)) return false;
  if (record['startedAt'] !== undefined && !validDate(record['startedAt'])) return false;
  if (record['completedAt'] !== undefined && !validDate(record['completedAt'])) return false;
  if (record['cancelledAt'] !== undefined && !validDate(record['cancelledAt'])) return false;
  const status = record['status'];
  if (status === 'PLANNED') return record['startedAt'] === undefined && record['completedAt'] === undefined && record['cancelledAt'] === undefined;
  if (status === 'ACTIVE') return record['startedAt'] !== undefined && record['completedAt'] === undefined && record['cancelledAt'] === undefined;
  if (status === 'COMPLETED') return record['startedAt'] !== undefined && record['completedAt'] !== undefined && record['cancelledAt'] === undefined;
  return record['completedAt'] === undefined && record['cancelledAt'] !== undefined;
}

function validDate(value: unknown): value is string {
  return typeof value === 'string' && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;
}

export function isAssessmentStatus(value: unknown): value is AssessmentStatus {
  return typeof value === 'string' && (ASSESSMENT_STATUSES as readonly string[]).includes(value);
}

function isAssessmentAuthorizationDeclaration(value: unknown): value is AssessmentAuthorizationDeclaration {
  if (typeof value !== 'object' || value === null) return false;
  const record = value as Record<string, unknown>;
  return exactKeys(record, ['targetUrl', 'state', 'declaredAt']) && isSafeDastUrl(record['targetUrl']) &&
    (record['state'] === 'USER_DECLARED' || record['state'] === 'WITHDRAWN') && validDate(record['declaredAt']);
}

function isEngagementScopePath(value: unknown): value is string {
  return boundedText(value, ENGAGEMENT_PATH_MAX_LENGTH) && value.startsWith('/') && !value.includes('..') && !value.includes(' ');
}

export function isAssessmentEngagement(value: unknown): value is AssessmentEngagement {
  if (typeof value !== 'object' || value === null) return false;
  const record = value as Record<string, unknown>;
  const allowed = ['id', 'clientName', 'targetUrl', 'inScopeHosts', 'scopePaths', 'allowedScanTypes', 'validFrom', 'validUntil', 'statement', 'declaredBy', 'declaredAt', 'state', 'withdrawnAt'];
  if (Object.keys(record).some((key) => !allowed.includes(key)) ||
      typeof record['id'] !== 'string' || !ENGAGEMENT_ID_PATTERN.test(record['id']) ||
      !boundedText(record['clientName'], ENGAGEMENT_CLIENT_MAX_LENGTH) ||
      !isSafeDastUrl(record['targetUrl']) ||
      !Array.isArray(record['inScopeHosts']) || record['inScopeHosts'].length < 1 ||
      record['inScopeHosts'].length > ASSESSMENT_HOSTS_MAX_COUNT || !record['inScopeHosts'].every(isAssessmentHostname) ||
      new Set(record['inScopeHosts'] as string[]).size !== (record['inScopeHosts'] as string[]).length ||
      !Array.isArray(record['scopePaths']) || record['scopePaths'].length > ENGAGEMENT_PATHS_MAX_COUNT || !record['scopePaths'].every(isEngagementScopePath) ||
      !Array.isArray(record['allowedScanTypes']) || record['allowedScanTypes'].length < 1 ||
      record['allowedScanTypes'].length > 4 || !record['allowedScanTypes'].every(isScanType) ||
      new Set(record['allowedScanTypes'] as string[]).size !== (record['allowedScanTypes'] as string[]).length ||
      !validDate(record['validFrom']) || !validDate(record['validUntil']) ||
      !boundedText(record['statement'], ENGAGEMENT_STATEMENT_MAX_LENGTH) ||
      !boundedText(record['declaredBy'], ENGAGEMENT_ACTOR_MAX_LENGTH) ||
      !validDate(record['declaredAt']) ||
      (record['state'] !== 'DECLARED' && record['state'] !== 'WITHDRAWN')) return false;
  const from = Date.parse(record['validFrom'] as string);
  const until = Date.parse(record['validUntil'] as string);
  if (!(until > from) || until - from > 366 * 24 * 60 * 60 * 1000) return false;
  if (record['state'] === 'WITHDRAWN') return validDate(record['withdrawnAt']);
  return record['withdrawnAt'] === undefined;
}

/** Time-derived state. Pure and deterministic; `nowIso` is injected in tests. */
export function engagementStatus(engagement: AssessmentEngagement, nowIso: string): EngagementStatus {
  if (engagement.state === 'WITHDRAWN') return 'WITHDRAWN';
  const now = Date.parse(nowIso);
  if (now < Date.parse(engagement.validFrom)) return 'NOT_YET_VALID';
  if (now >= Date.parse(engagement.validUntil)) return 'EXPIRED';
  return 'ACTIVE';
}

/**
 * The authorization GATE. When no engagement exists the caller keeps the
 * legacy `UNVERIFIED` behaviour (no silent upgrade, no hidden block).
 * Once an engagement is declared it becomes the authority for linked scans.
 */
export function engagementAllowsScan(
  engagements: readonly AssessmentEngagement[] | undefined,
  options: { scanType: ScanType; hostname?: string; path?: string; nowIso: string },
): { allowed: true; engagementId?: string } | { allowed: false; reason: string } {
  const records = engagements ?? [];
  if (records.length === 0) return { allowed: true };
  if (!Number.isFinite(Date.parse(options.nowIso))) return { allowed: false, reason: 'The engagement evaluation time is invalid.' };
  const active = records.filter((item) =>
    item.state === 'DECLARED' && engagementStatus(item, options.nowIso) === 'ACTIVE' && item.allowedScanTypes.includes(options.scanType));
  if (active.length === 0) return { allowed: false, reason: 'No active engagement authorizes this scan type.' };
  if (options.hostname !== undefined) {
    const host = options.hostname.toLowerCase();
    const inHost = active.filter((item) => item.inScopeHosts.includes(host));
    if (inHost.length === 0) return { allowed: false, reason: 'No active engagement covers this target hostname.' };
    if (options.path !== undefined) {
      const path = options.path;
      // Encoded separators/dots can be decoded or normalised differently by
      // proxies and target frameworks. Do not treat an ambiguous path as in scope.
      if (/%(?:2f|5c|2e|25)/i.test(path) || path.includes('\\')) {
        return { allowed: false, reason: 'The target path uses ambiguous encoded separators or traversal.' };
      }
      const inPath = inHost.filter((item) => item.scopePaths.length === 0 || item.scopePaths.some((prefix) => {
        if (prefix === '/') return true;
        const base = prefix.endsWith('/') ? prefix.slice(0, -1) : prefix;
        return path === base || path.startsWith(`${base}/`);
      }));
      if (inPath.length === 0) return { allowed: false, reason: 'The target path is outside the engagement scope.' };
      const picked = inPath[0]?.id;
      return picked === undefined ? { allowed: true } : { allowed: true, engagementId: picked };
    }
    const picked = inHost[0]?.id;
    return picked === undefined ? { allowed: true } : { allowed: true, engagementId: picked };
  }
  const picked = active[0]?.id;
  return picked === undefined ? { allowed: true } : { allowed: true, engagementId: picked };
}

export function isEngagementsResponse(value: unknown): value is EngagementsResponse {
  if (typeof value !== 'object' || value === null) return false;
  const record = value as Record<string, unknown>;
  return exactKeys(record, ['engagements']) && Array.isArray(record['engagements']) && record['engagements'].length <= ASSESSMENT_ENGAGEMENTS_MAX_COUNT && record['engagements'].every(isEngagementView);
}

export function isEngagementResponse(value: unknown): value is EngagementResponse {
  if (typeof value !== 'object' || value === null) return false;
  const record = value as Record<string, unknown>;
  return exactKeys(record, ['engagement']) && isEngagementView(record['engagement']);
}

function isEngagementView(value: unknown): value is EngagementView {
  if (typeof value !== 'object' || value === null) return false;
  const record = value as Record<string, unknown>;
  if (typeof record['status'] !== 'string' ||
      !(['ACTIVE', 'NOT_YET_VALID', 'EXPIRED', 'WITHDRAWN'] as readonly string[]).includes(record['status'])) return false;
  const rest: Record<string, unknown> = { ...record };
  delete rest['status'];
  if (!isAssessmentEngagement(rest)) return false;
  const keys = ['id', 'clientName', 'targetUrl', 'inScopeHosts', 'scopePaths', 'allowedScanTypes', 'validFrom', 'validUntil', 'statement', 'declaredBy', 'declaredAt', 'state', 'status'];
  if (rest['withdrawnAt'] !== undefined) keys.push('withdrawnAt');
  return exactKeys(record, keys);
}

function isAssessmentEvent(value: unknown): value is AssessmentEvent {
  if (typeof value !== 'object' || value === null) return false;
  const record = value as Record<string, unknown>;
  if (typeof record['id'] !== 'string' || !ASSESSMENT_EVENT_ID_PATTERN.test(record['id']) ||
      typeof record['type'] !== 'string' || !(ASSESSMENT_EVENT_TYPES as readonly string[]).includes(record['type']) ||
      !validDate(record['at'])) return false;
  if (record['type'] === 'STATUS_CHANGED') return exactKeys(record, ['id', 'type', 'at', 'status']) && isAssessmentStatus(record['status']);
  if (record['type'] === 'AUTHORIZATION_DECLARED' || record['type'] === 'AUTHORIZATION_WITHDRAWN') return exactKeys(record, ['id', 'type', 'at', 'targetUrl']) && isSafeDastUrl(record['targetUrl']);
  return exactKeys(record, ['id', 'type', 'at']);
}

export function isAssessmentScanSummary(value: unknown): value is AssessmentScanSummary {
  if (typeof value !== 'object' || value === null) return false;
  const record = value as Record<string, unknown>;
  const allowed = ['id', 'scanType', 'status', 'createdAt', 'completedAt', 'targetUrl', 'findingsTotal', 'reportAvailable'];
  return !Object.keys(record).some((key) => !allowed.includes(key)) && typeof record['id'] === 'string' && SCAN_ID_PATTERN.test(record['id']) &&
    isScanType(record['scanType']) && isScanStatus(record['status']) && validDate(record['createdAt']) &&
    (record['completedAt'] === undefined || validDate(record['completedAt'])) &&
    (record['targetUrl'] === undefined || isSafeDastUrl(record['targetUrl'])) &&
    (record['findingsTotal'] === undefined || (Number.isInteger(record['findingsTotal']) && (record['findingsTotal'] as number) >= 0 && (record['findingsTotal'] as number) <= 200)) &&
    typeof record['reportAvailable'] === 'boolean';
}

export function isAssessmentProgress(value: unknown): value is AssessmentProgress {
  if (typeof value !== 'object' || value === null) return false;
  const record = value as Record<string, unknown>;
  return exactKeys(record, ['totalScans', 'completedScans', 'failedScans', 'activeScans', 'findingsTotal', 'recentScans']) &&
    [record['totalScans'], record['completedScans'], record['failedScans'], record['activeScans'], record['findingsTotal']].every((item) => Number.isInteger(item) && (item as number) >= 0 && (item as number) <= 100_000) &&
    (record['completedScans'] as number) + (record['failedScans'] as number) + (record['activeScans'] as number) <= (record['totalScans'] as number) &&
    Array.isArray(record['recentScans']) && record['recentScans'].length <= 20 && record['recentScans'].every(isAssessmentScanSummary);
}

export function isAssessmentsResponse(value: unknown): value is AssessmentsResponse {
  if (typeof value !== 'object' || value === null) return false;
  const record = value as Record<string, unknown>;
  return exactKeys(record, ['assessments']) && Array.isArray(record['assessments']) && record['assessments'].length <= ASSESSMENT_LIST_MAX_COUNT && record['assessments'].every(isAssessment);
}

export function isAssessmentResponse(value: unknown): value is AssessmentResponse {
  if (typeof value !== 'object' || value === null) return false;
  const record = value as Record<string, unknown>;
  return exactKeys(record, ['assessment']) && isAssessment(record['assessment']);
}

export function isAssessmentDetailResponse(value: unknown): value is AssessmentDetailResponse {
  if (typeof value !== 'object' || value === null) return false;
  const record = value as Record<string, unknown>;
  return exactKeys(record, ['assessment', 'progress']) && isAssessment(record['assessment']) && isAssessmentProgress(record['progress']);
}

/**
 * Assessment engagement summary (Phase 22 Pump 3): a bounded, computed
 * aggregate over an assessment's LINKED completed scans — per-scan
 * severity lines plus assessment-level totals. It summarizes real
 * persisted records only; it never invents findings, verdicts, or
 * security scores, and truncated/partial scans are surfaced so totals
 * are never presented as complete coverage.
 */
export interface AssessmentSummaryScanLine {
  scanId: string;
  scanType: ScanType;
  status: ScanStatus;
  createdAt: string;
  completedAt?: string;
  findingsTotal?: number;
  findingsBySeverity?: Record<FindingSeverity, number>;
  /** True when the engine hit a configured limit on this scan. */
  partial?: boolean;
  reportAvailable: boolean;
}

export interface AssessmentSummaryResponse {
  assessment: {
    id: string;
    title: string;
    status: AssessmentStatus;
    createdAt: string;
    startedAt?: string;
    completedAt?: string;
    cancelledAt?: string;
  };
  objectivesTotal: number;
  scope: {
    inScopeHosts: string[];
    outOfScopeHosts: string[];
  };
  totals: {
    scansLinked: number;
    scansCompleted: number;
    scansFailed: number;
    scansActive: number;
    findingsTotal: number;
    findingsBySeverity?: Record<FindingSeverity, number>;
    /** Completed scans whose engine reported a partial sweep — totals may undercount. */
    partialScans: number;
  };
  scans: AssessmentSummaryScanLine[];
  generatedAt: string;
}

const SEVERITY_KEYS: readonly FindingSeverity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

function isSeverityCountMap(value: unknown): value is Record<FindingSeverity, number> {
  if (typeof value !== 'object' || value === null) return false;
  const record = value as Record<string, unknown>;
  if (Object.keys(record).length !== SEVERITY_KEYS.length) return false;
  return SEVERITY_KEYS.every((key) => Number.isInteger(record[key]) && (record[key] as number) >= 0);
}

function isSummaryScanLine(value: unknown): value is AssessmentSummaryScanLine {
  if (typeof value !== 'object' || value === null) return false;
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  if (keys.length < 5 || keys.length > 9) return false;
  if (
    typeof record['scanId'] !== 'string' || !SCAN_ID_PATTERN.test(record['scanId']) ||
    !isScanType(record['scanType']) || !isScanStatus(record['status']) ||
    typeof record['createdAt'] !== 'string' || Number.isNaN(Date.parse(record['createdAt'])) ||
    typeof record['reportAvailable'] !== 'boolean'
  ) {
    return false;
  }
  if (record['completedAt'] !== undefined && (typeof record['completedAt'] !== 'string' || Number.isNaN(Date.parse(record['completedAt'])))) return false;
  if (record['findingsTotal'] !== undefined && (!Number.isInteger(record['findingsTotal']) || (record['findingsTotal'] as number) < 0 || (record['findingsTotal'] as number) > 200)) return false;
  if (record['findingsBySeverity'] !== undefined && !isSeverityCountMap(record['findingsBySeverity'])) return false;
  if (record['partial'] !== undefined && typeof record['partial'] !== 'boolean') return false;
  return true;
}

export function isAssessmentSummaryResponse(value: unknown): value is AssessmentSummaryResponse {
  if (typeof value !== 'object' || value === null) return false;
  const record = value as Record<string, unknown>;
  if (Object.keys(record).length !== 6) return false;
  const { assessment, objectivesTotal, scope, totals, scans, generatedAt } = record as Record<string, unknown>;
  if (
    typeof assessment !== 'object' || assessment === null ||
    !Number.isInteger(objectivesTotal) || (objectivesTotal as number) < 0 ||
    typeof scope !== 'object' || scope === null ||
    typeof totals !== 'object' || totals === null ||
    !Array.isArray(scans) || scans.length > 20 ||
    typeof generatedAt !== 'string' || Number.isNaN(Date.parse(generatedAt))
  ) {
    return false;
  }
  const assessmentRecord = assessment as Record<string, unknown>;
  if (
    Object.keys(assessmentRecord).length < 4 || Object.keys(assessmentRecord).length > 7 ||
    typeof assessmentRecord['id'] !== 'string' || !ASSESSMENT_ID_PATTERN.test(assessmentRecord['id']) ||
    typeof assessmentRecord['title'] !== 'string' || assessmentRecord['title'].length === 0 ||
    !isAssessmentStatus(assessmentRecord['status']) ||
    typeof assessmentRecord['createdAt'] !== 'string' || Number.isNaN(Date.parse(assessmentRecord['createdAt']))
  ) {
    return false;
  }
  const scopeRecord = scope as Record<string, unknown>;
  if (
    Object.keys(scopeRecord).length !== 2 ||
    !Array.isArray(scopeRecord['inScopeHosts']) || scopeRecord['inScopeHosts'].length > ASSESSMENT_HOSTS_MAX_COUNT ||
    !Array.isArray(scopeRecord['outOfScopeHosts']) || scopeRecord['outOfScopeHosts'].length > ASSESSMENT_HOSTS_MAX_COUNT ||
    !scopeRecord['inScopeHosts'].every((host) => typeof host === 'string') ||
    !scopeRecord['outOfScopeHosts'].every((host) => typeof host === 'string')
  ) {
    return false;
  }
  const totalsRecord = totals as Record<string, unknown>;
  const totalKeys = Object.keys(totalsRecord);
  if (totalKeys.length !== 6 && totalKeys.length !== 7) return false;
  for (const key of ['scansLinked', 'scansCompleted', 'scansFailed', 'scansActive', 'findingsTotal', 'partialScans']) {
    if (!Number.isInteger(totalsRecord[key]) || (totalsRecord[key] as number) < 0) return false;
  }
  if (totalsRecord['findingsBySeverity'] !== undefined && !isSeverityCountMap(totalsRecord['findingsBySeverity'])) return false;
  return scans.every(isSummaryScanLine);
}
