import { isSafeDastUrl } from './dast.js';
import { PROJECT_ID_PATTERN } from './projects.js';
import { ASSESSMENT_ID_PATTERN } from './assessmentIds.js';
import { SCAN_ID_PATTERN, isScanStatus, isScanType, type ScanStatus, type ScanType } from './scans.js';

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
  const allowed = ['id', 'projectId', 'title', 'objectives', 'scope', 'status', 'createdAt', 'updatedAt', 'startedAt', 'completedAt', 'cancelledAt', 'authorizationDeclarations', 'history'];
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
