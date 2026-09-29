import {
  FINDING_SEVERITIES,
  MAX_FINDINGS_PER_SCAN,
  SCAN_TYPES,
  isFinding,
  isFindingSeverity,
  FINDING_RULE_ID_PATTERN,
  isScan,
  findingScanner,
  type Finding,
  type FindingSeverity,
  type Scan,
  type ScanType,
} from './scans.js';
import { isProject, PROJECT_ID_PATTERN, type Project } from './projects.js';

/** Server-side findings pages remain bounded by the existing per-scan cap. */
export const FINDINGS_PAGE_SIZE_MAX = 100;
export const FINDINGS_PAGE_MAX = 10_000;
export const FINDING_LIFECYCLE_STATES = ['OPEN', 'ACKNOWLEDGED', 'IN_PROGRESS', 'RESOLVED', 'REOPENED'] as const;
export type FindingLifecycleState = (typeof FINDING_LIFECYCLE_STATES)[number];
export const FINDING_NOTE_MAX_LENGTH = 1_000;
export const FINDING_NOTES_MAX_COUNT = 20;
export const FINDING_HISTORY_PAGE_SIZE_MAX = 50;
export const FINDING_HISTORY_PAGE_MAX = 10_000;
export const FINDING_HISTORY_EVENTS_MAX = 200;
export const FINDING_WORKFLOWS_MAX = 2_000;
export const FINDING_WORKFLOW_ID_PATTERN = /^fwf_[0-9a-f-]{36}$/;
export const FINDING_NOTE_ID_PATTERN = /^fnt_[0-9a-f-]{36}$/;
export const FINDING_EVENT_ID_PATTERN = /^fev_[0-9a-f-]{36}$/;

export type FindingVerificationState = 'OBSERVED' | 'NOT_OBSERVED_IN_LATEST_SCAN';
export type FindingLifecycleAction = 'FINDING_OBSERVED' | 'STATE_CHANGED' | 'FINDING_REOBSERVED' | 'NOT_OBSERVED' | 'NOTE_ADDED';

export interface FindingRemediationNote {
  id: string;
  text: string;
  actorId: string;
  createdAt: string;
  redacted: boolean;
}

export interface FindingWorkflow {
  id: string;
  projectId: string;
  findingId: string;
  fingerprint: string;
  scanner: ScanType;
  ruleId: string;
  state: FindingLifecycleState;
  firstObservedScanId: string;
  firstObservedAt: string;
  lastObservedScanId: string;
  lastObservedAt: string;
  lastVerificationScanId: string;
  lastVerificationAt: string;
  verificationState: FindingVerificationState;
  notes: FindingRemediationNote[];
  historyTotal: number;
  updatedAt: string;
}

export interface FindingLifecycleEvent {
  id: string;
  findingId: string;
  previousState: FindingLifecycleState | null;
  newState: FindingLifecycleState;
  actorId: string;
  actorType: 'USER' | 'SYSTEM';
  action: FindingLifecycleAction;
  at: string;
  noteId?: string;
}

export interface FindingHistoryResponse {
  events: FindingLifecycleEvent[];
  page: number;
  pageSize: number;
  total: number;
  totalPages: number;
}

export interface FindingWorkflowResponse {
  workflow: FindingWorkflow;
}

export interface FindingRemediationExample {
  before: string;
  after: string;
  caveat?: string;
}

export interface FindingRemediationGuidance {
  ruleId: string;
  status: 'RULE_SPECIFIC' | 'LIMITED' | 'UNAVAILABLE';
  whyItMatters: string;
  actions: string[];
  verification: string;
  standardId?: string;
  example?: FindingRemediationExample;
}

export interface FindingsPageResponse {
  findings: Finding[];
  page: number;
  pageSize: number;
  total: number;
  totalPages: number;
  severity?: FindingSeverity;
  scanner?: ScanType;
}

export interface FindingDetailResponse {
  project: Project;
  scan: Scan;
  finding: Finding;
  /** Added in Pump 13; absent only on legacy-compatible reads. */
  workflow?: FindingWorkflow;
  /** Rule-based guidance; never executes or mutates source code. */
  guidance?: FindingRemediationGuidance;
}

function isPositiveInteger(value: unknown, max: number): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 1 && value <= max;
}

function hasExactKeys(record: Record<string, unknown>, keys: readonly string[]): boolean {
  return Object.keys(record).length === keys.length && keys.every((key) => Object.prototype.hasOwnProperty.call(record, key));
}

function isSafeWorkflowText(value: unknown, maxLength: number): value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > maxLength || value !== value.normalize('NFC')) return false;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if ((code < 0x20 && code !== 0x09 && code !== 0x0a) || code === 0x7f) return false;
  }
  return true;
}

function isTimestamp(value: unknown): value is string {
  return typeof value === 'string' && !Number.isNaN(Date.parse(value));
}

function isLifecycleState(value: unknown): value is FindingLifecycleState {
  return typeof value === 'string' && (FINDING_LIFECYCLE_STATES as readonly string[]).includes(value);
}

export function isFindingRemediationNote(value: unknown): value is FindingRemediationNote {
  if (typeof value !== 'object' || value === null) return false;
  const record = value as Record<string, unknown>;
  return hasExactKeys(record, ['id', 'text', 'actorId', 'createdAt', 'redacted']) &&
    typeof record['id'] === 'string' && FINDING_NOTE_ID_PATTERN.test(record['id']) &&
    isSafeWorkflowText(record['text'], FINDING_NOTE_MAX_LENGTH) && !/<\/?[a-z][^>]*>/i.test(record['text']) &&
    typeof record['actorId'] === 'string' && record['actorId'].length > 0 && record['actorId'].length <= 80 &&
    isTimestamp(record['createdAt']) && typeof record['redacted'] === 'boolean';
}

export function isFindingWorkflow(value: unknown): value is FindingWorkflow {
  if (typeof value !== 'object' || value === null) return false;
  const record = value as Record<string, unknown>;
  if (!hasExactKeys(record, [
    'id', 'projectId', 'findingId', 'fingerprint', 'scanner', 'ruleId', 'state',
    'firstObservedScanId', 'firstObservedAt', 'lastObservedScanId', 'lastObservedAt',
    'lastVerificationScanId', 'lastVerificationAt', 'verificationState', 'notes', 'historyTotal', 'updatedAt',
  ])) return false;
  return typeof record['id'] === 'string' && FINDING_WORKFLOW_ID_PATTERN.test(record['id']) &&
    typeof record['projectId'] === 'string' && PROJECT_ID_PATTERN.test(record['projectId']) &&
    typeof record['findingId'] === 'string' && /^fnd_[0-9a-f]{24}$/.test(record['findingId']) &&
    typeof record['fingerprint'] === 'string' && /^[0-9a-f]{64}$/.test(record['fingerprint']) &&
    isFindingScanner(record['scanner']) &&
    typeof record['ruleId'] === 'string' && FINDING_RULE_ID_PATTERN.test(record['ruleId']) &&
    isLifecycleState(record['state']) &&
    typeof record['firstObservedScanId'] === 'string' && /^scan_[0-9a-f-]{36}$/.test(record['firstObservedScanId']) &&
    isTimestamp(record['firstObservedAt']) &&
    typeof record['lastObservedScanId'] === 'string' && /^scan_[0-9a-f-]{36}$/.test(record['lastObservedScanId']) &&
    isTimestamp(record['lastObservedAt']) &&
    typeof record['lastVerificationScanId'] === 'string' && /^scan_[0-9a-f-]{36}$/.test(record['lastVerificationScanId']) &&
    isTimestamp(record['lastVerificationAt']) &&
    (record['verificationState'] === 'OBSERVED' || record['verificationState'] === 'NOT_OBSERVED_IN_LATEST_SCAN') &&
    Array.isArray(record['notes']) && record['notes'].length <= FINDING_NOTES_MAX_COUNT && record['notes'].every(isFindingRemediationNote) &&
    typeof record['historyTotal'] === 'number' && Number.isInteger(record['historyTotal']) && record['historyTotal'] >= 1 && record['historyTotal'] <= FINDING_HISTORY_EVENTS_MAX &&
    isTimestamp(record['updatedAt']);
}

export function isFindingLifecycleEvent(value: unknown): value is FindingLifecycleEvent {
  if (typeof value !== 'object' || value === null) return false;
  const record = value as Record<string, unknown>;
  const keys = record['noteId'] === undefined
    ? ['id', 'findingId', 'previousState', 'newState', 'actorId', 'actorType', 'action', 'at']
    : ['id', 'findingId', 'previousState', 'newState', 'actorId', 'actorType', 'action', 'at', 'noteId'];
  return hasExactKeys(record, keys) &&
    typeof record['id'] === 'string' && FINDING_EVENT_ID_PATTERN.test(record['id']) &&
    typeof record['findingId'] === 'string' && /^fnd_[0-9a-f]{24}$/.test(record['findingId']) &&
    (record['previousState'] === null || isLifecycleState(record['previousState'])) &&
    isLifecycleState(record['newState']) &&
    typeof record['actorId'] === 'string' && record['actorId'].length > 0 && record['actorId'].length <= 80 &&
    (record['actorType'] === 'USER' || record['actorType'] === 'SYSTEM') &&
    (record['action'] === 'FINDING_OBSERVED' || record['action'] === 'STATE_CHANGED' || record['action'] === 'FINDING_REOBSERVED' || record['action'] === 'NOT_OBSERVED' || record['action'] === 'NOTE_ADDED') &&
    isTimestamp(record['at']) &&
    (record['noteId'] === undefined || (typeof record['noteId'] === 'string' && FINDING_NOTE_ID_PATTERN.test(record['noteId'])));
}

export function isFindingWorkflowResponse(value: unknown): value is FindingWorkflowResponse {
  if (typeof value !== 'object' || value === null) return false;
  const record = value as Record<string, unknown>;
  return hasExactKeys(record, ['workflow']) && isFindingWorkflow(record['workflow']);
}

export function isFindingHistoryResponse(value: unknown): value is FindingHistoryResponse {
  if (typeof value !== 'object' || value === null) return false;
  const record = value as Record<string, unknown>;
  return hasExactKeys(record, ['events', 'page', 'pageSize', 'total', 'totalPages']) &&
    Array.isArray(record['events']) && record['events'].length <= FINDING_HISTORY_PAGE_SIZE_MAX &&
    record['events'].every(isFindingLifecycleEvent) &&
    isPositiveInteger(record['page'], FINDING_HISTORY_PAGE_MAX) &&
    isPositiveInteger(record['pageSize'], FINDING_HISTORY_PAGE_SIZE_MAX) &&
    typeof record['total'] === 'number' && Number.isInteger(record['total']) && record['total'] >= 0 && record['total'] <= FINDING_HISTORY_EVENTS_MAX &&
    typeof record['totalPages'] === 'number' && Number.isInteger(record['totalPages']) && record['totalPages'] === Math.ceil(record['total'] / record['pageSize']);
}

export function isFindingRemediationGuidance(value: unknown): value is FindingRemediationGuidance {
  if (typeof value !== 'object' || value === null) return false;
  const record = value as Record<string, unknown>;
  const keys = record['standardId'] !== undefined
    ? [...(record['example'] === undefined ? [] : ['example']), 'ruleId', 'status', 'whyItMatters', 'actions', 'verification', 'standardId']
    : [...(record['example'] === undefined ? [] : ['example']), 'ruleId', 'status', 'whyItMatters', 'actions', 'verification'];
  if (!hasExactKeys(record, keys) || typeof record['ruleId'] !== 'string' || !FINDING_RULE_ID_PATTERN.test(record['ruleId']) ||
      (record['status'] !== 'RULE_SPECIFIC' && record['status'] !== 'LIMITED' && record['status'] !== 'UNAVAILABLE') ||
      !isSafeWorkflowText(record['whyItMatters'], 400) || !isSafeWorkflowText(record['verification'], 400) ||
      !Array.isArray(record['actions']) || record['actions'].length < 1 || record['actions'].length > 8 ||
      !record['actions'].every((action) => isSafeWorkflowText(action, 300))) return false;
  if (record['standardId'] !== undefined && (typeof record['standardId'] !== 'string' || !/^CWE-[0-9]{1,5}$/.test(record['standardId']))) return false;
  if (record['example'] !== undefined) {
    const example = record['example'];
    if (typeof example !== 'object' || example === null) return false;
    const exampleRecord = example as Record<string, unknown>;
    const exampleKeys = exampleRecord['caveat'] === undefined ? ['before', 'after'] : ['before', 'after', 'caveat'];
    if (!hasExactKeys(exampleRecord, exampleKeys) || !isSafeWorkflowText(exampleRecord['before'], 250) || !isSafeWorkflowText(exampleRecord['after'], 250) ||
        (exampleRecord['caveat'] !== undefined && !isSafeWorkflowText(exampleRecord['caveat'], 250))) return false;
  }
  return true;
}

export function isFindingsPageResponse(value: unknown): value is FindingsPageResponse {
  if (typeof value !== 'object' || value === null) return false;
  const record = value as Record<string, unknown>;
  const allowed = ['findings', 'page', 'pageSize', 'total', 'totalPages', 'severity', 'scanner'];
  const keys = Object.keys(record);
  if (keys.some((key) => !allowed.includes(key)) ||
      !Array.isArray(record['findings']) || record['findings'].length > FINDINGS_PAGE_SIZE_MAX ||
      !isPositiveInteger(record['page'], FINDINGS_PAGE_MAX) ||
      !isPositiveInteger(record['pageSize'], FINDINGS_PAGE_SIZE_MAX) ||
      typeof record['total'] !== 'number' || !Number.isInteger(record['total']) ||
      record['total'] < 0 || record['total'] > MAX_FINDINGS_PER_SCAN ||
      typeof record['totalPages'] !== 'number' || !Number.isInteger(record['totalPages']) ||
      record['totalPages'] !== Math.ceil(record['total'] / record['pageSize']) ||
      record['findings'].length > record['pageSize'] ||
      !record['findings'].every(isFinding)) return false;
  if (record['severity'] !== undefined && !isFindingSeverity(record['severity'])) return false;
  if (record['scanner'] !== undefined && !(SCAN_TYPES as readonly unknown[]).includes(record['scanner'])) return false;
  if (record['severity'] !== undefined && record['findings'].some((finding) => finding.severity !== record['severity'])) return false;
  if (record['scanner'] !== undefined && record['findings'].some((finding) => findingScanner(finding) !== record['scanner'])) return false;
  return true;
}

export function isFindingDetailResponse(value: unknown): value is FindingDetailResponse {
  if (typeof value !== 'object' || value === null) return false;
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  const legacy = keys.length === 3 && !Object.prototype.hasOwnProperty.call(record, 'workflow') && !Object.prototype.hasOwnProperty.call(record, 'guidance');
  const current = keys.length === 5 && Object.prototype.hasOwnProperty.call(record, 'workflow') && Object.prototype.hasOwnProperty.call(record, 'guidance');
  if ((!legacy && !current) || !isProject(record['project']) || !isScan(record['scan']) || !isFinding(record['finding'])) return false;
  const scan = record['scan'] as Scan;
  const finding = record['finding'] as Finding;
  if (scan.projectId !== record['project'].id || finding.scanId !== scan.id || findingScanner(finding) !== scan.scanType ||
      (finding.projectId !== undefined && finding.projectId !== record['project'].id)) return false;
  if (legacy) return true;
  const workflow = record['workflow'];
  const guidance = record['guidance'];
  return isFindingWorkflow(workflow) && workflow.projectId === record['project'].id &&
    workflow.findingId === finding.id && workflow.fingerprint === finding.fingerprint &&
    workflow.scanner === findingScanner(finding) && workflow.ruleId === finding.ruleId &&
    isFindingRemediationGuidance(guidance) && guidance.ruleId === finding.ruleId;
}

/** A shared closed vocabulary check used by route query parsing. */
export function isFindingScanner(value: unknown): value is ScanType {
  return typeof value === 'string' && (SCAN_TYPES as readonly string[]).includes(value);
}

/** Keep the severity vocabulary available to consumers without duplicating it. */
export const FINDING_FILTER_SEVERITIES: readonly FindingSeverity[] = FINDING_SEVERITIES;
