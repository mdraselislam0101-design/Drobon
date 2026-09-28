import { FINDING_LIFECYCLE_STATES, type FindingLifecycleState } from './findings.js';
import { isRecord } from './guards.js';
import { REPORT_ID_PATTERN } from './reports.js';
import { PROJECT_ID_PATTERN, isProjectStatus, type ProjectStatus } from './projects.js';
import { isScaAssessmentState, isScaDatasetStatus, type ScaAssessmentState, type ScaDatasetStatus } from './sca.js';
import {
  FINDING_ID_PATTERN,
  FINDING_SEVERITIES,
  SCAN_ID_PATTERN,
  SCAN_STATUSES,
  isFindingSeverity,
  isScanStatus,
  isScanType,
  type FindingSeverity,
  type ScanStatus,
  type ScanType,
} from './scans.js';

/** Fixed response bounds for the authenticated, account-scoped overview. */
export const WORKSPACE_PROJECTS_MAX = 6;
export const WORKSPACE_SCANS_MAX = 8;
export const WORKSPACE_FINDINGS_MAX = 8;
export const WORKSPACE_REPORTS_MAX = 5;

export interface WorkspaceProjectCard {
  id: string;
  name: string;
  status: ProjectStatus;
  updatedAt: string;
  /** Only indicates a canonical target is stored on this owned project; it is not authorization proof. */
  dastTargetConfigured: boolean;
}

export interface WorkspaceProjectsSummary {
  total: number;
  active: number;
  archived: number;
  /** Exact account-scoped count of project records with a configured DAST target. */
  dastTargetsConfigured: number;
  recent: WorkspaceProjectCard[];
}

export interface WorkspaceScanCard {
  scanId: string;
  projectId: string;
  scanType: ScanType;
  status: ScanStatus;
  createdAt: string;
  completedAt: string | null;
  /** Null when the completed scan predates a result summary; never guessed as zero. */
  findingsTotal: number | null;
  /** Null when the engine did not publish partial-coverage metadata. */
  partial: boolean | null;
  reportAvailable: boolean;
  /** Bounded passive DAST response count; null when not a DAST result. */
  dastObservationsCount: number | null;
  /** Explicit SCA intelligence state; null when not an SCA result. */
  scaAssessmentState: ScaAssessmentState | null;
  scaDatasetStatus: ScaDatasetStatus | null;
}

export interface WorkspaceScansSummary {
  total: number;
  byStatus: Record<ScanStatus, number>;
  recent: WorkspaceScanCard[];
}

export interface WorkspaceFindingCard {
  findingId: string;
  projectId: string;
  scanId: string;
  scanner: ScanType;
  ruleId: string;
  severity: FindingSeverity;
  lifecycleState: FindingLifecycleState;
  verificationState: 'OBSERVED' | 'NOT_OBSERVED_IN_LATEST_SCAN';
  observedAt: string;
  workflowUpdatedAt: string;
}

export interface WorkspaceFindingsSummary {
  /** Unique finding identities, using the latest persisted observation per project. */
  currentObserved: number;
  unresolved: number;
  unresolvedBySeverity: Record<FindingSeverity, number>;
  byLifecycleState: Record<FindingLifecycleState, number>;
  byVerificationState: Record<'OBSERVED' | 'NOT_OBSERVED_IN_LATEST_SCAN', number>;
  recent: WorkspaceFindingCard[];
}

export interface WorkspaceReportCard {
  reportId: string;
  projectId: string;
  scanId: string;
  generatedAt: string;
}

export interface WorkspaceReportsSummary {
  availableCount: number;
  recent: WorkspaceReportCard[];
}

/**
 * Authenticated self-service overview. Every count is derived from persisted
 * project/scan/finding/report records owned by the session account; this is not
 * an overall security verdict and does not imply that all scanners ran.
 */
export interface WorkspaceSecurityOverview {
  generatedAt: string;
  projects: WorkspaceProjectsSummary;
  scans: WorkspaceScansSummary;
  findings: WorkspaceFindingsSummary;
  reports: WorkspaceReportsSummary;
}

export interface WorkspaceSecurityOverviewResponse {
  overview: WorkspaceSecurityOverview;
}

function exactKeys(record: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(record);
  return actual.length === keys.length && keys.every((key) => Object.prototype.hasOwnProperty.call(record, key));
}

function isCount(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function isTimestamp(value: unknown): value is string {
  return typeof value === 'string' && !Number.isNaN(Date.parse(value));
}

function sumCounts(value: Record<string, number>): number {
  return Object.values(value).reduce((sum, count) => sum + count, 0);
}

function isProjectCard(value: unknown): value is WorkspaceProjectCard {
  return isRecord(value) && exactKeys(value, ['id', 'name', 'status', 'updatedAt', 'dastTargetConfigured']) &&
    typeof value['id'] === 'string' && PROJECT_ID_PATTERN.test(value['id']) &&
    typeof value['name'] === 'string' && value['name'].length > 0 && value['name'].length <= 120 &&
    isProjectStatus(value['status']) && isTimestamp(value['updatedAt']) && typeof value['dastTargetConfigured'] === 'boolean';
}

function isScanCard(value: unknown): value is WorkspaceScanCard {
  return isRecord(value) && exactKeys(value, [
    'scanId', 'projectId', 'scanType', 'status', 'createdAt', 'completedAt',
    'findingsTotal', 'partial', 'reportAvailable', 'dastObservationsCount',
    'scaAssessmentState', 'scaDatasetStatus',
  ]) && typeof value['scanId'] === 'string' && SCAN_ID_PATTERN.test(value['scanId']) &&
    typeof value['projectId'] === 'string' && PROJECT_ID_PATTERN.test(value['projectId']) &&
    isScanType(value['scanType']) && isScanStatus(value['status']) && isTimestamp(value['createdAt']) &&
    (value['completedAt'] === null || isTimestamp(value['completedAt'])) &&
    (value['findingsTotal'] === null || isCount(value['findingsTotal'])) &&
    (value['partial'] === null || typeof value['partial'] === 'boolean') &&
    typeof value['reportAvailable'] === 'boolean' &&
    (value['dastObservationsCount'] === null || isCount(value['dastObservationsCount'])) &&
    (value['scanType'] === 'DAST' && value['status'] === 'COMPLETED' ? value['dastObservationsCount'] !== null : value['dastObservationsCount'] === null) &&
    (value['scaAssessmentState'] === null || isScaAssessmentState(value['scaAssessmentState'])) &&
    (value['scaDatasetStatus'] === null || isScaDatasetStatus(value['scaDatasetStatus'])) &&
    (value['scanType'] === 'SCA' && value['status'] === 'COMPLETED' ? value['scaAssessmentState'] !== null && value['scaDatasetStatus'] !== null : value['scaAssessmentState'] === null && value['scaDatasetStatus'] === null);
}

function isFindingCard(value: unknown): value is WorkspaceFindingCard {
  return isRecord(value) && exactKeys(value, [
    'findingId', 'projectId', 'scanId', 'scanner', 'ruleId', 'severity',
    'lifecycleState', 'verificationState', 'observedAt', 'workflowUpdatedAt',
  ]) && typeof value['findingId'] === 'string' && FINDING_ID_PATTERN.test(value['findingId']) &&
    typeof value['projectId'] === 'string' && PROJECT_ID_PATTERN.test(value['projectId']) &&
    typeof value['scanId'] === 'string' && SCAN_ID_PATTERN.test(value['scanId']) &&
    isScanType(value['scanner']) && typeof value['ruleId'] === 'string' && value['ruleId'].length > 0 &&
    isFindingSeverity(value['severity']) &&
    (FINDING_LIFECYCLE_STATES as readonly unknown[]).includes(value['lifecycleState']) &&
    (value['verificationState'] === 'OBSERVED' || value['verificationState'] === 'NOT_OBSERVED_IN_LATEST_SCAN') &&
    isTimestamp(value['observedAt']) && isTimestamp(value['workflowUpdatedAt']);
}

function isReportCard(value: unknown): value is WorkspaceReportCard {
  return isRecord(value) && exactKeys(value, ['reportId', 'projectId', 'scanId', 'generatedAt']) &&
    typeof value['reportId'] === 'string' && REPORT_ID_PATTERN.test(value['reportId']) &&
    typeof value['projectId'] === 'string' && PROJECT_ID_PATTERN.test(value['projectId']) &&
    typeof value['scanId'] === 'string' && SCAN_ID_PATTERN.test(value['scanId']) &&
    isTimestamp(value['generatedAt']);
}

function isCountRecord<K extends string>(value: unknown, keys: readonly K[]): value is Record<K, number> {
  return isRecord(value) && Object.keys(value).length === keys.length &&
    keys.every((key) => Object.prototype.hasOwnProperty.call(value, key) && isCount(value[key]));
}

/** Closed-shape guard for the overview API response; rejects accidental evidence/owner leakage. */
export function isWorkspaceSecurityOverview(value: unknown): value is WorkspaceSecurityOverview {
  if (!isRecord(value) || !exactKeys(value, ['generatedAt', 'projects', 'scans', 'findings', 'reports']) || !isTimestamp(value['generatedAt'])) return false;
  const projects = value['projects'];
  if (!isRecord(projects) || !exactKeys(projects, ['total', 'active', 'archived', 'dastTargetsConfigured', 'recent']) ||
      !isCount(projects['total']) || !isCount(projects['active']) || !isCount(projects['archived']) ||
      !isCount(projects['dastTargetsConfigured']) || projects['dastTargetsConfigured'] > projects['total'] ||
      projects['active'] + projects['archived'] !== projects['total'] || !Array.isArray(projects['recent']) ||
      projects['recent'].length > WORKSPACE_PROJECTS_MAX || projects['recent'].length > projects['total'] ||
      !projects['recent'].every(isProjectCard) || projects['recent'].filter((project) => project.dastTargetConfigured).length > projects['dastTargetsConfigured']) return false;
  const scans = value['scans'];
  if (!isRecord(scans) || !exactKeys(scans, ['total', 'byStatus', 'recent']) || !isCount(scans['total']) ||
      !isCountRecord(scans['byStatus'], SCAN_STATUSES) ||
      Object.values(scans['byStatus'] as Record<string, number>).reduce((sum, count) => sum + count, 0) !== scans['total'] ||
      !Array.isArray(scans['recent']) || scans['recent'].length > WORKSPACE_SCANS_MAX || scans['recent'].length > scans['total'] || !scans['recent'].every(isScanCard)) return false;
  const findings = value['findings'];
  if (!isRecord(findings) || !exactKeys(findings, [
    'currentObserved', 'unresolved', 'unresolvedBySeverity', 'byLifecycleState', 'byVerificationState', 'recent',
  ]) || !isCount(findings['currentObserved']) || !isCount(findings['unresolved']) ||
      findings['unresolved'] > findings['currentObserved'] || !isCountRecord(findings['unresolvedBySeverity'], FINDING_SEVERITIES) ||
      !isCountRecord(findings['byLifecycleState'], FINDING_LIFECYCLE_STATES) ||
      !isRecord(findings['byVerificationState']) || Object.keys(findings['byVerificationState']).length !== 2 ||
      !isCount(findings['byVerificationState']['OBSERVED']) || !isCount(findings['byVerificationState']['NOT_OBSERVED_IN_LATEST_SCAN']) ||
      !Array.isArray(findings['recent']) || findings['recent'].length > WORKSPACE_FINDINGS_MAX || findings['recent'].length > findings['currentObserved'] ||
      sumCounts(findings['unresolvedBySeverity'] as Record<string, number>) !== findings['unresolved'] ||
      sumCounts(findings['byLifecycleState'] as Record<string, number>) !== findings['currentObserved'] ||
      sumCounts(findings['byVerificationState'] as Record<string, number>) !== findings['currentObserved'] ||
      !findings['recent'].every(isFindingCard)) return false;
  const reports = value['reports'];
  if (!isRecord(reports) || !exactKeys(reports, ['availableCount', 'recent']) || !isCount(reports['availableCount']) ||
      !Array.isArray(reports['recent']) || reports['recent'].length > WORKSPACE_REPORTS_MAX || reports['recent'].length > reports['availableCount'] || !reports['recent'].every(isReportCard)) return false;
  return true;
}

export function isWorkspaceSecurityOverviewResponse(value: unknown): value is WorkspaceSecurityOverviewResponse {
  return isRecord(value) && exactKeys(value, ['overview']) && isWorkspaceSecurityOverview(value['overview']);
}

export function emptyWorkspaceFindingsSummary(): WorkspaceFindingsSummary {
  return {
    currentObserved: 0,
    unresolved: 0,
    unresolvedBySeverity: Object.fromEntries(FINDING_SEVERITIES.map((severity) => [severity, 0])) as Record<FindingSeverity, number>,
    byLifecycleState: Object.fromEntries(FINDING_LIFECYCLE_STATES.map((state) => [state, 0])) as Record<FindingLifecycleState, number>,
    byVerificationState: { OBSERVED: 0, NOT_OBSERVED_IN_LATEST_SCAN: 0 },
    recent: [],
  };
}

export function emptyWorkspaceScansSummary(): WorkspaceScansSummary {
  return {
    total: 0,
    byStatus: Object.fromEntries(SCAN_STATUSES.map((status) => [status, 0])) as Record<ScanStatus, number>,
    recent: [],
  };
}
