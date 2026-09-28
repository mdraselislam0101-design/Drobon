import { isProjectStatus, PROJECT_ID_PATTERN, type ProjectStatus } from './projects.js';
import {
  FINDING_SEVERITIES,
  SCAN_TYPES,
  isFinding,
  isFindingSeverity,
  isScan,
  findingScanner,
  type Finding,
  type FindingSeverity,
  type Scan,
  type ScanType,
} from './scans.js';
import { isScaResult, type ScaResult } from './sca.js';
import { isDastResult, type DastResult } from './dast.js';

export const REPORT_SCHEMA_VERSION = 1 as const;
export const REPORT_VERSION = '1.0' as const;
export const REPORT_ID_PATTERN = /^rpt_[0-9a-f]{24}$/;
export const REPORT_DIGEST_PATTERN = /^[0-9a-f]{64}$/;
export const REPORT_MAX_BYTES = 512 * 1024;
export const REPORT_PERSISTED_MAX_COUNT = 100;

export interface ReportProjectContext {
  id: string;
  name: string;
  status: ProjectStatus;
}

export interface ReportScanContext extends Scan {
  status: 'COMPLETED';
  completedAt: string;
}

export interface ScannerCoverageEntry {
  scanner: ScanType;
  status: 'RAN' | 'NOT_RUN';
  reason?: string;
}

export interface ReportFindingSummary {
  total: number;
  bySeverity: Record<FindingSeverity, number>;
  byScanner: Record<ScanType, number>;
}

export interface ReportDependencyIntelligence {
  status: 'ASSESSED' | 'NOT_ASSESSED';
  reason?: string;
  providerId?: string;
  datasetStatus?: 'NO_DATA_LOADED' | 'DATASET_UNAVAILABLE';
  advisoriesTotal?: number;
}

export type ReportInventory =
  | { status: 'INCLUDED'; sca: ScaResult }
  | { status: 'NOT_INCLUDED'; reason: string };

/**
 * Persisted, deterministic security-assessment report. `contentDigest`
 * identifies the immutable scan/project result; `integrityDigest` hashes
 * the serialized report including its persisted generation timestamp.
 * Neither field is a digital signature.
 */
export interface SecurityReportResponse {
  report: SecurityReport;
}

export interface SecurityReport {
  reportId: string;
  reportVersion: typeof REPORT_VERSION;
  schemaVersion: typeof REPORT_SCHEMA_VERSION;
  generatedAt: string;
  project: ReportProjectContext;
  scan: ReportScanContext;
  scannerCoverage: ScannerCoverageEntry[];
  findingSummary: ReportFindingSummary;
  findings: Finding[];
  /** Bounded response metadata/evidence for DAST reports only; no raw bodies or sensitive headers. */
  dast?: DastResult;
  dependencyIntelligence: ReportDependencyIntelligence;
  inventory: ReportInventory;
  contentDigest: string;
  integrityDigest: string;
}

function isBoundedText(value: unknown, max: number): value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > max) return false;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return false;
  }
  return true;
}

function isCount(value: unknown, max: number): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0 && value <= max;
}

function hasExactKeys(record: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(record);
  return actual.length === keys.length && keys.every((key) => Object.prototype.hasOwnProperty.call(record, key));
}

function countFindings(findings: readonly Finding[]): ReportFindingSummary {
  const bySeverity: Record<FindingSeverity, number> = {
    CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0,
  };
  const byScanner: Record<ScanType, number> = { SAST: 0, SCA: 0, SECRETS: 0, DAST: 0 };
  for (const finding of findings) {
    bySeverity[finding.severity] += 1;
    const scanner = findingScanner(finding);
    if (scanner !== undefined) byScanner[scanner] += 1;
  }
  return { total: findings.length, bySeverity, byScanner };
}

export function isReportFindingSummary(value: unknown): value is ReportFindingSummary {
  if (typeof value !== 'object' || value === null) return false;
  const record = value as Record<string, unknown>;
  if (!hasExactKeys(record, ['total', 'bySeverity', 'byScanner']) || !isCount(record['total'], 200)) return false;
  const severity = record['bySeverity'];
  const scanner = record['byScanner'];
  if (typeof severity !== 'object' || severity === null || typeof scanner !== 'object' || scanner === null) return false;
  const severityRecord = severity as Record<string, unknown>;
  const scannerRecord = scanner as Record<string, unknown>;
  if (!hasExactKeys(severityRecord, FINDING_SEVERITIES) || !hasExactKeys(scannerRecord, SCAN_TYPES)) return false;
  if (!FINDING_SEVERITIES.every((key) => isCount(severityRecord[key], 200)) ||
      !SCAN_TYPES.every((key) => isCount(scannerRecord[key], 200))) return false;
  const severityTotal = FINDING_SEVERITIES.reduce((sum, key) => sum + (severityRecord[key] as number), 0);
  const scannerTotal = SCAN_TYPES.reduce((sum, key) => sum + (scannerRecord[key] as number), 0);
  return severityTotal === record['total'] && scannerTotal === record['total'];
}

function isReportProject(value: unknown): value is ReportProjectContext {
  if (typeof value !== 'object' || value === null) return false;
  const record = value as Record<string, unknown>;
  return hasExactKeys(record, ['id', 'name', 'status']) &&
    typeof record['id'] === 'string' && PROJECT_ID_PATTERN.test(record['id']) &&
    isBoundedText(record['name'], 80) && isProjectStatus(record['status']);
}

function isReportScan(value: unknown): value is ReportScanContext {
  return isScan(value) && value.status === 'COMPLETED' && typeof value.completedAt === 'string';
}

function isCoverage(value: unknown, scanType: ScanType): value is ScannerCoverageEntry[] {
  if (!Array.isArray(value) || value.length !== SCAN_TYPES.length) return false;
  return value.every((entry, index) => {
    if (typeof entry !== 'object' || entry === null) return false;
    const record = entry as Record<string, unknown>;
    if (!hasExactKeys(record, record['status'] === 'NOT_RUN' ? ['scanner', 'status', 'reason'] : ['scanner', 'status'])) return false;
    if (record['scanner'] !== SCAN_TYPES[index]) return false;
    const ran = record['scanner'] === scanType;
    return ran
      ? record['status'] === 'RAN' && record['reason'] === undefined
      : record['status'] === 'NOT_RUN' && record['reason'] === 'Not run in this single-scan assessment.';
  });
}

function isDependencyIntelligence(value: unknown, inventory: ReportInventory): value is ReportDependencyIntelligence {
  if (typeof value !== 'object' || value === null) return false;
  const record = value as Record<string, unknown>;
  const allowed = ['status', 'reason', 'providerId', 'datasetStatus', 'advisoriesTotal'];
  if (Object.keys(record).some((key) => !allowed.includes(key)) ||
      (record['status'] !== 'ASSESSED' && record['status'] !== 'NOT_ASSESSED')) return false;
  if (record['reason'] !== undefined && !isBoundedText(record['reason'], 200)) return false;
  if (record['providerId'] !== undefined && !isBoundedText(record['providerId'], 64)) return false;
  if (record['datasetStatus'] !== undefined && record['datasetStatus'] !== 'NO_DATA_LOADED' && record['datasetStatus'] !== 'DATASET_UNAVAILABLE') return false;
  if (record['advisoriesTotal'] !== undefined && !isCount(record['advisoriesTotal'], 200)) return false;
  if (inventory.status === 'NOT_INCLUDED') {
    return record['status'] === 'NOT_ASSESSED' &&
      record['reason'] === 'Dependency analysis was not run in this scan.' &&
      record['providerId'] === undefined && record['datasetStatus'] === undefined && record['advisoriesTotal'] === undefined;
  }
  const summary = inventory.sca.summary;
  return record['status'] === summary.assessmentState &&
    record['providerId'] === summary.providerId &&
    record['datasetStatus'] === summary.datasetStatus &&
    record['advisoriesTotal'] === summary.advisoriesTotal &&
    (summary.assessmentState === 'ASSESSED'
      ? record['reason'] === undefined
      : record['reason'] === `Vulnerability intelligence is NOT ASSESSED (${summary.datasetStatus.toLowerCase().replaceAll('_', ' ')}).`);
}

function isInventory(value: unknown, scanType: ScanType): value is ReportInventory {
  if (typeof value !== 'object' || value === null) return false;
  const record = value as Record<string, unknown>;
  if (record['status'] === 'INCLUDED') {
    return hasExactKeys(record, ['status', 'sca']) && scanType === 'SCA' && isScaResult(record['sca']);
  }
  return record['status'] === 'NOT_INCLUDED' &&
    hasExactKeys(record, ['status', 'reason']) && scanType !== 'SCA' &&
    record['reason'] === 'Dependency inventory was not part of this scan.';
}

export function isSecurityReport(value: unknown): value is SecurityReport {
  if (typeof value !== 'object' || value === null) return false;
  const record = value as Record<string, unknown>;
  const requiredKeys = [
    'reportId', 'reportVersion', 'schemaVersion', 'generatedAt', 'project', 'scan',
    'scannerCoverage', 'findingSummary', 'findings', 'dependencyIntelligence',
    'inventory', 'contentDigest', 'integrityDigest',
  ];
  if (Object.keys(record).some((key) => ![...requiredKeys, 'dast'].includes(key)) ||
      requiredKeys.some((key) => !Object.prototype.hasOwnProperty.call(record, key))) return false;
  if (typeof record['reportId'] !== 'string' || !REPORT_ID_PATTERN.test(record['reportId']) ||
      record['reportVersion'] !== REPORT_VERSION || record['schemaVersion'] !== REPORT_SCHEMA_VERSION ||
      typeof record['generatedAt'] !== 'string' || Number.isNaN(Date.parse(record['generatedAt'])) ||
      !isReportProject(record['project']) || !isReportScan(record['scan']) ||
      !Array.isArray(record['findings']) || record['findings'].length > 200 ||
      !record['findings'].every(isFinding) || !isReportFindingSummary(record['findingSummary']) ||
      typeof record['contentDigest'] !== 'string' || !REPORT_DIGEST_PATTERN.test(record['contentDigest']) ||
      typeof record['integrityDigest'] !== 'string' || !REPORT_DIGEST_PATTERN.test(record['integrityDigest'])) return false;
  const scan = record['scan'] as ReportScanContext;
  const project = record['project'] as ReportProjectContext;
  const inventory = record['inventory'] as ReportInventory;
  if (scan.projectId !== project.id || !isInventory(inventory, scan.scanType) ||
      !isCoverage(record['scannerCoverage'], scan.scanType) ||
      !isDependencyIntelligence(record['dependencyIntelligence'], inventory)) return false;
  if (scan.scanType === 'DAST') {
    if (!isDastResult(record['dast']) || record['dast'].targetUrl !== scan.targetUrl) return false;
  } else if (record['dast'] !== undefined) return false;
  const findings = record['findings'] as Finding[];
  if (findings.some((finding) => finding.scanId !== scan.id ||
      (finding.projectId !== undefined && finding.projectId !== project.id))) return false;
  const summary = countFindings(findings);
  const suppliedSummary = record['findingSummary'] as ReportFindingSummary;
  return summary.total === suppliedSummary.total &&
    FINDING_SEVERITIES.every((severity) => summary.bySeverity[severity] === suppliedSummary.bySeverity[severity]) &&
    SCAN_TYPES.every((scanner) => summary.byScanner[scanner] === suppliedSummary.byScanner[scanner]);
}

export function isSecurityReportResponse(value: unknown): value is SecurityReportResponse {
  if (typeof value !== 'object' || value === null) return false;
  const record = value as Record<string, unknown>;
  return hasExactKeys(record, ['report']) && isSecurityReport(record['report']);
}

/** Build counts with all severity/scanner keys present, including zeroes. */
export function summarizeReportFindings(findings: readonly Finding[]): ReportFindingSummary {
  return countFindings(findings);
}

export function isReportSeverity(value: unknown): value is FindingSeverity {
  return isFindingSeverity(value);
}
