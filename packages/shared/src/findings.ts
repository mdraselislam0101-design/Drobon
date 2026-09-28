import {
  FINDING_SEVERITIES,
  MAX_FINDINGS_PER_SCAN,
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
import { isProject, type Project } from './projects.js';

/** Server-side findings pages remain bounded by the existing per-scan cap. */
export const FINDINGS_PAGE_SIZE_MAX = 100;
export const FINDINGS_PAGE_MAX = 10_000;

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
}

function isPositiveInteger(value: unknown, max: number): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 1 && value <= max;
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
  if (Object.keys(record).length !== 3 || !isProject(record['project']) || !isScan(record['scan']) || !isFinding(record['finding'])) return false;
  const scan = record['scan'] as Scan;
  const finding = record['finding'] as Finding;
  return scan.projectId === record['project'].id &&
    finding.scanId === scan.id &&
    findingScanner(finding) === scan.scanType &&
    (finding.projectId === undefined || finding.projectId === record['project'].id);
}

/** A shared closed vocabulary check used by route query parsing. */
export function isFindingScanner(value: unknown): value is ScanType {
  return typeof value === 'string' && (SCAN_TYPES as readonly string[]).includes(value);
}

/** Keep the severity vocabulary available to consumers without duplicating it. */
export const FINDING_FILTER_SEVERITIES: readonly FindingSeverity[] = FINDING_SEVERITIES;
