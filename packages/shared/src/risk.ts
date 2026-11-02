/**
 * Correlated risk assessment contract.
 *
 * WHAT THIS IS: a read-only, deterministic projection over scans the project
 * already has. It groups the findings of the latest completed scan of each
 * scanner into *clusters* where the evidence genuinely overlaps (one endpoint,
 * one file, one weakness class, one deployed package), and states the combined
 * exposure with an explicit, versioned scoring model.
 *
 * WHAT THIS IS NOT: a new scan, a CVSS score, an exploit-chain proof, a live
 * SIEM, or a statement that the project is safe when no cluster exists. Every
 * cluster names the finding ids it was built from, and every score is computed
 * from recorded severity by the published formula in `docs/RISK_ASSESSMENT.md`.
 */
import { FINDING_ID_PATTERN, SCAN_ID_PATTERN, SCAN_TYPES, type FindingSeverity, type ScanType } from './scans.js';
import { PROJECT_ID_PATTERN } from './projects.js';

/** Findings a single assessment may consider (the per-scan caps are lower). */
export const RISK_MAX_FINDINGS = 400;
/** Clusters a single assessment may return. */
export const RISK_MAX_CLUSTERS = 50;
/** Evidence items per cluster. */
export const RISK_MAX_EVIDENCE = 8;
/** Bounded disclosure strings. */
export const RISK_MAX_DISCLOSURES = 12;

export const RISK_ASSESSMENT_LEVEL = 'DERIVED_CORRELATION' as const;
export const RISK_SCORING_MODEL = 'SEVERITY_SUM_V1' as const;

/**
 * The closed set of correlations. Each one is built ONLY from fields the
 * scanners already recorded; the kind names the evidence, not a conclusion.
 */
export const RISK_CORRELATION_KINDS = [
  /** Two or more DAST findings on the same observed endpoint path. */
  'ENDPOINT_CLUSTER',
  /** Two or more DAST findings from one response (same status/time window). */
  'SAME_RESPONSE',
  /** A SAST and a DAST finding with the same CWE class. */
  'CODE_AND_RUNTIME_CWE',
  /** A secret and a code weakness in the same file. */
  'SECRET_IN_WEAK_FILE',
  /** The same rule seen on two or more distinct assets. */
  'RECURRING_RULE',
] as const;
export type RiskCorrelationKind = (typeof RISK_CORRELATION_KINDS)[number];

export const RISK_BANDS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'] as const;
export type RiskBand = (typeof RISK_BANDS)[number];

export const RISK_STATUSES = ['ASSESSED', 'NO_FINDINGS', 'NO_COMPLETED_SCANS'] as const;
export type RiskStatus = (typeof RISK_STATUSES)[number];

/** Severity → exposure weight of the published scoring model. */
export const RISK_SEVERITY_WEIGHTS: Record<FindingSeverity, number> = {
  CRITICAL: 10,
  HIGH: 6,
  MEDIUM: 3,
  LOW: 1,
  INFO: 0,
};

/** Band boundaries over a cluster's computed score (descending). */
export const RISK_BAND_THRESHOLDS = { CRITICAL: 20, HIGH: 12, MEDIUM: 5, LOW: 1 } as const;

/** The single source of truth for "score → band". */
export function riskBandForScore(score: number): RiskBand {
  if (score >= RISK_BAND_THRESHOLDS.CRITICAL) return 'CRITICAL';
  if (score >= RISK_BAND_THRESHOLDS.HIGH) return 'HIGH';
  if (score >= RISK_BAND_THRESHOLDS.MEDIUM) return 'MEDIUM';
  if (score >= RISK_BAND_THRESHOLDS.LOW) return 'LOW';
  return 'UNKNOWN';
}

/** One recorded finding that supports a cluster. No content, only identity. */
export interface RiskEvidenceRef {
  findingId: string;
  scanner: ScanType;
  severity: FindingSeverity;
  ruleId: string;
  /** Endpoint path, file path or dependency name — bounded, already recorded. */
  asset: string;
}

export interface RiskCluster {
  /** Deterministic id derived from kind + asset. */
  id: string;
  kind: RiskCorrelationKind;
  band: RiskBand;
  /** Sum of member severity weights + corroborating scanners. See the model. */
  score: number;
  /** Distinct scanners that recorded evidence in this cluster. */
  scanners: ScanType[];
  /** One bounded sentence: what overlaps. */
  title: string;
  /** Why the overlap matters, and what it does NOT prove. */
  summary: string;
  /** The shared asset (endpoint path, file path or dependency name). */
  asset: string;
  evidence: RiskEvidenceRef[];
}

export interface RiskSourceCoverage {
  scanner: ScanType;
  /** The scan this assessment read for the scanner, when one completed. */
  scanId: string | null;
  completedAt: string | null;
  /** Findings that scan contributed (0 when it has no completed scan). */
  findings: number;
}

export interface RiskAssessment {
  schemaVersion: '1.0';
  assessmentLevel: typeof RISK_ASSESSMENT_LEVEL;
  scoringModel: typeof RISK_SCORING_MODEL;
  projectId: string;
  generatedAt: string;
  status: RiskStatus;
  /** Highest cluster band; UNKNOWN when nothing correlated. */
  band: RiskBand;
  /** Highest cluster score (0 when nothing correlated). */
  score: number;
  sources: RiskSourceCoverage[];
  findingsAnalysed: number;
  correlatedFindings: number;
  unclusteredFindings: number;
  clusters: RiskCluster[];
  /** Always present: what this assessment cannot claim. */
  disclosures: string[];
  truncated: boolean;
}

export interface RiskAssessmentResponse {
  assessment: RiskAssessment;
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

function validCount(value: unknown, max = 1_000_000): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0 && value <= max;
}

function validDate(value: unknown): value is string {
  return typeof value === 'string' && Number.isFinite(Date.parse(value));
}

function isScanner(value: unknown): value is ScanType {
  return typeof value === 'string' && (SCAN_TYPES as readonly string[]).includes(value);
}

function isSeverity(value: unknown): value is FindingSeverity {
  return typeof value === 'string' && Object.hasOwn(RISK_SEVERITY_WEIGHTS, value);
}

function isEvidenceRef(value: unknown): value is RiskEvidenceRef {
  if (!isRecord(value) || !exactKeys(value, ['findingId', 'scanner', 'severity', 'ruleId', 'asset'])) return false;
  return typeof value['findingId'] === 'string' && FINDING_ID_PATTERN.test(value['findingId']) &&
    isScanner(value['scanner']) && isSeverity(value['severity']) &&
    safeText(value['ruleId'], 64) && safeText(value['asset'], 300);
}

function isCluster(value: unknown): value is RiskCluster {
  if (!isRecord(value) || !exactKeys(value, ['id', 'kind', 'band', 'score', 'scanners', 'title', 'summary', 'asset', 'evidence'])) return false;
  if (typeof value['id'] !== 'string' || !/^risk_[a-f0-9]{24}$/.test(value['id'])) return false;
  if (!(RISK_CORRELATION_KINDS as readonly unknown[]).includes(value['kind'])) return false;
  if (!validCount(value['score'], 1_000)) return false;
  // The band is never free-form: it must be exactly what the model derives.
  if (value['band'] !== riskBandForScore(value['score'] as number)) return false;
  if (!safeText(value['title'], 160) || !safeText(value['summary'], 400) || !safeText(value['asset'], 300)) return false;
  const scanners = value['scanners'];
  if (!Array.isArray(scanners) || scanners.length === 0 || scanners.length > SCAN_TYPES.length ||
      !scanners.every(isScanner) || new Set(scanners).size !== scanners.length) return false;
  const evidence = value['evidence'];
  if (!Array.isArray(evidence) || evidence.length < 2 || evidence.length > RISK_MAX_EVIDENCE) return false;
  if (!evidence.every(isEvidenceRef)) return false;
  // Evidence must be distinct findings, and must be the scanners the cluster claims.
  const ids = evidence.map((item: RiskEvidenceRef) => item.findingId);
  if (new Set(ids).size !== ids.length) return false;
  const evidenceScanners = new Set(evidence.map((item: RiskEvidenceRef) => item.scanner));
  if (evidenceScanners.size !== scanners.length ||
      !scanners.every((scanner) => evidenceScanners.has(scanner))) return false;
  // A cluster can never score less than its own evidence.
  const floor = Math.max(...evidence.map((item: RiskEvidenceRef) => RISK_SEVERITY_WEIGHTS[item.severity]));
  return value['score'] >= floor;
}

function isSourceCoverage(value: unknown, scanner: ScanType): boolean {
  if (!isRecord(value) || !exactKeys(value, ['scanner', 'scanId', 'completedAt', 'findings'])) return false;
  if (value['scanner'] !== scanner) return false;
  if (!validCount(value['findings'], RISK_MAX_FINDINGS)) return false;
  const hasScan = value['scanId'] !== null;
  if (hasScan) {
    if (typeof value['scanId'] !== 'string' || !SCAN_ID_PATTERN.test(value['scanId'])) return false;
    if (!validDate(value['completedAt'])) return false;
  } else if (value['completedAt'] !== null || value['findings'] !== 0) {
    return false;
  }
  return true;
}

export function isRiskAssessment(value: unknown): value is RiskAssessment {
  if (!isRecord(value) || !exactKeys(value, [
    'schemaVersion', 'assessmentLevel', 'scoringModel', 'projectId', 'generatedAt', 'status', 'band',
    'score', 'sources', 'findingsAnalysed', 'correlatedFindings', 'unclusteredFindings', 'clusters',
    'disclosures', 'truncated',
  ])) return false;
  if (value['schemaVersion'] !== '1.0' || value['assessmentLevel'] !== RISK_ASSESSMENT_LEVEL ||
      value['scoringModel'] !== RISK_SCORING_MODEL) return false;
  if (typeof value['projectId'] !== 'string' || !PROJECT_ID_PATTERN.test(value['projectId'])) return false;
  if (!validDate(value['generatedAt'])) return false;
  if (!(RISK_STATUSES as readonly unknown[]).includes(value['status'])) return false;
  if (!(RISK_BANDS as readonly unknown[]).includes(value['band'])) return false;
  if (!validCount(value['score'], 1_000) || value['band'] !== riskBandForScore(value['score'] as number)) return false;

  const sources = value['sources'];
  if (!Array.isArray(sources) || sources.length !== SCAN_TYPES.length) return false;
  if (!SCAN_TYPES.every((scanner, index) => isSourceCoverage(sources[index], scanner))) return false;
  const withScan = sources.filter((source: RiskSourceCoverage) => source.scanId !== null) as RiskSourceCoverage[];

  if (!validCount(value['findingsAnalysed'], RISK_MAX_FINDINGS)) return false;
  if (!validCount(value['correlatedFindings'], RISK_MAX_FINDINGS)) return false;
  if (!validCount(value['unclusteredFindings'], RISK_MAX_FINDINGS)) return false;
  if ((value['correlatedFindings'] as number) + (value['unclusteredFindings'] as number) !== value['findingsAnalysed']) return false;
  if (sources.reduce((sum: number, source: RiskSourceCoverage) => sum + source.findings, 0) !== value['findingsAnalysed']) return false;

  const clusters = value['clusters'];
  if (!Array.isArray(clusters) || clusters.length > RISK_MAX_CLUSTERS) return false;
  if (!clusters.every(isCluster)) return false;
  if (new Set(clusters.map((cluster: RiskCluster) => cluster.id)).size !== clusters.length) return false;

  // A cluster may only cite evidence from a scanner that really contributed.
  const knownFindings = new Set<ScanType>(withScan.map((source) => source.scanner));
  for (const cluster of clusters as RiskCluster[]) {
    if (cluster.evidence.some((item) => !knownFindings.has(item.scanner))) return false;
  }

  // The headline is derived, never supplied: it is the max cluster score.
  const maxScore = clusters.length === 0 ? 0 : Math.max(...(clusters as RiskCluster[]).map((cluster) => cluster.score));
  if (value['score'] !== maxScore) return false;
  if (clusters.length === 0 && value['band'] !== 'UNKNOWN') return false;

  // Status must match the evidence that exists.
  if (value['status'] === 'NO_COMPLETED_SCANS' && (withScan.length !== 0 || value['findingsAnalysed'] !== 0 || clusters.length !== 0)) return false;
  if (value['status'] === 'NO_FINDINGS' && (withScan.length === 0 || value['findingsAnalysed'] !== 0)) return false;
  if (value['status'] === 'ASSESSED' && (withScan.length === 0 || value['findingsAnalysed'] === 0)) return false;
  if ((value['status'] === 'NO_FINDINGS' || value['status'] === 'NO_COMPLETED_SCANS') && clusters.length !== 0) return false;

  if (!Array.isArray(value['disclosures']) || value['disclosures'].length === 0 ||
      value['disclosures'].length > RISK_MAX_DISCLOSURES ||
      !value['disclosures'].every((item: unknown) => safeText(item, 400))) return false;
  return typeof value['truncated'] === 'boolean';
}

export function isRiskAssessmentResponse(value: unknown): value is RiskAssessmentResponse {
  return isRecord(value) && exactKeys(value, ['assessment']) && isRiskAssessment(value['assessment']);
}
