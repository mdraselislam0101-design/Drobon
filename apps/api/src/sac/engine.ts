/**
 * SAC: an honest, deterministic coverage ledger for one completed scan.
 *
 * It uses only data persisted with that scan and report. It never reads the
 * CURRENT dataset configuration to guess which rules ran in a past scan,
 * never calls a model, and never asserts a compliance certification.
 */
import {
  SAC_ASSESSMENT_LEVEL,
  type DastResult,
  type ReportFindingSummary,
  type ReportScanContext,
  type SacAssessment,
  type SacMetrics,
  type ScannerCoverageEntry,
} from '@drobon/shared';

export interface SacInput {
  scan: ReportScanContext;
  scannerCoverage: readonly ScannerCoverageEntry[];
  findings: ReportFindingSummary;
  dast?: DastResult;
}

/** Derive metrics exactly from recorded summary fields; unknown stays null. */
export function createSacMetrics(input: SacInput): SacMetrics {
  const summary = input.scan.resultSummary;
  if (summary === undefined) throw new TypeError('A completed scan summary is required.');
  return {
    filesScanned: summary.filesScanned ?? null,
    filesSkipped: summary.filesSkipped ?? null,
    requestsMade: summary.requestsMade ?? null,
    redirectsFollowed: summary.redirectsFollowed ?? null,
    declarationRulesEvaluated: summary.declarationRulesEvaluated ?? null,
    declarationRulesNotEvaluated: summary.declarationRulesNotEvaluated ?? null,
    astFilesAnalyzed: summary.astFilesAnalyzed ?? null,
    astFlowsFound: summary.astFlowsFound ?? null,
    partial: summary.partial ?? null,
    truncated: summary.truncated ?? null,
    partialReason: summary.partialReason ?? null,
  };
}

export function createSacAssessment(input: SacInput): SacAssessment {
  const { scan, findings, dast } = input;
  const metrics = createSacMetrics(input);
  const incomplete = metrics.partial === true || metrics.truncated === true || dast?.partial === true ||
    scan.resultSummary?.astSupplement?.status === 'PARTIAL';
  const hasFindings = findings.total > 0;
  const recordedSastRules = scan.scanType === 'SAST' && scan.resultSummary?.astCoverage !== undefined;
  const limitations = [
    'Only this saved scan is covered; other scan types are marked NOT_RUN.',
    'Zero recorded findings do not prove that the target is secure or that all checks were performed.',
    recordedSastRules
      ? 'The saved hash and count identify the effective SAST rule set, not the full dataset or a digital signature; pack identity may be unavailable.'
      : 'Rule-pack identity, version and count at scan time were not recorded and cannot be reconstructed reliably.',
    'Automated observations can contain false positives and can miss vulnerabilities, including unknown vulnerabilities.',
    'Authorization is not independently verified; the operator must obtain permission and respect the agreed scope.',
  ];
  if (scan.scanType === 'DAST') {
    limitations.push('The scan covers only its recorded HTTP observations. It does not prove exploitability or cover the whole application.');
    limitations.push('Authenticated pages, browser JavaScript, business logic and external infrastructure were not assessed by this report.');
    if (scan.assessmentId !== undefined) {
      limitations.push('For linked scans, current engagement scope is rechecked before each request; declarations are unverified and an in-flight request cannot be recalled.');
    }
  } else if (scan.scanType === 'SAST') {
    limitations.push('Source analysis covers only supported, uploaded files; it does not execute the application or establish runtime behaviour.');
    limitations.push(scan.resultSummary?.astCoverage === undefined
      ? 'The recorded syntax-tree pass covers JS/TS/JSX/TSX only and needs applicable rules; other languages use bounded heuristics.'
      : 'Syntax parsers cover JS/TS/JSX/TSX, Python, PHP and Java; project flow handles only a bounded JS/TS subset and needs applicable rules.');
    if (recordedSastRules) limitations.push('AST flow reporters are selected by category; a specific rule pattern or exploitability is not proven.');
  } else if (scan.scanType === 'SCA') {
    limitations.push('Inventory and advisory coverage depend on supported manifest formats and the provider; partial inputs may be missed.');
  } else {
    limitations.push('Secret patterns are heuristic and redacted. A recorded match is not proof that a credential is valid.');
  }
  const supplement = scan.resultSummary?.astSupplement;
  if (supplement?.mode === 'DAST_RESPONSE_SCRIPTS') limitations.push('AST inspects only the recorded baseline response scripts; external scripts are not fetched or executed. Category attribution is not proof of a rule check or exploit.');
  else if (supplement?.mode === 'SECRETS_LITERAL_CONTEXT') limitations.push('AST literal overlap only adds context to existing secret matches; it does not verify credentials or cover every language.');
  else if (supplement?.mode === 'SCA_JSON_MANIFEST') limitations.push('The package.json AST counts syntactic entries, not installed dependencies or vulnerability coverage.');
  if (supplement?.status === 'PARTIAL') limitations.push('The scanner-specific AST supplement was incomplete or skipped inputs.');
  if (incomplete) limitations.push('The recorded scan was partial or truncated; additional findings may exist.');

  return {
    schemaVersion: '1.0',
    assessmentLevel: SAC_ASSESSMENT_LEVEL,
    verdict: hasFindings ? 'FINDINGS_PRESENT' : 'NO_FINDINGS_RECORDED',
    verdictStatement: hasFindings
      ? `${findings.total} finding(s) were recorded for this bounded scan. Other vulnerabilities may remain undetected.`
      : 'No findings were recorded in this scan. This does not establish that the target is secure.',
    scope: {
      projectId: scan.projectId,
      scanId: scan.id,
      scanType: scan.scanType,
      completedAt: scan.completedAt,
      ...(scan.targetUrl === undefined ? {} : { targetUrl: scan.targetUrl }),
      ...(scan.assessmentId === undefined ? {} : { assessmentId: scan.assessmentId }),
    },
    scannerCoverage: input.scannerCoverage.map((entry) => entry.status === 'NOT_RUN'
      ? { scanner: entry.scanner, status: 'NOT_RUN' as const, reason: entry.reason ?? 'Not run in this single-scan report.' }
      : {
          scanner: entry.scanner,
          status: incomplete ? 'PARTIAL' as const : 'RAN' as const,
          reason: incomplete ? 'The saved result reports partial or truncated coverage.' : 'The scanner completed; rule-level completeness is not established.',
        }),
    metrics,
    findings: { total: findings.total, bySeverity: { ...findings.bySeverity } },
    ruleProvenance: recordedSastRules ? 'SAST_EFFECTIVE_RULES_RECORDED' : 'NOT_RECORDED_AT_SCAN',
    limitations,
    residualRisk: {
      status: 'UNKNOWN',
      statement: 'Residual risk is unknown: a bounded automated scan cannot establish complete safety.',
    },
    compliance: {
      status: 'NOT_ASSESSED',
      statement: 'This report is technical evidence, not a PCI DSS, ISO 27001, SOC 2 or other compliance certification.',
    },
    nextSteps: [
      'Review and prioritise recorded findings, then re-scan after changes.',
      'Assess untested areas through an appropriately authorised human security review.',
      'Keep software, advisory sources and security rules current; inspect provider availability before relying on results.',
    ],
  };
}
