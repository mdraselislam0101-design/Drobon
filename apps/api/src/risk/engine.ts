/**
 * Correlated risk engine (deterministic, bounded, evidence-only).
 *
 * The engine receives the ALREADY-RECORDED findings of the latest completed
 * scan of each scanner and returns clusters where the evidence genuinely
 * overlaps. It invents nothing: every cluster is a set of existing finding ids
 * plus a documented statement of what that overlap does and does not mean.
 *
 * Correlation rules (all use fields the scanners recorded):
 *  - ENDPOINT_CLUSTER      ≥2 DAST findings on one observed endpoint (origin+path)
 *  - SAME_RESPONSE         ≥2 DAST findings recorded from the same response
 *  - CODE_AND_RUNTIME_CWE  ≥1 SAST + ≥1 DAST finding carrying the same CWE
 *  - SECRET_IN_WEAK_FILE   ≥1 SECRETS + ≥1 SAST finding in the same file
 *  - RECURRING_RULE        one ruleId seen on ≥2 distinct assets
 *
 * Scoring (SEVERITY_SUM_V1): sum of the severity weights of the cluster's
 * reported evidence (CRITICAL 10, HIGH 6, MEDIUM 3, LOW 1, INFO 0; at most
 * RISK_MAX_EVIDENCE items) + 1 per additional distinct scanner, capped at 100.
 * Because the score is computed from exactly the evidence that is shipped,
 * anyone can recompute it by hand. The band is derived, never supplied.
 */
import { createHash } from 'node:crypto';
import {
  RISK_BAND_THRESHOLDS,
  RISK_MAX_CLUSTERS,
  RISK_MAX_DISCLOSURES,
  RISK_MAX_EVIDENCE,
  RISK_MAX_FINDINGS,
  RISK_SEVERITY_WEIGHTS,
  SCAN_TYPES,
  riskBandForScore,
  type FindingSeverity,
  type RiskAssessment,
  type RiskBand,
  type RiskCluster,
  type RiskCorrelationKind,
  type RiskEvidenceRef,
  type RiskSourceCoverage,
  type ScanType,
} from '@drobon/shared';

/** A recorded finding, reduced to the fields correlation is allowed to use. */
export interface RiskFindingView {
  id: string;
  scanner: ScanType;
  severity: FindingSeverity;
  ruleId: string;
  cwe?: string;
  /** Source findings only. */
  file?: string;
  /** DAST findings only (already validated as a safe URL). */
  endpoint?: string;
  observedAt?: string;
  responseStatus?: number;
}

export interface RiskSourceScan {
  scanner: ScanType;
  scanId: string;
  completedAt: string;
  findings: readonly RiskFindingView[];
  /** True when this scan held more findings than the assessment could read. */
  omitted: boolean;
}

export interface RiskInput {
  projectId: string;
  generatedAt: string;
  sources: readonly RiskSourceScan[];
  /** Scanners with no COMPLETED scan at all. */
  missingScanners: readonly ScanType[];
}

const MAX_SCORE = 100;

function clusterId(kind: RiskCorrelationKind, asset: string): string {
  return `risk_${createHash('sha256').update(`${kind}\n${asset}`, 'utf8').digest('hex').slice(0, 24)}`;
}

function bounded(value: string | undefined): string | undefined {
  if (value === undefined || value.length === 0) return undefined;
  // eslint-disable-next-line no-control-regex -- the contract forbids control characters.
  const printable = value.replace(/[\u0000-\u001f\u007f]/g, '');
  if (printable.length === 0) return undefined;
  return printable.length > 300 ? printable.slice(0, 300) : printable;
}

/**
 * The shared asset of a finding: origin+path for DAST (the query is dropped so
 * two probes of one path group together), the file path for source findings.
 */
function assetFor(finding: RiskFindingView): string | undefined {
  if (finding.scanner === 'DAST') {
    const endpoint = finding.endpoint;
    if (endpoint === undefined) return undefined;
    try {
      const url = new URL(endpoint);
      return bounded(`${url.origin}${url.pathname}`);
    } catch {
      // Already a bounded path (legacy/relative endpoint) — use it unchanged.
      return bounded(endpoint.split('?')[0]);
    }
  }
  return bounded(finding.file);
}

function bySeverityDesc(a: RiskFindingView, b: RiskFindingView): number {
  const diff = RISK_SEVERITY_WEIGHTS[b.severity] - RISK_SEVERITY_WEIGHTS[a.severity];
  if (diff !== 0) return diff;
  return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
}

function evidenceOf(findings: readonly RiskFindingView[]): RiskEvidenceRef[] {
  return [...findings].sort(bySeverityDesc).slice(0, RISK_MAX_EVIDENCE).map((finding) => {
    const asset = assetFor(finding);
    return {
      findingId: finding.id,
      scanner: finding.scanner,
      severity: finding.severity,
      ruleId: finding.ruleId,
      asset: asset === undefined ? 'unattributed' : asset,
    };
  });
}

/** The published model. Members are unique findings; the cap keeps it bounded. */
export function scoreCluster(members: readonly RiskFindingView[]): number {
  const unique = new Map<string, RiskFindingView>();
  for (const member of members) {
    if (!unique.has(member.id)) unique.set(member.id, member);
  }
  const scored = [...unique.values()].sort(bySeverityDesc).slice(0, RISK_MAX_EVIDENCE);
  let base = 0;
  for (const member of scored) base += RISK_SEVERITY_WEIGHTS[member.severity];
  const scanners = new Set(scored.map((member) => member.scanner)).size;
  const corroboration = Math.max(0, scanners - 1);
  return Math.min(MAX_SCORE, base + corroboration);
}

function buildCluster(input: {
  kind: RiskCorrelationKind;
  asset: string;
  members: readonly RiskFindingView[];
  title: string;
  summary: string;
}): RiskCluster {
  const evidence = evidenceOf(input.members);
  const scanners = [...new Set(evidence.map((item) => item.scanner))].sort();
  const score = scoreCluster(input.members);
  return {
    id: clusterId(input.kind, input.asset),
    kind: input.kind,
    band: riskBandForScore(score),
    score,
    scanners,
    title: input.title.slice(0, 160),
    summary: input.summary.slice(0, 400),
    asset: input.asset.slice(0, 300),
    evidence,
  };
}

const DISCLOSURE_CORRELATION =
  'Correlation groups findings that were already recorded. It does not prove exploitability, an attack chain, or that an observed endpoint runs the flagged code.';
const DISCLOSURE_SCORING =
  'Scores use the published model SEVERITY_SUM_V1: the severity weights of the listed evidence (CRITICAL 10, HIGH 6, MEDIUM 3, LOW 1, INFO 0) plus one point per additional scanner, capped at 100. Every score can be recomputed from the evidence shown. Scores are triage aids, not CVSS and not a risk certification.';
const DISCLOSURE_SCOPE =
  'Only the latest completed scan of each scanner contributes. Older scans, findings marked FALSE_POSITIVE, and engineers\' judgement are not part of the score.';

export function buildRiskAssessment(input: RiskInput): RiskAssessment {
  const sources = [...input.sources].sort(
    (a, b) => SCAN_TYPES.indexOf(a.scanner) - SCAN_TYPES.indexOf(b.scanner),
  );

  // Bounded, deterministic reading: findings are taken in id order, and the
  // global cap is shared round-robin by scanner so one noisy scanner cannot
  // starve the others. Coverage counts what was READ, not what existed.
  const accepted = new Map<ScanType, RiskFindingView[]>();
  const queues = sources.map((source) => ({
    scanner: source.scanner,
    remaining: [...source.findings].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)),
    index: 0,
  }));
  for (const queue of queues) accepted.set(queue.scanner, []);
  let truncated = sources.some((source) => source.omitted);
  let taken = 0;
  let advanced = true;
  while (taken < RISK_MAX_FINDINGS && advanced) {
    advanced = false;
    for (const queue of queues) {
      if (taken >= RISK_MAX_FINDINGS) break;
      const next = queue.remaining[queue.index];
      if (next === undefined) continue;
      queue.index += 1;
      taken += 1;
      advanced = true;
      (accepted.get(queue.scanner) as RiskFindingView[]).push(next);
    }
  }
  if (taken < queues.reduce((sum, queue) => sum + queue.remaining.length, 0)) truncated = true;

  const ordered: RiskFindingView[] = [];
  const coverage: RiskSourceCoverage[] = SCAN_TYPES.map((scanner) => {
    const source = sources.find((candidate) => candidate.scanner === scanner);
    if (source === undefined) {
      return { scanner, scanId: null, completedAt: null, findings: 0 };
    }
    const read = accepted.get(scanner) ?? [];
    ordered.push(...read);
    return { scanner, scanId: source.scanId, completedAt: source.completedAt, findings: read.length };
  });

  const dast = ordered.filter((finding) => finding.scanner === 'DAST');
  const sast = ordered.filter((finding) => finding.scanner === 'SAST');
  const secrets = ordered.filter((finding) => finding.scanner === 'SECRETS');
  const clusters: RiskCluster[] = [];

  if (ordered.length === 0) {
    return {
      schemaVersion: '1.0',
      assessmentLevel: 'DERIVED_CORRELATION',
      scoringModel: 'SEVERITY_SUM_V1',
      projectId: input.projectId,
      generatedAt: input.generatedAt,
      status: sources.length === 0 ? 'NO_COMPLETED_SCANS' : 'NO_FINDINGS',
      band: 'UNKNOWN',
      score: 0,
      sources: coverage,
      findingsAnalysed: 0,
      correlatedFindings: 0,
      unclusteredFindings: 0,
      clusters: [],
      disclosures: emptyDisclosures(sources, input.missingScanners),
      truncated,
    };
  }

  // --- rule 1: one endpoint, several observed defects -----------------------
  const byEndpoint = new Map<string, RiskFindingView[]>();
  for (const finding of dast) {
    const asset = assetFor(finding);
    if (asset === undefined) continue;
    const list = byEndpoint.get(asset);
    if (list === undefined) byEndpoint.set(asset, [finding]);
    else list.push(finding);
  }
  for (const asset of [...byEndpoint.keys()].sort()) {
    const members = byEndpoint.get(asset) ?? [];
    if (members.length < 2) continue;
    const rules = [...new Set(members.map((member) => member.ruleId))].sort();
    clusters.push(buildCluster({
      kind: 'ENDPOINT_CLUSTER',
      asset,
      members,
      title: `${members.length} defects observed on one endpoint`,
      summary: `${members.length} DAST observations (${rules.join(', ')}) were recorded against this exact path. One weakness can make another easier to reach or to exploit; the combination is not proof of an attack chain.`,
    }));
  }

  // --- rule 2: one response, several observed defects ----------------------
  const byResponse = new Map<string, RiskFindingView[]>();
  for (const finding of dast) {
    const asset = assetFor(finding);
    if (asset === undefined || finding.observedAt === undefined) continue;
    const key = `${asset}\n${finding.observedAt}\n${finding.responseStatus ?? 0}`;
    const list = byResponse.get(key);
    if (list === undefined) byResponse.set(key, [finding]);
    else list.push(finding);
  }
  for (const key of [...byResponse.keys()].sort()) {
    const members = byResponse.get(key) ?? [];
    if (members.length < 2) continue;
    const path = assetFor(members[0] as RiskFindingView) ?? 'unattributed';
    const status = members[0]?.responseStatus ?? 0;
    // The asset carries the observation instant: two responses from one path
    // are two clusters, never one merged claim.
    const asset = `${path} @ ${members[0]?.observedAt ?? 'unknown'}`.slice(0, 300);
    clusters.push(buildCluster({
      kind: 'SAME_RESPONSE',
      asset,
      members,
      title: `Several defects in one HTTP ${status} response`,
      summary: `${members.length} rules matched the same recorded response. Missing or weak controls on one response compound each other, but the response alone does not show how the endpoint behaves under attack.`,
    }));
  }

  // --- rule 3: the same weakness class in code and at runtime --------------
  const dastByCwe = new Map<string, RiskFindingView[]>();
  for (const finding of dast) {
    if (finding.cwe === undefined) continue;
    const list = dastByCwe.get(finding.cwe);
    if (list === undefined) dastByCwe.set(finding.cwe, [finding]);
    else list.push(finding);
  }
  for (const cwe of [...dastByCwe.keys()].sort()) {
    const runtime = dastByCwe.get(cwe) ?? [];
    const code = sast.filter((finding) => finding.cwe === cwe);
    if (code.length === 0) continue;
    clusters.push(buildCluster({
      kind: 'CODE_AND_RUNTIME_CWE',
      asset: cwe,
      members: [...code, ...runtime],
      title: `${cwe} is present in code and observed at runtime`,
      summary: `${code.length} SAST and ${runtime.length} DAST finding(s) carry ${cwe}. The same weakness class exists in the source and on a live surface; this is a correlation of class, not proof that the flagged file serves the observed endpoint.`,
    }));
  }

  // --- rule 4: a hardcoded secret inside a file with a code weakness -------
  const sastByFile = new Map<string, RiskFindingView[]>();
  for (const finding of sast) {
    if (finding.file === undefined) continue;
    const list = sastByFile.get(finding.file);
    if (list === undefined) sastByFile.set(finding.file, [finding]);
    else list.push(finding);
  }
  for (const file of [...sastByFile.keys()].sort()) {
    const code = sastByFile.get(file) ?? [];
    const leaks = secrets.filter((finding) => finding.file === file);
    if (leaks.length === 0) continue;
    clusters.push(buildCluster({
      kind: 'SECRET_IN_WEAK_FILE',
      asset: file,
      members: [...code, ...leaks],
      title: 'Hardcoded secret and code weakness in one file',
      summary: `${leaks.length} secret finding(s) and ${code.length} code finding(s) sit in the same file. A leaked credential next to an injectable path raises the consequence of both; the value is redacted and never repeated here.`,
    }));
  }

  // --- rule 5: one rule, several assets ------------------------------------
  const byRule = new Map<string, RiskFindingView[]>();
  for (const finding of ordered) {
    const asset = assetFor(finding);
    if (asset === undefined) continue;
    const key = `${finding.scanner}\n${finding.ruleId}`;
    const list = byRule.get(key);
    if (list === undefined) byRule.set(key, [finding]);
    else list.push(finding);
  }
  for (const key of [...byRule.keys()].sort()) {
    const members = byRule.get(key) ?? [];
    const assets = new Set(members.map((member) => assetFor(member)));
    if (assets.size < 2) continue;
    const ruleId = members[0]?.ruleId ?? 'unknown';
    clusters.push(buildCluster({
      kind: 'RECURRING_RULE',
      asset: ruleId,
      members,
      title: `${ruleId} recurs across ${assets.size} assets`,
      summary: `The same rule matched in ${assets.size} different assets. A recurring pattern is usually a missing shared control (helper, middleware, framework default) rather than ${assets.size} separate bugs.`,
    }));
  }

  // Deterministic order and a hard cluster cap.
  clusters.sort((a, b) => {
    if (b.score !== a.score) return b.score - a.score;
    if (a.kind !== b.kind) return a.kind < b.kind ? -1 : 1;
    return a.asset < b.asset ? -1 : a.asset > b.asset ? 1 : 0;
  });
  let clippedClusters = 0;
  if (clusters.length > RISK_MAX_CLUSTERS) {
    clippedClusters = clusters.length - RISK_MAX_CLUSTERS;
    clusters.length = RISK_MAX_CLUSTERS;
    truncated = true;
  }

  const correlatedFindings = new Set<string>();
  for (const cluster of clusters) {
    for (const item of cluster.evidence) correlatedFindings.add(item.findingId);
  }

  const disclosures = [
    DISCLOSURE_CORRELATION,
    DISCLOSURE_SCORING,
    DISCLOSURE_SCOPE,
  ];
  if (clusters.length === 0) {
    disclosures.push(
      'No evidence overlap was found between the analysed findings. That is an absence of correlation, not evidence that the project is safe.',
    );
  }
  if (input.missingScanners.length > 0) {
    disclosures.push(
      `${input.missingScanners.join(', ')} has no completed scan in this project yet, so correlations that need it cannot appear. A missing correlation is not evidence of safety.`,
    );
  }
  if (truncated) {
    disclosures.push(
      `The assessment was bounded: only the first ${RISK_MAX_FINDINGS} findings and ${RISK_MAX_CLUSTERS} clusters are reported${clippedClusters > 0 ? ` (${clippedClusters} cluster(s) omitted)` : ''}.`,
    );
  }

  const top = clusters[0]?.score ?? 0;
  const band: RiskBand = clusters.length === 0 ? 'UNKNOWN' : riskBandForScore(top);

  return {
    schemaVersion: '1.0',
    assessmentLevel: 'DERIVED_CORRELATION',
    scoringModel: 'SEVERITY_SUM_V1',
    projectId: input.projectId,
    generatedAt: input.generatedAt,
    status: 'ASSESSED',
    band,
    score: Math.min(top, RISK_BAND_THRESHOLDS.CRITICAL * 5),
    sources: coverage,
    findingsAnalysed: ordered.length,
    correlatedFindings: correlatedFindings.size,
    unclusteredFindings: ordered.length - correlatedFindings.size,
    clusters,
    disclosures: disclosures.slice(0, RISK_MAX_DISCLOSURES),
    truncated,
  };
}

function emptyDisclosures(
  sources: readonly RiskSourceScan[],
  missing: readonly ScanType[],
): string[] {
  const disclosures = [DISCLOSURE_CORRELATION, DISCLOSURE_SCORING, DISCLOSURE_SCOPE];
  if (sources.length === 0) {
    disclosures.push('No completed scan exists for this project, so there is nothing to correlate. This is not a statement that the project is safe.');
  } else {
    disclosures.push('The completed scans of this project recorded no findings, so there is nothing to correlate. An empty result is not proof that the project is secure.');
  }
  if (missing.length > 0) {
    disclosures.push(`${missing.join(', ')} has no completed scan in this project yet, so the assessment covers only the scanners listed in sources.`);
  }
  return disclosures.slice(0, RISK_MAX_DISCLOSURES);
}
