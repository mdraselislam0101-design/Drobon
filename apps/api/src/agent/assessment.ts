import {
  engagementAllowsScan, findingScanner, isSafeDastUrl,
  type AgentAssessment, type AgentAttackPath, type AgentFindingReview, type AgentTask,
  type Assessment, type Finding, type FindingSeverity, type ScanType,
} from '@drobon/shared';
import type { ProjectRecord } from '../projects/store.js';
import type { SourceSnapshotRecord } from '../scans/sources.js';
import type { ScanRecord } from '../scans/store.js';
import { digestSource } from './snapshot.js';
import { inventory } from './recon.js';

export const AGENT_SCANNERS: readonly ScanType[] = ['SAST', 'SECRETS', 'SCA', 'DAST'];
const PRIORITY: Record<FindingSeverity, number> = { CRITICAL: 100, HIGH: 80, MEDIUM: 60, LOW: 40, INFO: 20 };

export interface AgentAssessmentInput {
  project: ProjectRecord;
  assessment: Assessment;
  snapshot: SourceSnapshotRecord | undefined;
  scans: readonly ScanRecord[];
  executionEnabled: boolean;
  agentStorageReady: boolean;
  datasetConfigured: boolean;
  quotaExhausted: boolean;
  now: string;
}

function eligibility(input: AgentAssessmentInput, scanner: ScanType): string | undefined {
  const { project, assessment, snapshot } = input;
  if (!input.executionEnabled) return 'Experimental agent execution is disabled; production enablement is blocked pending an approved migration and rollback.';
  if (!input.agentStorageReady) return 'The existing version-1 scan store requires a reviewed offline compatibility migration; no data has been changed.';
  if (project.status !== 'ACTIVE') return 'The project is archived.';
  if (assessment.status !== 'ACTIVE') return 'Start the assessment before requesting agent scans.';
  if ((assessment.engagements?.length ?? 0) === 0) return 'An active, scoped engagement is required for agent scans.';
  if (!input.datasetConfigured) return 'A separately configured Dataset is required; its freshness has not been verified.';
  if (input.quotaExhausted) return 'The current scan allowance is exhausted.';
  let target: URL | undefined;
  if (scanner === 'DAST') {
    if (project.dastTargetUrl === undefined || !isSafeDastUrl(project.dastTargetUrl)) return 'Configure a valid project DAST target first.';
    target = new URL(project.dastTargetUrl);
    const hostname = target.hostname.toLowerCase();
    if (!assessment.scope.inScopeHosts.includes(hostname) || assessment.scope.outOfScopeHosts.includes(hostname)) {
      return 'The target hostname is outside this assessment scope.';
    }
  } else if (snapshot === undefined || snapshot.ownerId !== project.ownerId || snapshot.files.length === 0) {
    return 'An owned source snapshot is required for this scanner.';
  }
  const gate = engagementAllowsScan(assessment.engagements, {
    scanType: scanner, nowIso: input.now,
    ...(target === undefined ? {} : { hostname: target.hostname.toLowerCase(), path: target.pathname || '/' }),
  });
  if (!gate.allowed) return 'No active engagement permits this scanner and target scope.';
  return undefined;
}

function taskFor(input: AgentAssessmentInput, scanner: ScanType): AgentTask {
  const scan = input.scans.find((candidate) => candidate.ownerId === input.project.ownerId &&
    candidate.projectId === input.project.id && candidate.assessmentId === input.assessment.id &&
    candidate.scanType === scanner && candidate.agent !== undefined);
  if (scan === undefined) {
    const blocked = eligibility(input, scanner);
    return blocked === undefined
      ? { scanner, state: 'READY', reason: 'Selected from the available context; authorization and Dataset freshness are rechecked before execution.' }
      : { scanner, state: 'BLOCKED', reason: blocked };
  }
  const common = { scanner, scanId: scan.id, ...(scan.agent === undefined ? {} : { datasetDigest: scan.agent.datasetDigest }),
    ...(scan.resultSummary === undefined ? {} : { findingsTotal: scan.resultSummary.findingsTotal }) };
  if (scan.agent?.cancelRequestedAt !== undefined) {
    return scan.status === 'QUEUED' || scan.status === 'RUNNING'
      ? { ...common, state: 'CANCELLING', reason: 'Cancellation is recorded; the worker still needs to settle the job.' }
      : { ...common, state: 'CANCELLED', reason: 'The job is terminal. Sent requests cannot be recalled; non-cooperative transports may continue.' };
  }
  if (scan.status === 'QUEUED' || scan.status === 'RUNNING') return { ...common, state: scan.status, reason: 'The existing durable scanner job is in progress.' };
  if (scan.status === 'FAILED' || scan.status === 'TIMED_OUT') return { ...common, state: 'FAILED', reason: 'The scanner job failed or timed out; inspect its existing scan record.' };
  if (scan.resultSummary?.partial === true || scan.resultSummary?.truncated === true || scan.dast?.partial === true) {
    const evaluated = scan.resultSummary?.declarationRulesEvaluated;
    const omitted = scan.resultSummary?.declarationRulesNotEvaluated;
    const reason = scanner === 'SCA' && evaluated !== undefined && omitted !== undefined
      ? `Partial SCA: ${evaluated} declaration rules evaluated and ${omitted} not evaluated; blocked and unrenderable cases are not passes.`
      : 'The scanner reported partial or truncated coverage; absence is not a clean result.';
    return { ...common, state: 'PARTIAL', reason };
  }
  return { ...common, state: 'COMPLETED', reason: 'The bounded scanner job completed; findings still require independent human verification.' };
}

function review(scan: ScanRecord, finding: Finding, sourceDigest: string | undefined, lineCounts: ReadonlyMap<string, number>): AgentFindingReview {
  const common = { scanId: scan.id, findingId: finding.id, ruleId: finding.ruleId,
    scanner: findingScanner(finding) ?? scan.scanType, severity: finding.severity, priority: PRIORITY[finding.severity] };
  if (scan.resultSummary?.partial === true || scan.resultSummary?.truncated === true || scan.dast?.partial === true) {
    return { ...common, verdict: 'INCONCLUSIVE', basis: 'The originating scan is partial or truncated; severity is rule-assigned, not proven exploitability.' };
  }
  if (finding.scanner === 'DAST') {
    const linked = scan.dast?.observations.some((observation) => observation.endpoint === finding.endpoint &&
      observation.status === finding.responseStatus && observation.method === finding.method) ?? false;
    return linked
      ? { ...common, verdict: 'SUSPECTED', basis: 'A saved response record matches the finding endpoint and status; this is not an independent exploit reproduction.' }
      : { ...common, verdict: 'NOT_VERIFIED', basis: 'No matching saved response record was available; no exploit or false positive is inferred.' };
  }
  if (sourceDigest === undefined || scan.agent?.sourceDigest === undefined || sourceDigest !== scan.agent.sourceDigest) {
    return { ...common, verdict: 'NOT_VERIFIED', basis: 'The original uploaded source snapshot is unavailable or changed; no absence or exploit is inferred.' };
  }
  const lines = lineCounts.get(finding.file);
  if (lines === undefined || finding.line < 1 || finding.line > lines) {
    return { ...common, verdict: 'INCONCLUSIVE', basis: 'The referenced file or line could not be corroborated in the matching snapshot.' };
  }
  return { ...common, verdict: 'SUSPECTED', basis: 'The source location exists in the matching snapshot; neither exploitability nor credential validity was independently confirmed.' };
}

/** Read-only assessment over the existing persisted jobs; no source text is returned. */
export function buildAgentAssessment(input: AgentAssessmentInput): AgentAssessment {
  const tasks = AGENT_SCANNERS.map((scanner) => taskFor(input, scanner));
  const agentScans = AGENT_SCANNERS.flatMap((scanner) => {
    const selected = input.scans.find((scan) => scan.ownerId === input.project.ownerId && scan.projectId === input.project.id &&
      scan.assessmentId === input.assessment.id && scan.scanType === scanner && scan.agent !== undefined && scan.status === 'COMPLETED');
    return selected === undefined ? [] : [selected];
  });
  // Hash and index the bounded snapshot once rather than once per finding.
  const currentSourceDigest = input.snapshot === undefined ? undefined : digestSource(input.snapshot);
  const lineCounts = new Map((input.snapshot?.files ?? []).map((file) => [file.path, file.content.split(/\r\n?|\n/).length]));
  const unique = new Set<string>();
  const all: Array<{ scan: ScanRecord; finding: Finding; review: AgentFindingReview }> = [];
  for (const scan of agentScans) {
    for (const finding of scan.findings ?? []) {
      if (unique.has(finding.fingerprint)) continue;
      unique.add(finding.fingerprint);
      all.push({ scan, finding, review: review(scan, finding, currentSourceDigest, lineCounts) });
    }
  }
  all.sort((a, b) => b.review.priority - a.review.priority || a.review.findingId.localeCompare(b.review.findingId));
  const reviews = all.slice(0, 100).map((entry) => entry.review);
  const reviewedIds = new Set(reviews.map((entry) => entry.findingId));
  const paths: AgentAttackPath[] = [];
  const pairs = new Set<string>();
  // Only propose same-file cross-scanner relationships, never a verified
  // exploit chain; do not emit untrusted filenames, source or rule prose.
  for (let i = 0; i < all.length && paths.length < 20; i += 1) {
    const left = all[i];
    if (left === undefined || left.finding.scanner === 'DAST' || !reviewedIds.has(left.finding.id) ||
        currentSourceDigest === undefined || left.scan.agent?.sourceDigest !== currentSourceDigest ||
        left.review.verdict === 'NOT_VERIFIED') continue;
    for (let j = i + 1; j < all.length && paths.length < 20; j += 1) {
      const right = all[j];
      if (right === undefined || right.finding.scanner === 'DAST' || !reviewedIds.has(right.finding.id) ||
          right.scan.agent?.sourceDigest !== currentSourceDigest ||
          right.review.verdict === 'NOT_VERIFIED' || left.finding.file !== right.finding.file ||
          left.review.scanner === right.review.scanner) continue;
      const key = [left.finding.id, right.finding.id].sort().join(':');
      if (pairs.has(key)) continue;
      pairs.add(key);
      paths.push({ status: 'THEORETICAL', confidence: 'LOW', entryPoint: 'NOT_ESTABLISHED',
        findingIds: [left.finding.id, right.finding.id],
        explanation: 'Two scanner observations share a source file; a dependency or exploit chain has not been established.',
        prerequisites: 'Determine reachability, component relationships and whether both observations are valid.',
        impact: 'Impact and cumulative risk are unknown until the relationship is independently validated.',
        remediation: 'Review each finding and its existing guidance; apply changes manually and rerun authorized scans.' });
    }
  }
  const state: AgentAssessment['state'] = tasks.some((task) => task.state === 'QUEUED' || task.state === 'RUNNING' || task.state === 'CANCELLING') ? 'ACTIVE'
    : tasks.every((task) => task.state === 'BLOCKED') ? 'BLOCKED'
    : tasks.every((task) => task.state === 'COMPLETED') ? 'COMPLETE'
    : tasks.some((task) => task.scanId !== undefined) ? 'PARTIAL' : 'NOT_STARTED';
  return {
    assessmentId: input.assessment.id, generatedAt: input.now, mode: 'DETERMINISTIC', model: 'NONE', state,
    inventory: inventory(input.snapshot, input.project.dastTargetUrl !== undefined), tasks, reviews,
    reviewsOmitted: Math.max(0, all.length - reviews.length), paths,
    limitations: [
      'No AI model is running; free-form objectives and untrusted source text are not interpreted as instructions.',
      'An engagement is an operator attestation, not independently verified legal authorization. Passive GET requests may have side effects.',
      'Route candidates are literal JS/TS syntax shapes, not a complete route inventory or live discovery.',
      'Source and response cross-checks do not independently reproduce exploits, confirm secrets, or classify false positives.',
      'Theoretical same-file relationships are not confirmed attack paths; impact and reachability are unknown.',
      'Scanner coverage, SCA applicability, blocked or unrenderable cases, and missing rules are never assumed complete.',
      'Dataset digests are change detectors, not signatures; immutable read-only deployment and protection against concurrent replacement remain necessary.',
      'Only one agent attempt per scanner and assessment is supported; create a new assessment for a new run.',
    ],
  };
}
