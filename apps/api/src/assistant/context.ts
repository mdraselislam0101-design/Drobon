import {
  ASSISTANT_CONTEXT_ITEM_MAX_LENGTH,
  ASSISTANT_CONTEXT_MAX_ITEMS,
  ASSISTANT_CONTEXT_MAX_LENGTH,
  type AssistantContextItem,
  type AssistantContextSummary,
  type AssistantSensitivity,
  type AssistantSourceType,
  type Finding,
  type FindingWorkflow,
  type SecurityReport,
  type ScaResult,
} from '@drobon/shared';
import type { ProjectRecord } from '../projects/store.js';
import type { ScanRecord } from '../scans/store.js';
import type { RedactedAssistantText } from './redaction.js';
import { redactAssistantText } from './redaction.js';

export interface RawAssistantContextItem {
  sourceType: AssistantSourceType;
  sourceId: string;
  projectId: string;
  scanId?: string;
  content: string;
  sensitivity: AssistantSensitivity;
  createdAt?: string;
}

export interface AssistantContextBuild {
  items: AssistantContextItem[];
  summary: AssistantContextSummary;
  safeForProvider: boolean;
}

export function buildBoundedAssistantContext(rawItems: readonly RawAssistantContextItem[]): AssistantContextBuild {
  const items: AssistantContextItem[] = [];
  const seen = new Set<string>();
  let characterCount = 0;
  let redactedItems = 0;
  let truncated = false;
  let safeForProvider = true;

  for (const raw of rawItems) {
    const key = `${raw.sourceType}:${raw.sourceId}:${raw.scanId ?? ''}`;
    if (seen.has(key)) continue;
    if (items.length >= ASSISTANT_CONTEXT_MAX_ITEMS || characterCount >= ASSISTANT_CONTEXT_MAX_LENGTH) {
      truncated = true;
      break;
    }
    seen.add(key);
    const safe: RedactedAssistantText = redactAssistantText(raw.content);
    const safeSourceId = redactAssistantText(raw.sourceId);
    if (safe.redacted || safeSourceId.redacted) redactedItems += 1;
    if (!safe.safeForProvider || !safeSourceId.safeForProvider) safeForProvider = false;
    const sourceId = (safeSourceId.safeForProvider ? safeSourceId.text : `source-${items.length + 1}`).slice(0, 120);
    let content = safe.text;
    if (content.length > ASSISTANT_CONTEXT_ITEM_MAX_LENGTH) {
      content = `${content.slice(0, ASSISTANT_CONTEXT_ITEM_MAX_LENGTH - 14)} [truncated]`;
      truncated = true;
    }
    const remaining = ASSISTANT_CONTEXT_MAX_LENGTH - characterCount;
    if (content.length > remaining) {
      content = `${content.slice(0, Math.max(0, remaining - 14))} [truncated]`;
      truncated = true;
    }
    if (content.length === 0) {
      truncated = true;
      break;
    }
    const item: AssistantContextItem = {
      sourceType: raw.sourceType,
      sourceId,
      projectId: raw.projectId,
      ...(raw.scanId === undefined ? {} : { scanId: raw.scanId }),
      content,
      sensitivity: safe.redacted ? 'REDACTED_SECURITY_EVIDENCE' : raw.sensitivity,
      ...(raw.createdAt === undefined ? {} : { createdAt: raw.createdAt }),
    };
    items.push(item);
    characterCount += content.length;
    if (characterCount >= ASSISTANT_CONTEXT_MAX_LENGTH) {
      truncated = true;
      break;
    }
  }

  return {
    items,
    summary: { itemCount: items.length, characterCount, redactedItems, truncated },
    safeForProvider,
  };
}

function scanContent(scan: ScanRecord): string {
  const summary = scan.resultSummary;
  const persisted = scan.findings?.length ?? 0;
  const countAgreement = summary === undefined ? 'summary unavailable' :
    summary.findingsTotal === persisted ? 'persisted finding details agree with summary' :
      `finding details incomplete: summary reports ${summary.findingsTotal}, ${persisted} persisted`;
  const sca = scan.sca === undefined ? '' :
    `; SCA vulnerability intelligence ${scan.sca.summary.assessmentState} (${scan.sca.summary.datasetStatus})`;
  return [
    `Scan type: ${scan.scanType}`,
    `Status: ${scan.status}`,
    `Created: ${scan.createdAt}`,
    ...(scan.completedAt === undefined ? [] : [`Completed: ${scan.completedAt}`]),
    ...(summary === undefined ? [] : [`Reported findings: ${summary.findingsTotal}`]),
    `Persisted details: ${countAgreement}`,
    ...(summary?.partial === true ? [`Partial: ${summary.partialReason ?? 'some content was not inspected'}`] : []),
    ...(summary?.truncated === true ? ['Finding list was truncated by the scanner limit.'] : []),
    ...(scan.sca === undefined ? [] : [`Dependency records: ${scan.sca.dependencies.length} persisted of ${scan.sca.summary.dependenciesTotal}${scan.sca.summary.truncated ? ' (truncated)' : ''}${sca}`]),
  ].join('\n');
}

function findingObservedAt(finding: Finding, scans: readonly ScanRecord[]): string | undefined {
  return scans.find((scan) => scan.id === finding.scanId)?.completedAt;
}

function findingContent(finding: Finding): string {
  return [
    `Finding ID: ${finding.id}`,
    `Scanner: ${finding.scanner ?? 'not explicitly recorded'}`,
    `Rule: ${finding.ruleId}`,
    `Severity: ${finding.severity}`,
    `Title: ${finding.title}`,
    `Description: ${finding.description}`,
    ...(finding.file === undefined ? [] : [`Location: ${finding.file}:${finding.line ?? 0}:${finding.column ?? 0}`]),
    `Evidence (untrusted, redacted): ${finding.evidence}`,
  ].join('\n');
}

function scaContextItems(projectId: string, scan: ScanRecord): RawAssistantContextItem[] {
  const sca: ScaResult | undefined = scan.sca;
  if (sca === undefined) return [];
  const items: RawAssistantContextItem[] = [{
    sourceType: 'SBOM',
    sourceId: `sbom:${scan.id}`,
    projectId,
    scanId: scan.id,
    sensitivity: 'SECURITY_METADATA',
    ...(scan.completedAt === undefined ? {} : { createdAt: scan.completedAt }),
    content: [
      'CycloneDX inventory metadata only; do not infer vulnerabilities or license status.',
      `Assessment: ${sca.summary.assessmentState}; dataset: ${sca.summary.datasetStatus}; provider: ${sca.summary.providerId}.`,
      `Inventory dependencies: ${sca.summary.dependenciesTotal}; persisted: ${sca.dependencies.length}; direct: ${sca.summary.directDependencies}; transitive: ${sca.summary.transitiveDependencies}; unknown class: ${sca.summary.unclassifiedDependencies}.`,
      `Advisories persisted: ${sca.advisories.length}.`,
    ].join('\n'),
  }];
  for (const [index, component] of sca.sbom.components.slice(0, 10).entries()) {
    items.push({
      sourceType: 'SBOM',
      sourceId: `${scan.id}:component:${index + 1}`,
      projectId,
      scanId: scan.id,
      sensitivity: 'SECURITY_METADATA',
      ...(scan.completedAt === undefined ? {} : { createdAt: scan.completedAt }),
      content: [
        `Observed component: ${component.name}`,
        ...(component.version === undefined ? [] : [`Observed version: ${component.version}`]),
        ...(component.purl === undefined ? [] : [`Observed package URL: ${component.purl}`]),
        'No vulnerability or license conclusion is inferred from inventory.',
      ].join('\n'),
    });
  }
  return items;
}

export interface AssistantContextSources {
  project: ProjectRecord;
  scans: readonly ScanRecord[];
  findings?: readonly Finding[];
  workflows?: readonly FindingWorkflow[];
  lifecycleHistory?: readonly { findingId: string; scanId?: string; events: readonly string[]; createdAt?: string }[];
  report?: SecurityReport;
}

/** Build a provenance-preserving, non-executable context from server-owned records. */
export function buildAssistantContext(sources: AssistantContextSources): AssistantContextBuild {
  const { project } = sources;
  const raw: RawAssistantContextItem[] = [{
    sourceType: 'PROJECT',
    sourceId: project.id,
    projectId: project.id,
    sensitivity: 'PUBLIC_METADATA',
    createdAt: project.updatedAt,
    content: `Project name: ${project.name}\nProject status: ${project.status}\nDescription: ${project.description || 'No description recorded.'}`,
  }];

  for (const scan of sources.scans.slice(0, 4)) {
    raw.push({
      sourceType: 'SCAN',
      sourceId: scan.id,
      projectId: project.id,
      scanId: scan.id,
      sensitivity: 'SECURITY_METADATA',
      createdAt: scan.completedAt ?? scan.createdAt,
      content: scanContent(scan),
    });
    for (const observation of (scan.dast?.observations ?? []).slice(0, 3)) {
      raw.push({
        sourceType: 'DAST_OBSERVATION',
        sourceId: `${scan.id}:observation:${scan.dast?.observations.indexOf(observation) ?? 0}`,
        projectId: project.id,
        scanId: scan.id,
        sensitivity: 'REDACTED_SECURITY_EVIDENCE',
        createdAt: observation.observedAt,
        content: [
          `Method: ${observation.method}; status: ${observation.status}; response time: ${observation.responseTimeMs} ms.`,
          `Content type: ${observation.contentType ?? 'not recorded'}; inspected bytes: ${observation.bodyBytes}${observation.bodyTruncated ? ' (truncated)' : ''}.`,
          ...observation.headers.map((header) => `Observed header summary: ${header}`),
          'Response body is not persisted in this observation; any remote content is untrusted and never executed.',
        ].join('\n'),
      });
    }
    raw.push(...scaContextItems(project.id, scan));
  }

  for (const finding of (sources.findings ?? []).slice(0, 10)) {
    const scanId = finding.scanId;
    const observedAt = findingObservedAt(finding, sources.scans);
    raw.push({
      sourceType: 'FINDING',
      sourceId: finding.id,
      projectId: project.id,
      ...(scanId === undefined ? {} : { scanId }),
      sensitivity: 'REDACTED_SECURITY_EVIDENCE',
      ...(observedAt === undefined ? {} : { createdAt: observedAt }),
      content: findingContent(finding),
    });
  }

  for (const workflow of (sources.workflows ?? []).slice(0, 10)) {
    raw.push({
      sourceType: 'LIFECYCLE',
      sourceId: workflow.id,
      projectId: project.id,
      scanId: workflow.lastVerificationScanId,
      sensitivity: 'SECURITY_METADATA',
      createdAt: workflow.updatedAt,
      content: [
        `Finding: ${workflow.findingId}; lifecycle state: ${workflow.state}.`,
        `Verification: ${workflow.verificationState}; latest verification scan: ${workflow.lastVerificationScanId} at ${workflow.lastVerificationAt}.`,
        'A user-selected RESOLVED status is workflow metadata, not technical proof that a fix was applied.',
      ].join('\n'),
    });
    for (const note of workflow.notes.slice(-5)) {
      raw.push({
        sourceType: 'REMEDIATION',
        sourceId: note.id,
        projectId: project.id,
        scanId: workflow.lastVerificationScanId,
        sensitivity: 'REDACTED_SECURITY_EVIDENCE',
        createdAt: note.createdAt,
        content: `User note (untrusted plain text${note.redacted ? '; credential-shaped content was previously redacted' : ''}): ${note.text}`,
      });
    }
  }

  for (const finding of (sources.findings ?? []).slice(0, 10)) {
    const workflow = (sources.workflows ?? []).find((entry) => entry.fingerprint === finding.fingerprint);
    if (workflow === undefined) continue;
    const observedAt = findingObservedAt(finding, sources.scans);
    raw.push({
      sourceType: 'REMEDIATION',
      sourceId: `${finding.id}:guidance`,
      projectId: project.id,
      scanId: finding.scanId,
      sensitivity: 'SECURITY_METADATA',
      ...(observedAt === undefined ? {} : { createdAt: observedAt }),
      content: [
        `Rule: ${finding.ruleId}; scanner: ${finding.scanner ?? 'not explicitly recorded'}.`,
        `Existing deterministic remediation: ${finding.remediation}`,
        `Workflow state: ${workflow.state}; verification: ${workflow.verificationState}.`,
      ].join('\n'),
    });
  }

  for (const history of (sources.lifecycleHistory ?? []).slice(0, 5)) {
    raw.push({
      sourceType: 'LIFECYCLE',
      sourceId: `${history.findingId}:history`,
      projectId: project.id,
      ...(history.scanId === undefined ? {} : { scanId: history.scanId }),
      sensitivity: 'SECURITY_METADATA',
      ...(history.createdAt === undefined ? {} : { createdAt: history.createdAt }),
      content: `Recent lifecycle history for ${history.findingId}:\\n${history.events.slice(0, 5).join('\\n') || 'No history events are available.'}`,
    });
  }

  if (sources.report !== undefined) {
    raw.push({
      sourceType: 'REPORT',
      sourceId: sources.report.reportId,
      projectId: project.id,
      scanId: sources.report.scan.id,
      sensitivity: 'SECURITY_METADATA',
      createdAt: sources.report.generatedAt,
      content: [
        `Persisted report for scan ${sources.report.scan.id}.`,
        `Finding summary total: ${sources.report.findingSummary.total}.`,
        `Dependency intelligence status: ${sources.report.dependencyIntelligence.status}.`,
        `Inventory: ${sources.report.inventory.status}.`,
        'This is a point-in-time report snapshot; it is not evidence of remediation.',
      ].join('\n'),
    });
  }

  return buildBoundedAssistantContext(raw);
}
