import { createHash } from 'node:crypto';
import { SCAN_TYPES, type Finding, type FindingWorkflow, type ReportScanContext } from '@drobon/shared';
import {
  REPORT_MAX_BYTES,
  REPORT_SCHEMA_VERSION,
  REPORT_VERSION,
  isSecurityReport,
  summarizeReportFindings,
  type ReportDependencyIntelligence,
  type ReportInventory,
  type SecurityReport,
} from '@drobon/shared';
import type { ProjectRecord } from '../projects/store.js';
import type { ScanRecord } from '../scans/store.js';

/** JSON subset used by the canonical report serializer. */
type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

/** Canonical UTF-8 JSON: recursive object-key sort, array order preserved. */
export function canonicalJson(value: unknown): string {
  const visit = (item: unknown): JsonValue => {
    if (item === null || typeof item === 'string' || typeof item === 'boolean') return item;
    if (typeof item === 'number' && Number.isFinite(item)) return item;
    if (Array.isArray(item)) return item.map(visit);
    if (typeof item === 'object') {
      const prototype = Object.getPrototypeOf(item);
      if (prototype !== Object.prototype && prototype !== null) throw new TypeError('Report contains a non-JSON object.');
      const output: Record<string, JsonValue> = Object.create(null) as Record<string, JsonValue>;
      for (const key of Object.keys(item).sort()) {
        const field = (item as Record<string, unknown>)[key];
        if (field === undefined) throw new TypeError('Report contains an undefined field.');
        output[key] = visit(field);
      }
      return output;
    }
    throw new TypeError('Report contains a non-JSON value.');
  };
  return JSON.stringify(visit(value));
}

function sha256(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function contentMaterial(report: Pick<SecurityReport, 'project' | 'scan' | 'scannerCoverage' | 'findingSummary' | 'findings' | 'dast' | 'findingWorkflows' | 'dependencyIntelligence' | 'inventory'>): unknown {
  return {
    reportVersion: REPORT_VERSION,
    schemaVersion: REPORT_SCHEMA_VERSION,
    project: report.project,
    scan: report.scan,
    scannerCoverage: report.scannerCoverage,
    findingSummary: report.findingSummary,
    findings: report.findings,
    ...(report.dast === undefined ? {} : { dast: report.dast }),
    ...(report.findingWorkflows === undefined ? {} : { findingWorkflows: report.findingWorkflows }),
    dependencyIntelligence: report.dependencyIntelligence,
    inventory: report.inventory,
  };
}

export function verifySecurityReportIntegrity(value: unknown): value is SecurityReport {
  if (!isSecurityReport(value)) return false;
  const report = value;
  const { reportId, generatedAt, contentDigest, integrityDigest, ...remaining } = report;
  const material = contentMaterial(remaining);
  if (sha256(canonicalJson(material)) !== contentDigest || reportId !== `rpt_${contentDigest.slice(0, 24)}`) return false;
  const unsigned = { reportId, generatedAt, ...remaining, contentDigest };
  return sha256(canonicalJson(unsigned)) === integrityDigest;
}

function scanSnapshot(record: ScanRecord): ReportScanContext {
  if (record.status !== 'COMPLETED' || record.startedAt === undefined || record.completedAt === undefined || record.resultSummary === undefined) {
    throw new TypeError('Only completed scans can be reported.');
  }
  return {
    id: record.id,
    projectId: record.projectId,
    scanType: record.scanType,
    status: 'COMPLETED' as const,
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
    startedAt: record.startedAt,
    ...(record.dastTargetUrl === undefined ? {} : { targetUrl: record.dastTargetUrl }),
    completedAt: record.completedAt,
    resultSummary: record.resultSummary,
  };
}

export function buildSecurityReport(
  project: ProjectRecord,
  scan: ScanRecord,
  generatedAt: string,
  findingWorkflows?: readonly FindingWorkflow[],
): SecurityReport {
  const scanContext = scanSnapshot(scan);
  const findings: Finding[] = [...(scan.findings ?? [])];
  if (scan.resultSummary?.findingsTotal !== findings.length) {
    throw new TypeError('Persisted finding details do not agree with the completed scan summary.');
  }
  const inventory: ReportInventory = scan.sca === undefined
    ? { status: 'NOT_INCLUDED', reason: 'Dependency inventory was not part of this scan.' }
    : { status: 'INCLUDED', sca: scan.sca };
  const dependencyIntelligence: ReportDependencyIntelligence = scan.sca === undefined
    ? { status: 'NOT_ASSESSED', reason: 'Dependency analysis was not run in this scan.' }
    : {
        status: scan.sca.summary.assessmentState,
        providerId: scan.sca.summary.providerId,
        datasetStatus: scan.sca.summary.datasetStatus,
        advisoriesTotal: scan.sca.summary.advisoriesTotal,
        ...(scan.sca.summary.assessmentState === 'NOT_ASSESSED'
          ? { reason: `Vulnerability intelligence is NOT ASSESSED (${scan.sca.summary.datasetStatus.toLowerCase().replaceAll('_', ' ')}).` }
          : {}),
      };
  const payload = {
    project: { id: project.id, name: project.name, status: project.status },
    scan: scanContext,
    scannerCoverage: SCAN_TYPES.map((scanner) => scanner === scan.scanType
      ? { scanner, status: 'RAN' as const }
      : { scanner, status: 'NOT_RUN' as const, reason: 'Not run in this single-scan assessment.' }),
    findingSummary: summarizeReportFindings(findings),
    findings,
    ...(findingWorkflows === undefined ? {} : { findingWorkflows: [...findingWorkflows] }),
    ...(scan.dast === undefined ? {} : { dast: scan.dast }),
    dependencyIntelligence,
    inventory,
  };
  const contentDigest = sha256(canonicalJson(contentMaterial(payload)));
  const unsigned = {
    reportId: `rpt_${contentDigest.slice(0, 24)}`,
    reportVersion: REPORT_VERSION,
    schemaVersion: REPORT_SCHEMA_VERSION,
    generatedAt,
    ...payload,
    contentDigest,
  };
  const report: SecurityReport = {
    ...unsigned,
    integrityDigest: sha256(canonicalJson(unsigned)),
  };
  if (!verifySecurityReportIntegrity(report)) throw new TypeError('Generated report failed its integrity checks.');
  if (Buffer.byteLength(canonicalJson(report), 'utf8') > REPORT_MAX_BYTES) {
    throw new RangeError('The generated report exceeds the configured size limit.');
  }
  return report;
}

function escapeMarkdown(value: string): string {
  const markdownSpecial = new Set(['\\', '`', '*', '_', '{', '}', '[', ']', '(', ')', '#', '+', '-', '.', '!', '|']);
  let escaped = '';
  for (const character of value) escaped += markdownSpecial.has(character) ? `\\${character}` : character;
  return escaped.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
}

function quoteBlock(label: string, value: string): string {
  const safe = escapeMarkdown(value).replace(/\r\n?/g, '\n').split('\n').map((line) => `> ${line}`).join('\n');
  return `**${escapeMarkdown(label)}**\n\n${safe || '> (empty)'}\n`;
}

/** Human-readable, inert Markdown; all untrusted text is escaped as text. */
export function renderSecurityReportMarkdown(report: SecurityReport): string {
  const lines = [
    `# DROBON Security Assessment`,
    '',
    `Report: \`${report.reportId}\`  `,
    `Generated: ${escapeMarkdown(report.generatedAt)}  `,
    `Report version: ${report.reportVersion}  `,
    `Content SHA-256: \`${report.contentDigest}\`  `,
    `Integrity SHA-256: \`${report.integrityDigest}\` (digest only; not a signature)`,
    '',
    '## Project and scan',
    '',
    `- Project: ${escapeMarkdown(report.project.name)} (\`${report.project.id}\`, ${report.project.status})`,
    `- Scan: \`${report.scan.id}\` (${report.scan.scanType}, ${report.scan.status})`,
    `- Created: ${escapeMarkdown(report.scan.createdAt)}`,
    `- Completed: ${escapeMarkdown(report.scan.completedAt)}`,
    ...(report.scan.targetUrl === undefined ? [] : [`- Target: \`${escapeMarkdown(report.scan.targetUrl)}\``]),
    '',
    '## Scanner coverage',
    '',
    ...report.scannerCoverage.map((entry) => `- ${entry.scanner}: ${entry.status}${entry.reason === undefined ? '' : ` — ${escapeMarkdown(entry.reason)}`}`),
    '',
    '## Findings',
    '',
    `Total: ${report.findingSummary.total}`,
    ...Object.entries(report.findingSummary.bySeverity).map(([severity, count]) => `- ${severity}: ${count}`),
    ...Object.entries(report.findingSummary.byScanner).map(([scanner, count]) => `- ${scanner}: ${count}`),
    '',
  ];
  if (report.dast !== undefined) {
    lines.push('## Passive DAST observations', '', `Target: ${escapeMarkdown(report.dast.targetUrl)}`, '');
    for (const observation of report.dast.observations) {
      lines.push(
        `- ${observation.method} ${escapeMarkdown(observation.endpoint)} — HTTP ${observation.status}, ${observation.responseTimeMs} ms, ${observation.bodyBytes} bytes inspected${observation.bodyTruncated ? ' (bounded body truncated)' : ''}`,
        ...observation.headers.map((header) => `  - ${escapeMarkdown(header)}`),
      );
    }
    lines.push('');
  }
  const workflowByFindingId = new Map((report.findingWorkflows ?? []).map((workflow) => [workflow.findingId, workflow]));
  for (const finding of report.findings) {
    const source = finding.scanner === 'DAST'
      ? `${finding.method} ${finding.endpoint} (HTTP ${finding.responseStatus})`
      : `${finding.file}:${finding.line}:${finding.column}`;
    lines.push(
      `### ${escapeMarkdown(finding.title)}`,
      '',
      `- Severity: ${finding.severity}`,
      `- Scanner: ${finding.scanner ?? (finding.ruleId.startsWith('DG-SEC-') ? 'SECRETS' : 'SAST')}`,
      `- Rule: ${finding.ruleId}`,
      `- Location: ${escapeMarkdown(source)}`,
      `- Finding ID: \`${finding.id}\``,
      `- Fingerprint: \`${finding.fingerprint}\``,
      ...(finding.cwe === undefined ? [] : [`- CWE: ${finding.cwe}`]),
      '',
      escapeMarkdown(finding.description),
      '',
      quoteBlock('Evidence', finding.evidence),
      quoteBlock('Remediation', finding.remediation),
    );
    const workflow = workflowByFindingId.get(finding.id);
    if (workflow !== undefined) {
      lines.push(
        '#### Remediation workflow (snapshot)',
        '',
        `- User workflow state: ${workflow.state}${workflow.state === 'RESOLVED' ? ' (user-marked addressed; not proof of technical remediation)' : ''}`,
        `- Verification: ${workflow.verificationState === 'NOT_OBSERVED_IN_LATEST_SCAN' ? 'not observed in the latest completed same-scanner scan with complete finding details; this is not proof of a fix' : 'observed in the latest completed same-scanner scan with complete finding details'}`,
        `- Last verification scan: \`${workflow.lastVerificationScanId}\` (${escapeMarkdown(workflow.lastVerificationAt)})`,
        `- Last observed: \`${workflow.lastObservedScanId}\` (${escapeMarkdown(workflow.lastObservedAt)})`,
        ...workflow.notes.flatMap((note) => [
          `- Remediation note (${escapeMarkdown(note.createdAt)}${note.redacted ? ', credential-shaped text omitted' : ''}):`,
          ...note.text.split('\n').map((line) => `  > ${escapeMarkdown(line)}`),
        ]),
        '',
      );
    }
  }
  if (report.findings.length === 0) lines.push('No persisted findings were produced by the scanner that ran. This is not a statement about scanners that did not run or dependency vulnerabilities that were not assessed.', '');
  lines.push(
    '## Dependency intelligence',
    '',
    report.dependencyIntelligence.status === 'NOT_ASSESSED'
      ? `Dependency vulnerability intelligence: NOT ASSESSED\nReason: ${escapeMarkdown(report.dependencyIntelligence.reason ?? 'Unavailable.')}`
      : `Dependency vulnerability intelligence: ASSESSED by ${escapeMarkdown(report.dependencyIntelligence.providerId ?? 'provider')}; matched advisories: ${report.dependencyIntelligence.advisoriesTotal ?? 0}`,
    '',
  );
  if (report.inventory.status === 'INCLUDED') {
    const { summary, dependencies, advisories } = report.inventory.sca;
    lines.push(
      '## Dependency inventory and SBOM',
      '',
      `- Assessment state: ${summary.assessmentState}`,
      `- Dataset status: ${summary.datasetStatus}`,
      `- Inventory components: ${summary.dependenciesTotal} (${dependencies.length} persisted${summary.truncated ? ', truncated' : ''})`,
      `- SBOM: CycloneDX ${report.inventory.sca.sbom.specVersion} JSON subset; ${report.inventory.sca.sbom.components.length} components`,
      `- Direct/transitive/unknown: ${summary.directDependencies}/${summary.transitiveDependencies}/${summary.unclassifiedDependencies}`,
      '',
      ...dependencies.map((dependency) => {
        const version = dependency.resolvedVersion ?? dependency.declaredVersion ?? 'version not established';
        return `- ${escapeMarkdown(dependency.ecosystem)} ${escapeMarkdown(dependency.name)} @ ${escapeMarkdown(version)} (${escapeMarkdown(dependency.dependencyClass)})`;
      }),
      '',
      'Dependency coordinates are inventory, not vulnerability verdicts. Version and dependency relationships are only included where observed in supported manifests/lockfiles.',
      '',
    );
    if (advisories.length > 0) {
      lines.push('### Provider advisories', '');
      for (const advisory of advisories) lines.push(`- ${advisory.severity}: ${escapeMarkdown(advisory.id)} — ${escapeMarkdown(advisory.summary)} (${escapeMarkdown(advisory.ecosystem)}:${escapeMarkdown(advisory.name)}${advisory.version === undefined ? '' : `@${escapeMarkdown(advisory.version)}`})`);
      lines.push('');
    }
  } else {
    lines.push('## Dependency inventory and SBOM', '', `NOT INCLUDED: ${escapeMarkdown(report.inventory.reason)}`, '');
  }
  const markdown = `${lines.join('\n')}\n`;
  if (Buffer.byteLength(markdown, 'utf8') > REPORT_MAX_BYTES * 2) {
    throw new RangeError('The Markdown report exceeds the configured export size limit.');
  }
  return markdown;
}
