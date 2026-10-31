import { safeFindingEvidence, safeFindingWorkflow } from '../scans/findingIdentity.js';
import { createHash } from 'node:crypto';
import { AST_FLOW_KINDS, SCAN_TYPES, isFindingRemediationGuidance, type AstAnalysisCoverage, type AstFlowTrace, type DastAstContext, type SecretAstContext, type Finding, type FindingRemediationGuidance, type FindingWorkflow, type ReportScanContext } from '@drobon/shared';
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
import { createSacAssessment } from '../sac/engine.js';

/** Optional current Dataset guidance, kept outside the immutable v1 report. */
export interface ReportGuidanceEntry {
  findingId: string;
  guidance: FindingRemediationGuidance;
}

export const REPORT_GUIDANCE_NOTICE = 'Guidance is resolved at export time from the currently loaded, process-cached Dataset and is not covered by the saved report digest. Review and test suggestions; Drobon does not apply or verify fixes.';

/** Validate the association, bounds and shared guidance contract before any export. */
export function indexReportGuidance(report: SecurityReport, entries?: readonly ReportGuidanceEntry[]): Map<string, FindingRemediationGuidance> {
  const result = new Map<string, FindingRemediationGuidance>();
  if (entries === undefined) return result;
  if (entries.length !== report.findings.length) throw new TypeError('Report guidance is incomplete.');
  const findings = new Map(report.findings.map((finding) => [finding.id, finding]));
  for (const entry of entries) {
    const finding = findings.get(entry.findingId);
    if (finding === undefined || result.has(entry.findingId) || !isFindingRemediationGuidance(entry.guidance) ||
        entry.guidance.ruleId !== finding.ruleId) throw new TypeError('Report guidance does not match its finding.');
    result.set(entry.findingId, entry.guidance);
  }
  return result;
}

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

function contentMaterial(report: Pick<SecurityReport, 'project' | 'scan' | 'scannerCoverage' | 'findingSummary' | 'findings' | 'dast' | 'findingWorkflows' | 'dependencyIntelligence' | 'inventory' | 'sac'>): unknown {
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
    ...(report.sac === undefined ? {} : { sac: report.sac }),
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

/** Redacted view of an older immutable report. Re-hash the derived view so
 * neither the original digest nor the stored record is falsely represented. */
export function safeReportProjection(report: SecurityReport): SecurityReport {
  if (!verifySecurityReportIntegrity(report)) throw new TypeError('Report integrity check failed.');
  const { reportId: _reportId, generatedAt, contentDigest: _contentDigest, integrityDigest: _integrityDigest, ...remaining } = report;
  void _reportId; void _contentDigest; void _integrityDigest;
  const payload = {
    ...remaining,
    findings: remaining.findings.map(safeFindingEvidence),
    ...(remaining.findingWorkflows === undefined ? {} : { findingWorkflows: remaining.findingWorkflows.map(safeFindingWorkflow) }),
  };
  const contentDigest = sha256(canonicalJson(contentMaterial(payload)));
  const unsigned = { reportId: `rpt_${contentDigest.slice(0, 24)}`, generatedAt, ...payload, contentDigest };
  const projected: SecurityReport = { ...unsigned, integrityDigest: sha256(canonicalJson(unsigned)) };
  if (!verifySecurityReportIntegrity(projected)) throw new TypeError('Safe report projection failed integrity checks.');
  return projected;
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
    ...(record.assessmentId === undefined ? {} : { assessmentId: record.assessmentId }),
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
    startedAt: record.startedAt,
    ...(record.dastTargetUrl === undefined ? {} : { targetUrl: record.dastTargetUrl }),
    ...(record.dastMode === undefined ? {} : { dastMode: record.dastMode }),
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
  const findings: Finding[] = (scan.findings ?? []).map(safeFindingEvidence);
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
  const scannerCoverage = SCAN_TYPES.map((scanner) => scanner === scan.scanType
    ? { scanner, status: 'RAN' as const }
    : { scanner, status: 'NOT_RUN' as const, reason: 'Not run in this single-scan assessment.' });
  const findingSummary = summarizeReportFindings(findings);
  const sac = createSacAssessment({
    scan: scanContext,
    scannerCoverage,
    findings: findingSummary,
    ...(scan.dast === undefined ? {} : { dast: scan.dast }),
  });
  const payload = {
    project: { id: project.id, name: project.name, status: project.status },
    scan: scanContext,
    scannerCoverage,
    findingSummary,
    findings,
    ...(findingWorkflows === undefined ? {} : { findingWorkflows: findingWorkflows.map(safeFindingWorkflow) }),
    sac,
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

function astCoverageLines(coverage: AstAnalysisCoverage): string[] {
  const { rules, parsers, projectFlow } = coverage;
  const incomplete = coverage.files.filter((file) => file.status !== 'OK');
  return [
    `- Effective rules: ${rules.source}, ${rules.count}; SHA-256: \`${rules.sha256}\` (not a signature)`,
    ...(rules.packId === undefined ? ['- Dataset pack identity: not recorded'] : [`- Dataset pack: ${escapeMarkdown(rules.packId)} ${escapeMarkdown(rules.packVersion ?? 'unknown')}`]),
    `- Parser versions: TypeScript ${escapeMarkdown(parsers.typescript)}, Python/Lezer ${escapeMarkdown(parsers.python)}, PHP ${escapeMarkdown(parsers.php)}, Java/Lezer ${escapeMarkdown(parsers.java)}`,
    `- Project flow: ${projectFlow.status}; ${projectFlow.examinedFiles} files examined, ${projectFlow.unresolvedImports} unresolved relative named imports, ${projectFlow.findings} additional findings.`,
    `- Files without a structured parser: ${coverage.unstructuredFiles}`,
    ...coverage.families.map(({ family, reporters }) => {
      const available = AST_FLOW_KINDS.filter((kind) => reporters[kind] !== undefined).map((kind) => `${kind}=${reporters[kind]}`).join(', ') || 'none';
      const missing = AST_FLOW_KINDS.filter((kind) => reporters[kind] === undefined).join(', ') || 'none';
      return `- ${family}: category reporters ${escapeMarkdown(available)}; missing ${escapeMarkdown(missing)}`;
    }),
    ...(incomplete.length === 0 ? ['- Incomplete parser files: none recorded'] : incomplete.map((file) => `- Incomplete: ${escapeMarkdown(file.path)} (${file.family}, ${file.status})`)),
    '- Category reporter attribution does not establish that its exact rule pattern matched; severity is inherited, not independently validated.',
  ];
}

/** Human-readable, inert Markdown; all untrusted text is escaped as text. */
export function renderSecurityReportMarkdown(input: SecurityReport, guidance?: readonly ReportGuidanceEntry[]): string {
  // Exporters are also called outside HTTP routes. Never rely solely on the
  // caller having projected a historical snapshot first.
  const report = safeReportProjection(input);
  const guidanceByFinding = indexReportGuidance(report, guidance);
  const lines = [
    `# DROBON Security Assessment`,
    '',
    `Report: \`${report.reportId}\`  `,
    `Generated: ${escapeMarkdown(report.generatedAt)}  `,
    `Report version: ${report.reportVersion}  `,
    `Content SHA-256: \`${report.contentDigest}\`  `,
    `Integrity SHA-256: \`${report.integrityDigest}\` (digest only; not a signature)`,
    '',
    ...(guidance === undefined ? [] : [escapeMarkdown(REPORT_GUIDANCE_NOTICE), '']),
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
    '## Coverage and residual risk',
    '',
    ...(report.sac === undefined
      ? ['This older report has no saved coverage ledger; missing coverage cannot be inferred.', '']
      : [
          `- Assessment: ${report.sac.assessmentLevel}`,
          `- Verdict: ${report.sac.verdict}`,
          `- ${escapeMarkdown(report.sac.verdictStatement)}`,
          `- Residual risk: ${report.sac.residualRisk.status} — ${escapeMarkdown(report.sac.residualRisk.statement)}`,
          `- Compliance: ${report.sac.compliance.status} — ${escapeMarkdown(report.sac.compliance.statement)}`,
          `- Rule pack provenance: ${report.sac.ruleProvenance}`,
          ...report.sac.scannerCoverage.map((entry) => `- ${entry.scanner}: ${entry.status} — ${escapeMarkdown(entry.reason)}`),
          '',
          '### Recorded scan metrics',
          '',
          ...Object.entries(report.sac.metrics).map(([key, value]) => `- ${escapeMarkdown(key)}: ${value === null ? 'NOT RECORDED' : escapeMarkdown(String(value))}`),
          '',
          '### Limitations',
          '',
          ...report.sac.limitations.map((item) => `- ${escapeMarkdown(item)}`),
          '',
          '### Suggested next steps',
          '',
          ...report.sac.nextSteps.map((item) => `- ${escapeMarkdown(item)}`),
          '',
        ]),
    ...(report.scan.resultSummary?.astParser === undefined ? [] : [
      '## AST syntax-parser coverage',
      '',
      report.scan.resultSummary.astCoverage === undefined
        ? '- Recorded scope: JavaScript, TypeScript, JSX and TSX; other languages use earlier bounded heuristics.'
        : '- Scope: JavaScript, TypeScript, JSX, TSX, Python, PHP and Java; project-flow analysis is a bounded JS/TS subset.',
      `- Successfully parsed files: ${report.scan.resultSummary.astParser.parsedFiles}`,
      `- Incomplete files: ${report.scan.resultSummary.astParser.incompleteFiles}`,
      `- Parsed files without applicable AST flow rules: ${report.scan.resultSummary.astParser.filesWithoutRules}`,
      `- Additional parser findings after deduplication: ${report.scan.resultSummary.astParser.findings}`,
      ...(report.scan.resultSummary.astCoverage === undefined ? [] : astCoverageLines(report.scan.resultSummary.astCoverage)),
      '- Each flow class needs an applicable rule; some classes may be missing even when the count of files without rules is zero.',
      '- Findings are review candidates, not proof of exploitation or complete coverage.',
      '',
    ]),
    ...(report.scan.resultSummary?.astSupplement === undefined ? [] : [
      '## Scanner-specific AST supplement',
      '',
      `- Mode: ${report.scan.resultSummary.astSupplement.mode}; status: ${report.scan.resultSummary.astSupplement.status}`,
      `- Parsed: ${report.scan.resultSummary.astSupplement.parsed}; incomplete: ${report.scan.resultSummary.astSupplement.incomplete}; skipped: ${report.scan.resultSummary.astSupplement.skipped}; signals: ${report.scan.resultSummary.astSupplement.signals}`,
      `- TypeScript parser: ${escapeMarkdown(report.scan.resultSummary.astSupplement.parserVersion)}; DAST category reporter: ${escapeMarkdown(report.scan.resultSummary.astSupplement.reporterRuleId ?? 'not recorded')}`,
      '- DAST: only already-observed inline/direct script; no script execution or extra fetch. Secrets: literal overlap is context only. SCA: package.json declaration counts are syntactic, not vulnerability findings.',
      '- Partial, unsupported, missing rules and unobserved inputs remain coverage gaps; manual review is required.',
      '',
    ]),
    '## Findings',
    '',
    `Total: ${report.findingSummary.total}`,
    ...Object.entries(report.findingSummary.bySeverity).map(([severity, count]) => `- ${severity}: ${count}`),
    ...Object.entries(report.findingSummary.byScanner).map(([scanner, count]) => `- ${scanner}: ${count}`),
    '',
  ];
  if (report.dast !== undefined) {
    const mode = report.scan.dastMode ?? report.dast.mode ?? 'PASSIVE';
    lines.push(`## DAST observations (${mode})`, '', `Target: ${escapeMarkdown(report.dast.targetUrl)}`, '');
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
      `- Scanner: ${finding.scanner ?? (finding.ruleId.startsWith('DG-SEC-') || finding.ruleId.startsWith('DPK-SEC-') ? 'SECRETS' : 'SAST')}`,
      `- Rule: ${finding.ruleId}`,
      `- Location: ${escapeMarkdown(source)}`,
      `- Finding ID: \`${finding.id}\``,
      `- Fingerprint: \`${finding.fingerprint}\``,
      ...(finding.cwe === undefined ? [] : [`- CWE: ${finding.cwe}`]),
      ...(finding.astContext === undefined ? [] : finding.astContext.kind === 'SECRETS_STRING_LITERAL'
        ? ['- AST context: matched value overlaps a parsed string literal; this does not verify the credential.']
        : [`- AST response script ${finding.astContext.script}, line ${finding.astContext.line}, column ${finding.astContext.column}: ${finding.astContext.category} flow heuristic; category-selected rule, exact check not established.`]),
      ...(finding.astFlow === undefined ? [] : [
        `- AST attribution: ${finding.astFlow.mode}, ${finding.astFlow.category}, category-selected reporter (exact rule pattern not established).`,
        ...(finding.astFlow.source === undefined ? ['- Source location: not recorded'] : [
          `- Source: ${escapeMarkdown(finding.astFlow.source.file)}:${finding.astFlow.source.line}:${finding.astFlow.source.column}`,
          ...(finding.astFlow.via ?? []).map((step) => `- Call: ${escapeMarkdown(step.file)}:${step.line}:${step.column}`),
        ]),
      ]),
      '',
      escapeMarkdown(finding.description),
      '',
      quoteBlock('Evidence', finding.evidence),
      quoteBlock('Remediation', finding.remediation),
    );
    const advice = guidanceByFinding.get(finding.id);
    if (advice !== undefined) {
      lines.push(
        `#### Dataset guidance (${advice.status})`,
        '',
        quoteBlock('Why it matters', advice.whyItMatters),
        ...advice.actions.map((action, index) => quoteBlock(`Action ${index + 1}`, action)),
        quoteBlock('Verification', advice.verification),
        ...(advice.standardId === undefined ? [] : [`- Standard: ${escapeMarkdown(advice.standardId)}`, '']),
        ...(advice.example === undefined ? [] : [
          quoteBlock('Illustrative before', advice.example.before),
          quoteBlock('Illustrative after', advice.example.after),
          ...(advice.example.caveat === undefined ? [] : [quoteBlock('Example caveat', advice.example.caveat)]),
        ]),
      );
    }
    const workflow = workflowByFindingId.get(finding.id);
    if (workflow !== undefined) {
      lines.push(
        '#### Remediation workflow (snapshot)',
        '',
        `- User workflow state: ${workflow.state}${workflow.state === 'RESOLVED' ? ' (user-marked addressed; not proof of technical remediation)' : ''}`,
        `- Verification: ${workflow.verificationState === 'NOT_OBSERVED_IN_LATEST_SCAN' ? 'not observed in the recorded verification scan; this is not proof of a fix' : 'observed in the recorded verification scan'}`,
        '- Partial or truncated scans do not verify absence; the recorded verification can predate the latest scan. Check the recorded scan coverage, including for older records.',
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

/** SARIF 2.1.0 severity mapping: rule-fixed DROBON severity to SARIF level. */
function sarifLevel(severity: Finding['severity']): 'error' | 'warning' | 'note' {
  if (severity === 'CRITICAL' || severity === 'HIGH') return 'error';
  if (severity === 'MEDIUM') return 'warning';
  return 'note';
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  help: { text: string };
  defaultConfiguration: { level: 'error' | 'warning' | 'note' };
  properties: { tags: string[] };
}

interface SarifResult {
  ruleId: string;
  ruleIndex: number;
  level: 'error' | 'warning' | 'note';
  message: { text: string };
  locations: SarifLocation[];
  fingerprints: Record<string, string>;
  properties?: { 'drobon/astFlow'?: AstFlowTrace; 'drobon/astContext'?: DastAstContext | SecretAstContext; 'drobon/remediationGuidance'?: FindingRemediationGuidance };
}

type SarifLocation =
  | { physicalLocation: { artifactLocation: { uri: string }; region: { startLine: number; startColumn?: number } } }
  | { logicalLocations: Array<{ fullyQualifiedName: string }> };

/**
 * Machine-readable SARIF 2.1.0 rendering of a persisted security report
 * (Phase 22). Pure transformation of already-persisted, already-authorized
 * report data — no new trust surface: same route, same ownership checks.
 * Rules are deduplicated by stable ruleId in first-occurrence order; DAST
 * findings (no source location) use logical locations. Fingerprints carry
 * the DROBON stable fingerprint so CI importers can correlate across runs.
 */
export function renderSecurityReportSarif(input: SecurityReport, guidance?: readonly ReportGuidanceEntry[]): string {
  const report = safeReportProjection(input);
  const guidanceByFinding = indexReportGuidance(report, guidance);
  const rules: SarifRule[] = [];
  const ruleIndexById = new Map<string, number>();
  const results: SarifResult[] = [];
  for (const finding of report.findings) {
    let ruleIndex = ruleIndexById.get(finding.ruleId);
    if (ruleIndex === undefined) {
      ruleIndex = rules.length;
      ruleIndexById.set(finding.ruleId, ruleIndex);
      const tags = ['security', ...(finding.cwe === undefined ? [] : [finding.cwe])];
      rules.push({
        id: finding.ruleId,
        name: finding.ruleId,
        shortDescription: { text: finding.title },
        fullDescription: { text: finding.description },
        help: { text: finding.remediation },
        defaultConfiguration: { level: sarifLevel(finding.severity) },
        properties: { tags },
      });
    }
    const location: SarifLocation = finding.scanner === 'DAST'
      ? { logicalLocations: [{ fullyQualifiedName: `${finding.method} ${finding.endpoint} (HTTP ${finding.responseStatus})` }] }
      : {
          physicalLocation: {
            artifactLocation: { uri: finding.file },
            region: { startLine: Math.max(1, finding.line), ...(finding.column >= 1 ? { startColumn: finding.column } : {}) },
          },
        };
    const advice = guidanceByFinding.get(finding.id);
    results.push({
      ruleId: finding.ruleId,
      ruleIndex,
      level: sarifLevel(finding.severity),
      message: { text: `${finding.title} — ${finding.description}` },
      locations: [location],
      fingerprints: { 'drobon/v1': finding.fingerprint },
      ...(finding.astFlow === undefined && finding.astContext === undefined && advice === undefined ? {} : { properties: {
        ...(finding.astFlow === undefined ? {} : { 'drobon/astFlow': finding.astFlow }),
        ...(finding.astContext === undefined ? {} : { 'drobon/astContext': finding.astContext }),
        ...(advice === undefined ? {} : { 'drobon/remediationGuidance': advice }),
      } }),
    });
  }
  const log = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'DROBON AEGIS',
            version: report.reportVersion,
            semanticVersion: report.reportVersion,
            rules,
          },
        },
        results,
        properties: {
          'drobon/reportId': report.reportId,
          'drobon/generatedAt': report.generatedAt,
          'drobon/contentDigest': report.contentDigest,
          'drobon/projectId': report.project.id,
          'drobon/projectName': report.project.name,
          'drobon/scanId': report.scan.id,
          'drobon/scanType': report.scan.scanType,
          'drobon/dependencyIntelligence': report.dependencyIntelligence.status,
          'drobon/honesty': 'A bounded scan cannot establish safety; dependency intelligence is not a verdict when NOT_ASSESSED.',
          ...(guidance === undefined ? {} : { 'drobon/guidanceNotice': REPORT_GUIDANCE_NOTICE }),
          ...(report.scan.resultSummary?.astParser === undefined ? {} : {
            'drobon/astParser': report.scan.resultSummary.astParser,
            'drobon/astParserScope': report.scan.resultSummary.astCoverage === undefined
              ? 'JavaScript, TypeScript, JSX and TSX only; findings require applicable rules.'
              : 'JavaScript, TypeScript, JSX, TSX, Python, PHP and Java; bounded JS/TS project flow; findings require applicable rules.',
            ...(report.scan.resultSummary.astCoverage === undefined ? {} : { 'drobon/astCoverage': report.scan.resultSummary.astCoverage }),
          }),
          ...(report.scan.resultSummary?.astSupplement === undefined ? {} : { 'drobon/astSupplement': report.scan.resultSummary.astSupplement }),
          ...(report.sac === undefined ? {} : {
            'drobon/assessmentLevel': report.sac.assessmentLevel,
            'drobon/coverageVerdict': report.sac.verdict,
            'drobon/residualRisk': report.sac.residualRisk.status,
            'drobon/compliance': report.sac.compliance.status,
            'drobon/coverage': report.sac.scannerCoverage,
            'drobon/limitations': report.sac.limitations,
          }),
        },
      },
    ],
  };
  const sarif = `${JSON.stringify(log, null, 2)}\n`;
  if (Buffer.byteLength(sarif, 'utf8') > REPORT_MAX_BYTES * 2) {
    throw new RangeError('The SARIF report exceeds the configured export size limit.');
  }
  return sarif;
}

/**
 * Standalone CycloneDX SBOM export (Phase 22). The document is the exact
 * persisted `inventory.sca.sbom` subset — re-serialized for delivery, not
 * regenerated. Throws when the scan produced no dependency inventory.
 */
export function renderSbomExport(report: SecurityReport): string | undefined {
  if (report.inventory.status !== 'INCLUDED') return undefined;
  return `${JSON.stringify(report.inventory.sca.sbom, null, 2)}\n`;
}
