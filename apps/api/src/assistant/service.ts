import {
  ASSISTANT_EVIDENCE_REFS_MAX,
  ASSISTANT_LIST_MAX,
  type AssistantEvidenceReference,
  type AssistantProviderState,
  type AssistantQuestionRequest,
  type AssistantResponse,
  type AssistantState,
  type AssistantStatusResponse,
  type Finding,
  findingScanner,
  compareFindings,
} from '@drobon/shared';
import type { ProjectRecord } from '../projects/store.js';
import type { ScanRecord, ScanStore } from '../scans/store.js';
import { remediationGuidanceForFinding, scaInventoryGuidance } from '../scans/remediationGuidance.js';
import { buildAssistantContext, type AssistantContextBuild } from './context.js';
import { redactAssistantText } from './redaction.js';
import type { AssistantProvider } from './provider.js';

export interface AssistantServiceDeps {
  scans: ScanStore;
  provider: AssistantProvider;
}

type Intent = 'TOP_FINDINGS' | 'EXPLAIN_FINDING' | 'REMEDIATION' | 'SCANNER' | 'LIFECYCLE' |
  'COMPARE_SCANS' | 'DEPENDENCIES' | 'NOT_ASSESSED' | 'LATEST_SCAN' | 'REPORT' | 'UNKNOWN';

/** Closed, deterministic intent recognizer. It never parses evidence as instructions. */
function classifyQuestion(question: string): Intent {
  const text = question.toLowerCase().replace(/[^a-z0-9\s_-]/g, ' ').replace(/\s+/g, ' ').trim();
  if (/\b(compare|changed between|what changed|difference between)\b/.test(text)) return 'COMPARE_SCANS';
  if (/\b(lifecycle|remediation status|current status|verification status|is this resolved)\b/.test(text)) return 'LIFECYCLE';
  if (/\b(which scanner|scanner produced|what scanner)\b/.test(text)) return 'SCANNER';
  if (/\b(remediat|what should i do|how do i fix|fix this finding)\b/.test(text)) return 'REMEDIATION';
  if (/\b(dependenc\w*|sbom|inventory|package list)\b/.test(text)) return 'DEPENDENCIES';
  if (/\b(not assessed|what was not assessed|assessment unavailable)\b/.test(text)) return 'NOT_ASSESSED';
  if (/\b(report|assessment summary)\b/.test(text)) return 'REPORT';
  if (/\b(latest scan|what did .* scan|what was observed|actually observe)\b/.test(text)) return 'LATEST_SCAN';
  if (/\b(most severe|highest severity|top findings|critical findings|high findings)\b/.test(text)) return 'TOP_FINDINGS';
  if (/\b(explain|describe)\b.*\bfinding\b|\bwhat is this finding\b/.test(text)) return 'EXPLAIN_FINDING';
  return 'UNKNOWN';
}

function orderScans(scans: readonly ScanRecord[]): ScanRecord[] {
  return [...scans].filter((scan) => scan.status === 'COMPLETED')
    .sort((a, b) => {
      const left = a.completedAt ?? '';
      const right = b.completedAt ?? '';
      if (left !== right) return left > right ? -1 : 1;
      return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
    });
}

function latestByScanner(scans: readonly ScanRecord[]): ScanRecord[] {
  const latest = new Map<string, ScanRecord>();
  for (const scan of orderScans(scans)) if (!latest.has(scan.scanType)) latest.set(scan.scanType, scan);
  return [...latest.values()].sort((a, b) => a.scanType < b.scanType ? -1 : a.scanType > b.scanType ? 1 : 0);
}

function mismatch(scan: ScanRecord): boolean {
  return scan.resultSummary === undefined || scan.resultSummary.findingsTotal !== (scan.findings?.length ?? 0);
}

function refs(context: AssistantContextBuild): AssistantEvidenceReference[] {
  const out: AssistantEvidenceReference[] = [];
  const seen = new Set<string>();
  for (const item of context.items) {
    const key = `${item.sourceType}:${item.sourceId}:${item.scanId ?? ''}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ sourceType: item.sourceType, sourceId: item.sourceId, projectId: item.projectId,
      ...(item.scanId === undefined ? {} : { scanId: item.scanId }) });
    if (out.length >= ASSISTANT_EVIDENCE_REFS_MAX) break;
  }
  return out;
}

function safeOutputText(value: string, maxLength: number): string {
  const safe = redactAssistantText(value);
  return (safe.safeForProvider ? safe.text : '[sensitive content omitted]').slice(0, maxLength);
}

function response(
  state: AssistantState,
  answer: string,
  context: AssistantContextBuild,
  providerState: AssistantProviderState,
  options: Partial<Pick<AssistantResponse, 'facts' | 'interpretations' | 'recommendations' | 'limitations' | 'evidence'>> = {},
): AssistantResponse {
  return {
    state,
    mode: 'DETERMINISTIC',
    providerState,
    answer: safeOutputText(answer, 4_000),
    facts: (options.facts ?? []).slice(0, ASSISTANT_LIST_MAX).map((value) => safeOutputText(value, 500)),
    interpretations: (options.interpretations ?? []).slice(0, ASSISTANT_LIST_MAX).map((value) => safeOutputText(value, 500)),
    recommendations: (options.recommendations ?? []).slice(0, ASSISTANT_LIST_MAX).map((value) => safeOutputText(value, 500)),
    limitations: (options.limitations ?? []).slice(0, ASSISTANT_LIST_MAX).map((value) => safeOutputText(value, 500)),
    evidence: (options.evidence ?? refs(context)).slice(0, ASSISTANT_EVIDENCE_REFS_MAX),
    context: context.summary,
  };
}

function findingSort(findings: readonly Finding[]): Finding[] {
  return [...findings].sort(compareFindings);
}

function isPartial(scans: readonly ScanRecord[], context: AssistantContextBuild): boolean {
  return scans.some((scan) => mismatch(scan) || scan.resultSummary?.partial === true || scan.resultSummary?.truncated === true) || context.summary.truncated;
}

export class AssistantService {
  private readonly scans: ScanStore;
  private readonly provider: AssistantProvider;

  constructor(deps: AssistantServiceDeps) {
    this.scans = deps.scans;
    this.provider = deps.provider;
  }

  status(): AssistantStatusResponse {
    const availability = this.provider.availability();
    return {
      providerState: availability.state,
      providerId: availability.state === 'AVAILABLE' ? availability.providerId : null,
      deterministicQuestionsAvailable: true,
      conversationPersistence: 'NOT_IMPLEMENTED',
      toolsEnabled: false,
    };
  }

  async answer(project: ProjectRecord, request: AssistantQuestionRequest): Promise<AssistantResponse> {
    const intent = classifyQuestion(request.question);
    const providerState = this.provider.availability().state;
    if (intent === 'UNKNOWN') {
      // Do not gather project security evidence for an unsupported generative
      // request when no provider-backed intent handler exists.
      const context = buildAssistantContext({ project, scans: [] });
      const answer = providerState !== 'AVAILABLE'
        ? 'No configured AI provider is available for open-ended generation. Ask a supported question about an existing project scan, finding, remediation state, report, or dependency inventory.'
        : 'Open-ended provider generation is not implemented in this release; no AI-generated answer was created.';
      return response('UNAVAILABLE', answer, context, providerState, { evidence: refs(context), limitations: [answer] });
    }
    // Never copy an unbounded project's full scan history into assistant
    // memory. The dedicated store query returns at most one completed scan
    // per supported scanner type; explicit IDs are resolved individually.
    const allScans = request.scanId === undefined
      ? await this.scans.listLatestCompletedByScannerForAssistant(project.id)
      : [];
    const completed = orderScans(allScans);
    let selectedScan: ScanRecord | undefined;
    let comparedScan: ScanRecord | undefined;
    if (request.scanId !== undefined) selectedScan = await this.scans.findByProjectAndId(project.id, request.scanId);
    if (request.compareScanId !== undefined) comparedScan = await this.scans.findByProjectAndId(project.id, request.compareScanId);

    const applicableScans = request.scanId !== undefined
      ? selectedScan === undefined || selectedScan.status !== 'COMPLETED' ? [] : [selectedScan]
      : intent === 'DEPENDENCIES' || intent === 'NOT_ASSESSED'
        ? completed.filter((scan) => scan.scanType === 'SCA').slice(0, 1)
        : intent === 'TOP_FINDINGS' ? latestByScanner(completed) : completed.slice(0, 1);
    const contextScans = intent === 'COMPARE_SCANS' && selectedScan !== undefined && comparedScan !== undefined
      ? [selectedScan, comparedScan]
      : applicableScans;

    let finding: Finding | undefined;
    let findingMissingButSummaryDisagrees = false;
    if (request.findingId !== undefined && selectedScan?.status === 'COMPLETED') {
      finding = selectedScan.findings?.find((entry) => entry.id === request.findingId);
      findingMissingButSummaryDisagrees = finding === undefined && mismatch(selectedScan);
    }
    const workflow = finding === undefined ? undefined : await this.scans.getFindingWorkflow(project.id, finding.fingerprint);
    const selectedHistory = finding === undefined
      ? undefined
      : await this.scans.getFindingHistory(project.id, finding.fingerprint, 1, 5);
    const historyEvents = selectedHistory?.events.map((event) => `${event.action}: ${event.previousState ?? '—'} → ${event.newState} at ${event.at}`) ?? [];

    const findingsForContext = finding !== undefined
      ? [finding]
      : findingSort(contextScans.flatMap((scan) => scan.findings ?? [])).slice(0, 10);
    const workflows = finding !== undefined && workflow !== undefined
      ? [workflow]
      : await this.scans.getFindingWorkflowsForFindings(project.id, findingsForContext);
    const lifecycleHistory = finding === undefined ? [] : [{
      findingId: finding.id,
      ...(selectedScan === undefined ? {} : { scanId: selectedScan.id }),
      events: historyEvents,
      ...(selectedHistory?.events[0] === undefined ? {} : { createdAt: selectedHistory.events[0].at }),
    }];
    let report = selectedScan === undefined ? undefined : await this.scans.findReportByProjectAndScan(project.id, selectedScan.id);
    if (report === undefined && applicableScans.length === 1 && intent === 'REPORT') {
      report = await this.scans.findReportByProjectAndScan(project.id, applicableScans[0]!.id);
    }
    const context = buildAssistantContext({
      project,
      scans: contextScans,
      findings: findingsForContext,
      workflows,
      lifecycleHistory,
      ...(report === undefined ? {} : { report }),
    });
    const evidence = refs(context);
    const unsupported = (reason: string, state: AssistantState = 'UNAVAILABLE'): AssistantResponse =>
      response(state, reason, context, providerState, { evidence, limitations: [reason] });

    if (request.scanId !== undefined && (selectedScan === undefined || selectedScan.status !== 'COMPLETED')) {
      return unsupported('The selected scan is not a completed scan. Assistant answers use completed, persisted scan results only.');
    }
    if ((intent === 'EXPLAIN_FINDING' || intent === 'REMEDIATION' || intent === 'SCANNER' || intent === 'LIFECYCLE') && request.findingId === undefined) {
      return unsupported('Select a finding from an authorized completed scan to answer this question.');
    }
    if (request.findingId !== undefined && finding === undefined) {
      if (findingMissingButSummaryDisagrees) {
        return unsupported('The scan summary reports findings but persisted finding details are incomplete. This assistant cannot identify or explain a finding from missing details.', 'PARTIALLY_SUPPORTED');
      }
      return unsupported('That finding is not present in the selected completed scan.', 'UNAVAILABLE');
    }

    if (intent === 'EXPLAIN_FINDING' && finding !== undefined) {
      const scanner = findingScanner(finding) ?? 'unknown scanner';
      const state: AssistantState = mismatch(selectedScan!) ? 'PARTIALLY_SUPPORTED' : 'SUPPORTED';
      const facts = [
        `The persisted finding ${finding.id} is classified ${finding.severity} by ${scanner}, rule ${finding.ruleId}.`,
        `Scanner title: ${finding.title}.`,
        `Scanner description: ${finding.description}`,
      ];
      const interpretations = ['This is an explanation of the scanner record, not an independent exploitability assessment or proof of a fix.'];
      const limitations = mismatch(selectedScan!) ? ['The scan summary and persisted finding details disagree; the available finding record may be incomplete.'] : [];
      return response(state, `${finding.title}: ${finding.description}`, context, providerState, { evidence, facts, interpretations, limitations });
    }

    if (intent === 'REMEDIATION' && finding !== undefined) {
      const guidance = remediationGuidanceForFinding(finding);
      const facts = [`Rule ${finding.ruleId} from ${findingScanner(finding) ?? 'an unidentified scanner'} produced this finding.`];
      const interpretations = [finding.remediation];
      const recommendations = [...guidance.actions, guidance.verification];
      const limitations = [
        'Remediation guidance is not a code change, credential rotation, or verification.',
        ...(workflow?.state === 'RESOLVED' ? ['RESOLVED is user-managed workflow state and does not prove technical remediation.'] : []),
      ];
      const state: AssistantState = guidance.status === 'UNAVAILABLE' ? 'PARTIALLY_SUPPORTED' : 'SUPPORTED';
      return response(state, `Existing ${guidance.status.toLowerCase().replaceAll('_', ' ')} guidance for ${finding.ruleId}. Review it in the application context; only a later authorized scan can update observation status.`, context, providerState,
        { evidence, facts, interpretations, recommendations, limitations });
    }

    if (intent === 'SCANNER' && finding !== undefined) {
      const scanner = findingScanner(finding);
      if (scanner === undefined) return unsupported('The persisted finding does not identify a scanner.', 'PARTIALLY_SUPPORTED');
      return response('SUPPORTED', `The finding was produced by ${scanner}.`, context, providerState, {
        evidence, facts: [`Finding ${finding.id} records scanner ${scanner} and rule ${finding.ruleId}.`],
        limitations: ['The scanner identity is from persisted application evidence.'],
      });
    }

    if (intent === 'LIFECYCLE' && finding !== undefined) {
      if (workflow === undefined) return unsupported('Finding lifecycle details are unavailable for this record.', 'PARTIALLY_SUPPORTED');
      const facts = [
        `Current workflow state: ${workflow.state}.`,
        `Latest verification state: ${workflow.verificationState}.`,
        `Last verification scan: ${workflow.lastVerificationScanId} at ${workflow.lastVerificationAt}.`,
        `Recent lifecycle events available: ${historyEvents.length}.`,
      ];
      const interpretations = workflow.state === 'RESOLVED'
        ? ['RESOLVED is user-managed and does not mean the scanner verified a fix.']
        : workflow.verificationState === 'NOT_OBSERVED_IN_LATEST_SCAN'
          ? ['Not observed is limited to that completed scan; it is not proof of remediation or global absence.']
          : ['The finding was observed in the recorded verification scan.'];
      return response('SUPPORTED', `Lifecycle is ${workflow.state}; verification is ${workflow.verificationState}. These are workflow and scan-observation records, not proof of a technical fix.`, context, providerState,
        { evidence, facts, interpretations, limitations: ['The assistant does not change finding lifecycle state.'] });
    }

    if (intent === 'COMPARE_SCANS') {
      if (request.scanId === undefined || request.compareScanId === undefined || selectedScan === undefined || comparedScan === undefined) {
        return unsupported('Choose two scans from this project to compare; scan identifiers are resolved only inside the authorized project.');
      }
      if (selectedScan.status !== 'COMPLETED' || comparedScan.status !== 'COMPLETED') {
        return unsupported('Both scans must be completed before they can be compared.');
      }
      if (selectedScan.id === comparedScan.id) return unsupported('Choose two different completed scans.');
      const before = new Set((comparedScan.findings ?? []).map((entry) => entry.fingerprint));
      const after = new Set((selectedScan.findings ?? []).map((entry) => entry.fingerprint));
      const added = [...after].filter((fingerprint) => !before.has(fingerprint)).length;
      const notInSelected = [...before].filter((fingerprint) => !after.has(fingerprint)).length;
      const partial = mismatch(selectedScan) || mismatch(comparedScan);
      const state: AssistantState = partial ? 'PARTIALLY_SUPPORTED' : 'SUPPORTED';
      const facts = [
        `Selected scan ${selectedScan.id} persisted ${selectedScan.findings?.length ?? 0} finding details (summary: ${selectedScan.resultSummary?.findingsTotal ?? 'unavailable'}).`,
        `Compared scan ${comparedScan.id} persisted ${comparedScan.findings?.length ?? 0} finding details (summary: ${comparedScan.resultSummary?.findingsTotal ?? 'unavailable'}).`,
        `Deterministic fingerprint comparison: ${added} new identities in the selected scan; ${notInSelected} prior identities not observed there.`,
      ];
      const limitations = partial ? ['One or both scan summaries disagree with persisted finding details; fingerprint differences are incomplete and do not prove fixes.'] : ['A fingerprint absent from the selected scan is only not observed there, not proof of remediation.'];
      return response(state, `Compared persisted finding fingerprints between the selected scans: ${added} new identity(ies); ${notInSelected} prior identity(ies) not observed in the selected scan.`, context, providerState,
        { evidence, facts, limitations });
    }

    if (intent === 'DEPENDENCIES' || intent === 'NOT_ASSESSED') {
      const scaScan = request.scanId !== undefined
        ? selectedScan?.scanType === 'SCA' ? selectedScan : undefined
        : completed.find((scan) => scan.scanType === 'SCA');
      if (scaScan?.sca === undefined) {
        const wording = request.scanId === undefined
          ? 'No completed SCA result is available for this project. Dependency inventory and vulnerability intelligence cannot be determined from the available records.'
          : 'The selected scan does not contain SCA inventory. Dependency vulnerability intelligence was not assessed by this scan.';
        return unsupported(wording, 'NOT_ASSESSED');
      }
      const sca = scaScan.sca;
      const guidance = scaInventoryGuidance(sca);
      const dependencies = sca.dependencies.slice(0, 10).map((dependency) =>
        `${dependency.ecosystem} ${dependency.name}${dependency.resolvedVersion === undefined ? '' : `@${dependency.resolvedVersion}`}`,
      );
      const facts = [
        `SCA scan ${scaScan.id} recorded ${sca.summary.dependenciesTotal} dependency component(s); ${sca.dependencies.length} are persisted${sca.summary.truncated ? ' (truncated)' : ''}.`,
        `Vulnerability intelligence state: ${sca.summary.assessmentState}; dataset status: ${sca.summary.datasetStatus}; provider: ${sca.summary.providerId}.`,
        ...(dependencies.length === 0 ? [] : [`Observed examples: ${dependencies.join(', ')}`]),
      ];
      const limitations = [guidance.message, 'Inventory does not establish that a dependency is vulnerable, safe, exploitable, or licensed.'];
      const state: AssistantState = sca.summary.assessmentState === 'NOT_ASSESSED' ? 'NOT_ASSESSED' : 'SUPPORTED';
      const questionAnswer = intent === 'DEPENDENCIES'
        ? `The selected SCA result records ${sca.summary.dependenciesTotal} dependencies. ${sca.summary.assessmentState === 'NOT_ASSESSED' ? 'Vulnerability intelligence remains NOT ASSESSED.' : 'Use only the advisories actually present in this result.'}`
        : `The SCA result reports vulnerability intelligence as ${sca.summary.assessmentState} (${sca.summary.datasetStatus}).`;
      return response(state, questionAnswer, context, providerState, {
        evidence, facts,
        recommendations: [guidance.verification],
        limitations,
      });
    }

    if (intent === 'REPORT') {
      if (report === undefined) return unsupported('No persisted report is available for the selected/latest completed scan. Generate a report through the existing authorized report workflow first.');
      return response('SUPPORTED', `Persisted report ${report.reportId} summarizes ${report.findingSummary.total} finding record(s) for scan ${report.scan.id}. It is a point-in-time snapshot.`, context, providerState, {
        evidence,
        facts: [`Report ${report.reportId} was generated at ${report.generatedAt}.`, `Report finding summary: ${report.findingSummary.total}.`, `Dependency intelligence: ${report.dependencyIntelligence.status}.`],
        limitations: ['Report context is read-only and reflects the persisted snapshot, not a new scan or verification.'],
      });
    }

    if (intent === 'TOP_FINDINGS') {
      if (applicableScans.length === 0) return unsupported('No completed scan is available for this project; findings cannot be summarized.', 'UNAVAILABLE');
      const findings = findingSort(applicableScans.flatMap((scan) => scan.findings ?? [])).slice(0, 10);
      const partial = isPartial(applicableScans, context);
      const reported = applicableScans.reduce((sum, scan) => sum + (scan.resultSummary?.findingsTotal ?? 0), 0);
      if (findings.length === 0 && reported > 0) {
        return unsupported(`Completed scan summaries report ${reported} findings, but persisted finding details are incomplete. The assistant cannot claim there are no findings.`, 'PARTIALLY_SUPPORTED');
      }
      const facts = findings.map((entry) => `${entry.severity}: ${entry.title} (${findingScanner(entry) ?? 'scanner unavailable'}, ${entry.ruleId}).`);
      const answer = findings.length === 0
        ? 'No finding records are persisted in the selected completed scan result. This is not a security guarantee; review scan scope, partial/truncated indicators, and scanners not run.'
        : `The highest-severity persisted findings in the selected/latest completed scan set are: ${findings.slice(0, 5).map((entry) => `${entry.severity} ${entry.title}`).join('; ')}.`;
      return response(partial ? 'PARTIALLY_SUPPORTED' : 'SUPPORTED', answer, context, providerState, {
        evidence,
        facts,
        limitations: ['This uses persisted scan findings only; it is not a deduplicated vulnerability count across every possible scanner or data source.', ...(partial ? ['One or more scan results are partial, truncated, or have incomplete persisted details.'] : [])],
      });
    }

    if (intent === 'LATEST_SCAN') {
      const latest = request.scanId === undefined ? completed[0] : selectedScan;
      if (latest === undefined || latest.status !== 'COMPLETED') return unsupported('No completed scan is available to answer what was observed.', 'UNAVAILABLE');
      const total = latest.resultSummary?.findingsTotal;
      const persistedCount = latest.findings?.length ?? 0;
      const incomplete = mismatch(latest);
      const facts = [
        `Latest selected completed scan: ${latest.scanType}, completed ${latest.completedAt ?? 'time unavailable'}.`,
        `Engine summary reports ${total ?? 'an unavailable number of'} findings; ${persistedCount} finding detail record(s) are persisted.`,
        ...(latest.sca === undefined ? [] : [`SCA assessment: ${latest.sca.summary.assessmentState}; dataset: ${latest.sca.summary.datasetStatus}.`]),
        ...(latest.dast === undefined ? [] : [`Passive DAST recorded ${latest.dast.observations.length} bounded observation(s); response bodies are not returned to this assistant.`]),
      ];
      const answer = incomplete
        ? `The ${latest.scanType} scan completed, but the engine summary and persisted finding details do not agree. The summary reports ${total ?? 'an unknown number of'} findings; only ${persistedCount} detail record(s) are available, so this is incomplete evidence.`
        : `The latest selected completed ${latest.scanType} scan reported ${total ?? 0} finding(s), with ${persistedCount} persisted detail record(s). This describes that scanner result only.`;
      return response(incomplete || isPartial([latest], context) ? 'PARTIALLY_SUPPORTED' : 'SUPPORTED', answer, context, providerState, {
        evidence,
        facts,
        limitations: ['This describes only the selected scan; scanners not run and dependency intelligence not assessed by this result are outside its scope.', ...(incomplete ? ['Incomplete finding details prevent any zero-finding conclusion.'] : [])],
      });
    }

    return unsupported('This supported question type is not implemented in the current version.');
  }
}
