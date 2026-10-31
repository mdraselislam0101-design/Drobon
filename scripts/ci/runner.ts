import { createHash } from 'node:crypto';
import { realpath } from 'node:fs/promises';
import { type FindingSeverity, type ScanType, type SecurityReport } from '@drobon/shared';
import { createDatasetService } from '../../apps/api/src/external/service.js';
import { createMemoryProjectStore } from '../../apps/api/src/projects/store.js';
import { buildSecurityReport, renderSecurityReportSarif } from '../../apps/api/src/reports/build.js';
import { createSastEngine } from '../../apps/api/src/scans/sast/engine.js';
import { createScaEngine } from '../../apps/api/src/scans/sca/engine.js';
import { createFilesystemIntelligenceProvider } from '../../apps/api/src/scans/sca/filesystemProvider.js';
import { createSecretsEngine } from '../../apps/api/src/scans/secrets/engine.js';
import { createMemorySourceStore } from '../../apps/api/src/scans/sources.js';
import { createMemoryScanStore } from '../../apps/api/src/scans/store.js';
import type { ScanEngine } from '../../apps/api/src/scans/engines.js';
import { collectSources } from './collector.js';
import { inspectDataset } from './datasetPreflight.js';

export type CiScanner = Extract<ScanType, 'SAST' | 'SECRETS' | 'SCA'>;
export interface CiOptions {
  root: string;
  datasetPath: string;
  scanners: readonly CiScanner[];
  threshold: FindingSeverity;
  /** Stable operator-chosen repository identity; defaults to canonical root. */
  projectKey?: string;
  /** Explicit acceptance of coverage gaps, NOT an assertion of safety. */
  allowIncomplete: boolean;
}
export interface CiSummary {
  status: 'FINDINGS' | 'INCOMPLETE' | 'PASS';
  scanners: readonly CiScanner[];
  files: number;
  batches: number;
  findings: number;
  advisoryMatches: number;
  thresholdHits: number;
  incompleteReasons: string[];
  omissions: { invalidPath: number; sensitiveOrHidden: number; symlink: number; oversized: number; nonText: number; capacity: number };
  /** SCA provider outcomes, not inferred from the absence of matches. */
  scaAssessmentStates: string[];
}
export interface CiResult { summary: CiSummary; sarif: string; exitCode: 0 | 1 | 2 }

const SEVERITY: Record<FindingSeverity, number> = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
function rank(value: FindingSeverity): number { return SEVERITY[value]; }
function level(value: FindingSeverity): 'error' | 'warning' | 'note' {
  return rank(value) >= rank('HIGH') ? 'error' : value === 'MEDIUM' ? 'warning' : 'note';
}
function digest(value: string): string { return createHash('sha256').update(value).digest('hex'); }
function stableProjectId(key: string): string {
  // This ID is local CI context, not an authorization/account identifier.
  const hex = digest(`drobon-ci-project-v1\u0000${key}`).slice(0, 32);
  return `prj_${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}
function safeHelpUri(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && url.username === '' && url.password === '' ? url.href : undefined;
  } catch { return undefined; }
}

/** Existing engine SCA advisories are separate from source findings. Include
 * actual matched advisories in the gate and SARIF; never infer a clean verdict. */
function advisoryRun(report: SecurityReport): Record<string, unknown> | undefined {
  if (report.inventory.status !== 'INCLUDED' || report.inventory.sca.advisories.length === 0) return undefined;
  const sca = report.inventory.sca;
  const rules = sca.advisories.map((item) => ({
    id: `${item.id}:${item.dependencyId}`,
    name: item.id,
    shortDescription: { text: item.summary },
    ...(safeHelpUri(item.url) === undefined ? {} : { helpUri: safeHelpUri(item.url) }),
    defaultConfiguration: { level: level(item.severity) },
  }));
  const results = sca.advisories.map((item, index) => {
    const dependency = sca.dependencies.find((candidate) => candidate.dependencyId === item.dependencyId);
    const location = dependency === undefined ? [] : [{ physicalLocation: { artifactLocation: { uri: dependency.lockfilePath ?? dependency.manifestPath } } }];
    return {
      ruleId: `${item.id}:${item.dependencyId}`, ruleIndex: index, level: level(item.severity),
      message: { text: `${item.name}${item.version === undefined ? '' : ` ${item.version}`}: ${item.summary}` },
      locations: location,
      fingerprints: { 'drobon/advisory-v1': digest(`${report.project.id}\n${item.id}\n${item.dependencyId}`) },
    };
  });
  return { tool: { driver: { name: 'DROBON SCA ADVISORY MATCHES', version: '1.0.0', rules } }, results,
    properties: { 'drobon/assessmentState': sca.summary.assessmentState, 'drobon/datasetStatus': sca.summary.datasetStatus } };
}

/**
 * Run the same existing engines against local, explicitly selected files.
 * It uses ephemeral stores and does not mutate the server, user project,
 * dataset, target repository, or quota; only the caller writes an output file.
 * DAST is intentionally absent: a repository CI run does not grant permission
 * to send network traffic to a third-party target.
 */
export async function runCiCheck(options: CiOptions): Promise<CiResult> {
  const selected = [...new Set(options.scanners)];
  if (selected.length === 0 || selected.some((scanner) => !['SAST', 'SECRETS', 'SCA'].includes(scanner))) {
    throw new TypeError('Select SAST, SECRETS or SCA.');
  }
  if (!Object.prototype.hasOwnProperty.call(SEVERITY, options.threshold)) throw new TypeError('Invalid severity threshold.');
  if (options.projectKey !== undefined && (options.projectKey.trim().length === 0 || options.projectKey.length > 256 || Array.from(options.projectKey).some((char) => (char.codePointAt(0) ?? 0) < 32))) {
    throw new TypeError('Invalid project key.');
  }
  const projectKey = options.projectKey?.trim() ?? await realpath(options.root);
  const sources = await collectSources(options.root);
  // Keep CI's strict preflight even though the service also reports unreadable
  // files and refuses to traverse symlinks. Compare discovered counts as well.
  const rawRuleCounts = await inspectDataset(options.datasetPath);
  const dataset = createDatasetService({ providerId: 'filesystem', datasetPath: options.datasetPath });
  const status = await dataset.status();
  const reasons: string[] = [];
  let hardFailure = false;
  const addReason = (reason: string, hard = false): void => {
    if (!reasons.includes(reason)) reasons.push(reason);
    if (hard) hardFailure = true;
  };
  if (!status.configured) addReason('Dataset is not configured.', true);
  for (const scanner of selected) {
    const pack = scanner === 'SAST' ? status.sastPacks : scanner === 'SECRETS' ? status.secretsPacks : status.scaPacks;
    const conform = scanner === 'SAST' ? status.conformance.sast : scanner === 'SECRETS' ? status.conformance.secrets : status.conformance.sca;
    if (pack.status !== 'AVAILABLE' || pack.count === 0) addReason(`${scanner} rules are unavailable.`, true);
    const family = scanner === 'SAST' ? 'sast' : scanner === 'SECRETS' ? 'secrets' : 'sca';
    if (rawRuleCounts[family] !== conform.filesSeen || conform.rejected.some((issue) => issue.reason.includes('malformed JSON'))) {
      addReason(`${scanner} pack contains unreadable or malformed rule files.`, true);
    }
    if (conform.enumerationFailures > 0) addReason(`${scanner} pack could not be fully enumerated.`, true);
    if (conform.manifestIssue !== undefined) addReason(`${scanner} pack manifest could not be safely read.`, true);
    if (conform.accepted < conform.filesSeen || conform.failedTests > 0 || conform.skippedTests > 0) addReason(`${scanner} pack contains rejected rules or incomplete declared tests.`, true);
  }
  if (selected.includes('SCA') && status.vulnIntel.status !== 'AVAILABLE') addReason('SCA vulnerability intelligence is unavailable.', true);
  if (sources.batches.length === 0) addReason('No eligible text source files were collected.', true);
  if (sources.batches.length > 1) addReason('Multiple bounded snapshots limit cross-file flow and manifest/lockfile correlation.');
  if (Object.values(sources.omitted).some((count) => count > 0)) addReason('Some files, paths, symlinks or hidden/credential material were omitted by source policy.');

  const temporaryProject = await createMemoryProjectStore().create({ ownerId: 'usr_ci_local', name: 'Local CI security check', description: '' });
  // Stable context is essential for finding fingerprints across CI reruns.
  // It never enters or grants access to the real app's project store.
  const project = { ...temporaryProject, id: stableProjectId(projectKey) };
  const sourceStore = createMemorySourceStore();
  const scans = createMemoryScanStore();
  const provider = createFilesystemIntelligenceProvider({ datasetPath: options.datasetPath, logger: {
    info: () => undefined,
    warn: () => addReason('SCA intelligence includes invalid or unreadable advisory data.', true),
    error: () => addReason('SCA intelligence could not be loaded.', true),
  } });
  const engines: Record<CiScanner, ScanEngine> = {
    SAST: createSastEngine({ sources: sourceStore, dataset }),
    SECRETS: createSecretsEngine({ sources: sourceStore, dataset }),
    SCA: createScaEngine({ sources: sourceStore, dataset, provider }),
  };
  const reports: SecurityReport[] = [];
  const scaAssessmentStates = new Set<string>();
  let findings = 0;
  let advisoryMatches = 0;
  let thresholdHits = 0;
  for (const batch of sources.batches) {
    await sourceStore.replace({ ownerId: project.ownerId, projectId: project.id, files: batch });
    for (const scanner of selected) {
      const created = await scans.createScanWithQuota({ ownerId: project.ownerId, projectId: project.id, scanType: scanner, consume: async () => ({ ok: true }) });
      if (created.outcome !== 'created') throw new Error('Could not create the local scan.');
      const running = await scans.claimNextQueued();
      if (running === undefined) throw new Error('Could not claim the local scan.');
      const outcome = await engines[scanner].execute(running, { signal: AbortSignal.timeout(30_000) });
      if (outcome.kind !== 'completed') {
        await scans.failScan(running.id, outcome.failureCode, outcome.failureMessage);
        addReason(`${scanner} engine did not complete (${outcome.failureCode}).`, true);
        continue;
      }
      const completed = await scans.completeScan(running.id, outcome.resultSummary, outcome.findings, outcome.sca, outcome.dast);
      if (completed === undefined) { addReason(`${scanner} result failed validation.`, true); continue; }
      if (outcome.resultSummary.partial === true || outcome.resultSummary.truncated === true || outcome.resultSummary.astSupplement?.status === 'PARTIAL') {
        addReason(`${scanner} reported partial or truncated coverage.`);
      }
      if (scanner === 'SAST' && (outcome.resultSummary.filesSkipped ?? 0) > 0) addReason('SAST skipped one or more files in its bounded input.');
      if (outcome.sca !== undefined) {
        scaAssessmentStates.add(outcome.sca.summary.assessmentState);
        if (outcome.sca.summary.assessmentState !== 'ASSESSED') addReason('SCA dependency intelligence is NOT_ASSESSED for at least one snapshot.');
        if (outcome.sca.manifests.some((item) => item.status !== 'ANALYZED')) addReason('SCA could not fully analyze at least one manifest.');
        advisoryMatches += outcome.sca.advisories.length;
        thresholdHits += outcome.sca.advisories.filter((item) => rank(item.severity) >= rank(options.threshold)).length;
      }
      findings += outcome.findings?.length ?? 0;
      thresholdHits += outcome.findings?.filter((item) => rank(item.severity) >= rank(options.threshold)).length ?? 0;
      reports.push(buildSecurityReport(project, completed, new Date().toISOString()));
    }
  }
  const runs: unknown[] = [];
  const scannerRuns = new Map<ScanType, number>();
  for (const report of reports) {
    const index = (scannerRuns.get(report.scan.scanType) ?? 0) + 1;
    scannerRuns.set(report.scan.scanType, index);
    const category = `drobon-ci/${report.scan.scanType.toLowerCase()}/batch-${index}`;
    const rendered = JSON.parse(renderSecurityReportSarif(report)) as { runs: Array<Record<string, unknown>> };
    runs.push(...rendered.runs.map((run) => ({ ...run, automationDetails: { id: category } })));
    const advisory = advisoryRun(report);
    if (advisory !== undefined) runs.push({ ...advisory, automationDetails: { id: `${category}/advisories` } });
  }
  const incomplete = reasons.length > 0;
  const state = thresholdHits > 0 ? 'FINDINGS' : incomplete ? 'INCOMPLETE' : 'PASS';
  const exitCode: 0 | 1 | 2 = thresholdHits > 0 ? 1 : hardFailure || (incomplete && !options.allowIncomplete) ? 2 : 0;
  const summary: CiSummary = {
    status: state, scanners: selected, files: sources.batches.reduce((count, batch) => count + batch.length, 0),
    batches: sources.batches.length, findings, advisoryMatches, thresholdHits, incompleteReasons: reasons,
    omissions: sources.omitted, scaAssessmentStates: [...scaAssessmentStates],
  };
  const sarif = JSON.stringify({
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json', version: '2.1.0', runs,
  }, null, 2) + '\n';
  if (Buffer.byteLength(sarif, 'utf8') > 10 * 1024 * 1024) throw new RangeError('SARIF output exceeds the 10 MiB safety limit.');
  return { summary, sarif, exitCode };
}
