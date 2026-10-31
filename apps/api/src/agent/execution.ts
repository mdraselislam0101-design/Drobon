import { engagementAllowsScan, type ScanType } from '@drobon/shared';
import type { AssessmentStore } from '../assessments/store.js';
import type { ProjectStore } from '../projects/store.js';
import type { SourceSnapshotStore } from '../scans/sources.js';
import type { ScanRecord, ScanStore } from '../scans/store.js';
import type { EngineOutcome, ScanEngineContext } from '../scans/engines.js';
import { createSastEngine } from '../scans/sast/engine.js';
import { createSecretsEngine } from '../scans/secrets/engine.js';
import { createScaEngine } from '../scans/sca/engine.js';
import { createDastEngine } from '../scans/dast/engine.js';
import { createAssessmentDastAuthorizer } from '../scans/dast/authorization.js';
import type { DastTargetPolicy } from '../scans/dast/target.js';
import { createNodeDastTransport, DastHttpError, runBoundedDastProbe, type DastTransport } from '../scans/dast/http.js';
import { createFilesystemIntelligenceProvider } from '../scans/sca/filesystemProvider.js';
import { createDatasetService } from '../external/service.js';
import { createAdvisoryService } from '../external/advisory.js';
import { digestDataset, digestSource } from './snapshot.js';

export interface AgentExecutorOptions {
  executionEnabled: boolean;
  datasetPath?: string | undefined;
  providerId: string;
  advisoryPath?: string | undefined;
  projects: ProjectStore;
  assessments: AssessmentStore;
  scans: ScanStore;
  sources: SourceSnapshotStore;
  targetPolicy: DastTargetPolicy;
  transport?: DastTransport | undefined;
  now?: () => number;
}

function failure(message: string): EngineOutcome {
  return { kind: 'failed', failureCode: 'SCAN_ENGINE_ERROR', failureMessage: message };
}

/**
 * The agent always requires an active, scoped engagement, even when the
 * existing legacy scan API runs in compatibility mode. The attestation is
 * not independent legal verification.
 */
export async function agentAuthorizationIssue(
  record: ScanRecord,
  options: Pick<AgentExecutorOptions, 'projects' | 'assessments' | 'sources' | 'now'>,
): Promise<string | undefined> {
  if (record.agent === undefined || record.assessmentId === undefined) return 'Agent assessment context is missing.';
  if (record.agent.cancelRequestedAt !== undefined) return 'Agent cancellation was requested.';
  const project = await options.projects.findById(record.projectId);
  if (project === undefined || project.ownerId !== record.ownerId || project.status !== 'ACTIVE') return 'The project is no longer active.';
  const assessment = await options.assessments.findByProjectAndId(record.ownerId, record.projectId, record.assessmentId);
  if (assessment === undefined || assessment.status !== 'ACTIVE' || (assessment.engagements?.length ?? 0) === 0) {
    return 'An active assessment and scoped engagement are required.';
  }
  let target: URL | undefined;
  if (record.scanType === 'DAST') {
    if (record.dastTargetUrl === undefined || project.dastTargetUrl !== record.dastTargetUrl || record.dastMode === 'ACTIVE_SAFE') {
      return 'The passive DAST target has changed or is unavailable.';
    }
    try { target = new URL(record.dastTargetUrl); } catch { return 'The DAST target is invalid.'; }
    const hostname = target.hostname.toLowerCase();
    if (!assessment.scope.inScopeHosts.includes(hostname) || assessment.scope.outOfScopeHosts.includes(hostname)) {
      return 'The DAST target is outside the assessment scope.';
    }
  }
  const snapshot = await options.sources.findByProject(record.projectId);
  const sourceDigest = snapshot === undefined ? undefined : digestSource(snapshot);
  if ((snapshot !== undefined && snapshot.ownerId !== record.ownerId) || sourceDigest !== record.agent.sourceDigest ||
      (record.scanType !== 'DAST' && sourceDigest === undefined)) return 'The source snapshot changed or is unavailable.';
  const engagement = assessment.engagements?.find((item) => item.id === record.agent?.engagementId);
  if (engagement === undefined) return 'The original agent engagement is unavailable.';
  const gate = engagementAllowsScan([engagement], {
    scanType: record.scanType,
    nowIso: new Date((options.now ?? Date.now)()).toISOString(),
    ...(target === undefined ? {} : { hostname: target.hostname.toLowerCase(), path: target.pathname || '/' }),
  });
  return gate.allowed ? undefined : 'The current engagement does not authorize this scan.';
}

/** Commit a result while holding the lock used to withdraw its engagement. */
export async function finalizeAuthorizedAgentScan(
  assessments: AssessmentStore,
  now: () => number,
  record: ScanRecord,
  complete: () => Promise<ScanRecord | undefined>,
): Promise<ScanRecord | undefined> {
  if (record.agent === undefined || record.assessmentId === undefined) return undefined;
  const agent = record.agent;
  const result = await assessments.withActiveAssessment(record.ownerId, record.projectId, record.assessmentId, async (assessment) => {
    const engagement = assessment.engagements?.find((item) => item.id === agent.engagementId);
    if (engagement === undefined) return undefined;
    const target = record.scanType === 'DAST' && record.dastTargetUrl !== undefined ? new URL(record.dastTargetUrl) : undefined;
    if (target !== undefined && (!assessment.scope.inScopeHosts.includes(target.hostname.toLowerCase()) ||
        assessment.scope.outOfScopeHosts.includes(target.hostname.toLowerCase()))) return undefined;
    const gate = engagementAllowsScan([engagement], { scanType: record.scanType, nowIso: new Date(now()).toISOString(),
      ...(target === undefined ? {} : { hostname: target.hostname.toLowerCase(), path: target.pathname || '/' }) });
    return gate.allowed ? complete() : undefined;
  });
  return result.outcome === 'ready' ? result.value : undefined;
}

function packKey(scanType: ScanType): 'sastPacks' | 'secretsPacks' | 'scaPacks' | 'dastPacks' {
  switch (scanType) {
    case 'SAST': return 'sastPacks';
    case 'SECRETS': return 'secretsPacks';
    case 'SCA': return 'scaPacks';
    case 'DAST': return 'dastPacks';
  }
}

/**
 * Execute only the existing scanner implementations, using a fresh Dataset
 * loader and (for SCA) fresh intelligence provider for every agent job.
 * The queued, pre-load, post-load and post-execution fingerprints must agree.
 * This does not turn a mutable filesystem into an atomic or signed snapshot.
 */
export function createAgentExecutor(options: AgentExecutorOptions) {
  const clock = options.now ?? Date.now;
  const authorizeDast = createAssessmentDastAuthorizer(options.assessments, clock, { requireEngagement: true });
  return {
    execute: async (record: ScanRecord, context: ScanEngineContext): Promise<EngineOutcome> => {
      const agent = record.agent;
      if (agent === undefined) return failure('Agent execution context is missing.');
      if (!options.executionEnabled) return failure('Experimental agent execution is disabled.');
      try {
        const issue = await agentAuthorizationIssue(record, options);
        if (issue !== undefined) return failure(issue);
        if (options.providerId !== 'filesystem' || options.datasetPath === undefined ||
            await digestDataset(options.datasetPath, context.signal) !== agent.datasetDigest) {
          return failure('The Dataset changed or is unavailable; the agent did not run the scanner.');
        }
        const dataset = createDatasetService({ providerId: 'filesystem', datasetPath: options.datasetPath });
        const status = await dataset.status();
        const category = status[packKey(record.scanType)];
        if (category.status !== 'AVAILABLE' || category.incomplete === true ||
            await digestDataset(options.datasetPath, context.signal) !== agent.datasetDigest) {
          return failure('The required Dataset rules are incomplete, changed or unavailable.');
        }
        const preExecutionIssue = await agentAuthorizationIssue(record, options);
        if (preExecutionIssue !== undefined) return failure(preExecutionIssue);
        const underlyingTransport = options.transport ?? createNodeDastTransport();
        const datasetPath = options.datasetPath;
        // This final guard runs immediately before each actual socket probe,
        // including redirects. It cannot recall an already in-flight request
        // or make a mutable filesystem atomic; the post-check still discards
        // results when the context changes.
        const guardedTransport: DastTransport = { probe: async (target, probeOptions) => {
          let allowed = false;
          try {
            allowed = !probeOptions.signal.aborted && !context.signal.aborted &&
              await digestDataset(datasetPath, context.signal) === agent.datasetDigest &&
              await agentAuthorizationIssue(record, options) === undefined &&
              await authorizeDast(record, target.url) && !probeOptions.signal.aborted && !context.signal.aborted;
          } catch { /* fail closed without leaking filesystem details */ }
          if (!allowed || record.assessmentId === undefined) throw new DastHttpError('aborted');
          const assessmentId = record.assessmentId;
          // Linearize the actual probe *start* with engagement withdrawal
          // and persisted cancellation. Hold both queues only until the
          // transport returns its promise; never wait for network I/O while
          // holding either lock. The order is assessment -> scan everywhere.
          const started = await options.assessments.withActiveAssessment(record.ownerId, record.projectId, assessmentId, async (assessment) => {
            const engagement = assessment.engagements?.find((item) => item.id === agent.engagementId);
            const url = new URL(target.url);
            const hostname = url.hostname.toLowerCase();
            if (engagement === undefined || !assessment.scope.inScopeHosts.includes(hostname) ||
                assessment.scope.outOfScopeHosts.includes(hostname) ||
                !engagementAllowsScan([engagement], { scanType: 'DAST', hostname, path: url.pathname || '/', nowIso: new Date(clock()).toISOString() }).allowed) return undefined;
            return options.scans.beginAgentProbe({ ownerId: record.ownerId, projectId: record.projectId,
              assessmentId, scanId: record.id, engagementId: agent.engagementId }, () => {
              if (probeOptions.signal.aborted || context.signal.aborted) throw new DastHttpError('aborted');
              return runBoundedDastProbe(underlyingTransport, target, probeOptions);
            });
          });
          if (started.outcome !== 'ready' || started.value === undefined) throw new DastHttpError('aborted');
          const response = await started.value.value;
          // A custom/uncooperative transport can finish after abort; discard
          // that response rather than following its redirect or saving it.
          if (probeOptions.signal.aborted || context.signal.aborted) throw new DastHttpError('aborted');
          return response;
        } };
        // Separate, newly loaded local advisory data is never an external AI
        // service. It is not part of the Dataset digest and is not signed.
        const advisory = createAdvisoryService(options.advisoryPath === undefined ? {} : { path: options.advisoryPath });
        const engine = record.scanType === 'SAST' ? createSastEngine({ sources: options.sources, dataset })
          : record.scanType === 'SECRETS' ? createSecretsEngine({ sources: options.sources, dataset })
          : record.scanType === 'SCA' ? createScaEngine({ sources: options.sources, dataset,
              provider: createFilesystemIntelligenceProvider({ datasetPath: options.datasetPath }), advisory })
          : createDastEngine({ targetPolicy: options.targetPolicy, dataset, advisory,
              authorize: async (current, url) => {
                // Scope and engagement are checked before each actual request.
                const project = await options.projects.findById(current.projectId);
                return project?.ownerId === current.ownerId && project.status === 'ACTIVE' &&
                  project.dastTargetUrl === current.dastTargetUrl && await authorizeDast(current, url);
              },
              transport: guardedTransport });
        if (context.signal.aborted) return failure('Agent execution was cancelled before the scanner started.');
        const outcome = await engine.execute(record, context);
        const afterIssue = await agentAuthorizationIssue(record, options);
        if (afterIssue !== undefined) return failure(afterIssue);
        if (await digestDataset(options.datasetPath, context.signal) !== agent.datasetDigest) {
          return failure('The Dataset changed during the scan; its result was not recorded.');
        }
        if (context.signal.aborted) return failure('Agent execution was cancelled; its result was not recorded.');
        return outcome;
      } catch {
        // Never expose paths, raw source, rule text or filesystem errors.
        return failure('Agent safety checks could not verify current authorization and Dataset availability.');
      }
    },
  };
}
