import {
  ASSESSMENT_ID_PATTERN, SCAN_ID_PATTERN, type AgentAssessment, type AgentCancellationResponse, type AgentExecutionResponse, type ScanType,
} from '@drobon/shared';
import type { ApiConfig } from '../config.js';
import { conflict, isAppError, notFound, unauthorized, validationError } from '../errors.js';
import type { Route } from '../http.js';
import { readJsonBody } from '../lib/body.js';
import * as v from '../lib/validate.js';
import { sendSuccess } from '../respond.js';
import type { UserRepository } from '../auth/repositories.js';
import type { AssessmentStore } from '../assessments/store.js';
import { createOwnProjectResolver } from '../projects/access.js';
import type { ProjectRecord, ProjectStore } from '../projects/store.js';
import type { SourceSnapshotStore } from '../scans/sources.js';
import type { ScanStore } from '../scans/store.js';
import type { ScanProcessor } from '../scans/processor.js';
import type { ScanRequestService } from '../scans/request.js';
import type { UsageService } from '../usage/service.js';
import { createDatasetService } from '../external/service.js';
import { buildAgentAssessment } from '../agent/assessment.js';
import { digestDataset, digestSource } from '../agent/snapshot.js';

export interface AgentRouteDeps {
  config: ApiConfig;
  users: UserRepository;
  projects: ProjectStore;
  assessments: AssessmentStore;
  scans: ScanStore;
  sources: SourceSnapshotStore;
  usage: UsageService;
  processor: ScanProcessor;
  requestService: ScanRequestService;
  now?: () => number;
}

const PACK_KEYS: Record<ScanType, 'sastPacks' | 'secretsPacks' | 'scaPacks' | 'dastPacks'> = {
  SAST: 'sastPacks', SECRETS: 'secretsPacks', SCA: 'scaPacks', DAST: 'dastPacks',
};

export function createAgentRoutes(deps: AgentRouteDeps): Route[] {
  const { config, users, projects, assessments, scans, sources, usage, processor, requestService } = deps;
  const access = createOwnProjectResolver(projects);
  const now = deps.now ?? Date.now;
  const confirmSchema = v.object({ confirm: v.boolean() });
  const owned = async (projectId: unknown, assessmentId: unknown, actorId: string) => {
    const project = await access.ownProjectOr403(projectId, actorId);
    if (typeof assessmentId !== 'string' || !ASSESSMENT_ID_PATTERN.test(assessmentId)) throw notFound('Assessment not found.');
    const assessment = await assessments.findByProjectAndId(actorId, project.id, assessmentId);
    if (assessment === undefined) throw notFound('Assessment not found.');
    return { project, assessment };
  };
  const build = async (project: ProjectRecord, assessmentId: string, actorId: string, deviceHash: string | undefined): Promise<AgentAssessment> => {
    const assessment = await assessments.findByProjectAndId(actorId, project.id, assessmentId);
    if (assessment === undefined) throw notFound('Assessment not found.');
    const user = await users.findById(actorId);
    if (user === undefined) throw unauthorized();
    if (deviceHash === undefined) throw conflict('A device session is required to evaluate scan allowance.');
    const [snapshot, records] = await Promise.all([sources.findByProject(project.id), scans.listByProject(project.id)]);
    return buildAgentAssessment({ project, assessment, snapshot, scans: records,
      executionEnabled: config.agentExperimentalEnabled === true && config.env !== 'production',
      agentStorageReady: scans.agentStorageReady(),
      datasetConfigured: config.vulnIntelProvider === 'filesystem' && config.datasetPath !== undefined,
      quotaExhausted: usage.getUsageView(user, deviceHash).quotaStatus === 'EXHAUSTED', now: new Date(now()).toISOString() });
  };
  return [
    {
      method: 'GET', path: '/api/v1/projects/:projectId/assessments/:assessmentId/agent', requireAuth: true,
      handler: async (req, res, ctx): Promise<void> => {
        v.rejectUnexpectedQuery(req);
        if (ctx.user === undefined) throw unauthorized();
        const { project, assessment } = await owned(ctx.params['projectId'], ctx.params['assessmentId'], ctx.user.id);
        sendSuccess(res, ctx, { agent: await build(project, assessment.id, ctx.user.id, ctx.deviceHash) });
      },
    },
    {
      method: 'POST', path: '/api/v1/projects/:projectId/assessments/:assessmentId/agent/scans/:scanId/cancel', requireAuth: true,
      handler: async (req, res, ctx): Promise<void> => {
        v.rejectUnexpectedQuery(req);
        if (ctx.user === undefined) throw unauthorized();
        const actorId = ctx.user.id;
        const { project, assessment } = await owned(ctx.params['projectId'], ctx.params['assessmentId'], actorId);
        const scanId = ctx.params['scanId'];
        if (scanId === undefined || !SCAN_ID_PATTERN.test(scanId)) throw notFound('Agent scan not found.');
        const parsed = confirmSchema.parse(await readJsonBody(req, { maxBytes: Math.min(config.bodyMaxBytes, 1024) }));
        if (!parsed.ok) throw validationError(parsed.issues);
        if (parsed.value.confirm !== true) throw validationError([{ path: 'confirm', message: 'Explicit cancellation confirmation is required.' }]);
        const result = await scans.requestAgentCancellation({ ownerId: actorId, projectId: project.id, assessmentId: assessment.id, scanId });
        if (result.outcome === 'not-found') throw notFound('Agent scan not found.');
        if (result.outcome === 'terminal') throw conflict('The agent job has already finished; cancellation was not applied.');
        // Commit intent before signal/acknowledgement. This remains available
        // even if new Agent execution is disabled, as a safety operation.
        processor.abortAgentJob(scanId);
        processor.kick();
        const state = result.scan.status === 'QUEUED' || result.scan.status === 'RUNNING' ? 'CANCELLING' : 'CANCELLED';
        const response: AgentCancellationResponse = { scanId, state };
        sendSuccess(res, ctx, response, state === 'CANCELLING' ? 202 : 200);
      },
    },
    {
      method: 'POST', path: '/api/v1/projects/:projectId/assessments/:assessmentId/agent/execute', requireAuth: true,
      handler: async (req, res, ctx): Promise<void> => {
        v.rejectUnexpectedQuery(req);
        if (ctx.user === undefined) throw unauthorized();
        const actorId = ctx.user.id;
        const { project, assessment } = await owned(ctx.params['projectId'], ctx.params['assessmentId'], actorId);
        const raw = await readJsonBody(req, { maxBytes: Math.min(config.bodyMaxBytes, 2048) });
        const parsed = confirmSchema.parse(raw);
        if (!parsed.ok) throw validationError(parsed.issues);
        if (parsed.value.confirm !== true) throw validationError([{ path: 'confirm', message: 'Explicit confirmation is required.' }]);
        const plan = await build(project, assessment.id, actorId, ctx.deviceHash);
        const candidates = plan.tasks.filter((task) => task.state === 'READY');
        if (candidates.length === 0) {
          const actions: AgentExecutionResponse['actions'] = plan.tasks.map((task) => ({ scanner: task.scanner,
            result: task.scanId === undefined ? 'BLOCKED' : 'EXISTING', reason: task.reason }));
          sendSuccess(res, ctx, { agent: plan, actions } satisfies AgentExecutionResponse);
          return;
        }
        const initialSource = await sources.findByProject(project.id);
        if (initialSource !== undefined && initialSource.ownerId !== actorId) throw conflict('The source snapshot owner is inconsistent.');
        const initialSourceDigest = initialSource === undefined ? undefined : digestSource(initialSource);
        // Read and validate the separately configured Dataset without writing
        // it. Nothing is queued or charged if the source is unavailable or
        // changes while the fresh service loads.
        let datasetDigest: string;
        let datasetStatus: Awaited<ReturnType<ReturnType<typeof createDatasetService>['status']>>;
        try {
          if (config.vulnIntelProvider !== 'filesystem' || config.datasetPath === undefined) throw new Error('not configured');
          datasetDigest = await digestDataset(config.datasetPath);
          datasetStatus = await createDatasetService({ providerId: 'filesystem', datasetPath: config.datasetPath }).status();
          if (await digestDataset(config.datasetPath) !== datasetDigest) throw new Error('changed');
        } catch {
          throw conflict('The Dataset is unavailable or changed during agent preflight; no new scan was queued.');
        }
        const snapshot = await sources.findByProject(project.id);
        if (snapshot !== undefined && snapshot.ownerId !== actorId) throw conflict('The source snapshot owner is inconsistent.');
        const sourceDigest = snapshot === undefined ? undefined : digestSource(snapshot);
        if (sourceDigest !== initialSourceDigest) throw conflict('The source snapshot changed during preflight; no new scan was queued.');
        const actions: AgentExecutionResponse['actions'] = [];
        let uncertain = false;
        for (const task of candidates) {
          if (uncertain) {
            actions.push({ scanner: task.scanner, result: 'BLOCKED', reason: 'Not attempted because an earlier queue operation has an uncertain outcome.' });
            continue;
          }
          const category = datasetStatus[PACK_KEYS[task.scanner]];
          if (category.status !== 'AVAILABLE' || category.incomplete === true) {
            actions.push({ scanner: task.scanner, result: 'BLOCKED', reason: 'Required Dataset rules are unavailable or incomplete.' });
            continue;
          }
          try {
            const currentProject = await projects.findById(project.id);
            if (currentProject === undefined || currentProject.ownerId !== actorId || currentProject.status !== 'ACTIVE') {
              throw conflict('The project is no longer active.');
            }
            const outcome = await requestService.request({ actorId, deviceHash: ctx.deviceHash, project: currentProject,
              scanType: task.scanner, assessmentId: assessment.id,
              ...(task.scanner === 'DAST' ? { dastMode: 'PASSIVE' as const } : {}),
              agent: { version: 1, datasetDigest, ...(sourceDigest === undefined ? {} : { sourceDigest }) } });
            if (outcome.outcome === 'created') {
              actions.push({ scanner: task.scanner, result: 'CREATED', reason: 'Queued through the existing quota and scan store.' });
              processor.kick();
              if (outcome.quotaCommitPending === true) ctx.logger.error('Agent scan quota reservation needs startup reconciliation', { scanId: outcome.scan.id, projectId: project.id });
            } else if (outcome.outcome === 'replayed') {
              actions.push({ scanner: task.scanner, result: 'EXISTING', reason: 'The assessment already has an agent attempt for this scanner.' });
            } else {
              const reason = outcome.outcome === 'quota-denied' ? 'The current scan allowance is exhausted.'
                : outcome.outcome === 'conflict' ? 'The agent context changed; create a new assessment for a new snapshot.'
                : outcome.outcome === 'compatibility-required' ? 'The version-1 scan store requires reviewed offline compatibility migration; no job was queued.'
                : 'The scan target or agent context is invalid.';
              actions.push({ scanner: task.scanner, result: 'BLOCKED', reason });
            }
          } catch (error) {
            if (isAppError(error) && error.statusCode < 500) {
              actions.push({ scanner: task.scanner, result: 'BLOCKED', reason: 'Authorization, scope or source changed before this scan could be queued.' });
            } else {
              // A failed storage/quota write may be ambiguous. Do not call it
              // blocked or success, and do not attempt additional jobs.
              ctx.logger.error('Agent queue outcome uncertain', { projectId: project.id, assessmentId: assessment.id, scanner: task.scanner });
              actions.push({ scanner: task.scanner, result: 'INCONCLUSIVE', reason: 'Queue outcome is uncertain; inspect saved jobs and quota, and resolve the service error before retrying.' });
              uncertain = true;
            }
          }
        }
        const latest = await projects.findById(project.id);
        if (latest === undefined || latest.ownerId !== actorId) throw conflict('The project became unavailable.');
        const agent = await build(latest, assessment.id, actorId, ctx.deviceHash);
        sendSuccess(res, ctx, { agent, actions } satisfies AgentExecutionResponse);
      },
    },
  ];
}
