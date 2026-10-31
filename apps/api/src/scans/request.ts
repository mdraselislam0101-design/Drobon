import { ASSESSMENT_ID_PATTERN, engagementAllowsScan, type Assessment, type ScanType } from '@drobon/shared';
import type { ApiConfig } from '../config.js';
import { conflict, internal, notFound, projectArchived, unauthorized, validationError } from '../errors.js';
import type { UserRepository } from '../auth/repositories.js';
import type { AssessmentStore } from '../assessments/store.js';
import type { ProjectRecord } from '../projects/store.js';
import type { UsageService } from '../usage/service.js';
import type { SourceSnapshotStore } from './sources.js';
import type { AgentScanContext, AgentScanIntent, CreateScanOutcome, ScanStore } from './store.js';
import { createDastTargetPolicy, DastTargetError, normalizeDastTarget, type DastTargetPolicy } from './dast/target.js';
import { digestSource } from '../agent/snapshot.js';

export interface ScanRequestServiceOptions {
  config: ApiConfig;
  users: UserRepository;
  assessments: AssessmentStore;
  scans: ScanStore;
  sources: SourceSnapshotStore;
  usage: UsageService;
  dastTargetPolicy?: DastTargetPolicy;
  now?: () => number;
}

export interface ScanRequest {
  actorId: string;
  deviceHash?: string | undefined;
  project: ProjectRecord;
  scanType: ScanType;
  assessmentId?: string | undefined;
  dastMode?: string | undefined;
  dastActiveConsent?: boolean | undefined;
  /** Evaluated after scope preflight, preserving ordinary API validation order. */
  idempotencyKeyFromRequest?: (() => string | undefined) | undefined;
  /** Server-only: never taken from the HTTP scan body. */
  agent?: AgentScanIntent | undefined;
}

/**
 * The single scan-creation authority shared by ordinary requests and the
 * agent coordinator. It preserves the existing quota, ownership, target,
 * engagement and serialized creation gates; the agent is strictly stronger.
 */
export function createScanRequestService(options: ScanRequestServiceOptions) {
  const { config, users, assessments, scans, sources, usage } = options;
  const policy = options.dastTargetPolicy ?? createDastTargetPolicy();
  const at = (): string => new Date((options.now ?? Date.now)()).toISOString();
  return {
    request: async (input: ScanRequest): Promise<CreateScanOutcome> => {
      const { project, actorId, scanType, agent } = input;
      if (project.ownerId !== actorId) throw unauthorized();
      if (project.status === 'ARCHIVED') throw projectArchived();
      let assessmentId: string | undefined;
      let linkedAssessment: Assessment | undefined;
      if (input.assessmentId !== undefined) {
        if (!ASSESSMENT_ID_PATTERN.test(input.assessmentId)) throw notFound('Assessment not found.');
        const assessment = await assessments.findByProjectAndId(actorId, project.id, input.assessmentId);
        if (assessment === undefined) throw notFound('Assessment not found.');
        if (assessment.status !== 'ACTIVE') throw conflict('Only an active project assessment can be linked to a new scan.');
        assessmentId = assessment.id;
        linkedAssessment = assessment;
      }
      if (agent !== undefined && (config.agentExperimentalEnabled !== true || config.env === 'production')) {
        throw conflict('Experimental agent execution is disabled.');
      }
      if (agent !== undefined && assessmentId === undefined) throw conflict('Agent scans require an active assessment.');
      if ((input.dastMode !== undefined || input.dastActiveConsent !== undefined) && scanType !== 'DAST') {
        throw validationError([{ path: 'dastMode', message: 'dastMode only allowed for DAST scans.' }]);
      }
      if (input.dastMode !== undefined && input.dastMode !== 'PASSIVE' && input.dastMode !== 'ACTIVE_SAFE') {
        throw validationError([{ path: 'dastMode', message: 'dastMode must be PASSIVE or ACTIVE_SAFE.' }]);
      }
      const dastMode = input.dastMode;
      if (input.dastActiveConsent !== undefined && input.dastActiveConsent !== true) {
        throw validationError([{ path: 'dastActiveConsent', message: 'Active DAST requires explicit consent (true).' }]);
      }
      if (input.dastMode === 'ACTIVE_SAFE' && input.dastActiveConsent !== true) {
        throw validationError([{ path: 'dastActiveConsent', message: 'Active DAST requires dastActiveConsent: true.' }]);
      }
      if (agent !== undefined && (input.dastMode === 'ACTIVE_SAFE' || input.dastActiveConsent === true)) {
        throw conflict('The agent supports passive DAST only.');
      }
      let targetUrl: string | undefined;
      if (scanType === 'DAST') {
        if (project.dastTargetUrl === undefined) throw conflict('Configure a DAST target on this project before requesting a scan.');
        try { targetUrl = normalizeDastTarget(project.dastTargetUrl).url; }
        catch { throw conflict('The configured DAST target no longer passes the public-address safety policy.'); }
        if (assessmentId !== undefined) {
          const linked = await assessments.findByProjectAndId(actorId, project.id, assessmentId);
          const hostname = new URL(targetUrl).hostname.toLowerCase();
          if (linked === undefined || linked.status !== 'ACTIVE') throw conflict('The linked assessment is no longer active.');
          if (!linked.scope.inScopeHosts.includes(hostname) || linked.scope.outOfScopeHosts.includes(hostname)) {
            throw conflict('The DAST target host is not explicitly included in this assessment scope.');
          }
        }
      } else {
        const snapshot = await sources.findByProject(project.id);
        if (snapshot === undefined || snapshot.files.length === 0) {
          throw conflict(`Upload a source snapshot before requesting a ${scanType} scan.`);
        }
        if (agent !== undefined && (snapshot.ownerId !== actorId || digestSource(snapshot) !== agent.sourceDigest)) {
          throw conflict('The source snapshot changed before the agent scan was queued.');
        }
      }
      if (agent !== undefined && scanType === 'DAST') {
        const snapshot = await sources.findByProject(project.id);
        const currentDigest = snapshot === undefined ? undefined : digestSource(snapshot);
        if ((snapshot !== undefined && snapshot.ownerId !== actorId) || currentDigest !== agent.sourceDigest) {
          throw conflict('The source snapshot changed before the agent scan was queued.');
        }
      }
      const requireEngagement = agent !== undefined || (scanType === 'DAST' && config.dastRequireEngagement === true);
      const engagementRequiredMessage = agent === undefined
        ? 'DAST requires a linked active assessment with an active scoped engagement.'
        : 'This scan requires a linked active assessment with an active scoped engagement.';
      if (requireEngagement && (linkedAssessment?.engagements?.length ?? 0) === 0) {
        throw conflict(engagementRequiredMessage);
      }
      const gateFor = (assessment: Assessment, initial = false): { allowed: true; engagementId?: string } => {
        if (requireEngagement && (assessment.engagements?.length ?? 0) === 0) {
          throw conflict(engagementRequiredMessage);
        }
        const target = targetUrl === undefined ? undefined : new URL(targetUrl);
        if (target !== undefined && (!assessment.scope.inScopeHosts.includes(target.hostname.toLowerCase()) ||
            assessment.scope.outOfScopeHosts.includes(target.hostname.toLowerCase()))) {
          throw conflict('The DAST target host is not explicitly included in this assessment scope.');
        }
        const gate = engagementAllowsScan(assessment.engagements, {
          scanType, nowIso: at(),
          ...(target === undefined ? {} : { hostname: target.hostname.toLowerCase(), path: target.pathname || '/' }),
        });
        if (!gate.allowed) throw conflict(`Authorization gate: ${gate.reason}${initial ? ' Declare an active engagement for this target, scope and scan type first.' : ''}`);
        return gate;
      };
      if (linkedAssessment !== undefined) gateFor(linkedAssessment, true);
      const idempotencyKey = input.idempotencyKeyFromRequest?.();
      if (targetUrl !== undefined) {
        try {
          const prepared = await policy.prepare(targetUrl);
          if (prepared.url !== targetUrl) throw new DastTargetError('DAST_TARGET_INVALID');
        } catch (error) {
          const message = error instanceof DastTargetError && error.code === 'DAST_DNS_FAILED'
            ? 'The configured DAST target cannot currently be resolved safely.'
            : 'The configured DAST target no longer passes the public-address safety policy.';
          throw conflict(message);
        }
      }
      if (input.deviceHash === undefined) throw internal('Device identity missing for an authenticated request.');
      const user = await users.findById(actorId);
      if (user === undefined) throw unauthorized();
      const deviceHash = input.deviceHash;
      const create = (boundAgent?: AgentScanContext): Promise<CreateScanOutcome> => scans.createScanWithQuota({
        ownerId: actorId, projectId: project.id, scanType,
        ...(assessmentId === undefined ? {} : { assessmentId }),
        ...(targetUrl === undefined ? {} : { targetUrl }),
        ...(dastMode === undefined ? {} : { dastMode }),
        ...(input.dastActiveConsent === undefined ? {} : { dastActiveConsent: input.dastActiveConsent }),
        ...(idempotencyKey === undefined ? {} : { idempotencyKey }),
        ...(boundAgent === undefined ? {} : { agent: boundAgent }),
        consume: (scanId) => usage.reserveScan(user, deviceHash, project.id, scanId),
      });
      if (assessmentId === undefined) return create();
      const gated = await assessments.withActiveAssessment(actorId, project.id, assessmentId, async (current) => {
        const authorization = gateFor(current); // linearized with withdrawal/cancellation
        if (agent !== undefined) {
          if (authorization.engagementId === undefined) throw conflict('Agent scans require an explicitly authorized engagement.');
          // One agent attempt per scanner and assessment, durable across
          // restarts and independent of the bounded idempotency-key cache.
          const priorScans = (await scans.listByProject(project.id)).filter((scan) => scan.ownerId === actorId &&
            scan.assessmentId === assessmentId && scan.agent !== undefined);
          if (priorScans.some((scan) => scan.agent?.datasetDigest !== agent.datasetDigest ||
              scan.agent?.sourceDigest !== agent.sourceDigest)) return { outcome: 'conflict' as const };
          const prior = priorScans.find((scan) => scan.scanType === scanType);
          if (prior !== undefined) return { outcome: 'replayed' as const, scan: prior };
          // Bind to this exact declaration. A later different engagement
          // must not silently reauthorize a withdrawn job.
          return create({ ...agent, engagementId: authorization.engagementId });
        }
        return create();
      });
      if (gated.outcome === 'not-found') throw notFound('Assessment not found.');
      if (gated.outcome === 'inactive') throw conflict('Only an active project assessment can be linked to a new scan.');
      return gated.value;
    },
  };
}

export type ScanRequestService = ReturnType<typeof createScanRequestService>;
