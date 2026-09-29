import type { IncomingMessage } from 'node:http';
import {
  ASSESSMENT_HOSTS_MAX_COUNT,
  ASSESSMENT_ID_PATTERN,
  ASSESSMENT_OBJECTIVES_MAX_COUNT,
  ASSESSMENT_OBJECTIVE_MAX_LENGTH,
  ASSESSMENT_SCOPE_NOTES_MAX_LENGTH,
  ASSESSMENT_TITLE_MAX_LENGTH,
  isAssessmentHostname,
  isAssessmentScope,
  isAssessmentStatus,
  isSafeDastUrl,
  type Assessment,
  type AssessmentDetailResponse,
  type AssessmentProgress,
  type AssessmentResponse,
  type AssessmentStatus,
  type AssessmentScanSummary,
  type AssessmentsResponse,
} from '@drobon/shared';
import type { ApiConfig } from '../config.js';
import { badRequest, conflict, internal, notFound, projectArchived, unauthorized, validationError } from '../errors.js';
import type { Route } from '../http.js';
import { readJsonBody } from '../lib/body.js';
import * as v from '../lib/validate.js';
import type { ProjectStore } from '../projects/store.js';
import { createOwnProjectResolver } from '../projects/access.js';
import type { AssessmentStore } from '../assessments/store.js';
import type { ScanRecord, ScanStore } from '../scans/store.js';
import { sendSuccess } from '../respond.js';

export interface AssessmentRouteDeps {
  config: ApiConfig;
  projects: ProjectStore;
  assessments: AssessmentStore;
  scans: ScanStore;
  now?: () => number;
}

function rejectUnknownQuery(req: IncomingMessage): void {
  const raw = req.url ?? '/';
  let url: URL;
  try { url = new URL(raw, 'http://drobon.invalid'); }
  catch { throw badRequest('Assessment request URL is invalid.'); }
  if ([...url.searchParams.keys()].length > 0) throw badRequest('Assessment routes do not accept query parameters.');
}

function normalizeText(value: string): string { return value.normalize('NFC'); }

function parseScope(raw: unknown): { ok: true; value: Assessment['scope'] } | { ok: false } {
  const scopeShape = v.object({
    inScopeHosts: v.array(v.string({ minLength: 1, maxLength: 253, trim: true }), { maxLength: ASSESSMENT_HOSTS_MAX_COUNT }),
    outOfScopeHosts: v.array(v.string({ minLength: 1, maxLength: 253, trim: true }), { maxLength: ASSESSMENT_HOSTS_MAX_COUNT }),
    notes: v.optional(v.string({ maxLength: ASSESSMENT_SCOPE_NOTES_MAX_LENGTH, trim: true })),
  });
  const parsed = scopeShape.parse(raw, 'scope');
  if (!parsed.ok) return { ok: false };
  const value: Assessment['scope'] = {
    inScopeHosts: parsed.value.inScopeHosts.map((host) => host.normalize('NFC').toLowerCase()),
    outOfScopeHosts: parsed.value.outOfScopeHosts.map((host) => host.normalize('NFC').toLowerCase()),
    ...(parsed.value.notes === undefined || parsed.value.notes.length === 0 ? {} : { notes: normalizeText(parsed.value.notes) }),
  };
  return isAssessmentScope(value) ? { ok: true, value } : { ok: false };
}

function parseDetails(raw: unknown): { ok: true; title: string; objectives: string[]; scope: Assessment['scope'] } | { ok: false; issues: { path: string; message: string }[] } {
  const shape = v.object({
    title: v.string({ minLength: 3, maxLength: ASSESSMENT_TITLE_MAX_LENGTH, trim: true }),
    objectives: v.array(v.string({ minLength: 3, maxLength: ASSESSMENT_OBJECTIVE_MAX_LENGTH, trim: true }), { minLength: 1, maxLength: ASSESSMENT_OBJECTIVES_MAX_COUNT }),
    scope: v.object({
      inScopeHosts: v.array(v.string({ minLength: 1, maxLength: 253, trim: true }), { maxLength: ASSESSMENT_HOSTS_MAX_COUNT }),
      outOfScopeHosts: v.array(v.string({ minLength: 1, maxLength: 253, trim: true }), { maxLength: ASSESSMENT_HOSTS_MAX_COUNT }),
      notes: v.optional(v.string({ maxLength: ASSESSMENT_SCOPE_NOTES_MAX_LENGTH, trim: true })),
    }),
  });
  const parsed = shape.parse(raw);
  if (!parsed.ok) return parsed;
  const scope = parseScope(parsed.value.scope);
  if (!scope.ok) return { ok: false, issues: [{ path: 'scope', message: 'Scope must contain unique, lowercase DNS hostnames, without overlap; IP literals and wildcard hosts are not accepted.' }] };
  const title = normalizeText(parsed.value.title);
  const objectives = parsed.value.objectives.map(normalizeText);
  if (title.trim().length < 3 || objectives.some((item) => item.trim().length < 3)) return { ok: false, issues: [{ path: 'objectives', message: 'Title and objectives must contain meaningful text.' }] };
  return { ok: true, title, objectives, scope: scope.value };
}

function targetHostInScope(assessment: Assessment, targetUrl: string): boolean {
  if (!isSafeDastUrl(targetUrl)) return false;
  const host = new URL(targetUrl).hostname.toLowerCase();
  return isAssessmentHostname(host) && assessment.scope.inScopeHosts.includes(host) && !assessment.scope.outOfScopeHosts.includes(host);
}

function progressFor(records: ScanRecord[], ownerId: string, projectId: string, assessmentId: string): { scans: ScanRecord[]; progress: Omit<AssessmentProgress, 'recentScans'> } {
  const scans = records.filter((scan) => scan.ownerId === ownerId && scan.projectId === projectId && scan.assessmentId === assessmentId);
  const completed = scans.filter((scan) => scan.status === 'COMPLETED');
  const failed = scans.filter((scan) => scan.status === 'FAILED' || scan.status === 'TIMED_OUT');
  const active = scans.filter((scan) => scan.status === 'QUEUED' || scan.status === 'RUNNING');
  return { scans, progress: {
    totalScans: scans.length,
    completedScans: completed.length,
    failedScans: failed.length,
    activeScans: active.length,
    findingsTotal: completed.reduce((total, scan) => total + (scan.resultSummary?.findingsTotal ?? 0), 0),
  } };
}

function assessmentIdFrom(raw: unknown): string {
  if (typeof raw !== 'string' || raw.length > 64 || !ASSESSMENT_ID_PATTERN.test(raw)) throw notFound('Assessment not found.');
  return raw;
}

export function createAssessmentRoutes(deps: AssessmentRouteDeps): Route[] {
  const { config, projects, assessments, scans } = deps;
  const access = createOwnProjectResolver(projects);
  const now = deps.now ?? Date.now;
  const at = (): string => new Date(now()).toISOString();
  const ownedAssessment = async (rawProjectId: unknown, rawAssessmentId: unknown, ownerId: string): Promise<{ project: Awaited<ReturnType<typeof access.ownProjectOr403>>; assessment: Assessment }> => {
    const project = await access.ownProjectOr403(rawProjectId, ownerId);
    const assessmentId = assessmentIdFrom(rawAssessmentId);
    const assessment = await assessments.findByProjectAndId(ownerId, project.id, assessmentId);
    if (assessment === undefined) throw notFound('Assessment not found.');
    return { project, assessment };
  };
  const statusSchema = v.object({ status: v.string({ maxLength: 16, trim: true }) });
  const authorizationSchema = v.object({ action: v.string({ maxLength: 16, trim: true }), confirm: v.boolean() });

  return [
    {
      method: 'GET', path: '/api/v1/projects/:projectId/assessments', requireAuth: true,
      handler: async (req, res, ctx): Promise<void> => {
        rejectUnknownQuery(req);
        const actor = ctx.user;
        if (actor === undefined) throw unauthorized();
        const project = await access.ownProjectOr403(ctx.params['projectId'], actor.id);
        const response: AssessmentsResponse = { assessments: await assessments.listByProject(actor.id, project.id) };
        sendSuccess(res, ctx, response);
      },
    },
    {
      method: 'POST', path: '/api/v1/projects/:projectId/assessments', requireAuth: true,
      handler: async (req, res, ctx): Promise<void> => {
        const actor = ctx.user;
        if (actor === undefined) throw unauthorized();
        const project = await access.ownProjectOr403(ctx.params['projectId'], actor.id);
        if (project.status === 'ARCHIVED') throw projectArchived();
        rejectUnknownQuery(req);
        const raw = await readJsonBody(req, { maxBytes: Math.min(config.bodyMaxBytes, 16_384) });
        const parsed = parseDetails(raw);
        if (!parsed.ok) throw validationError(parsed.issues);
        const result = await assessments.create({ ownerId: actor.id, projectId: project.id, ...parsed, now: at() });
        if ('outcome' in result) throw conflict('Assessment capacity has been reached for this project.');
        const response: AssessmentResponse = { assessment: result };
        sendSuccess(res, ctx, response, 201);
      },
    },
    {
      method: 'GET', path: '/api/v1/projects/:projectId/assessments/:assessmentId', requireAuth: true,
      handler: async (req, res, ctx): Promise<void> => {
        rejectUnknownQuery(req);
        const actor = ctx.user;
        if (actor === undefined) throw unauthorized();
        const { project, assessment } = await ownedAssessment(ctx.params['projectId'], ctx.params['assessmentId'], actor.id);
        const records = await scans.listByProject(project.id);
        const summary = progressFor(records, actor.id, project.id, assessment.id);
        const recentScans: AssessmentScanSummary[] = await Promise.all(summary.scans.slice(0, 20).map(async (scan) => ({
          id: scan.id, scanType: scan.scanType, status: scan.status, createdAt: scan.createdAt,
          ...(scan.completedAt === undefined ? {} : { completedAt: scan.completedAt }),
          ...(scan.dastTargetUrl === undefined ? {} : { targetUrl: scan.dastTargetUrl }),
          ...(scan.resultSummary === undefined ? {} : { findingsTotal: scan.resultSummary.findingsTotal }),
          reportAvailable: scan.status === 'COMPLETED' && await scans.findReportByProjectAndScan(project.id, scan.id) !== undefined,
        })));
        const response: AssessmentDetailResponse = { assessment, progress: { ...summary.progress, recentScans } };
        sendSuccess(res, ctx, response);
      },
    },
    {
      method: 'PATCH', path: '/api/v1/projects/:projectId/assessments/:assessmentId', requireAuth: true,
      handler: async (req, res, ctx): Promise<void> => {
        const actor = ctx.user;
        if (actor === undefined) throw unauthorized();
        const { project, assessment } = await ownedAssessment(ctx.params['projectId'], ctx.params['assessmentId'], actor.id);
        if (project.status === 'ARCHIVED') throw projectArchived();
        rejectUnknownQuery(req);
        const raw = await readJsonBody(req, { maxBytes: Math.min(config.bodyMaxBytes, 16_384) });
        const parsed = parseDetails(raw);
        if (!parsed.ok) throw validationError(parsed.issues);
        const outcome = await assessments.update({ ownerId: actor.id, projectId: project.id, assessmentId: assessment.id, ...parsed, now: at() });
        if (outcome.outcome === 'not-found') throw notFound('Assessment not found.');
        if (outcome.outcome === 'not-planned') throw conflict('Assessment scope and objectives can be edited only while PLANNED.');
        if (outcome.outcome === 'history-limit') throw conflict('Assessment history is full; no changes were made.');
        if (outcome.assessment === undefined) throw internal('Assessment update returned no record.');
        const response: AssessmentResponse = { assessment: outcome.assessment };
        sendSuccess(res, ctx, response);
      },
    },
    {
      method: 'POST', path: '/api/v1/projects/:projectId/assessments/:assessmentId/status', requireAuth: true,
      handler: async (req, res, ctx): Promise<void> => {
        const actor = ctx.user;
        if (actor === undefined) throw unauthorized();
        const { project, assessment } = await ownedAssessment(ctx.params['projectId'], ctx.params['assessmentId'], actor.id);
        if (project.status === 'ARCHIVED') throw projectArchived();
        rejectUnknownQuery(req);
        const parsed = statusSchema.parse(await readJsonBody(req, { maxBytes: Math.min(config.bodyMaxBytes, 1024) }));
        if (!parsed.ok) throw validationError(parsed.issues);
        if (!isAssessmentStatus(parsed.value.status) || parsed.value.status === 'PLANNED') throw validationError([{ path: 'status', message: 'Choose ACTIVE, COMPLETED, or CANCELLED.' }]);
        let guardMessage: string | undefined;
        const outcome = await assessments.transition(
          { ownerId: actor.id, projectId: project.id, assessmentId: assessment.id, status: parsed.value.status as AssessmentStatus, now: at() },
          async () => {
            const records = await scans.listByProject(project.id);
            const linked = progressFor(records, actor.id, project.id, assessment.id);
            if (parsed.value.status === 'COMPLETED') {
              if (linked.progress.activeScans > 0) {
                guardMessage = 'Wait for linked scans to finish before completing the assessment.';
                return false;
              }
              if (linked.progress.completedScans === 0) {
                guardMessage = 'Complete at least one linked scan before closing the assessment.';
                return false;
              }
            }
            if (parsed.value.status === 'CANCELLED' && linked.progress.activeScans > 0) {
              guardMessage = 'Wait for linked scans to finish before cancelling the assessment.';
              return false;
            }
            return true;
          },
        );
        if (outcome.outcome === 'not-found') throw notFound('Assessment not found.');
        if (outcome.outcome === 'invalid-transition') throw conflict('That assessment lifecycle transition is not allowed.');
        if (outcome.outcome === 'guard-rejected') throw conflict(guardMessage ?? 'Assessment lifecycle prerequisites are not met.');
        if (outcome.outcome === 'history-limit') throw conflict('Assessment history is full; no lifecycle change was made.');
        if (outcome.assessment === undefined) throw internal('Assessment lifecycle returned no record.');
        const response: AssessmentResponse = { assessment: outcome.assessment };
        sendSuccess(res, ctx, response);
      },
    },
    {
      method: 'POST', path: '/api/v1/projects/:projectId/assessments/:assessmentId/authorization-declarations', requireAuth: true,
      handler: async (req, res, ctx): Promise<void> => {
        const actor = ctx.user;
        if (actor === undefined) throw unauthorized();
        const { project, assessment } = await ownedAssessment(ctx.params['projectId'], ctx.params['assessmentId'], actor.id);
        if (project.status === 'ARCHIVED') throw projectArchived();
        rejectUnknownQuery(req);
        const parsed = authorizationSchema.parse(await readJsonBody(req, { maxBytes: Math.min(config.bodyMaxBytes, 1024) }));
        if (!parsed.ok) throw validationError(parsed.issues);
        if (parsed.value.confirm !== true || (parsed.value.action !== 'DECLARE' && parsed.value.action !== 'WITHDRAW')) throw validationError([{ path: 'action', message: 'Provide action DECLARE or WITHDRAW and confirm true.' }]);
        if (assessment.status !== 'ACTIVE') throw conflict('Authorization declarations are available only during an active assessment.');
        const targetUrl = project.dastTargetUrl;
        if (targetUrl === undefined) throw conflict('Configure the project DAST target before recording an authorization declaration.');
        if (!targetHostInScope(assessment, targetUrl)) throw conflict('The configured DAST target host is not explicitly included in this assessment scope.');
        const outcome = await assessments.recordAuthorization({ ownerId: actor.id, projectId: project.id, assessmentId: assessment.id, targetUrl, action: parsed.value.action, now: at() });
        if (outcome.outcome === 'not-found') throw notFound('Assessment not found.');
        if (outcome.outcome === 'inactive') throw conflict('Authorization declarations are available only during an active assessment.');
        if (outcome.outcome === 'not-declared') throw conflict('There is no active user declaration for this exact configured target to withdraw.');
        if (outcome.outcome === 'declarations-limit') throw conflict('Authorization declaration history reached its limit.');
        if (outcome.outcome === 'history-limit') throw conflict('Assessment history is full; no declaration was recorded.');
        if (outcome.assessment === undefined) throw internal('Authorization declaration returned no record.');
        const response: AssessmentResponse = { assessment: outcome.assessment };
        sendSuccess(res, ctx, response);
      },
    },
  ];
}
