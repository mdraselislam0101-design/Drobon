import { sourceFindingIdentity } from '../scans/findingIdentity.js';
import type { ServerResponse } from 'node:http';
import {
  FINDING_SEVERITIES,
  IDEMPOTENCY_KEY_PATTERN,
  type ScanComparisonEntry,
  type ScanComparisonEntryState,
  type ScanComparisonResponse,
  type ScanDetailResponse,
  type ScanResponse,
  type ScansResponse,
  isScanType,
} from '@drobon/shared';
import type { ApiConfig } from '../config.js';
import {
  badRequest,
  conflict,
  notFound,
  projectArchived,
  quotaExceeded,
  unauthorized,
  validationError,
} from '../errors.js';
import type { RequestContext, Route } from '../http.js';
import { readJsonBody } from '../lib/body.js';
import * as v from '../lib/validate.js';
import type { ProjectStore } from '../projects/store.js';
import type { AssessmentStore } from '../assessments/store.js';
import {
  createOwnProjectResolver,
  type OwnProjectResolver,
} from '../projects/access.js';
import type { ScanRecord, ScanStore } from '../scans/store.js';
import { toScanDetailResponse, toScanResponse } from '../scans/store.js';
import type { SourceSnapshotStore } from '../scans/sources.js';
import type { ScanProcessor } from '../scans/processor.js';
import type { UserRepository } from '../auth/repositories.js';
import type { UsageService } from '../usage/service.js';
import { sendSuccess } from '../respond.js';
import type { DastTargetPolicy } from '../scans/dast/target.js';
import { createScanRequestService, type ScanRequestService } from '../scans/request.js';

/**
 * Scan-job API — the authenticated orchestration boundary for the
 * configured scanner engines. Results and limitations are reported by
 * each engine; missing rules or data are not evidence of safety.
 *
 * Surface (all behind `requireAuth`; ownership from the session ONLY):
 * - `POST /api/v1/projects/:projectId/scans`        request a scan
 * - `GET  /api/v1/projects/:projectId/scans`        list the project's scans
 * - `GET  /api/v1/projects/:projectId/scans/:scanId` read one scan
 *
 * There is deliberately NO scan mutation endpoint: status, timestamps,
 * results and failures are set ONLY by the server-side processor.
 *
 * Security rules (covered by targeted tests, not an exhaustive proof):
 * - PROJECT access follows the Pump 6 uniform policy: unknown, foreign
 *   and malformed project ids answer the SAME 403 — no existence
 *   oracle. (A distinct PROJECT_ARCHIVED 409 is safe: it is only
 *   reachable for a project the caller already owns.)
 * - scan lookup happens ONLY inside the caller's own project; an
 *   unknown/malformed/foreign scan id answers a uniform 404 there —
 *   cross-account probing cannot distinguish "exists elsewhere" from
 *   "does not exist", because it never leaves the caller's scope.
 * - the body accepts `scanType` and optional assessment/DAST mode and
 *   consent fields; `id`, `projectId`,
 *   `requestedBy`, `status`, timestamps, `result`, plan/role claims
 *   are UNKNOWN properties → 422 (strict validation — see the Pump 6
 *   own-property fix; the prototype-chain keys can never smuggle
 *   fields through).
 * - a durable quota reservation and job append are separate writes,
 *   serialized in-process and reconciled on restart (not a transaction).
 *   FREE = 3/month (account or shared device, whichever is stricter);
 *   active PRO does not consume the shared device quota.
 *   Denied → uniform 429 QUOTA_EXCEEDED + Retry-After.
 * - an optional `Idempotency-Key` header (8–64 URL-safe chars) makes
 *   network retries safe: the same key + same request replays the
 *   ORIGINAL scan (200, no second quota consumption); the same key
 *   with a different request → 409 conflict. Keys are scoped to the
 *   authenticated account — another account's key is simply unknown.
 * - responses carry the public scan shape only: no `ownerId`, no
 *   worker internals, no filesystem paths, no stack traces.
 */

export interface ScanRouteDeps {
  config: ApiConfig;
  users: UserRepository;
  projects: ProjectStore;
  assessments: AssessmentStore;
  scans: ScanStore;
  /** Source snapshots (Pump 8) — the SAST scan target, for pre-flight. */
  sources: SourceSnapshotStore;
  usage: UsageService;
  processor: ScanProcessor;
  dastTargetPolicy?: DastTargetPolicy;
  requestService?: ScanRequestService;
  /** Injectable clock (tests); defaults to the system clock. */
  now?: () => number;
}

export function createScanRoutes(deps: ScanRouteDeps): Route[] {
  const { config, projects, scans, processor } = deps;
  const requestService = deps.requestService ?? createScanRequestService(deps);
  const access: OwnProjectResolver = createOwnProjectResolver(projects);
  const now = deps.now ?? Date.now;
  const at = (): string => new Date(now()).toISOString();

  const createSchema = v.object({
    scanType: v.string({ maxLength: 16, trim: true }),
    assessmentId: v.optional(v.string({ maxLength: 64, trim: true })),
    dastMode: v.optional(v.string({ maxLength: 16, trim: true })),
    dastActiveConsent: v.optional(v.boolean()),
  });

  /**
   * Read + strictly validate the optional Idempotency-Key header.
   * Returns the normalized key, or undefined when absent. Malformed
   * keys never reach the store.
   */
  const idempotencyKeyFrom = (req: NodeJS.Dict<string | string[]>): string | undefined => {
    const raw = req['idempotency-key'];
    if (raw === undefined) {
      return undefined;
    }
    if (Array.isArray(raw)) {
      throw badRequest('Idempotency-Key must be a single header value.');
    }
    const key = raw.trim();
    if (!IDEMPOTENCY_KEY_PATTERN.test(key)) {
      throw validationError([
        { path: 'idempotencyKey', message: 'Must be 8–64 characters: letters, digits, - or _.' },
      ]);
    }
    return key;
  };

  const sendScan = (
    res: ServerResponse,
    ctx: RequestContext,
    record: ScanRecord,
    statusCode = 200,
  ): void => {
    const body: ScanResponse = { scan: toScanResponse(record) };
    sendSuccess(res, ctx, body, statusCode);
  };

  return [
    {
      method: 'POST',
      path: '/api/v1/projects/:projectId/scans',
      requireAuth: true,
      handler: async (req, res, ctx): Promise<void> => {
        const actor = ctx.user;
        if (actor === undefined) {
          throw unauthorized(); // Defensive: requireAuth rejects first.
        }
        // Query hardening (Pump 3): scan routes define no query
        // parameters at all, so ANY query string is rejected before the
        // project lookup, body parse, DAST preflight or quota
        // consumption — a junk request never reaches side effects, and
        // the response is the uniform 422 (no existence oracle added:
        // the answer does not depend on project ownership).
        v.rejectUnexpectedQuery(req);
        // Project ownership first — the uniform Pump 6 policy.
        const project = await access.ownProjectOr403(ctx.params['projectId'], actor.id);
        // ACTIVE projects only: archived projects cannot START new
        // scans (their historical scans stay readable below). Safe to
        // answer distinctly — the caller already owns this project.
        if (project.status === 'ARCHIVED') {
          throw projectArchived();
        }
        // Body: { scanType, assessmentId? }. Every other
        // security-sensitive field (id, projectId, ownerId, requestedBy,
        // status, timestamps, result, subscription, plan, role, userType,
        // target, …) is unknown and rejected (422). assessmentId is only
        // a same-owner/project link validated below.
        const raw = await readJsonBody(req, { maxBytes: config.bodyMaxBytes });
        const parsed = createSchema.parse(raw);
        if (!parsed.ok) {
          throw validationError(parsed.issues);
        }
        const scanType = parsed.value.scanType;
        if (!isScanType(scanType)) {
          throw validationError([
            { path: 'scanType', message: 'Unsupported scan type.' },
          ]);
        }
        const outcome = await requestService.request({
          actorId: actor.id,
          deviceHash: ctx.deviceHash,
          project,
          scanType,
          assessmentId: parsed.value.assessmentId,
          dastMode: parsed.value.dastMode,
          dastActiveConsent: parsed.value.dastActiveConsent,
          idempotencyKeyFromRequest: () => idempotencyKeyFrom(req.headers),
        });
        if (outcome.outcome === 'invalid-target') {
          throw conflict('The DAST target is missing or no longer passes the safety policy.');
        }
        if (outcome.outcome === 'compatibility-required') {
          throw conflict('The scan store requires a reviewed compatibility migration.');
        }
        if (outcome.outcome === 'quota-denied') {
          // Uniform 429 QUOTA_EXCEEDED + Retry-After (next UTC month).
          // Nothing was appended; no hint which limit tripped.
          ctx.logger.info('Scan quota denied', {
            requestId: ctx.logId,
            userId: actor.id,
            projectId: project.id,
          });
          throw quotaExceeded(outcome.retryAfterSec);
        }
        if (outcome.outcome === 'conflict') {
          throw conflict(
            'This idempotency key was already used for a different scan request.',
          );
        }
        if (outcome.outcome === 'replayed') {
          // A safe retry: the ORIGINAL scan, no second consumption.
          ctx.logger.info('Scan request replayed', {
            requestId: ctx.logId,
            userId: actor.id,
            scanId: outcome.scan.id,
          });
          sendScan(res, ctx, outcome.scan);
          return;
        }
        if (outcome.quotaCommitPending === true) {
          ctx.logger.error('Scan quota reservation requires startup reconciliation', { scanId: outcome.scan.id, projectId: project.id });
        }
        ctx.logger.info('Scan created', {
          requestId: ctx.logId,
          userId: actor.id,
          projectId: project.id,
          scanId: outcome.scan.id,
        });
        sendScan(res, ctx, outcome.scan, 201);
        // Async processing kick (no-op unless the processor runs).
        processor.kick();
      },
    },
    {
      method: 'GET',
      path: '/api/v1/projects/:projectId/scans',
      requireAuth: true,
      handler: async (req, res, ctx): Promise<void> => {
        const actor = ctx.user;
        if (actor === undefined) {
          throw unauthorized(); // Defensive: requireAuth rejects first.
        }
        v.rejectUnexpectedQuery(req);
        const project = await access.ownProjectOr403(ctx.params['projectId'], actor.id);
        const records = await scans.listByProject(project.id);
        const body: ScansResponse = {
          scans: records.map((record) => toScanResponse(record)),
        };
        sendSuccess(res, ctx, body);
      },
    },
    {
      method: 'GET',
      path: '/api/v1/projects/:projectId/scans/:scanId',
      requireAuth: true,
      handler: async (req, res, ctx): Promise<void> => {
        const actor = ctx.user;
        if (actor === undefined) {
          throw unauthorized(); // Defensive: requireAuth rejects first.
        }
        v.rejectUnexpectedQuery(req);
        const project = await access.ownProjectOr403(ctx.params['projectId'], actor.id);
        // Scan lookup is scoped to the caller's OWN project. Unknown,
        // malformed (pattern-fail/oversized — can never exist) and
        // foreign scan ids all answer the SAME 404: probing another
        // account's scan ids through this path cannot distinguish
        // "exists elsewhere" from "does not exist".
        const rawScanId = ctx.params['scanId'];
        if (typeof rawScanId !== 'string' || rawScanId.length > 64) {
          throw notFound('Scan not found.');
        }
        const record = await scans.findByProjectAndId(project.id, rawScanId);
        if (record === undefined) {
          throw notFound('Scan not found.');
        }
        // Pump 8: the detail response carries the scan AND its real
        // findings (bounded by MAX_FINDINGS_PER_SCAN by construction;
        // deterministically ordered). List responses stay lean.
        const body: ScanDetailResponse = { scan: toScanDetailResponse(record) };
        sendSuccess(res, ctx, body);
      },
    },
    {
      // Regression visibility (Phase 22 Pump 3): compare two COMPLETED
      // scans of the same type within the SAME owned project by finding
      // fingerprint. Path-carried ids (no query surface), uniform 404
      // for unknown/malformed/foreign ids, honest absence-based states.
      method: 'GET',
      path: '/api/v1/projects/:projectId/scans/:scanId/compare/:baselineScanId',
      requireAuth: true,
      handler: async (req, res, ctx): Promise<void> => {
        const actor = ctx.user;
        if (actor === undefined) {
          throw unauthorized(); // Defensive: requireAuth rejects first.
        }
        v.rejectUnexpectedQuery(req);
        const project = await access.ownProjectOr403(ctx.params['projectId'], actor.id);
        const rawCurrentId = ctx.params['scanId'];
        const rawBaselineId = ctx.params['baselineScanId'];
        if (typeof rawCurrentId !== 'string' || rawCurrentId.length > 64 || typeof rawBaselineId !== 'string' || rawBaselineId.length > 64) {
          throw notFound('Scan not found.');
        }
        if (rawCurrentId === rawBaselineId) {
          throw validationError([{ path: 'baselineScanId', message: 'Choose two different scans to compare.' }]);
        }
        // Same id-probing defense as the detail route: every failure
        // shape outside this project answers the SAME 404.
        const current = await scans.findByProjectAndId(project.id, rawCurrentId);
        if (current === undefined) throw notFound('Scan not found.');
        const baseline = await scans.findByProjectAndId(project.id, rawBaselineId);
        if (baseline === undefined) throw notFound('Scan not found.');
        if (current.status !== 'COMPLETED' || baseline.status !== 'COMPLETED') {
          throw conflict('Only completed scans can be compared.');
        }
        if (current.scanType !== baseline.scanType) {
          throw conflict('Only scans of the same type can be compared.');
        }
        const baselineFindings = baseline.findings ?? [];
        const currentFindings = current.findings ?? [];
        const usedBaseline = new Set<string>();
        const pairs: Array<{ baseline?: (typeof baselineFindings)[number]; current?: (typeof currentFindings)[number] }> = [];
        for (const finding of currentFindings) {
          let prior = baselineFindings.find((item) => item.fingerprint === finding.fingerprint && !usedBaseline.has(item.fingerprint));
          const identity = sourceFindingIdentity(finding, project.id);
          if (prior === undefined && identity !== undefined) {
            const candidates = baselineFindings.filter((item) => !usedBaseline.has(item.fingerprint) && sourceFindingIdentity(item, project.id) === identity);
            const currentMatches = currentFindings.filter((item) => sourceFindingIdentity(item, project.id) === identity);
            if (candidates.length > 0 && (candidates.length !== 1 || currentMatches.length !== 1)) {
              throw conflict('Finding comparison is ambiguous for a legacy source location; review the scans manually.');
            }
            prior = candidates[0];
          }
          if (prior !== undefined) usedBaseline.add(prior.fingerprint);
          pairs.push({ ...(prior === undefined ? {} : { baseline: prior }), current: finding });
        }
        for (const prior of baselineFindings) if (!usedBaseline.has(prior.fingerprint)) pairs.push({ baseline: prior });
        const entries: ScanComparisonEntry[] = [];
        for (const pair of pairs) {
          const inBaseline = pair.baseline;
          const inCurrent = pair.current;
          const reference = inCurrent ?? inBaseline;
          if (reference === undefined) continue;
          const fingerprint = reference.fingerprint;
          let state: ScanComparisonEntryState;
          if (inBaseline === undefined) {
            state = 'NEW';
          } else if (inCurrent === undefined) {
            // Absence is comparison evidence, not proof of repair.
            state = 'RESOLVED';
          } else {
            const workflow = await scans.getFindingWorkflow(project.id, fingerprint) ??
              (inBaseline.fingerprint === fingerprint ? undefined : await scans.getFindingWorkflow(project.id, inBaseline.fingerprint));
            if (workflow?.state === 'REOPENED') state = 'REOPENED';
            else state = inBaseline.severity === inCurrent.severity ? 'UNCHANGED' : 'CHANGED';
          }
          entries.push({
            fingerprint, findingId: reference.id, ruleId: reference.ruleId,
            location: reference.scanner === 'DAST' ? reference.endpoint : reference.file,
            state,
            ...(inBaseline === undefined ? {} : { baselineSeverity: inBaseline.severity }),
            ...(inCurrent === undefined ? {} : { currentSeverity: inCurrent.severity }),
          });
        }
        // Severity-then-location ordering, mirroring the report ordering.
        entries.sort((a, b) => {
          const rank = (entry: ScanComparisonEntry): number =>
            FINDING_SEVERITIES.indexOf(entry.currentSeverity ?? entry.baselineSeverity ?? 'INFO');
          const rankDiff = rank(a) - rank(b);
          if (rankDiff !== 0) return rankDiff;
          if (a.location !== b.location) return a.location < b.location ? -1 : 1;
          if (a.ruleId !== b.ruleId) return a.ruleId < b.ruleId ? -1 : 1;
          return a.fingerprint < b.fingerprint ? -1 : a.fingerprint > b.fingerprint ? 1 : 0;
        });
        const countKeys: Record<ScanComparisonEntryState, 'new' | 'unchanged' | 'resolved' | 'reopened' | 'changed'> = {
          NEW: 'new',
          UNCHANGED: 'unchanged',
          RESOLVED: 'resolved',
          REOPENED: 'reopened',
          CHANGED: 'changed',
        };
        const counts = { new: 0, unchanged: 0, resolved: 0, reopened: 0, changed: 0 };
        for (const entry of entries) {
          counts[countKeys[entry.state]] += 1;
        }
        const body: ScanComparisonResponse = {
          projectId: project.id,
          scanType: current.scanType,
          baselineScanId: baseline.id,
          currentScanId: current.id,
          generatedAt: at(),
          counts,
          entries,
        };
        sendSuccess(res, ctx, body);
      },
    },
  ];
}
