import type { ServerResponse } from 'node:http';
import {
  IDEMPOTENCY_KEY_PATTERN,
  type ScanDetailResponse,
  type ScanResponse,
  type ScansResponse,
  isScanType,
} from '@drobon/shared';
import type { ApiConfig } from '../config.js';
import {
  badRequest,
  conflict,
  internal,
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

/**
 * Scan-job API (Pump 7) — the secure orchestration boundary future
 * scanner engines plug into. NOT a scanner: no engine exists yet, so
 * every scan deterministically FAILS with SCAN_ENGINE_NOT_IMPLEMENTED
 * (never a fabricated result; no vulnerability datasets — the dataset
 * lock holds).
 *
 * Surface (all behind `requireAuth`; ownership from the session ONLY):
 * - `POST /api/v1/projects/:projectId/scans`        request a scan
 * - `GET  /api/v1/projects/:projectId/scans`        list the project's scans
 * - `GET  /api/v1/projects/:projectId/scans/:scanId` read one scan
 *
 * There is deliberately NO scan mutation endpoint: status, timestamps,
 * results and failures are set ONLY by the server-side processor.
 *
 * Security rules (tested exhaustively):
 * - PROJECT access follows the Pump 6 uniform policy: unknown, foreign
 *   and malformed project ids answer the SAME 403 — no existence
 *   oracle. (A distinct PROJECT_ARCHIVED 409 is safe: it is only
 *   reachable for a project the caller already owns.)
 * - scan lookup happens ONLY inside the caller's own project; an
 *   unknown/malformed/foreign scan id answers a uniform 404 there —
 *   cross-account probing cannot distinguish "exists elsewhere" from
 *   "does not exist", because it never leaves the caller's scope.
 * - the request body may carry ONLY `{ scanType }`; `id`, `projectId`,
 *   `requestedBy`, `status`, timestamps, `result`, plan/role claims
 *   are UNKNOWN properties → 422 (strict validation — see the Pump 6
 *   own-property fix; the prototype-chain keys can never smuggle
 *   fields through).
 * - quota is consumed exactly once per created scan, atomically with
 *   job creation (the store's serialized section) via the Pump 5
 *   UsageService — the single quota authority. FREE = 3/month (account
 *   or shared device, whichever is stricter); PRO+ACTIVE exempt.
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
  scans: ScanStore;
  /** Source snapshots (Pump 8) — the SAST scan target, for pre-flight. */
  sources: SourceSnapshotStore;
  usage: UsageService;
  processor: ScanProcessor;
}

export function createScanRoutes(deps: ScanRouteDeps): Route[] {
  const { config, users, projects, scans, sources, usage, processor } = deps;
  const access: OwnProjectResolver = createOwnProjectResolver(projects);

  const createSchema = v.object({
    scanType: v.string({ maxLength: 16, trim: true }),
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
        // Project ownership first — the uniform Pump 6 policy.
        const project = await access.ownProjectOr403(ctx.params['projectId'], actor.id);
        // ACTIVE projects only: archived projects cannot START new
        // scans (their historical scans stay readable below). Safe to
        // answer distinctly — the caller already owns this project.
        if (project.status === 'ARCHIVED') {
          throw projectArchived();
        }
        // Body: exactly { scanType } — every security-sensitive field
        // (id, projectId, ownerId, requestedBy, status, createdAt,
        // startedAt, completedAt, result, subscription, plan, role,
        // userType, …) is an unknown property and rejected (422).
        const raw = await readJsonBody(req, { maxBytes: config.bodyMaxBytes });
        const parsed = createSchema.parse(raw);
        if (!parsed.ok) {
          throw validationError(parsed.issues);
        }
        if (!isScanType(parsed.value.scanType)) {
          throw validationError([
            { path: 'scanType', message: 'Unsupported scan type.' },
          ]);
        }
        // PUMP 8 PRE-FLIGHT (quota protection): a SAST scan needs a
        // source snapshot as its deterministic target. Rejecting the
        // request BEFORE quota consumption keeps a FREE account from
        // burning its monthly allowance on a scan that can only fail
        // with SAST_TARGET_NOT_FOUND. Race-window defense: if the
        // snapshot disappears between here and processing, the engine
        // still fails the scan closed.
        if (parsed.value.scanType === 'SAST') {
          const snapshot = await sources.findByProject(project.id);
          if (snapshot === undefined || snapshot.files.length === 0) {
            throw conflict(
              'Upload a source snapshot before requesting a SAST scan.',
            );
          }
        }
        const idempotencyKey = idempotencyKeyFrom(req.headers);
        // Quota decision + creation are ONE atomic operation (the
        // store's serialized section calls the UsageService — the
        // single quota authority — and persists the job only on
        // grant). The device hash is server-derived (opaque cookie →
        // SHA-256); the account record is re-loaded live so the plan
        // verdict is never stale.
        const deviceHash = ctx.deviceHash;
        if (deviceHash === undefined) {
          throw internal('Device identity missing for an authenticated request.');
        }
        const record = await users.findById(actor.id);
        if (record === undefined) {
          // Account vanished mid-session — the session is worthless.
          throw unauthorized();
        }
        const outcome = await scans.createScanWithQuota({
          ownerId: actor.id,
          projectId: project.id,
          scanType: parsed.value.scanType,
          ...(idempotencyKey === undefined ? {} : { idempotencyKey }),
          consume: () => usage.consumeScan(record, deviceHash),
        });
        if (outcome.outcome === 'quota-denied') {
          // Uniform 429 QUOTA_EXCEEDED + Retry-After (next UTC month).
          // Nothing was appended; no hint which limit tripped.
          ctx.logger.info('Scan quota denied', {
            requestId: ctx.id,
            userId: record.id,
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
            requestId: ctx.id,
            userId: record.id,
            scanId: outcome.scan.id,
          });
          sendScan(res, ctx, outcome.scan);
          return;
        }
        ctx.logger.info('Scan created', {
          requestId: ctx.id,
          userId: record.id,
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
      handler: async (_req, res, ctx): Promise<void> => {
        const actor = ctx.user;
        if (actor === undefined) {
          throw unauthorized(); // Defensive: requireAuth rejects first.
        }
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
      handler: async (_req, res, ctx): Promise<void> => {
        const actor = ctx.user;
        if (actor === undefined) {
          throw unauthorized(); // Defensive: requireAuth rejects first.
        }
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
  ];
}
