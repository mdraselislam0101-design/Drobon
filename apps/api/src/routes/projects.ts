import type { ServerResponse } from 'node:http';
import {
  PROJECT_DESCRIPTION_MAX_LENGTH,
  PROJECT_ID_PATTERN,
  PROJECT_NAME_MAX_LENGTH,
  type ProjectResponse,
  type ProjectsResponse,
} from '@drobon/shared';
import type { ApiConfig } from '../config.js';
import { forbidden, internal, projectArchived, unauthorized, validationError } from '../errors.js';
import { AUTHZ_DENIED_MESSAGE } from '../auth/authorization.js';
import type { RequestContext, Route } from '../http.js';
import { readJsonBody } from '../lib/body.js';
import * as v from '../lib/validate.js';
import type { ProjectRecord, ProjectStore } from '../projects/store.js';
import { toProjectResponse } from '../projects/store.js';
import { createDastTargetPolicy, DastTargetError, type DastTargetPolicy } from '../scans/dast/target.js';
import { sendSuccess } from '../respond.js';

/**
 * Projects API (Pump 6) — the secure ownership boundary future scans,
 * jobs, findings, reports, SBOMs and remediation attach to.
 *
 * Surface (all behind `requireAuth`; ownership from the session ONLY):
 * - `POST   /api/v1/projects`              create (status always ACTIVE)
 * - `GET    /api/v1/projects`              list OWN projects, ordered
 *                                          `updatedAt` DESC then `id` ASC
 * - `GET    /api/v1/projects/:projectId`   read own project
 * - `PATCH  /api/v1/projects/:projectId`   update name/description only
 * - `POST   /api/v1/projects/:projectId/archive`   explicit lifecycle op
 * - `POST   /api/v1/projects/:projectId/unarchive` explicit lifecycle op
 *
 * Ownership rules (tested exhaustively):
 * - the authenticated account IS the owner of everything it creates;
 * - `ownerId`, `status`, `id`, timestamps in bodies are UNKNOWN
 *   properties → 422 (strict validation — client-controlled ownership
 *   and lifecycle injection are structurally impossible);
 * - cross-account reads/writes answer the SAME 403 as unknown and
 *   malformed ids (the Pump 3 no-existence-oracle policy);
 * - AccountRole and UserType NEVER grant ownership: ADMIN and
 *   ACCOUNT_OWNER receive the same uniform 403 for other accounts'
 *   projects; future admin visibility is a later, explicit design;
 * - responses never contain `ownerId` — the API is self-only, so the
 *   caller is by construction the owner of everything it can see.
 *
 * Usage boundary (Pump 5): project CRUD never calls the usage service —
 * only a future real scan execution will consume a scan. Verified by
 * tests.
 */

export interface ProjectRouteDeps {
  config: ApiConfig;
  projects: ProjectStore;
  /** Injectable address resolver for controlled safety tests. */
  dastTargetPolicy?: DastTargetPolicy;
}

/**
 * Normalizes untrusted project text: NFC Unicode normalization (so
 * visually identical text has exactly one stored form), rejection of
 * control characters (names are single-line; descriptions may keep
 * tab/newline only). Returns the normalized value or a validation issue.
 */
function normalizeProjectText(
  value: unknown,
  path: string,
  maxLength: number,
  allowLinebreaks: boolean,
): { ok: true; value: string } | { ok: false; issue: { path: string; message: string } } {
  if (typeof value !== 'string') {
    return { ok: false, issue: { path, message: 'Expected a string.' } };
  }
  // NFC-normalize first so every check and the stored form are stable.
  const normalized = value.normalize('NFC');
  if (normalized.length > maxLength) {
    return {
      ok: false,
      issue: { path, message: `Must be at most ${maxLength} characters.` },
    };
  }
  for (const char of normalized) {
    const code = char.codePointAt(0) ?? 0;
    const allowed = allowLinebreaks ? code === 0x0a || code === 0x09 : false;
    if (!allowed && (code < 0x20 || code === 0x7f)) {
      return {
        ok: false,
        issue: { path, message: 'Must not contain control characters.' },
      };
    }
  }
  return { ok: true, value: normalized };
}

export function createProjectRoutes(deps: ProjectRouteDeps): Route[] {
  const { config, projects } = deps;
  const dastTargetPolicy = deps.dastTargetPolicy ?? createDastTargetPolicy();

  const dastTargetSchema = v.object({
    targetUrl: v.string({ maxLength: 2048 }),
  });

  const createSchema = v.object({
    name: v.string({
      minLength: 1,
      maxLength: PROJECT_NAME_MAX_LENGTH,
      trim: true,
    }),
    description: v.optional(
      v.string({ maxLength: PROJECT_DESCRIPTION_MAX_LENGTH, trim: true }),
    ),
  });

  const updateSchema = v.object({
    name: v.optional(
      v.string({ minLength: 1, maxLength: PROJECT_NAME_MAX_LENGTH, trim: true }),
    ),
    description: v.optional(
      v.string({ maxLength: PROJECT_DESCRIPTION_MAX_LENGTH, trim: true }),
    ),
  });

  /**
   * Resolve the path's projectId to the caller's OWN project, or throw
   * the uniform 403 (unknown, malformed, or someone else's — all
   * identical, no existence oracle). Oversized ids get the same answer
   * before any lookup.
   */
  const ownProjectOr403 = (
    rawId: unknown,
    actorId: string,
  ): Promise<ProjectRecord> => {
    if (typeof rawId !== 'string' || rawId.length === 0 || rawId.length > 64) {
      throw forbidden(AUTHZ_DENIED_MESSAGE);
    }
    if (!PROJECT_ID_PATTERN.test(rawId)) {
      throw forbidden(AUTHZ_DENIED_MESSAGE);
    }
    return projects.findById(rawId).then((record) => {
      if (record === undefined || record.ownerId !== actorId) {
        throw forbidden(AUTHZ_DENIED_MESSAGE);
      }
      return record;
    });
  };

  const sendProject = (
    res: ServerResponse,
    ctx: RequestContext,
    record: ProjectRecord,
    statusCode = 200,
  ): void => {
    const body: ProjectResponse = { project: toProjectResponse(record) };
    sendSuccess(res, ctx, body, statusCode);
  };

  return [
    {
      method: 'POST',
      path: '/api/v1/projects',
      requireAuth: true,
      handler: async (req, res, ctx): Promise<void> => {
        const actor = ctx.user;
        if (actor === undefined) {
          throw unauthorized(); // Defensive: requireAuth rejects first.
        }
        // Query hardening (Pump 4): project routes define no query
        // parameters at all — any query string is fail-closed (422,
        // uniform for owned/foreign/unknown projects; no oracle added,
        // and tampering never silently ignored). The exact same posture
        // applied to scan/source routes in Pump 3.
        v.rejectUnexpectedQuery(req);
        const raw = await readJsonBody(req, { maxBytes: config.bodyMaxBytes });
        const parsed = createSchema.parse(raw);
        if (!parsed.ok) {
          throw validationError(parsed.issues);
        }
        const name = normalizeProjectText(parsed.value.name, 'name', PROJECT_NAME_MAX_LENGTH, false);
        if (!name.ok) {
          throw validationError([name.issue]);
        }
        let description = '';
        if (parsed.value.description !== undefined) {
          const normalized = normalizeProjectText(
            parsed.value.description,
            'description',
            PROJECT_DESCRIPTION_MAX_LENGTH,
            true,
          );
          if (!normalized.ok) {
            throw validationError([normalized.issue]);
          }
          description = normalized.value;
        }
        // Ownership is SERVER-side only: the authenticated account is the
        // owner. Body `ownerId`/`status`/timestamps never reached here —
        // the strict schema rejected them as unknown properties.
        const record = await projects.create({
          ownerId: actor.id,
          name: name.value,
          description,
        });
        ctx.logger.info('Project created', { requestId: ctx.id, userId: actor.id, projectId: record.id });
        sendProject(res, ctx, record, 201);
      },
    },
    {
      method: 'GET',
      path: '/api/v1/projects',
      requireAuth: true,
      handler: async (req, res, ctx): Promise<void> => {
        const actor = ctx.user;
        if (actor === undefined) {
          throw unauthorized(); // Defensive: requireAuth rejects first.
        }
        v.rejectUnexpectedQuery(req);
        // Server-side scoping: only the caller's own projects, never
        // frontend filtering. Ordering is the documented shared contract
        // (updatedAt DESC, then id ASC) and is computed in the store.
        const records = await projects.listByOwner(actor.id);
        const body: ProjectsResponse = {
          projects: records.map((record) => toProjectResponse(record)),
        };
        sendSuccess(res, ctx, body);
      },
    },
    {
      method: 'GET',
      path: '/api/v1/projects/:projectId',
      requireAuth: true,
      handler: async (req, res, ctx): Promise<void> => {
        const actor = ctx.user;
        if (actor === undefined) {
          throw unauthorized(); // Defensive: requireAuth rejects first.
        }
        v.rejectUnexpectedQuery(req);
        const record = await ownProjectOr403(ctx.params['projectId'], actor.id);
        sendProject(res, ctx, record);
      },
    },
    {
      method: 'PATCH',
      path: '/api/v1/projects/:projectId',
      requireAuth: true,
      handler: async (req, res, ctx): Promise<void> => {
        const actor = ctx.user;
        if (actor === undefined) {
          throw unauthorized(); // Defensive: requireAuth rejects first.
        }
        v.rejectUnexpectedQuery(req);
        const record = await ownProjectOr403(ctx.params['projectId'], actor.id);
        const raw = await readJsonBody(req, { maxBytes: config.bodyMaxBytes });
        const parsed = updateSchema.parse(raw);
        if (!parsed.ok) {
          throw validationError(parsed.issues);
        }
        if (parsed.value.name === undefined && parsed.value.description === undefined) {
          throw validationError([
            { path: 'body', message: 'At least one of name or description is required.' },
          ]);
        }
        const patch: { name?: string; description?: string } = {};
        if (parsed.value.name !== undefined) {
          const name = normalizeProjectText(
            parsed.value.name,
            'name',
            PROJECT_NAME_MAX_LENGTH,
            false,
          );
          if (!name.ok) {
            throw validationError([name.issue]);
          }
          patch.name = name.value;
        }
        if (parsed.value.description !== undefined) {
          const description = normalizeProjectText(
            parsed.value.description,
            'description',
            PROJECT_DESCRIPTION_MAX_LENGTH,
            true,
          );
          if (!description.ok) {
            throw validationError([description.issue]);
          }
          patch.description = description.value;
        }
        // `status`, `ownerId`, `id`, `createdAt`, `updatedAt` never reach
        // here: the strict schema rejected them as unknown properties.
        const updated = await projects.update(record.id, patch);
        if (updated === undefined) {
          throw internal('Project disappeared during update.');
        }
        ctx.logger.info('Project updated', { requestId: ctx.id, userId: actor.id, projectId: updated.id });
        sendProject(res, ctx, updated);
      },
    },
    {
      method: 'PUT',
      path: '/api/v1/projects/:projectId/dast-target',
      requireAuth: true,
      handler: async (req, res, ctx): Promise<void> => {
        const actor = ctx.user;
        if (actor === undefined) throw unauthorized();
        v.rejectUnexpectedQuery(req);
        const project = await ownProjectOr403(ctx.params['projectId'], actor.id);
        if (project.status === 'ARCHIVED') {
          throw projectArchived();
        }
        const raw = await readJsonBody(req, { maxBytes: config.bodyMaxBytes });
        const parsed = dastTargetSchema.parse(raw);
        if (!parsed.ok) throw validationError(parsed.issues);
        let targetUrl: string;
        try {
          // Syntax, public DNS answers, and all address families are
          // validated before project state changes; scan execution
          // repeats resolution and pins the vetted address.
          targetUrl = (await dastTargetPolicy.prepare(parsed.value.targetUrl)).url;
        } catch (error) {
          const message = error instanceof DastTargetError && error.code === 'DAST_DNS_FAILED'
            ? 'The target could not be resolved safely.'
            : 'Use an HTTP(S) target on a public host; local, private and reserved addresses are blocked.';
          throw validationError([{ path: 'targetUrl', message }]);
        }
        const updated = await projects.setDastTargetUrl(project.id, targetUrl);
        if (updated === undefined) throw internal('Project disappeared during DAST target update.');
        ctx.logger.info('Project DAST target updated', { requestId: ctx.id, userId: actor.id, projectId: project.id });
        sendProject(res, ctx, updated);
      },
    },
    {
      method: 'DELETE',
      path: '/api/v1/projects/:projectId/dast-target',
      requireAuth: true,
      handler: async (req, res, ctx): Promise<void> => {
        const actor = ctx.user;
        if (actor === undefined) throw unauthorized();
        v.rejectUnexpectedQuery(req);
        const project = await ownProjectOr403(ctx.params['projectId'], actor.id);
        if (project.status === 'ARCHIVED') {
          throw projectArchived();
        }
        const updated = await projects.setDastTargetUrl(project.id, undefined);
        if (updated === undefined) throw internal('Project disappeared during DAST target removal.');
        ctx.logger.info('Project DAST target removed', { requestId: ctx.id, userId: actor.id, projectId: project.id });
        sendProject(res, ctx, updated);
      },
    },
    {
      method: 'POST',
      path: '/api/v1/projects/:projectId/archive',
      requireAuth: true,
      handler: async (req, res, ctx): Promise<void> => {
        const actor = ctx.user;
        if (actor === undefined) {
          throw unauthorized(); // Defensive: requireAuth rejects first.
        }
        v.rejectUnexpectedQuery(req);
        const record = await ownProjectOr403(ctx.params['projectId'], actor.id);
        // Explicit lifecycle operation — the ONLY way status changes.
        // Idempotent: archiving an archived project is a 200 no-op.
        const updated = await projects.setStatus(record.id, 'ARCHIVED');
        if (updated === undefined) {
          throw internal('Project disappeared during archive.');
        }
        ctx.logger.info('Project archived', { requestId: ctx.id, userId: actor.id, projectId: updated.id });
        sendProject(res, ctx, updated);
      },
    },
    {
      method: 'POST',
      path: '/api/v1/projects/:projectId/unarchive',
      requireAuth: true,
      handler: async (req, res, ctx): Promise<void> => {
        const actor = ctx.user;
        if (actor === undefined) {
          throw unauthorized(); // Defensive: requireAuth rejects first.
        }
        v.rejectUnexpectedQuery(req);
        const record = await ownProjectOr403(ctx.params['projectId'], actor.id);
        const updated = await projects.setStatus(record.id, 'ACTIVE');
        if (updated === undefined) {
          throw internal('Project disappeared during unarchive.');
        }
        ctx.logger.info('Project unarchived', { requestId: ctx.id, userId: actor.id, projectId: updated.id });
        sendProject(res, ctx, updated);
      },
    },
  ];
}

