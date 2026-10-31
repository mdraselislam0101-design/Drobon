import type { ServerResponse } from 'node:http';
import {
  SOURCE_MAX_FILES,
  SOURCE_MAX_FILE_BYTES,
  SOURCE_MAX_TOTAL_BYTES,
  isValidSourceContent,
  isValidSourcePath,
  type SourceSnapshotResponse,
} from '@drobon/shared';
import type { ApiConfig } from '../config.js';
import {
  notFound,
  payloadTooLarge,
  projectArchived,
  unauthorized,
  validationError,
} from '../errors.js';
import type { RequestContext, Route } from '../http.js';
import { readJsonBody } from '../lib/body.js';
import * as v from '../lib/validate.js';
import { createOwnProjectResolver, type OwnProjectResolver } from '../projects/access.js';
import type { ProjectStore } from '../projects/store.js';
import type {
  ReplaceSnapshotInput,
  SourceSnapshotRecord,
  SourceSnapshotStore,
} from '../scans/sources.js';
import { toSourceSnapshotResponse } from '../scans/sources.js';
import { sendSuccess } from '../respond.js';

/**
 * Source-snapshot API (Pump 8) — the SAST scan target.
 *
 * Surface (all behind `requireAuth`; ownership from the session ONLY,
 * resolved by the shared Pump 6 uniform project-access policy):
 * - `PUT /api/v1/projects/:projectId/sources` — replace the project's
 *   whole snapshot (deterministic engine input). Empty file list
 *   clears it. ACTIVE projects only (archived → 409, like scans).
 * - `GET  /api/v1/projects/:projectId/sources` — snapshot metadata
 *   (paths + byte sizes). Content is engine input, NOT client output.
 *
 * Validation (strict, tested exhaustively):
 * - the body may carry ONLY `{ files: [{ path, content }] }` — unknown
 *   properties and prototype-chain keys are rejected (422);
 * - paths obey the shared single path policy (relative ASCII, no
 *   traversal/absolute/backslash/NUL/control/percent, no dotfile
 *   segments, no credential-file extensions, bounded length/depth);
 * - content is TEXT-ONLY (control characters other than tab/CR/LF are
 *   rejected) with hard per-file and total byte caps (413/422);
 * - the whole request is bounded by the transport body limit (413);
 * - responses carry public metadata only: no content, no `ownerId`, no
 *   filesystem paths, no stack traces.
 */

export interface SourceRouteDeps {
  config: ApiConfig;
  projects: ProjectStore;
  sources: SourceSnapshotStore;
}

export function createSourceRoutes(deps: SourceRouteDeps): Route[] {
  const { config, projects, sources } = deps;
  const access: OwnProjectResolver = createOwnProjectResolver(projects);

  const uploadSchema = v.object({
    files: v.array(
      v.object({
        path: v.string({ maxLength: 400, trim: false }),
        content: v.string({ maxLength: SOURCE_MAX_FILE_BYTES, trim: false }),
      }),
      // Bounds parse work; the friendly file-count message is produced
      // by the explicit check below.
      { maxLength: SOURCE_MAX_FILES + 1 },
    ),
  });

  const sendSnapshot = (
    res: ServerResponse,
    ctx: RequestContext,
    record: SourceSnapshotRecord | undefined,
  ): void => {
    if (record === undefined) {
      throw notFound('No source snapshot is attached to this project.');
    }
    const body: SourceSnapshotResponse = toSourceSnapshotResponse(record);
    sendSuccess(res, ctx, body);
  };

  return [
    {
      method: 'PUT',
      path: '/api/v1/projects/:projectId/sources',
      requireAuth: true,
      handler: async (req, res, ctx): Promise<void> => {
        const actor = ctx.user;
        if (actor === undefined) {
          throw unauthorized(); // Defensive: requireAuth rejects first.
        }
        // Query hardening (Pump 3): source routes define no query
        // parameters — reject any query string before ownership lookup
        // or body parse (uniform 422; no existence oracle added).
        v.rejectUnexpectedQuery(req);
        // The uniform Pump 6 project-access policy (no existence oracle).
        const project = await access.ownProjectOr403(ctx.params['projectId'], actor.id);
        // ACTIVE projects only: an archived project is read-only (the
        // same rule as starting scans — its historical data stays
        // readable below).
        if (project.status === 'ARCHIVED') {
          throw projectArchived();
        }
        const raw = await readJsonBody(req, { maxBytes: config.bodyMaxBytes });
        const parsed = uploadSchema.parse(raw);
        if (!parsed.ok) {
          throw validationError(parsed.issues);
        }
        const files = parsed.value.files;
        // File-count cap (the schema allows one extra so the error can
        // explain the limit rather than a generic array failure).
        if (files.length > SOURCE_MAX_FILES) {
          throw validationError([
            {
              path: 'files',
              message: `A source snapshot may contain at most ${SOURCE_MAX_FILES} files.`,
            },
          ]);
        }
        // Per-file policy: path + text-only content. This is where
        // traversal, dotfiles, credential files and binary content die.
        const seenPaths = new Set<string>();
        let totalBytes = 0;
        for (const [index, file] of files.entries()) {
          if (!isValidSourcePath(file.path)) {
            throw validationError([
              {
                path: `files[${index}].path`,
                message:
                  'Paths must be relative ASCII (letters, digits, dot, underscore, hyphen, slash), must not start a segment with a dot, and must not use blocked extensions.',
              },
            ]);
          }
          if (seenPaths.has(file.path)) {
            throw validationError([
              { path: `files[${index}].path`, message: 'Duplicate file path.' },
            ]);
          }
          seenPaths.add(file.path);
          if (!isValidSourceContent(file.content)) {
            throw validationError([
              {
                path: `files[${index}].content`,
                message:
                  'File content must be text (control characters other than tab and newlines are not accepted).',
              },
            ]);
          }
          const bytes = Buffer.byteLength(file.content, 'utf8');
          if (bytes > SOURCE_MAX_FILE_BYTES) {
            throw payloadTooLarge(SOURCE_MAX_FILE_BYTES);
          }
          totalBytes += bytes;
          if (totalBytes > SOURCE_MAX_TOTAL_BYTES) {
            throw payloadTooLarge(SOURCE_MAX_TOTAL_BYTES);
          }
        }
        // Replace (or clear) the snapshot — the deterministic engine input.
        const input: ReplaceSnapshotInput = {
          ownerId: actor.id,
          projectId: project.id,
          files,
        };
        const record = await sources.replace(input);
        ctx.logger.info('Source snapshot stored', {
          requestId: ctx.logId,
          userId: actor.id,
          projectId: project.id,
          fileCount: files.length,
        });
        // A cleared snapshot answers 200 with the (now absent) state —
        // represented honestly as 404 for the metadata shape.
        if (record === undefined) {
          throw notFound('No source snapshot is attached to this project.');
        }
        sendSnapshot(res, ctx, record);
      },
    },
    {
      method: 'GET',
      path: '/api/v1/projects/:projectId/sources',
      requireAuth: true,
      handler: async (req, res, ctx): Promise<void> => {
        const actor = ctx.user;
        if (actor === undefined) {
          throw unauthorized(); // Defensive: requireAuth rejects first.
        }
        v.rejectUnexpectedQuery(req);
        const project = await access.ownProjectOr403(ctx.params['projectId'], actor.id);
        const record = await sources.findByProject(project.id);
        sendSnapshot(res, ctx, record);
      },
    },
  ];
}
