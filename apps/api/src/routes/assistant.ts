import type { IncomingMessage } from 'node:http';
import {
  ASSISTANT_QUESTION_MAX_LENGTH,
  FINDING_ID_PATTERN,
  SCAN_ID_PATTERN,
  type AssistantQuestionRequest,
  type AssistantStatusResponse,
} from '@drobon/shared';
import type { ApiConfig } from '../config.js';
import { badRequest, unauthorized, validationError } from '../errors.js';
import type { Route } from '../http.js';
import { readJsonBody } from '../lib/body.js';
import * as v from '../lib/validate.js';
import { createOwnProjectResolver, type OwnProjectResolver } from '../projects/access.js';
import type { ProjectStore } from '../projects/store.js';
import { sendSuccess } from '../respond.js';
import type { ScanStore } from '../scans/store.js';
import { createNoAssistantProvider } from '../assistant/provider.js';
import { AssistantService } from '../assistant/service.js';

export interface AssistantRouteDeps {
  config: ApiConfig;
  projects: ProjectStore;
  scans: ScanStore;
}

const questionSchema = v.object({
  question: v.string({ minLength: 1, maxLength: ASSISTANT_QUESTION_MAX_LENGTH, trim: true }),
  scanId: v.optional(v.string({ pattern: SCAN_ID_PATTERN })),
  findingId: v.optional(v.string({ pattern: FINDING_ID_PATTERN })),
  compareScanId: v.optional(v.string({ pattern: SCAN_ID_PATTERN })),
});

function queryIsEmpty(req: IncomingMessage): boolean {
  try {
    return new URL(req.url ?? '/', 'http://localhost').search.length === 0;
  } catch {
    throw badRequest('Malformed request URL.');
  }
}

export function createAssistantRoutes(deps: AssistantRouteDeps): Route[] {
  const { config, projects, scans } = deps;
  const access: OwnProjectResolver = createOwnProjectResolver(projects);
  const service = new AssistantService({ scans, provider: createNoAssistantProvider() });

  return [
    {
      method: 'GET',
      path: '/api/v1/assistant/status',
      requireAuth: true,
      handler: async (_req, res, ctx): Promise<void> => {
        const result: AssistantStatusResponse = service.status();
        sendSuccess(res, ctx, result);
      },
    },
    {
      method: 'POST',
      path: '/api/v1/projects/:projectId/assistant/ask',
      requireAuth: true,
      handler: async (req, res, ctx): Promise<void> => {
        const actor = ctx.user;
        if (actor === undefined) throw unauthorized();
        const project = await access.ownProjectOr403(ctx.params['projectId'], actor.id);
        if (!queryIsEmpty(req)) throw badRequest('Assistant requests do not accept query parameters.');
        const raw = await readJsonBody(req, { maxBytes: Math.min(config.bodyMaxBytes, 8_192) });
        const parsed = questionSchema.parse(raw);
        if (!parsed.ok) throw validationError(parsed.issues);
        if (parsed.value.findingId !== undefined && parsed.value.scanId === undefined) {
          throw validationError([{ path: 'scanId', message: 'A project-owned scan is required when selecting a finding.' }]);
        }
        if (parsed.value.compareScanId !== undefined && parsed.value.scanId === undefined) {
          throw validationError([{ path: 'scanId', message: 'A selected scan is required for scan comparison.' }]);
        }
        const request: AssistantQuestionRequest = {
          question: parsed.value.question,
          ...(parsed.value.scanId === undefined ? {} : { scanId: parsed.value.scanId }),
          ...(parsed.value.findingId === undefined ? {} : { findingId: parsed.value.findingId }),
          ...(parsed.value.compareScanId === undefined ? {} : { compareScanId: parsed.value.compareScanId }),
        };
        const result = await service.answer(project, request);
        ctx.logger.info('Assistant request processed', {
          requestId: ctx.id,
          userId: actor.id,
          projectId: project.id,
          state: result.state,
          mode: result.mode,
          contextItems: result.context.itemCount,
          redactedItems: result.context.redactedItems,
        });
        sendSuccess(res, ctx, result);
      },
    },
  ];
}
