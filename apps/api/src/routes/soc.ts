import { isSocPosture, type SocPostureResponse } from '@drobon/shared';
import { internal, unauthorized } from '../errors.js';
import type { Route } from '../http.js';
import * as v from '../lib/validate.js';
import { createOwnProjectResolver } from '../projects/access.js';
import type { ProjectStore } from '../projects/store.js';
import { sendSuccess } from '../respond.js';
import { buildSocPosture } from '../soc/engine.js';
import { gatherSocInput, type SocContextDeps } from '../soc/context.js';

export interface SocRouteDeps extends SocContextDeps {
  projects: ProjectStore;
  now?: () => number;
}

/** Read-only derived triage; session + project ownership required. */
export function createSocRoutes(deps: SocRouteDeps): Route[] {
  const access = createOwnProjectResolver(deps.projects);
  const now = deps.now ?? Date.now;
  return [{
    method: 'GET',
    path: '/api/v1/projects/:projectId/soc',
    requireAuth: true,
    handler: async (req, res, ctx): Promise<void> => {
      v.rejectUnexpectedQuery(req);
      const actor = ctx.user;
      if (actor === undefined) throw unauthorized();
      const project = await access.ownProjectOr403(ctx.params['projectId'], actor.id);
      const input = await gatherSocInput(deps, project.id, actor.id, new Date(now()).toISOString());
      const posture = buildSocPosture(input);
      if (!isSocPosture(posture)) throw internal('The operations snapshot could not be built safely.');
      const response: SocPostureResponse = { posture };
      sendSuccess(res, ctx, response);
    },
  }];
}
