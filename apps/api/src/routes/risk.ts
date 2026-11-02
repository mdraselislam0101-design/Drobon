import { isRiskAssessmentResponse } from '@drobon/shared';
import { internal, unauthorized } from '../errors.js';
import type { Route } from '../http.js';
import * as v from '../lib/validate.js';
import { createOwnProjectResolver } from '../projects/access.js';
import type { ProjectStore } from '../projects/store.js';
import { sendSuccess } from '../respond.js';
import { gatherRiskAssessment, type RiskContextDeps } from '../risk/context.js';

export interface RiskRouteDeps extends RiskContextDeps {
  projects: ProjectStore;
  now?: () => number;
}

/**
 * `GET /api/v1/projects/:projectId/risk` — read-only correlated risk.
 *
 * A projection over scans that are already saved: no scan runs, nothing is
 * written, and the guard is re-run on the response so a malformed assessment
 * fails loudly instead of reaching a client.
 */
export function createRiskRoutes(deps: RiskRouteDeps): Route[] {
  const access = createOwnProjectResolver(deps.projects);
  const now = deps.now ?? Date.now;
  return [{
    method: 'GET',
    path: '/api/v1/projects/:projectId/risk',
    requireAuth: true,
    handler: async (req, res, ctx): Promise<void> => {
      v.rejectUnexpectedQuery(req);
      const actor = ctx.user;
      if (actor === undefined) throw unauthorized();
      const project = await access.ownProjectOr403(ctx.params['projectId'], actor.id);
      const response = await gatherRiskAssessment(deps, project.id, actor.id, new Date(now()).toISOString());
      if (!isRiskAssessmentResponse(response)) {
        throw internal('The risk assessment could not be built safely.');
      }
      sendSuccess(res, ctx, response);
    },
  }];
}
