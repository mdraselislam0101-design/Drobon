import { unauthorized, validationError } from '../errors.js';
import type { Route } from '../http.js';
import type { ProjectStore } from '../projects/store.js';
import type { ScanStore } from '../scans/store.js';
import { sendSuccess } from '../respond.js';

export interface WorkspaceRouteDeps {
  projects: ProjectStore;
  scans: ScanStore;
  now?: () => number;
}

/** Self-only bounded overview; UserType and AccountRole grant no extra scope. */
export function createWorkspaceRoutes(deps: WorkspaceRouteDeps): Route[] {
  const clock = deps.now ?? Date.now;
  return [{
    method: 'GET',
    path: '/api/v1/me/security-overview',
    requireAuth: true,
    handler: async (req, res, ctx): Promise<void> => {
      const actor = ctx.user;
      if (actor === undefined) throw unauthorized();
      const target = new URL(req.url ?? '/', 'http://drobon.invalid');
      if ([...target.searchParams.keys()].length > 0) {
        throw validationError([...new Set(target.searchParams.keys())].map((key) => ({
          path: key,
          message: 'Unexpected query parameter.',
        })));
      }
      const [projects, activity] = await Promise.all([
        deps.projects.workspaceSummary(actor.id),
        deps.scans.workspaceSummary(actor.id),
      ]);
      sendSuccess(res, ctx, {
        overview: {
          generatedAt: new Date(clock()).toISOString(),
          projects,
          ...activity,
        },
      });
    },
  }];
}
