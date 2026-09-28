import { PROJECT_ID_PATTERN } from '@drobon/shared';
import { forbidden } from '../errors.js';
import { AUTHZ_DENIED_MESSAGE } from '../auth/authorization.js';
import type { ProjectRecord, ProjectStore } from './store.js';

/**
 * The Pump 6 uniform project-access policy, as one reusable resolver:
 * resolve the path's projectId to the caller's OWN project, or throw
 * the uniform 403 — unknown, malformed (pattern-fail/oversized) and
 * foreign (someone else's) ids answer IDENTICALLY, so the API offers no
 * existence oracle and `AccountRole`/`UserType` never grant foreign
 * access. Used by the project, scan and source-snapshot routes.
 */
export interface OwnProjectResolver {
  /**
   * The caller's own project record, or a uniform 403. Ownership comes
   * from the resolved path id + the session actor ONLY — never from
   * body fields, headers or query parameters.
   */
  ownProjectOr403(rawId: unknown, actorId: string): Promise<ProjectRecord>;
}

export function createOwnProjectResolver(projects: ProjectStore): OwnProjectResolver {
  return {
    ownProjectOr403: async (rawId, actorId) => {
      if (typeof rawId !== 'string' || rawId.length === 0 || rawId.length > 64) {
        throw forbidden(AUTHZ_DENIED_MESSAGE);
      }
      if (!PROJECT_ID_PATTERN.test(rawId)) {
        throw forbidden(AUTHZ_DENIED_MESSAGE);
      }
      const record = await projects.findById(rawId);
      if (record === undefined || record.ownerId !== actorId) {
        throw forbidden(AUTHZ_DENIED_MESSAGE);
      }
      return record;
    },
  };
}
