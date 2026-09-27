import { isRecord } from './guards.js';

/**
 * Project contracts (Pump 6).
 *
 * A Project is the primary user-owned container that future security
 * scans, jobs, findings, reports, SBOMs and remediation history attach
 * to. Pump 6 establishes ONLY the secure ownership boundary and CRUD
 * lifecycle — no scan engine, no findings, no per-plan limits.
 *
 * Ownership rules (mirrored by the API and tested there):
 * - every project belongs to exactly one account, decided by the
 *   server from the authenticated session — never from request bodies,
 *   query parameters, headers or client state;
 * - `AccountRole` and `UserType` never grant project ownership: an
 *   ADMIN/ACCOUNT_OWNER may not read or modify another account's
 *   project, and no classification bypasses ownership;
 * - responses carry NO owner identifier: the API is self-only, so the
 *   caller is by construction the owner of everything it can see.
 *
 * Usage boundary (Pump 5 integration): project CRUD never consumes a
 * scan. Only a future real scan execution will call the usage service.
 */

/** Project lifecycle states. Exactly two — creation always starts ACTIVE. */
export const PROJECT_STATUSES = ['ACTIVE', 'ARCHIVED'] as const;
export type ProjectStatus = (typeof PROJECT_STATUSES)[number];

/** Runtime guard: value is exactly one of the known project statuses. */
export function isProjectStatus(value: unknown): value is ProjectStatus {
  return (
    typeof value === 'string' &&
    (PROJECT_STATUSES as readonly string[]).includes(value)
  );
}

/** Bounded, single-line project name. */
export const PROJECT_NAME_MAX_LENGTH = 120;

/** Bounded, multi-line project description. */
export const PROJECT_DESCRIPTION_MAX_LENGTH = 2000;

/**
 * Project ids: `prj_` + a lowercase UUID v4 — the same convention as
 * account ids (`usr_` + UUID), generated with `crypto.randomUUID()`.
 * Never derived from counters; never exposes storage internals.
 */
export const PROJECT_ID_PATTERN = /^prj_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/**
 * The project as the API returns it (the caller's own). Deliberately
 * carries NO `ownerId` (self-only surface — the owner is always the
 * caller), no internal storage paths and no metadata beyond the
 * user-facing fields.
 */
export interface Project {
  id: string;
  name: string;
  description: string;
  status: ProjectStatus;
  createdAt: string;
  updatedAt: string;
}

/** `GET /api/v1/projects` — the caller's own projects, ordered. */
export interface ProjectsResponse {
  projects: Project[];
}

/** `GET/PATCH /api/v1/projects/:projectId` and archive responses. */
export interface ProjectResponse {
  project: Project;
}

/**
 * Deterministic list ordering (documented contract): `updatedAt`
 * DESC (most recently touched first), then `id` ASC as the stable
 * tie-breaker. Identical on every request for identical data.
 */
export function compareProjectsDesc(a: Project, b: Project): number {
  if (a.updatedAt !== b.updatedAt) {
    return a.updatedAt < b.updatedAt ? 1 : -1;
  }
  return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
}

/** Guard for {@link Project} (client boundary — rejects forged shapes). */
export function isProject(value: unknown): value is Project {
  return (
    isRecord(value) &&
    typeof value['id'] === 'string' &&
    PROJECT_ID_PATTERN.test(value['id']) &&
    typeof value['name'] === 'string' &&
    value['name'].length > 0 &&
    value['name'].length <= PROJECT_NAME_MAX_LENGTH &&
    typeof value['description'] === 'string' &&
    value['description'].length <= PROJECT_DESCRIPTION_MAX_LENGTH &&
    isProjectStatus(value['status']) &&
    typeof value['createdAt'] === 'string' &&
    !Number.isNaN(Date.parse(value['createdAt'])) &&
    typeof value['updatedAt'] === 'string' &&
    !Number.isNaN(Date.parse(value['updatedAt']))
  );
}

/** Guard for {@link ProjectsResponse}. */
export function isProjectsResponse(value: unknown): value is ProjectsResponse {
  return (
    isRecord(value) &&
    Array.isArray(value['projects']) &&
    value['projects'].every((entry) => isProject(entry))
  );
}

/** Guard for {@link ProjectResponse}. */
export function isProjectResponse(value: unknown): value is ProjectResponse {
  return isRecord(value) && isProject(value['project']);
}
