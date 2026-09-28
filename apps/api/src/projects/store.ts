import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { randomBytes, randomUUID } from 'node:crypto';
import {
  PROJECT_DESCRIPTION_MAX_LENGTH,
  PROJECT_ID_PATTERN,
  PROJECT_NAME_MAX_LENGTH,
  WORKSPACE_PROJECTS_MAX,
  isProjectStatus,
  isSafeDastUrl,
  type Project,
  type ProjectStatus,
  type WorkspaceProjectCard,
  type WorkspaceProjectsSummary,
} from '@drobon/shared';

/**
 * Durable project store (Pump 6) — the minimum persistence boundary for
 * the Projects foundation, following the exact architecture of the Pump 2
 * account store and the Pump 5 usage store:
 *
 * - one JSON document (`{ version: 1, projects: [...] }`), one writer,
 *   isolated behind the `ProjectStore` interface so the future database
 *   phase swaps this module with zero changes elsewhere;
 * - projects survive process restarts (loaded at startup, fail fast on
 *   a corrupt document or an invalid record — corrupt data is never
 *   silently erased);
 * - writes are atomic (temp file + rename in the same directory, mode
 *   0600), so a crash mid-write cannot tear the store;
 * - every mutation runs inside the serialized in-process queue and
 *   persists BEFORE it is observable: concurrent creates cannot lose
 *   records, overwrite each other or duplicate ids;
 * - ids are `prj_` + `crypto.randomUUID()` — cryptographically strong,
 *   never counters; unique by construction (and guarded against the
 *   astronomically unlikely collision).
 *
 * Honest limits: single-process/single-writer, foundation-scale data.
 * That is the documented pre-database posture of this repository.
 */

/** The stored record — includes the owner; the API response never does. */
export interface ProjectRecord {
  id: string;
  ownerId: string;
  name: string;
  description: string;
  status: ProjectStatus;
  createdAt: string;
  updatedAt: string;
  dastTargetUrl?: string;
}

export interface CreateProjectInput {
  ownerId: string;
  name: string;
  description: string;
}

export interface UpdateProjectPatch {
  name?: string;
  description?: string;
}

export interface ProjectStore {
  /** Create a project (server-generated id/timestamps, status ACTIVE). */
  create(input: CreateProjectInput): Promise<ProjectRecord>;
  /**
   * All projects of one owner, deterministically ordered:
   * `updatedAt` DESC, then `id` ASC (the shared documented contract).
   */
  listByOwner(ownerId: string): Promise<ProjectRecord[]>;
  /** Bounded, account-scoped project counts/cards for the authenticated workspace overview. */
  workspaceSummary(ownerId: string): Promise<WorkspaceProjectsSummary>;
  /** Aggregate-only platform overview; exposes no owner-scoped project rows. */
  adminCounts(): Promise<{ total: number; active: number; archived: number }>;
  findById(id: string): Promise<ProjectRecord | undefined>;
  /**
   * Apply a partial update (name/description only) inside the mutation
   * queue; bumps `updatedAt` server-side. Returns the updated record or
   * `undefined` when the id is unknown.
   */
  update(id: string, patch: UpdateProjectPatch): Promise<ProjectRecord | undefined>;
  /**
   * Explicit lifecycle transition (archive/unarchive). Status changes
   * happen ONLY here — never through the generic update. Idempotent:
   * re-archiving an archived project returns it unchanged (updatedAt is
   * only bumped when the status actually changes).
   */
  setStatus(id: string, status: ProjectStatus): Promise<ProjectRecord | undefined>;
  /** Set or clear the project-associated passive DAST target. */
  setDastTargetUrl(id: string, targetUrl: string | undefined): Promise<ProjectRecord | undefined>;
}

interface StoreDocument {
  version: 1;
  projects: ProjectRecord[];
}

function isSafeProjectText(
  value: unknown,
  maxLength: number,
  allowLinebreaks: boolean,
): value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > maxLength) {
    return false;
  }
  // Control characters (C0/C1) are never stored — with ONE deliberate
  // exception: descriptions may keep tab (0x09) and newline (0x0A) so
  // multi-line text survives round-trips. This mirrors the API
  // validation layer's normalizeProjectText policy EXACTLY; this is the
  // fail-fast backstop for stored data so the store itself can never
  // hold text the API would have rejected (a mismatch would brick
  // startup after a legitimate write).
  for (const char of value) {
    const code = char.codePointAt(0) ?? 0;
    const allowed = allowLinebreaks ? code === 0x0a || code === 0x09 : false;
    if (!allowed && (code < 0x20 || code === 0x7f)) {
      return false;
    }
  }
  return true;
}

function parseStoredProject(value: unknown): ProjectRecord | undefined {
  if (typeof value !== 'object' || value === null) {
    return undefined;
  }
  const record = value as Record<string, unknown>;
  if (
    typeof record['id'] !== 'string' ||
    !PROJECT_ID_PATTERN.test(record['id']) ||
    typeof record['ownerId'] !== 'string' ||
    record['ownerId'].length === 0 ||
    !isSafeProjectText(record['name'], PROJECT_NAME_MAX_LENGTH, false) ||
    (record['description'] !== '' &&
      !isSafeProjectText(record['description'], PROJECT_DESCRIPTION_MAX_LENGTH, true)) ||
    !isProjectStatus(record['status']) ||
    (record['dastTargetUrl'] !== undefined && !isSafeDastUrl(record['dastTargetUrl'])) ||
    typeof record['createdAt'] !== 'string' ||
    Number.isNaN(Date.parse(record['createdAt'])) ||
    typeof record['updatedAt'] !== 'string' ||
    Number.isNaN(Date.parse(record['updatedAt']))
  ) {
    return undefined;
  }
  return {
    id: record['id'],
    ownerId: record['ownerId'],
    name: record['name'],
    description: record['description'],
    status: record['status'],
    ...(typeof record['dastTargetUrl'] === 'string' ? { dastTargetUrl: record['dastTargetUrl'] } : {}),
    createdAt: record['createdAt'],
    updatedAt: record['updatedAt'],
  };
}

function loadDocument(path: string): StoreDocument {
  let raw: string;
  try {
    raw = readFileSync(path, 'utf8');
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') {
      return { version: 1, projects: [] };
    }
    throw new Error(`Cannot read project store at ${path}: ${String(code ?? error)}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw) as unknown;
  } catch {
    throw new Error(
      `Project store at ${path} is not valid JSON — refusing to start with corrupt project data.`,
    );
  }
  if (
    typeof parsed !== 'object' ||
    parsed === null ||
    (parsed as Record<string, unknown>)['version'] !== 1 ||
    !Array.isArray((parsed as Record<string, unknown>)['projects'])
  ) {
    throw new Error(`Project store at ${path} has an unexpected shape — refusing to start.`);
  }
  const rawProjects = (parsed as StoreDocument).projects;
  const seenIds = new Set<string>();
  const projects: ProjectRecord[] = [];
  rawProjects.forEach((entry, index) => {
    const record = parseStoredProject(entry);
    if (record === undefined) {
      throw new Error(
        `Project store at ${path} has an invalid record at index ${index} — refusing to start.`,
      );
    }
    if (seenIds.has(record.id)) {
      throw new Error(`Project store at ${path} contains duplicate ids — refusing to start.`);
    }
    seenIds.add(record.id);
    projects.push(record);
  });
  return { version: 1, projects };
}

interface StoreInternals {
  projects: ProjectRecord[];
  /** Persist the full next state atomically (called inside the queue). */
  persistWith(projects: ProjectRecord[]): void;
}

function createProjectStoreFrom(internals: StoreInternals): ProjectStore {
  // The single mutation queue — every change is linearized here, exactly
  // like the account and usage stores.
  let queue: Promise<unknown> = Promise.resolve();
  const runExclusive = <T>(task: () => T): Promise<T> => {
    const run = queue.then(task, task);
    queue = run.catch(() => undefined);
    return run;
  };

  const byId = new Map<string, ProjectRecord>();
  for (const record of internals.projects) {
    byId.set(record.id, record);
  }

  const toPublic = (record: ProjectRecord): ProjectRecord => ({ ...record });

  return {
    create: (input) =>
      runExclusive(() => {
        const record: ProjectRecord = {
          id: `prj_${randomUUID()}`,
          ownerId: input.ownerId,
          name: input.name,
          description: input.description,
          status: 'ACTIVE',
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        };
        // Guard against the astronomically unlikely id collision.
        if (byId.has(record.id)) {
          record.id = `prj_${randomUUID()}`;
        }
        const next = [...byId.values(), record];
        // Persist first: on write failure the caller sees the error and
        // memory stays consistent with disk.
        internals.persistWith(next);
        byId.set(record.id, record);
        return toPublic(record);
      }),
    listByOwner: (ownerId) =>
      Promise.resolve(
        [...byId.values()]
          .filter((record) => record.ownerId === ownerId)
          .sort(
            (a, b) =>
              (a.updatedAt < b.updatedAt ? 1 : a.updatedAt > b.updatedAt ? -1 : a.id < b.id ? -1 : 1),
          )
          .map(toPublic),
      ),
    workspaceSummary: (ownerId) => {
      let total = 0;
      let active = 0;
      let archived = 0;
      let dastTargetsConfigured = 0;
      const recent: WorkspaceProjectCard[] = [];
      for (const record of byId.values()) {
        if (record.ownerId !== ownerId) continue;
        total += 1;
        if (record.status === 'ACTIVE') active += 1;
        else archived += 1;
        const dastTargetConfigured = record.dastTargetUrl !== undefined;
        if (dastTargetConfigured) dastTargetsConfigured += 1;
        recent.push({ id: record.id, name: record.name, status: record.status, updatedAt: record.updatedAt, dastTargetConfigured });
        recent.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt) || a.id.localeCompare(b.id));
        if (recent.length > WORKSPACE_PROJECTS_MAX) recent.pop();
      }
      return Promise.resolve({ total, active, archived, dastTargetsConfigured, recent });
    },
    adminCounts: () => {
      let active = 0;
      let archived = 0;
      for (const record of byId.values()) {
        if (record.status === 'ACTIVE') active += 1;
        else archived += 1;
      }
      return Promise.resolve({ total: byId.size, active, archived });
    },
    findById: (id) => {
      const record = byId.get(id);
      return Promise.resolve(record === undefined ? undefined : toPublic(record));
    },
    update: (id, patch) =>
      runExclusive(() => {
        const current = byId.get(id);
        if (current === undefined) {
          return undefined;
        }
        const updated: ProjectRecord = {
          ...current,
          ...(patch.name === undefined ? {} : { name: patch.name }),
          ...(patch.description === undefined ? {} : { description: patch.description }),
          updatedAt: new Date().toISOString(),
        };
        const next = [...byId.values()].map((record) => (record.id === id ? updated : record));
        internals.persistWith(next);
        byId.set(id, updated);
        return toPublic(updated);
      }),
    setStatus: (id, status) =>
      runExclusive(() => {
        const current = byId.get(id);
        if (current === undefined) {
          return undefined;
        }
        if (current.status === status) {
          return toPublic(current); // Idempotent no-op.
        }
        const updated: ProjectRecord = {
          ...current,
          status,
          updatedAt: new Date().toISOString(),
        };
        const next = [...byId.values()].map((record) => (record.id === id ? updated : record));
        internals.persistWith(next);
        byId.set(id, updated);
        return toPublic(updated);
      }),
    setDastTargetUrl: (id, targetUrl) =>
      runExclusive(() => {
        const current = byId.get(id);
        if (current === undefined) return undefined;
        if (targetUrl !== undefined && !isSafeDastUrl(targetUrl)) {
          throw new Error('Project DAST target must be a canonical safe URL.');
        }
        if (current.dastTargetUrl === targetUrl) return toPublic(current);
        const updated: ProjectRecord = { ...current, updatedAt: new Date().toISOString() };
        if (targetUrl === undefined) delete updated.dastTargetUrl;
        else updated.dastTargetUrl = targetUrl;
        const next = [...byId.values()].map((record) => (record.id === id ? updated : record));
        internals.persistWith(next);
        byId.set(id, updated);
        return toPublic(updated);
      }),
  };
}

/** Durable project store: one JSON document, atomic writes. */
export function createJsonFileProjectStore(path: string): ProjectStore {
  const document = loadDocument(path);
  const persistWith = (projects: ProjectRecord[]): void => {
    mkdirSync(dirname(path), { recursive: true });
    const payload: StoreDocument = { version: 1, projects };
    const tempPath = join(dirname(path), `.${randomBytes(6).toString('hex')}.tmp`);
    writeFileSync(tempPath, `${JSON.stringify(payload, null, 2)}\n`, { mode: 0o600 });
    renameSync(tempPath, path);
  };
  return createProjectStoreFrom({ projects: document.projects, persistWith });
}

/** In-memory project store (tests and explicit `:memory:` setups). */
export function createMemoryProjectStore(): ProjectStore {
  return createProjectStoreFrom({ projects: [], persistWith: () => undefined });
}

/** The public project shape (no ownerId) for API responses. */
export function toProjectResponse(record: ProjectRecord): Project {
  return {
    id: record.id,
    name: record.name,
    description: record.description,
    status: record.status,
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
    ...(record.dastTargetUrl === undefined ? {} : { dastTargetUrl: record.dastTargetUrl }),
  };
}
