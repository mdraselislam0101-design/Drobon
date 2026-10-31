import { readFileSync } from 'node:fs';
import { writePrivateJson } from '../lib/writePrivateJson.js';
import {
  PROJECT_ID_PATTERN,
  SOURCE_MAX_FILES,
  SOURCE_MAX_FILE_BYTES,
  SOURCE_MAX_TOTAL_BYTES,
  isValidSourceContent,
  isValidSourcePath,
  type SourceFileInput,
  type StoredSourceFile,
  type StoredSourceSnapshot,
} from '@drobon/shared';

/**
 * Durable source-snapshot store (Pump 8) — the deterministic scan
 * TARGET of the real SAST engine, following the exact
 * minimum-persistence architecture of the account (Pump 2), usage
 * (Pump 5), project (Pump 6) and scan (Pump 7) stores:
 *
 * - one JSON document (`{ version: 1, snapshots: [...] }`), one writer,
 *   isolated behind the `SourceSnapshotStore` interface;
 * - snapshots survive restarts; a corrupt document, an invalid file
 *   path/content, an over-limit snapshot or a duplicate project entry
 *   REFUSES TO START (security state is never silently repaired);
 * - same-directory private temp+rename writes run in the serialized
 *   in-process queue; no fsync or cross-file transaction is provided;
 * - snapshots are VIRTUAL CONTENT TREES (path + text content stored in
 *   the document) — nothing is ever extracted to the filesystem, so
 *   symlink attacks are structurally impossible; paths re-validate
 *   against the shared single path policy on every load;
 * - credential-file extensions are blocked, but allowed source text may
 *   still contain secrets and is stored raw; access and retention matter.
 *
 * Replace semantics: a PUT replaces the project's whole snapshot (the
 * deterministic input the engine scans); an empty file list clears it.
 *
 * Honest limits: single-process/single-writer, foundation-scale data.
 */

/** The stored record — includes the owner; the API response never does. */
export interface SourceSnapshotRecord extends StoredSourceSnapshot {
  ownerId: string;
}

export interface ReplaceSnapshotInput {
  ownerId: string;
  projectId: string;
  /** Empty list CLEARS the project's snapshot. */
  files: SourceFileInput[];
}

export interface SourceSnapshotStore {
  /**
   * Replace (or clear) the project's snapshot. Re-validates every path
   * and content against the shared policy and the size limits — the
   * API boundary already enforced them, this is defense in depth (a
   * caller that bypassed the route still cannot store traversal-shaped
   * paths or oversized content).
   */
  replace(input: ReplaceSnapshotInput): Promise<SourceSnapshotRecord | undefined>;
  /** The project's snapshot, or `undefined` when none is attached. */
  findByProject(projectId: string): Promise<SourceSnapshotRecord | undefined>;
}

interface StoreDocument {
  version: 1;
  snapshots: SourceSnapshotRecord[];
}

/** UTF-8 byte size of stored content (the authoritative size metric). */
function byteLength(content: string): number {
  return Buffer.byteLength(content, 'utf8');
}

/**
 * Fail-fast snapshot validation — EXACTLY the policy the API boundary
 * enforces, so the store always accepts back what the API legitimately
 * wrote and refuses anything else at boot.
 */
function parseStoredSnapshot(value: unknown): SourceSnapshotRecord | undefined {
  if (typeof value !== 'object' || value === null) {
    return undefined;
  }
  const record = value as Record<string, unknown>;
  if (
    typeof record['projectId'] !== 'string' ||
    !PROJECT_ID_PATTERN.test(record['projectId']) ||
    typeof record['ownerId'] !== 'string' ||
    record['ownerId'].length === 0 ||
    !Array.isArray(record['files']) ||
    record['files'].length > SOURCE_MAX_FILES ||
    typeof record['createdAt'] !== 'string' ||
    Number.isNaN(Date.parse(record['createdAt'])) ||
    typeof record['updatedAt'] !== 'string' ||
    Number.isNaN(Date.parse(record['updatedAt']))
  ) {
    return undefined;
  }
  const seenPaths = new Set<string>();
  let totalBytes = 0;
  const files: StoredSourceFile[] = [];
  for (const entry of record['files']) {
    if (typeof entry !== 'object' || entry === null) {
      return undefined;
    }
    const file = entry as Record<string, unknown>;
    if (
      Object.keys(file).length !== 3 ||
      !isValidSourcePath(file['path']) ||
      !isValidSourceContent(file['content']) ||
      typeof file['bytes'] !== 'number' ||
      !Number.isInteger(file['bytes']) ||
      file['bytes'] < 0
    ) {
      return undefined;
    }
    if (byteLength(file['content']) > SOURCE_MAX_FILE_BYTES || file['bytes'] !== byteLength(file['content'])) {
      return undefined;
    }
    if (seenPaths.has(file['path'])) {
      return undefined;
    }
    seenPaths.add(file['path']);
    totalBytes += file['bytes'];
    files.push({ path: file['path'], bytes: file['bytes'], content: file['content'] });
  }
  if (totalBytes > SOURCE_MAX_TOTAL_BYTES) {
    return undefined;
  }
  return {
    projectId: record['projectId'],
    ownerId: record['ownerId'],
    files,
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
      return { version: 1, snapshots: [] };
    }
    throw new Error(`Cannot read source store at ${path}: ${String(code ?? error)}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw) as unknown;
  } catch {
    throw new Error(
      `Source store at ${path} is not valid JSON — refusing to start with corrupt source data.`,
    );
  }
  if (
    typeof parsed !== 'object' ||
    parsed === null ||
    (parsed as Record<string, unknown>)['version'] !== 1 ||
    !Array.isArray((parsed as Record<string, unknown>)['snapshots'])
  ) {
    throw new Error(`Source store at ${path} has an unexpected shape — refusing to start.`);
  }
  const rawSnapshots = (parsed as StoreDocument).snapshots;
  const seenProjectIds = new Set<string>();
  const snapshots: SourceSnapshotRecord[] = [];
  rawSnapshots.forEach((entry, index) => {
    const record = parseStoredSnapshot(entry);
    if (record === undefined) {
      throw new Error(
        `Source store at ${path} has an invalid snapshot at index ${index} — refusing to start.`,
      );
    }
    if (seenProjectIds.has(record.projectId)) {
      throw new Error(`Source store at ${path} contains duplicate snapshots — refusing to start.`);
    }
    seenProjectIds.add(record.projectId);
    snapshots.push(record);
  });
  return { version: 1, snapshots };
}

interface StoreInternals {
  snapshots: SourceSnapshotRecord[];
  persistWith(snapshots: SourceSnapshotRecord[]): void;
}

function createSourceStoreFrom(internals: StoreInternals): SourceSnapshotStore {
  let queue: Promise<unknown> = Promise.resolve();
  const runExclusive = <T>(task: () => T | Promise<T>): Promise<T> => {
    const run = queue.then(task, task);
    queue = run.catch(() => undefined);
    return run;
  };

  const byProject = new Map<string, SourceSnapshotRecord>();
  for (const record of internals.snapshots) {
    byProject.set(record.projectId, record);
  }

  const toPublic = (record: SourceSnapshotRecord): SourceSnapshotRecord => ({ ...record });

  return {
    replace: (input) =>
      runExclusive(() => {
        // Clear semantics: an empty file list removes the snapshot.
        if (input.files.length === 0) {
          if (!byProject.has(input.projectId)) {
            return undefined;
          }
          const next = [...byProject.values()].filter(
            (record) => record.projectId !== input.projectId,
          );
          internals.persistWith(next);
          byProject.delete(input.projectId);
          return undefined;
        }
        if (input.files.length > SOURCE_MAX_FILES) {
          throw new Error('Snapshot exceeds the file-count limit.');
        }
        const seenPaths = new Set<string>();
        const files: StoredSourceFile[] = [];
        let totalBytes = 0;
        for (const file of input.files) {
          if (!isValidSourcePath(file.path) || !isValidSourceContent(file.content)) {
            throw new Error('Snapshot contains an invalid file path or content.');
          }
          if (seenPaths.has(file.path)) {
            throw new Error('Snapshot contains duplicate file paths.');
          }
          seenPaths.add(file.path);
          const bytes = byteLength(file.content);
          if (bytes > SOURCE_MAX_FILE_BYTES) {
            throw new Error('Snapshot file exceeds the per-file size limit.');
          }
          totalBytes += bytes;
          if (totalBytes > SOURCE_MAX_TOTAL_BYTES) {
            throw new Error('Snapshot exceeds the total size limit.');
          }
          files.push({ path: file.path, bytes, content: file.content });
        }
        const previous = byProject.get(input.projectId);
        const now = new Date().toISOString();
        const record: SourceSnapshotRecord = {
          projectId: input.projectId,
          ownerId: input.ownerId,
          files,
          createdAt: previous?.createdAt ?? now,
          updatedAt: now,
        };
        const next = [
          ...[...byProject.values()].filter(
            (existing) => existing.projectId !== input.projectId,
          ),
          record,
        ];
        internals.persistWith(next);
        byProject.set(input.projectId, record);
        return toPublic(record);
      }),

    findByProject: (projectId) => {
      const record = byProject.get(projectId);
      return Promise.resolve(record === undefined ? undefined : toPublic(record));
    },
  };
}

/** Durable source snapshots: one JSON document and single-writer rename; no fsync or multi-file transaction. */
export function createJsonFileSourceStore(path: string): SourceSnapshotStore {
  const document = loadDocument(path);
  const persistWith = (snapshots: SourceSnapshotRecord[]): void => {
    const payload: StoreDocument = { version: 1, snapshots };
    writePrivateJson(path, `${JSON.stringify(payload, null, 2)}\n`);
  };
  return createSourceStoreFrom({ snapshots: document.snapshots, persistWith });
}

/** In-memory source-snapshot store (tests and `:memory:` setups). */
export function createMemorySourceStore(): SourceSnapshotStore {
  return createSourceStoreFrom({ snapshots: [], persistWith: () => undefined });
}

/**
 * The public snapshot metadata (no content, no ownerId) for API
 * responses — bounded by SOURCE_MAX_FILES by construction.
 */
export function toSourceSnapshotResponse(
  record: SourceSnapshotRecord,
): {
  snapshot: {
    projectId: string;
    fileCount: number;
    totalBytes: number;
    updatedAt: string;
    files: Array<{ path: string; bytes: number }>;
  };
} {
  return {
    snapshot: {
      projectId: record.projectId,
      fileCount: record.files.length,
      totalBytes: record.files.reduce((sum, file) => sum + file.bytes, 0),
      updatedAt: record.updatedAt,
      files: record.files.map((file) => ({ path: file.path, bytes: file.bytes })),
    },
  };
}
