/**
 * Source-snapshot contracts (Pump 8) — the deterministic scan TARGET of
 * the real SAST engine.
 *
 * A source snapshot is the set of text source files a project owner has
 * explicitly uploaded for scanning. It is a VIRTUAL CONTENT TREE stored
 * inside the application's own durable store — never an extraction to
 * the server filesystem, never a reference to server paths. The SAST
 * engine analyzes exactly this tree and nothing else (see
 * docs/SAST.md).
 *
 * Security posture:
 * - paths are STRICTLY validated: relative, ASCII, no traversal
 *   (`..`/absolute/backslash/NUL/control/percent), no dotfile segments
 *   (blocks `.env`, `.git`, …), no credential-file extensions
 *   (`.pem`/`.key`/…), bounded length and depth — the documented path
 *   charset makes traversal-shaped paths structurally unrepresentable;
 * - because snapshots are stored as CONTENT (not extracted onto disk),
 *   symlinks cannot exist inside them — the symlink-escape class is
 *   eliminated by construction, and the engine still canonicalizes and
 *   re-validates every path it resolves (defense in depth);
 * - content is TEXT-ONLY (control characters other than tab/CR/LF are
 *   rejected) and bounded per file and in total — a malicious project
 *   cannot push binary blobs or unbounded bytes through the scanner;
 * - limits are enforced at the API boundary AND re-validated when the
 *   durable store loads (corrupt/oversized state refuses to start).
 */

/** Maximum number of files in one snapshot (hard cap, both layers). */
export const SOURCE_MAX_FILES = 200;

/** Maximum UTF-8 byte size of one file's content (256 KiB). */
export const SOURCE_MAX_FILE_BYTES = 262_144;

/** Maximum total UTF-8 bytes of all file contents in one snapshot (768 KiB). */
export const SOURCE_MAX_TOTAL_BYTES = 786_432;

/** Maximum stored path length in characters. */
export const SOURCE_PATH_MAX_LENGTH = 160;

/** Maximum number of path segments (depth). */
export const SOURCE_PATH_MAX_SEGMENTS = 16;

/** Maximum number of characters in one path segment. */
export const SOURCE_PATH_MAX_SEGMENT_LENGTH = 64;

/**
 * The path charset: `segment(/segment)*` where a segment starts with an
 * ASCII letter or digit (never a dot — blocks `.env`, `.git`, `..`)
 * and continues with ASCII letters, digits, dots, underscores or
 * hyphens. No spaces, no percent signs, no backslashes, no colons, no
 * NUL — the traversal/encoding classes are unrepresentable.
 */
export const SOURCE_PATH_PATTERN =
  /^[A-Za-z0-9][A-Za-z0-9._-]*(?:\/[A-Za-z0-9][A-Za-z0-9._-]*)*$/;

/**
 * Credential-material file extensions that are never accepted into a
 * snapshot (uploading a private key or an env file for scanning would
 * move the secret INTO the application's stores — refused outright).
 * Dotfiles are already blocked by {@link SOURCE_PATH_PATTERN}.
 */
export const SOURCE_BLOCKED_EXTENSIONS = [
  '.pem',
  '.key',
  '.p12',
  '.pfx',
  '.jks',
  '.kdbx',
  '.keystore',
  '.env',
] as const;

/**
 * Full source-path validation (charset, shape, length, depth, blocked
 * extensions). Used by the API boundary, the durable store's fail-fast
 * loader and the SAST engine's defense-in-depth resolution — one
 * canonical implementation of the path policy.
 */
export function isValidSourcePath(value: unknown): value is string {
  if (typeof value !== 'string') {
    return false;
  }
  if (value.length === 0 || value.length > SOURCE_PATH_MAX_LENGTH) {
    return false;
  }
  if (!SOURCE_PATH_PATTERN.test(value)) {
    return false;
  }
  const segments = value.split('/');
  if (segments.length > SOURCE_PATH_MAX_SEGMENTS) {
    return false;
  }
  for (const segment of segments) {
    if (segment.length === 0 || segment.length > SOURCE_PATH_MAX_SEGMENT_LENGTH) {
      return false;
    }
    if (segment.startsWith('.')) {
      return false; // Unreachable via the pattern; kept for defense in depth.
    }
  }
  // Credential-material file types never enter a snapshot.
  const lowered = value.toLowerCase();
  for (const blocked of SOURCE_BLOCKED_EXTENSIONS) {
    if (lowered.endsWith(blocked)) {
      return false;
    }
  }
  return true;
}

/**
 * Text-only content rule: reject C0 control characters except tab,
 * LF, CR, and reject DEL. Binary blobs (NUL bytes, etc.) can therefore
 * never enter a snapshot or a finding's evidence.
 */
export function isValidSourceContent(value: unknown): value is string {
  if (typeof value !== 'string') {
    return false;
  }
  // Character-bound twin of the byte limits (the authoritative UTF-8
  // byte check needs Node's Buffer and lives at the API/store layers).
  if (value.length > SOURCE_MAX_FILE_BYTES) {
    return false;
  }
  for (const char of value) {
    const code = char.codePointAt(0) ?? 0;
    if (code < 0x20 && code !== 0x09 && code !== 0x0a && code !== 0x0d) {
      return false;
    }
    if (code === 0x7f) {
      return false;
    }
  }
  return true;
}

/** One file inside a snapshot, as the API accepts it (upload input). */
export interface SourceFileInput {
  path: string;
  content: string;
}

/** One file inside a snapshot, as stored (adds the UTF-8 byte size). */
export interface StoredSourceFile {
  path: string;
  bytes: number;
  content: string;
}

/** The stored snapshot record (ownerId never leaves the server). */
export interface StoredSourceSnapshot {
  projectId: string;
  files: StoredSourceFile[];
  createdAt: string;
  updatedAt: string;
}

/**
 * The public snapshot metadata (GET/PUT responses): file list WITHOUT
 * content — content is engine input, not client output. Bounded by
 * {@link SOURCE_MAX_FILES} by construction.
 */
export interface SourceSnapshotPublic {
  projectId: string;
  fileCount: number;
  totalBytes: number;
  updatedAt: string;
  files: Array<{ path: string; bytes: number }>;
}

export interface SourceSnapshotResponse {
  snapshot: SourceSnapshotPublic;
}

/** Closed-shape guard for the public snapshot metadata. */
export function isSourceSnapshotResponse(value: unknown): value is SourceSnapshotResponse {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  if (keys.length !== 1 || !isSourceSnapshotPublic(record['snapshot'])) {
    return false;
  }
  return true;
}

/** Closed-shape guard for the public snapshot metadata. */
export function isSourceSnapshotPublic(value: unknown): value is SourceSnapshotPublic {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  if (keys.length !== 5) {
    return false;
  }
  if (
    typeof record['projectId'] !== 'string' ||
    record['projectId'].length === 0 ||
    typeof record['fileCount'] !== 'number' ||
    !Number.isInteger(record['fileCount']) ||
    record['fileCount'] < 0 ||
    typeof record['totalBytes'] !== 'number' ||
    !Number.isInteger(record['totalBytes']) ||
    record['totalBytes'] < 0 ||
    typeof record['updatedAt'] !== 'string'
  ) {
    return false;
  }
  if (!Array.isArray(record['files'])) {
    return false;
  }
  if (record['files'].length !== record['fileCount']) {
    return false;
  }
  return record['files'].every((file) => {
    if (typeof file !== 'object' || file === null) {
      return false;
    }
    const fileRecord = file as Record<string, unknown>;
    return (
      Object.keys(fileRecord).length === 2 &&
      isValidSourcePath(fileRecord['path']) &&
      typeof fileRecord['bytes'] === 'number' &&
      Number.isInteger(fileRecord['bytes']) &&
      fileRecord['bytes'] >= 0
    );
  });
}
