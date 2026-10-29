import { constants, type Dirent } from 'node:fs';
import { lstat, open, opendir, realpath } from 'node:fs/promises';
import { basename, extname, isAbsolute, join, relative, sep } from 'node:path';
import {
  SOURCE_MAX_FILES, SOURCE_MAX_FILE_BYTES, SOURCE_MAX_TOTAL_BYTES, SOURCE_BLOCKED_EXTENSIONS,
  isValidSourceContent, isValidSourcePath, type SourceFileInput,
} from '@drobon/shared';
import { SAST_LANGUAGE_CATALOG } from '../../apps/api/src/scans/sast/languages.js';
import { SECRETS_SUPPORTED_EXTENSIONS } from '../../apps/api/src/scans/secrets/engine.js';

/** No target file is run, installed, followed through a symlink, or uploaded. */
const SKIP_DIRS = new Set(['.git', 'node_modules', 'vendor', 'dist', 'build', 'out', 'target', 'coverage', '.cache', '.next', '.venv']);
const MAX_VISITED_ENTRIES = 20_000;
const MAX_BATCHES = 10;
const SCA_FILENAMES = new Set(['package.json', 'package-lock.json', 'requirements.txt', 'pyproject.toml', 'go.mod', 'go.sum', 'gemfile.lock', 'cargo.lock', 'yarn.lock', 'pnpm-lock.yaml']);
const CANDIDATE_EXTENSIONS = new Set([
  ...SAST_LANGUAGE_CATALOG.flatMap((family) => family.extensions ?? []),
  ...SECRETS_SUPPORTED_EXTENSIONS,
]);
const CANDIDATE_NAMES = new Set(SAST_LANGUAGE_CATALOG.flatMap((family) => family.filenames ?? []));

export interface CollectedSources {
  batches: SourceFileInput[][];
  candidateFiles: number;
  visitedEntries: number;
  /** Counts only; no source content or credential values are exposed. */
  omitted: { invalidPath: number; sensitiveOrHidden: number; symlink: number; oversized: number; nonText: number; capacity: number };
}

function candidate(path: string): boolean {
  const name = basename(path).toLowerCase();
  return SCA_FILENAMES.has(name) || CANDIDATE_NAMES.has(name) || CANDIDATE_EXTENSIONS.has(extname(name));
}

function contained(root: string, full: string): boolean {
  const rel = relative(root, full);
  return rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel);
}

/**
 * Produce bounded virtual snapshots using the same shared source policy as the
 * app. Splitting preserves relative paths but cannot preserve every cross-file
 * flow or join all manifest/lockfile pairs across batches; callers must mark
 * multi-batch analyses as partial. Hidden and key files are never read.
 */
export async function collectSources(rootPath: string): Promise<CollectedSources> {
  const root = await realpath(rootPath);
  const stat = await lstat(root);
  if (!stat.isDirectory()) throw new TypeError('The scan root must be a directory.');
  const result: CollectedSources = {
    batches: [], candidateFiles: 0, visitedEntries: 0,
    omitted: { invalidPath: 0, sensitiveOrHidden: 0, symlink: 0, oversized: 0, nonText: 0, capacity: 0 },
  };
  const pending = [''];
  const paths: string[] = [];
  while (pending.length > 0) {
    const directory = pending.pop();
    if (directory === undefined) break;
    const entries: Dirent[] = [];
    let capacityReached = false;
    try {
      const handle = await opendir(join(root, directory));
      for await (const entry of handle) {
        // Bound even one extremely wide directory before retaining entries.
        if (result.visitedEntries + entries.length >= MAX_VISITED_ENTRIES) {
          result.omitted.capacity += 1;
          capacityReached = true;
          pending.length = 0;
          break;
        }
        entries.push(entry);
      }
    } catch { result.omitted.capacity += 1; continue; }
    entries.sort((a, b) => a.name.localeCompare(b.name, 'en'));
    for (const entry of entries) {
      result.visitedEntries += 1;
      const path = directory.length === 0 ? entry.name : `${directory}/${entry.name}`;
      if (entry.isSymbolicLink()) { result.omitted.symlink += 1; continue; }
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name.toLowerCase())) continue;
        if (entry.name.startsWith('.')) { result.omitted.sensitiveOrHidden += 1; continue; }
        if (!isValidSourcePath(path)) { result.omitted.invalidPath += 1; continue; }
        pending.push(path);
      } else if (entry.isFile()) {
        const lowerName = entry.name.toLowerCase();
        if (entry.name.startsWith('.')) {
          if (lowerName.startsWith('.env') || ['.npmrc', '.yarnrc', '.yarnrc.yml', '.pypirc', '.gitlab-ci.yml'].includes(lowerName) || candidate(entry.name)) result.omitted.sensitiveOrHidden += 1;
          continue;
        }
        if (SOURCE_BLOCKED_EXTENSIONS.some((ext) => lowerName.endsWith(ext))) { result.omitted.sensitiveOrHidden += 1; continue; }
        if (!candidate(path)) continue;
        result.candidateFiles += 1;
        if (!isValidSourcePath(path)) { result.omitted.invalidPath += 1; continue; }
        paths.push(path);
      }
    }
    if (capacityReached) pending.length = 0;
  }
  paths.sort();
  let batch: SourceFileInput[] = [];
  let batchBytes = 0;
  for (const path of paths) {
    if (result.batches.length >= MAX_BATCHES) { result.omitted.capacity += 1; continue; }
    let file;
    try {
      const full = join(root, path);
      const canonical = await realpath(full);
      if (!contained(root, canonical) || canonical !== full) { result.omitted.symlink += 1; continue; }
      file = await open(full, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
      const metadata = await file.stat();
      if (!metadata.isFile()) { result.omitted.symlink += 1; continue; }
      if (metadata.size > SOURCE_MAX_FILE_BYTES) { result.omitted.oversized += 1; continue; }
      // A file can grow between stat and read. Never allocate/read more than
      // one byte beyond the shared cap, even under a concurrent replacement.
      const buffer = Buffer.alloc(SOURCE_MAX_FILE_BYTES + 1);
      let length = 0;
      while (length < buffer.length) {
        const part = await file.read(buffer, length, buffer.length - length, null);
        if (part.bytesRead === 0) break;
        length += part.bytesRead;
      }
      if (length > SOURCE_MAX_FILE_BYTES) { result.omitted.oversized += 1; continue; }
      const bytes = buffer.subarray(0, length);
      let content: string;
      try { content = new TextDecoder('utf-8', { fatal: true }).decode(bytes); }
      catch { result.omitted.nonText += 1; continue; }
      if (!isValidSourceContent(content)) { result.omitted.nonText += 1; continue; }
      if (batch.length >= SOURCE_MAX_FILES || batchBytes + bytes.length > SOURCE_MAX_TOTAL_BYTES) {
        result.batches.push(batch);
        batch = [];
        batchBytes = 0;
      }
      if (result.batches.length >= MAX_BATCHES) { result.omitted.capacity += 1; continue; }
      batch.push({ path, content });
      batchBytes += bytes.length;
    } catch {
      result.omitted.nonText += 1;
    } finally {
      await file?.close();
    }
  }
  if (batch.length > 0) result.batches.push(batch);
  return result;
}
