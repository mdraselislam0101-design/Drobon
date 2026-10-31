import { constants } from 'node:fs';
import { lstat, open, opendir, realpath } from 'node:fs/promises';
import { createHash, type Hash } from 'node:crypto';
import { isAbsolute, join, relative, sep } from 'node:path';
import type { SourceSnapshotRecord } from '../scans/sources.js';

/**
 * Agent-only safety snapshot. This is NOT a Dataset signature or trusted
 * identity: it detects changes to the configured rules/intelligence tree
 * between bounded checks. No Dataset file is written or copied.
 *
 * A live mutable filesystem cannot provide a fully atomic snapshot. The
 * caller checks this digest around loading and execution and fails closed on
 * differences; an operator must still supply an immutable, read-only mount.
 */
const LIMITS = {
  entries: 50_000,
  files: 20_000,
  depth: 16,
  fileBytes: 2 * 1024 * 1024,
  totalBytes: 64 * 1024 * 1024,
} as const;

function add(hash: Hash, value: string | Buffer): void {
  const bytes = typeof value === 'string' ? Buffer.from(value, 'utf8') : value;
  const length = Buffer.allocUnsafe(8);
  length.writeBigUInt64BE(BigInt(bytes.length));
  hash.update(length).update(bytes);
}

function checkAbort(signal?: AbortSignal): void {
  if (signal?.aborted === true) throw new Error('Snapshot check cancelled.');
}

function inside(root: string, path: string): boolean {
  const value = relative(root, path);
  return value !== '..' && !value.startsWith(`..${sep}`) && !isAbsolute(value);
}

interface SnapshotState {
  entries: number;
  files: number;
  bytes: number;
  hash: Hash;
  root: string;
  signal?: AbortSignal;
}

async function visit(path: string, state: SnapshotState, depth: number): Promise<void> {
  checkAbort(state.signal);
  if (depth > LIMITS.depth || !inside(state.root, path)) throw new Error('Dataset snapshot boundary exceeded.');
  const info = await lstat(path);
  if (info.isSymbolicLink()) throw new Error('Dataset snapshot contains a symbolic link.');
  const name = relative(state.root, path).split(sep).join('/');
  if (info.isDirectory()) {
    add(state.hash, `D:${name}`);
    const names: string[] = [];
    const dir = await opendir(path);
    for await (const entry of dir) {
      state.entries += 1;
      if (state.entries > LIMITS.entries) throw new Error('Dataset snapshot entry limit exceeded.');
      names.push(entry.name);
    }
    names.sort();
    for (const child of names) await visit(join(path, child), state, depth + 1);
    return;
  }
  if (!info.isFile()) throw new Error('Dataset snapshot contains an unsupported entry.');
  // The existing Dataset loader reads JSON only; still count every entry and
  // inspect every directory/symlink so a hidden unsafe entry is not ignored.
  if (!path.endsWith('.json')) return;
  state.files += 1;
  if (state.files > LIMITS.files || info.size > LIMITS.fileBytes || info.size < 0) {
    throw new Error('Dataset snapshot file limit exceeded.');
  }
  state.bytes += info.size;
  if (state.bytes > LIMITS.totalBytes) throw new Error('Dataset snapshot byte limit exceeded.');
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await file.stat();
    if (!before.isFile() || before.dev !== info.dev || before.ino !== info.ino || before.size !== info.size) {
      throw new Error('Dataset snapshot file changed.');
    }
    // Read at most the bounded initial size plus one byte: a concurrently
    // growing file must not make readFile allocate an unbounded buffer.
    const buffer = Buffer.alloc(before.size + 1);
    let offset = 0;
    while (offset < buffer.length) {
      checkAbort(state.signal);
      const result = await file.read(buffer, offset, buffer.length - offset, offset);
      if (result.bytesRead === 0) break;
      offset += result.bytesRead;
    }
    const after = await file.stat();
    if (offset !== before.size || before.size !== after.size || before.mtimeMs !== after.mtimeMs ||
        before.ctimeMs !== after.ctimeMs || before.ino !== after.ino || before.dev !== after.dev) {
      throw new Error('Dataset snapshot file changed.');
    }
    add(state.hash, `F:${name}`);
    add(state.hash, buffer.subarray(0, offset));
  } finally {
    await file.close();
  }
}

/** Digest the configured Dataset's scanner packs and vulnerability intelligence. */
export async function digestDataset(path: string | undefined, signal?: AbortSignal): Promise<string> {
  if (path === undefined || path.length === 0) throw new Error('Dataset is not configured.');
  checkAbort(signal);
  const root = await realpath(path);
  const rootInfo = await lstat(root);
  if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) throw new Error('Dataset root is unavailable.');
  const hash = createHash('sha256');
  add(hash, 'drobon-agent-dataset-snapshot-v1');
  // A replaced/unmounted root is different even if another tree has equal bytes.
  add(hash, `${rootInfo.dev}:${rootInfo.ino}`);
  const state: SnapshotState = { entries: 0, files: 0, bytes: 0, hash, root, ...(signal === undefined ? {} : { signal }) };
  await visit(join(root, 'packs'), state, 0); // required
  const intel = join(root, 'vuln-intel');
  try {
    await lstat(intel);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    add(hash, 'NO_VULN_INTEL_DIRECTORY');
    const finalRoot = await realpath(path);
    const finalInfo = await lstat(finalRoot);
    if (finalRoot !== root || finalInfo.dev !== rootInfo.dev || finalInfo.ino !== rootInfo.ino) throw new Error('Dataset root changed.');
    checkAbort(signal);
    return hash.digest('hex');
  }
  await visit(intel, state, 0);
  const finalRoot = await realpath(path);
  const finalInfo = await lstat(finalRoot);
  if (finalRoot !== root || finalInfo.dev !== rootInfo.dev || finalInfo.ino !== rootInfo.ino) throw new Error('Dataset root changed.');
  checkAbort(signal);
  return hash.digest('hex');
}

/** Stable, private fingerprint over exactly the uploaded virtual source tree. */
export function digestSource(snapshot: SourceSnapshotRecord): string {
  const hash = createHash('sha256');
  add(hash, 'drobon-agent-source-snapshot-v1');
  for (const file of [...snapshot.files].sort((a, b) => a.path.localeCompare(b.path))) {
    add(hash, file.path);
    add(hash, file.content);
  }
  return hash.digest('hex');
}
