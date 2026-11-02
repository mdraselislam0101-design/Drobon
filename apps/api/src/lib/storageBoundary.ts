import { lstatSync, readdirSync, readFileSync, readlinkSync, realpathSync } from 'node:fs';
import { dirname, join, resolve, sep } from 'node:path';

/**
 * Fail-closed attestation of the filesystem boundary around a protected JSON
 * store. This is an *authorization* gate, not a filesystem sandbox: it can
 * prove that the running process owns an owner-only directory whose ancestors
 * cannot be replaced by another identity, and that no other local process is
 * currently holding the document (or its directory) write-open. It cannot
 * stop a foreign process that shares this effective UID and opens the path
 * later; only a separate OS identity (or equivalent enforced isolation) can.
 *
 * Therefore the Agent stays disabled unless this verdict is STORAGE_READY,
 * and a blocked verdict must be reported as STORAGE BLOCKED instead of
 * silently degrading.
 */

export const STORAGE_READY = 'STORAGE_READY' as const;
export const STORAGE_BLOCKED = 'STORAGE_BLOCKED' as const;
export const STORAGE_UNSUPPORTED = 'STORAGE_UNSUPPORTED' as const;

export type StorageBoundaryCode =
  | typeof STORAGE_READY
  | typeof STORAGE_BLOCKED
  | typeof STORAGE_UNSUPPORTED;

/** Stable, non-secret reason codes (never include a path or errno text). */
export type StorageBoundaryIssue =
  | 'platform-not-posix'
  | 'path-not-absolute'
  | 'ancestor-symlink'
  | 'ancestor-not-directory'
  | 'ancestor-world-writable'
  | 'ancestor-group-writable'
  | 'directory-owner-mismatch'
  | 'directory-group-writable'
  | 'directory-world-writable'
  | 'store-symlink'
  | 'store-not-regular'
  | 'store-hard-linked'
  | 'store-owner-mismatch'
  | 'store-group-accessible'
  | 'foreign-writer-process'
  | 'process-scan-inconclusive'
  | 'opaque-injected-adapter';

export interface StorageBoundaryVerdict {
  code: StorageBoundaryCode;
  ok: boolean;
  issues: StorageBoundaryIssue[];
  /** Number of distinct foreign process ids observed, never their details. */
  foreignWriterCount: number;
}

export interface StorageBoundaryOptions {
  /** Effective UID expected to own the protected directory and document. */
  euid?: number;
  platform?: NodeJS.Platform;
  /** Disable the /proc writer scan only for non-Linux test platforms. */
  scanForeignWriters?: boolean;
}

function modeOf(stat: { mode: bigint }): number {
  return Number(stat.mode & 0o7777n);
}

/** Ancestor chain from the filesystem root to (and including) `directory`. */
function ancestorChain(directory: string): string[] {
  const parts = resolve(directory).split(sep).filter((part) => part.length > 0);
  const chain: string[] = [sep];
  let current: string = sep;
  for (const part of parts) {
    current = join(current, part);
    chain.push(current);
  }
  return chain;
}

/**
 * A sticky world-writable directory (e.g. `/tmp`) may host the store's own
 * private subdirectory: the sticky bit stops other identities from renaming or
 * deleting entries they do not own. Every other group/world-writable ancestor
 * would let a foreign writer replace the private directory itself.
 */
function inspectAncestors(
  directory: string, issues: StorageBoundaryIssue[],
): void {
  for (const ancestor of ancestorChain(directory)) {
    let stat;
    try { stat = lstatSync(ancestor, { bigint: true }); }
    catch { issues.push('ancestor-not-directory'); continue; }
    if (stat.isSymbolicLink()) { issues.push('ancestor-symlink'); continue; }
    if (!stat.isDirectory()) { issues.push('ancestor-not-directory'); continue; }
    const mode = modeOf(stat);
    const sticky = (mode & 0o1000) !== 0;
    if ((mode & 0o002) !== 0 && !sticky) issues.push('ancestor-world-writable');
    if ((mode & 0o020) !== 0 && !sticky) issues.push('ancestor-group-writable');
  }
}

/** Inspect one store document path without opening it for reading or writing. */
export function inspectStorePath(
  path: string, options: StorageBoundaryOptions = {},
): StorageBoundaryIssue[] {
  const issues: StorageBoundaryIssue[] = [];
  const euid = options.euid ?? (typeof process.geteuid === 'function' ? process.geteuid() : -1);
  if (!path.startsWith(sep)) { issues.push('path-not-absolute'); return issues; }
  const directory = dirname(resolve(path));

  let directoryStat;
  try { directoryStat = lstatSync(directory, { bigint: true }); }
  catch { issues.push('ancestor-not-directory'); return issues; }
  if (directoryStat.isSymbolicLink()) issues.push('ancestor-symlink');
  else if (!directoryStat.isDirectory()) issues.push('ancestor-not-directory');
  else {
    const mode = modeOf(directoryStat);
    if (mode & 0o020) issues.push('directory-group-writable');
    if (mode & 0o002) issues.push('directory-world-writable');
    if (euid >= 0 && Number(directoryStat.uid) !== euid) issues.push('directory-owner-mismatch');
  }
  inspectAncestors(directory, issues);

  let fileStat;
  try { fileStat = lstatSync(path, { bigint: true }); }
  catch { return issues; } // Absent is allowed: the first atomic write creates it 0600.
  if (fileStat.isSymbolicLink()) issues.push('store-symlink');
  else if (!fileStat.isFile()) issues.push('store-not-regular');
  else {
    if (fileStat.nlink !== 1n) issues.push('store-hard-linked');
    if (euid >= 0 && Number(fileStat.uid) !== euid) issues.push('store-owner-mismatch');
    // Owner-only: no group/other bits at all.
    if ((modeOf(fileStat) & 0o077) !== 0) issues.push('store-group-accessible');
  }
  return issues;
}

function readOwnerUid(pid: number): number | undefined {
  try {
    const status = readFileSync(`/proc/${pid}/status`, 'utf8');
    const match = status.match(/^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$/m);
    return match === null ? undefined : Number(match[1]);
  } catch { return undefined; }
}

/**
 * Linux-only observation of other processes that currently hold a target (or
 * its directory) write-open. Only same-UID processes are inspected: a
 * different UID is already stopped by the directory mode. Descriptor numbers
 * and paths are never returned; only counts and pids of *other* processes.
 */
export function findForeignWriters(
  paths: readonly string[], options: { euid?: number } = {},
): { pids: number[]; inconclusive: boolean } {
  const euid = options.euid ?? (typeof process.geteuid === 'function' ? process.geteuid() : -1);
  const targets = new Set<string>();
  for (const path of paths) {
    const absolute = resolve(path);
    targets.add(absolute);
    try { targets.add(realpathSync(absolute)); } catch { /* Absent: only the absolute form exists. */ }
    const directory = dirname(absolute);
    targets.add(directory);
    try { targets.add(realpathSync(directory)); } catch { /* Parent is checked separately. */ }
  }
  let entries: string[];
  try { entries = readdirSync('/proc'); }
  catch { return { pids: [], inconclusive: true }; }
  const self = process.pid;
  const offenders = new Set<number>();
  let inconclusive = false;
  for (const entry of entries) {
    if (!/^\d+$/.test(entry)) continue;
    const pid = Number(entry);
    if (pid === self) continue;
    const uid = readOwnerUid(pid);
    if (uid === undefined) continue;
    if (uid !== euid) continue; // Already outside this identity's reach.
    let fds: string[];
    try { fds = readdirSync(`/proc/${pid}/fd`); } catch { continue; }
    for (const fd of fds) {
      let target: string;
      try { target = readlinkSync(`/proc/${pid}/fd/${fd}`); } catch { continue; }
      const normalized = target.endsWith(' (deleted)') ? target.slice(0, -' (deleted)'.length) : target;
      if (!targets.has(normalized)) continue;
      // /proc/<pid>/fdinfo/<fd> exposes the open flags in octal.
      try {
        const info = readFileSync(`/proc/${pid}/fdinfo/${fd}`, 'utf8');
        const flags = info.match(/^flags:\s+([0-7]+)$/m);
        if (flags === null) { inconclusive = true; continue; }
        const access = Number.parseInt(flags[1] ?? '0', 8) & 0o3; // O_RDONLY=0, O_WRONLY=1, O_RDWR=2
        if (access === 1 || access === 2) offenders.add(pid);
      } catch { inconclusive = true; }
    }
  }
  return { pids: [...offenders].sort((a, b) => a - b), inconclusive };
}

/**
 * Attest the whole Agent-write boundary. Every durable store the Agent can
 * mutate must pass; a single issue blocks the verdict.
 */
export function attestAgentStorage(
  paths: readonly string[], options: StorageBoundaryOptions = {},
): StorageBoundaryVerdict {
  const platform = options.platform ?? process.platform;
  if (platform !== 'linux' && platform !== 'darwin' && platform !== 'freebsd') {
    return { code: STORAGE_UNSUPPORTED, ok: false, issues: ['platform-not-posix'], foreignWriterCount: 0 };
  }
  const durable = paths.filter((path) => path !== ':memory:');
  const issues: StorageBoundaryIssue[] = [];
  for (const path of durable) issues.push(...inspectStorePath(path, options));
  let foreignWriterCount = 0;
  if (platform === 'linux' && options.scanForeignWriters !== false && durable.length > 0) {
    const found = findForeignWriters(durable, options);
    foreignWriterCount = found.pids.length;
    if (found.pids.length > 0) issues.push('foreign-writer-process');
    if (found.inconclusive) issues.push('process-scan-inconclusive');
  }
  const unique = [...new Set(issues)];
  return {
    code: unique.length === 0 ? STORAGE_READY : STORAGE_BLOCKED,
    ok: unique.length === 0,
    issues: unique,
    foreignWriterCount,
  };
}

export class StorageBlockedError extends Error {
  readonly issues: StorageBoundaryIssue[];
  constructor(issues: readonly StorageBoundaryIssue[]) {
    super('STORAGE BLOCKED: the Agent storage boundary is not attested; execution stays disabled.');
    this.name = 'StorageBlockedError';
    this.issues = [...issues];
  }
}
