import { createHash } from 'node:crypto';
import { closeSync, fstatSync, lstatSync, mkdirSync, openSync, readFileSync, rmdirSync, statSync, type BigIntStats } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { writePrivateJson } from './writePrivateJson.js';

interface FileIdentity { dev: bigint; ino: bigint }
export interface JsonFileSnapshot extends FileIdentity { bytes: Buffer; digest: string }
/** A non-file obstruction blocks writes, but may be removed without replacing the validated file. */
export class JsonStorePathUnavailableError extends Error {
  constructor() { super('JSON store path is not a regular file.'); this.name = 'JsonStorePathUnavailableError'; }
}

// Register only file stores actually constructed by this module's callers.
// Wrapped/third-party stores are opaque and still need external coordination.
const knownStorePaths = new WeakMap<object, string>();
export function registerJsonFileStore<T extends object>(store: T, path: string): T {
  knownStorePaths.set(store, path);
  return store;
}
export function knownJsonFileStorePath(store: object): string | undefined {
  return knownStorePaths.get(store);
}

function digest(bytes: Buffer | string): string {
  return createHash('sha256').update(bytes).digest('hex');
}
function sameIdentity(a: FileIdentity, b: FileIdentity): boolean {
  return a.dev === b.dev && a.ino === b.ino;
}

/** Read and identify one stable pathname snapshot; this is not an authenticated checksum. */
export function readJsonFileSnapshot(path: string): JsonFileSnapshot | undefined {
  let descriptor: number;
  try { descriptor = openSync(path, 'r'); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
    throw error;
  }
  try {
    const before = fstatSync(descriptor, { bigint: true });
    if (!before.isFile()) throw new JsonStorePathUnavailableError();
    const bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor, { bigint: true });
    const current = statSync(path, { bigint: true });
    if (!current.isFile() || !sameIdentity(before, after) || !sameIdentity(after, current) ||
        before.size !== after.size || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs ||
        after.size !== current.size || after.mtimeNs !== current.mtimeNs || after.ctimeNs !== current.ctimeNs ||
        BigInt(bytes.length) !== after.size) {
      throw new Error('JSON store changed while being read.');
    }
    return { bytes, digest: digest(bytes), dev: after.dev, ino: after.ino };
  } finally { closeSync(descriptor); }
}

/**
 * Fail-closed guard for cooperating store instances sharing one local
 * filesystem path. The private directory is an exclusive advisory lock,
 * NOT mandatory: old or uncooperative writers can ignore it. Its atomic
 * mkdir semantics depend on the filesystem. A crashed writer may leave it
 * behind; it is never automatically removed. SHA-256 plus inode identity
 * detect changes, not malicious authentication, and the pre-rename check
 * cannot eliminate a TOCTOU race against an uncooperative writer.
 */
export function createJsonFileWriteFence(path: string, initial: JsonFileSnapshot | undefined, label: 'Scan' | 'Assessment') {
  let expected: (FileIdentity & { digest: string }) | undefined = initial === undefined ? undefined
    : { dev: initial.dev, ino: initial.ino, digest: initial.digest };
  let fenced = false;
  const lockPath = join(dirname(path), `.${basename(path)}.drobon-write-lock`);
  const deny = (): never => {
    fenced = true;
    throw new Error(`${label} store changed or writer ownership was lost; this writer is fenced.`);
  };
  const assertCurrent = (): void => {
    if (fenced) deny();
    let current: JsonFileSnapshot | undefined;
    try { current = readJsonFileSnapshot(path); }
    catch (error) {
      // A directory obstruction is not accepted as a document. It blocks
      // all writes/probe starts, but a restored identical file can be retried.
      if (error instanceof JsonStorePathUnavailableError) throw error;
      return deny();
    }
    if ((current === undefined) !== (expected === undefined) ||
        (current !== undefined && expected !== undefined &&
          (current.digest !== expected.digest || !sameIdentity(current, expected)))) deny();
  };
  const acquire = (): { assertOwned: () => void; release: () => void } => {
    if (fenced) deny();
    mkdirSync(dirname(path), { recursive: true });
    try { mkdirSync(lockPath, { mode: 0o700 }); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'EEXIST') {
        throw new Error(`${label} store write lock is held or requires reviewed recovery.`);
      }
      throw error;
    }
    let identity: FileIdentity | undefined;
    let released = false;
    const release = (): void => {
      if (released) return;
      released = true;
      let removed = false;
      try {
        const current = lstatSync(lockPath, { bigint: true });
        if (identity !== undefined && current.isDirectory() && sameIdentity(current, identity)) {
          rmdirSync(lockPath); // only our empty lock directory, never a replaced or nonempty entry
          removed = true;
        }
      } catch { /* Never turn an already-published write into a rollback. */ }
      if (!removed) fenced = true;
    };
    try {
      const created = lstatSync(lockPath, { bigint: true });
      if (!created.isDirectory()) return deny();
      identity = { dev: created.dev, ino: created.ino };
      const assertOwned = (): void => {
        let current: BigIntStats;
        try { current = lstatSync(lockPath, { bigint: true }); } catch { return deny(); }
        if (!current.isDirectory() || !sameIdentity(current, identity!)) deny();
      };
      assertOwned();
      assertCurrent();
      return { assertOwned, release };
    } catch (error) { release(); throw error; }
  };
  const withLock = <T>(action: (assertOwned: () => void) => T): T => {
    const lock = acquire();
    try { return action(lock.assertOwned); } finally { lock.release(); }
  };
  return {
    assertCurrent,
    // Best-effort preflight avoids quota reservation when a lock is already
    // visible. Persist still rechecks under the lock after any reservation.
    assertAvailable: (): void => {
      assertCurrent();
      try { lstatSync(lockPath); }
      catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'ENOENT') return;
        return deny();
      }
      throw new Error(`${label} store write lock is held or requires reviewed recovery.`);
    },
    get fenced(): boolean { return fenced; },
    /** The synchronous action must not await network I/O while holding the lock. */
    withCurrent: <T>(action: () => T): T => withLock(() => action()),
    /** For existing assessment transactions; callers must bound what the action awaits. */
    withCurrentAsync: async <T>(action: () => Promise<T>): Promise<T> => {
      const lock = acquire();
      try { return await action(); } finally { lock.release(); }
    },
    persist: (serialized: string): void => withLock((assertOwned) => {
      const nextDigest = digest(serialized);
      let nextIdentity!: FileIdentity;
      writePrivateJson(path, serialized, { syncFile: true, beforeRename: (temporary) => {
        assertOwned();
        assertCurrent();
        nextIdentity = temporary;
      } });
      // After rename succeeds do not perform fallible I/O here: callers may
      // otherwise incorrectly compensate quota for an already-published job.
      expected = { ...nextIdentity, digest: nextDigest };
    }),
  };
}
