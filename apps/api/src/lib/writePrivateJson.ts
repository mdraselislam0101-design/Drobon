import { randomBytes } from 'node:crypto';
import { closeSync, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

/** Replace one JSON document via an exclusively created private temp file.
 * Cleanup after caught I/O failures is best-effort and can itself fail;
 * SIGKILL/power loss can leave a temp file. Optional file fsync happens
 * before rename; the directory is not synced, so this is not a power-loss
 * durability guarantee, a multi-file transaction, or a multi-writer lock. */
export function writePrivateJson(path: string, serialized: string, options: {
  syncFile?: boolean;
  beforeRename?: (temporary: { dev: bigint; ino: bigint }) => void;
} = {}): void {
  mkdirSync(dirname(path), { recursive: true });
  const temporary = join(dirname(path), `.${randomBytes(6).toString('hex')}.tmp`);
  let descriptor: number | undefined;
  let owned = false;
  let identity: { dev: bigint; ino: bigint } | undefined;
  try {
    descriptor = openSync(temporary, 'wx', 0o600);
    owned = true;
    const info = fstatSync(descriptor, { bigint: true });
    identity = { dev: info.dev, ino: info.ino };
    writeFileSync(descriptor, serialized, { encoding: 'utf8' });
    if (options.syncFile === true) fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;
    // Callers may refuse publication after all pre-commit I/O succeeds.
    // This check and rename are separate syscalls, not an atomic CAS.
    options.beforeRename?.(identity);
    renameSync(temporary, path);
    owned = false;
  } finally {
    if (descriptor !== undefined) {
      try { closeSync(descriptor); } catch { /* Preserve the original failure. */ }
    }
    if (owned && identity !== undefined) {
      try {
        const current = lstatSync(temporary, { bigint: true });
        // Do not intentionally remove a different file installed after our
        // exclusive create. The stat/unlink pair is not a multi-writer lock.
        if (current.isFile() && current.dev === identity.dev && current.ino === identity.ino) unlinkSync(temporary);
      } catch { /* Preserve the original failure. */ }
    }
  }
}
