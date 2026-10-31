import { randomBytes } from 'node:crypto';
import { closeSync, fstatSync, lstatSync, mkdirSync, openSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

/** Replace one JSON document via an exclusively created private temp file.
 * Cleanup after caught I/O failures is best-effort and can itself fail;
 * SIGKILL/power loss can leave a temp file. There is no fsync, multi-file
 * transaction or multi-writer guarantee. */
export function writePrivateJson(path: string, serialized: string): void {
  mkdirSync(dirname(path), { recursive: true });
  const temporary = join(dirname(path), `.${randomBytes(6).toString('hex')}.tmp`);
  let descriptor: number | undefined;
  let owned = false;
  let identity: { dev: number; ino: number } | undefined;
  try {
    descriptor = openSync(temporary, 'wx', 0o600);
    owned = true;
    const info = fstatSync(descriptor);
    identity = { dev: info.dev, ino: info.ino };
    writeFileSync(descriptor, serialized, { encoding: 'utf8' });
    closeSync(descriptor);
    descriptor = undefined;
    renameSync(temporary, path);
    owned = false;
  } finally {
    if (descriptor !== undefined) {
      try { closeSync(descriptor); } catch { /* Preserve the original failure. */ }
    }
    if (owned && identity !== undefined) {
      try {
        const current = lstatSync(temporary);
        // Do not intentionally remove a different file installed after our
        // exclusive create. The stat/unlink pair is not a multi-writer lock.
        if (current.isFile() && current.dev === identity.dev && current.ino === identity.ino) unlinkSync(temporary);
      } catch { /* Preserve the original failure. */ }
    }
  }
}
