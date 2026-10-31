import { createHash } from 'node:crypto';
import { realpathSync } from 'node:fs';
import { createServer, type Server } from 'node:net';
import { basename, dirname, join, resolve } from 'node:path';

/**
 * A best-effort local guard for the standard HTTP runtime, not a distributed
 * lock. Linux abstract sockets are scoped to the network namespace. Direct
 * store/createApp users, injected stores, other namespaces/hosts, hard links,
 * and hostile filesystem aliases are outside this guard. No lockfiles are
 * created and the kernel releases these leases on process exit or SIGKILL.
 */
export interface JsonStoreLeases {
  readonly guarded: boolean;
  release(): Promise<void>;
}

function canonicalPath(path: string): string {
  const absolute = resolve(path);
  let parent = dirname(absolute);
  const suffix = [basename(absolute)];
  for (;;) {
    try { return join(realpathSync(parent), ...suffix); }
    catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code !== 'ENOENT' && code !== 'ENOTDIR') throw new Error('Cannot resolve a configured JSON store directory.');
      const next = dirname(parent);
      if (next === parent) throw new Error('Cannot resolve a configured JSON store directory.');
      suffix.unshift(basename(parent));
      parent = next;
    }
  }
}

function bind(name: string): Promise<Server> {
  return new Promise((resolveServer, reject) => {
    const server = createServer();
    const onError = (error: NodeJS.ErrnoException): void => {
      reject(new Error(error.code === 'EADDRINUSE'
        ? 'A configured JSON store is already owned by another local server.'
        : 'Cannot acquire a local JSON store lease.'));
    };
    server.once('error', onError);
    server.listen({ path: name, exclusive: true }, () => {
      server.off('error', onError);
      // An unexpected later socket error remains fatal: silently losing a
      // lease while continuing to write would be unsafe.
      server.unref();
      resolveServer(server);
    });
  });
}

function close(server: Server): Promise<void> {
  return new Promise((resolveClose) => server.close(() => resolveClose()));
}

/** Acquire every configured default-store path before opening any store. */
export async function acquireJsonStoreLeases(paths: readonly string[]): Promise<JsonStoreLeases> {
  const canonical = paths.filter((path) => path !== ':memory:').map(canonicalPath);
  if (new Set(canonical).size !== canonical.length) {
    throw new Error('Distinct JSON stores must not share the same configured path.');
  }
  if (process.platform !== 'linux' || canonical.length === 0) {
    return { guarded: canonical.length === 0, release: async () => undefined };
  }
  const servers: Server[] = [];
  try {
    // Stable ordering and explicit rollback avoid leaving partial acquisitions.
    for (const path of canonical.sort()) {
      const digest = createHash('sha256').update(path).digest('hex');
      servers.push(await bind(`\0drobon-json-${digest}`));
    }
  } catch (error) {
    await Promise.all(servers.map(close));
    throw error;
  }
  let released = false;
  return {
    guarded: true,
    release: async () => {
      if (released) return;
      released = true;
      await Promise.all(servers.map(close));
    },
  };
}
