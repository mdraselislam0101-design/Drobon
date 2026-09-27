import type { UserRepository, UserRecord } from './repositories.js';

/**
 * Process-local user repository. Two uses:
 *
 * 1. Tests (the HTTP suite runs against it by default), and
 * 2. Explicitly ephemeral setups via `AUTH_STORE_PATH=:memory:` — which
 *    `loadConfig` REJECTS in production, so accounts can never silently
 *    become non-durable in a real deployment.
 *
 * Uniqueness is enforced under an in-process lock, mirroring the durable
 * repository's semantics.
 */
export function createMemoryUserRepository(): UserRepository {
  const byEmail = new Map<string, UserRecord>();
  const byId = new Map<string, UserRecord>();
  let queue: Promise<unknown> = Promise.resolve();

  const runExclusive = async <T>(task: () => T): Promise<T> => {
    const run = queue.then(task, task);
    queue = run.catch(() => undefined);
    return run;
  };

  return {
    create: (record) =>
      runExclusive(() => {
        if (byEmail.has(record.email)) {
          return false;
        }
        byEmail.set(record.email, record);
        byId.set(record.id, record);
        return true;
      }),
    findByEmail: (email) => runExclusive(() => byEmail.get(email)),
    findById: (id) => runExclusive(() => byId.get(id)),
  };
}
