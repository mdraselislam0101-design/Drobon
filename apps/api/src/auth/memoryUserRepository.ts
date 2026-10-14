import type { UserRepository, UserRecord } from './repositories.js';
import { buildAdminAccountCounts, buildAdminAccountPage } from './adminProjection.js';

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
    activatePro: (id, at) => runExclusive(() => {
      const current = byId.get(id);
      if (current === undefined) return 'NOT_FOUND' as const;
      if (current.subscription?.plan === 'PRO' && current.subscription.status === 'ACTIVE') return 'ALREADY_ACTIVE' as const;
      const updated: UserRecord = {
        ...current,
        subscription: { plan: 'PRO', status: 'ACTIVE', createdAt: at, updatedAt: at },
      };
      byId.set(id, updated);
      byEmail.set(updated.email, updated);
      return 'ACTIVATED' as const;
    }),
    setUserType: (id, userType) => runExclusive(() => {
      const current = byId.get(id);
      if (current === undefined) return undefined;
      // Classification-only: every other field is carried over untouched.
      const updated: UserRecord = { ...current, userType };
      byId.set(id, updated);
      byEmail.set(updated.email, updated);
      return updated;
    }),
    adminPage: (filters, page, pageSize) => Promise.resolve(buildAdminAccountPage(byId.values(), filters, page, pageSize)),
    adminCounts: () => Promise.resolve(buildAdminAccountCounts(byId.values())),
  };
}
