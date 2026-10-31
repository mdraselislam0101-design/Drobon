/** Serialize commercial account mutations within this single-writer process.
 * Durable recovery still handles crashes; this lock only prevents payment and
 * partner activation from racing each other while the process is running. */
export type AccountMutationLock = <T>(accountId: string, task: () => Promise<T>) => Promise<T>;

export function createAccountMutationLock(): AccountMutationLock {
  const tails = new Map<string, Promise<void>>();
  return async <T>(accountId: string, task: () => Promise<T>): Promise<T> => {
    const prior = tails.get(accountId) ?? Promise.resolve();
    let release!: () => void;
    const held = new Promise<void>((resolve) => { release = resolve; });
    const tail = prior.then(() => held, () => held);
    tails.set(accountId, tail);
    await prior.catch(() => undefined);
    try {
      return await task();
    } finally {
      release();
      if (tails.get(accountId) === tail) tails.delete(accountId);
    }
  };
}
