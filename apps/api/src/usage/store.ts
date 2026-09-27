import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { randomBytes } from 'node:crypto';

/**
 * Durable usage store (Pump 5) — the minimum persistence boundary for
 * quota/anti-abuse counters, following the exact architecture of the
 * Pump 2 account store (one JSON document, atomic temp+rename writes,
 * mode 0600, fail-fast on corruption, single-process/single-writer).
 * The future database phase replaces this module — the service never
 * touches the file format directly.
 *
 * ATOMICITY (the load-bearing property): every counter mutation runs
 * inside a serialized in-process queue, and the read-check-increment-
 * persist sequence is ONE indivisible task inside that queue. Concurrent
 * consume calls are therefore linearized: with a limit of 3 and ten
 * simultaneous consumptions, exactly three succeed — the classic
 * read-then-write race cannot happen because no other task can observe
 * intermediate state. The document is persisted BEFORE the mutation is
 * acknowledged (memory never diverges from disk).
 *
 * Keys are server-computed only (account ids, SHA-256 device hashes,
 * `YYYY-MM` periods); in-memory state uses `Map`s so no store key can
 * ever collide with Object.prototype.
 */

export interface UsageStore {
  /** Scans an account consumed in `period` (server-computed counts only). */
  getAccountUsed(accountId: string, period: string): number;
  /** Scans consumed on a device in `period` (FREE consumption only). */
  getDeviceUsed(deviceHash: string, period: string): number;
  /**
   * Atomic FREE consumption: inside the serialized mutation queue, check
   * BOTH the account and the device allowance; increment both ONLY when
   * both pass; persist before acknowledging. Returns which limit
   * refused (for logging only — callers answer uniformly).
   */
  consumeFree(options: {
    accountId: string;
    deviceHash: string;
    period: string;
    accountLimit: number;
    deviceLimit: number;
  }): Promise<'OK' | 'ACCOUNT_LIMIT' | 'DEVICE_LIMIT'>;
  /**
   * Atomic exempt (active PRO) consumption: increments the account count
   * only — exempt consumption NEVER touches the shared device allowance.
   */
  consumeExempt(options: { accountId: string; period: string }): Promise<void>;
}

interface StoreDocument {
  version: 1;
  accounts: Record<string, Record<string, number>>;
  devices: Record<string, Record<string, number>>;
}

const EMPTY_DOCUMENT: StoreDocument = { version: 1, accounts: {}, devices: {} };

function isCountRecord(value: unknown): value is Record<string, number> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false;
  }
  for (const [key, count] of Object.entries(value)) {
    if (!/^\d{4}-(0[1-9]|1[0-2])$/.test(key) || typeof count !== 'number' || !Number.isInteger(count) || count < 0) {
      return false;
    }
  }
  return true;
}

/**
 * Outer store maps: owner key (opaque account id or device hash) →
 * period → count. The owner keys are opaque server-side strings; each
 * nested value must be a well-formed count record.
 */
function isCountsByOwner(value: unknown): value is Record<string, Record<string, number>> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false;
  }
  for (const nested of Object.values(value)) {
    if (!isCountRecord(nested)) {
      return false;
    }
  }
  return true;
}

function loadDocument(path: string): StoreDocument {
  let raw: string;
  try {
    raw = readFileSync(path, 'utf8');
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') {
      return { version: 1, accounts: {}, devices: {} };
    }
    throw new Error(`Cannot read usage store at ${path}: ${String(code ?? error)}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw) as unknown;
  } catch {
    throw new Error(
      `Usage store at ${path} is not valid JSON — refusing to start with corrupt quota data.`,
    );
  }
  if (
    typeof parsed !== 'object' ||
    parsed === null ||
    (parsed as Record<string, unknown>)['version'] !== 1 ||
    !isCountsByOwner((parsed as Record<string, unknown>)['accounts']) ||
    !isCountsByOwner((parsed as Record<string, unknown>)['devices'])
  ) {
    throw new Error(`Usage store at ${path} has an unexpected shape — refusing to start.`);
  }
  return parsed as StoreDocument;
}

function toMap(record: Record<string, Record<string, number>>): Map<string, Map<string, number>> {
  const out = new Map<string, Map<string, number>>();
  for (const [key, periods] of Object.entries(record)) {
    out.set(key, new Map(Object.entries(periods)));
  }
  return out;
}

function toRecord(map: Map<string, Map<string, number>>): Record<string, Record<string, number>> {
  const out: Record<string, Record<string, number>> = {};
  for (const [key, periods] of map) {
    out[key] = Object.fromEntries(periods);
  }
  return out;
}

interface StoreInternals {
  accounts: Map<string, Map<string, number>>;
  devices: Map<string, Map<string, number>>;
  persist(): void;
}

function createUsageStoreFrom(internals: StoreInternals): UsageStore {
  // The single mutation queue — every counter change is linearized here.
  let queue: Promise<unknown> = Promise.resolve();
  const runExclusive = <T>(task: () => T): Promise<T> => {
    const run = queue.then(task, task);
    queue = run.catch(() => undefined);
    return run;
  };

  const accountCount = (accountId: string, period: string): number =>
    internals.accounts.get(accountId)?.get(period) ?? 0;

  const deviceCount = (deviceHash: string, period: string): number =>
    internals.devices.get(deviceHash)?.get(period) ?? 0;

  const bump = (
    map: Map<string, Map<string, number>>,
    key: string,
    period: string,
  ): void => {
    let periods = map.get(key);
    if (periods === undefined) {
      periods = new Map<string, number>();
      map.set(key, periods);
    }
    periods.set(period, (periods.get(period) ?? 0) + 1);
  };

  return {
    getAccountUsed: (accountId, period) => accountCount(accountId, period),
    getDeviceUsed: (deviceHash, period) => deviceCount(deviceHash, period),
    consumeFree: ({ accountId, deviceHash, period, accountLimit, deviceLimit }) =>
      runExclusive(() => {
        if (accountCount(accountId, period) >= accountLimit) {
          return 'ACCOUNT_LIMIT' as const;
        }
        if (deviceCount(deviceHash, period) >= deviceLimit) {
          return 'DEVICE_LIMIT' as const;
        }
        bump(internals.accounts, accountId, period);
        bump(internals.devices, deviceHash, period);
        // Persist first: on write failure the caller sees the error and
        // memory stays consistent with disk.
        internals.persist();
        return 'OK' as const;
      }),
    consumeExempt: ({ accountId, period }) =>
      runExclusive(() => {
        // Exempt consumption counts on the account only — never against
        // the shared FREE device allowance.
        bump(internals.accounts, accountId, period);
        internals.persist();
      }),
  };
}

/** Durable usage store: one JSON document, atomic writes (see file docs). */
export function createUsageFileStore(path: string): UsageStore {
  const document = loadDocument(path);
  const accounts = toMap(document.accounts);
  const devices = toMap(document.devices);
  const persist = (): void => {
    mkdirSync(dirname(path), { recursive: true });
    const payload: StoreDocument = {
      version: 1,
      accounts: toRecord(accounts),
      devices: toRecord(devices),
    };
    const tempPath = join(dirname(path), `.${randomBytes(6).toString('hex')}.tmp`);
    writeFileSync(tempPath, `${JSON.stringify(payload, null, 2)}\n`, { mode: 0o600 });
    renameSync(tempPath, path);
  };
  return createUsageStoreFrom({ accounts, devices, persist });
}

/** Process-local usage store (tests + explicit `:memory:` setups — rejected in production by config). */
export function createMemoryUsageStore(): UsageStore {
  return createUsageStoreFrom({
    accounts: new Map(),
    devices: new Map(),
    persist: () => undefined,
  });
}

/** Exposed for tests: the empty-document constant is stable. */
export const emptyUsageDocument = EMPTY_DOCUMENT;
