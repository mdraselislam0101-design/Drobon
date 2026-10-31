import { writePrivateJson } from '../lib/writePrivateJson.js';
import { readFileSync } from 'node:fs';
import { PROJECT_ID_PATTERN, SCAN_ID_PATTERN } from '@drobon/shared';

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

/** A scan reservation and its final reconciliation decision share the
 * counter document, so an interrupted cross-file write is recoverable. */
export interface ScanUsageReservation {
  scanId: string;
  projectId: string;
  accountId: string;
  period: string;
  deviceHash?: string;
  status: 'RESERVED' | 'COMMITTED' | 'RELEASED';
  createdAt: string;
  updatedAt: string;
  reason?: 'SCAN_PERSISTED' | 'SCAN_WRITE_FAILED' | 'RECOVERED_SCAN_PRESENT' | 'RECOVERED_SCAN_ABSENT';
}

export interface ReserveScanOptions {
  scanId: string; projectId: string; accountId: string; period: string;
  deviceHash?: string; accountLimit?: number; deviceLimit?: number; at: string;
}

export interface UsageStore {
  /** Reserve by scan id exactly once, in the same atomic write as the counters. */
  reserveScan(options: ReserveScanOptions): Promise<'OK' | 'ACCOUNT_LIMIT' | 'DEVICE_LIMIT'>;
  settleScan(scanId: string, status: 'COMMITTED' | 'RELEASED', reason: NonNullable<ScanUsageReservation['reason']>, at: string): Promise<void>;
  pendingScanReservations(): ScanUsageReservation[];
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
  /** Compensate a previously granted FREE consumption, including its device counter. */
  releaseFree(options: { accountId: string; deviceHash: string; period: string }): Promise<void>;
  /** Compensate a previously granted exempt consumption. */
  releaseExempt(options: { accountId: string; period: string }): Promise<void>;
}

interface StoreDocument {
  version: 1;
  accounts: Record<string, Record<string, number>>;
  devices: Record<string, Record<string, number>>;
  /** Missing on legacy documents; terminal records are retained for audit. */
  reservations?: ScanUsageReservation[];
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

const RESERVATIONS_MAX = 100_000;
function validReservation(value: unknown): value is ScanUsageReservation {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const r = value as Record<string, unknown>;
  if (Object.keys(r).some((key) => !['scanId', 'projectId', 'accountId', 'period', 'deviceHash', 'status', 'createdAt', 'updatedAt', 'reason'].includes(key))) return false;
  if (typeof r['scanId'] !== 'string' || !SCAN_ID_PATTERN.test(r['scanId']) ||
      typeof r['projectId'] !== 'string' || !PROJECT_ID_PATTERN.test(r['projectId']) ||
      typeof r['accountId'] !== 'string' || r['accountId'].length === 0 || r['accountId'].length > 128 ||
      typeof r['period'] !== 'string' || !/^\d{4}-(0[1-9]|1[0-2])$/.test(r['period']) ||
      (r['deviceHash'] !== undefined && (typeof r['deviceHash'] !== 'string' || r['deviceHash'].length === 0 || r['deviceHash'].length > 256)) ||
      typeof r['createdAt'] !== 'string' || !Number.isFinite(Date.parse(r['createdAt'])) ||
      typeof r['updatedAt'] !== 'string' || !Number.isFinite(Date.parse(r['updatedAt']))) return false;
  if (r['status'] === 'RESERVED') return r['reason'] === undefined;
  if (r['status'] === 'COMMITTED') return r['reason'] === 'SCAN_PERSISTED' || r['reason'] === 'RECOVERED_SCAN_PRESENT';
  if (r['status'] === 'RELEASED') return r['reason'] === 'SCAN_WRITE_FAILED' || r['reason'] === 'RECOVERED_SCAN_ABSENT';
  return false;
}
function validReservations(value: unknown, accounts: Record<string, Record<string, number>>, devices: Record<string, Record<string, number>>): boolean {
  if (value === undefined) return true;
  if (!Array.isArray(value) || value.length > RESERVATIONS_MAX || !value.every(validReservation)) return false;
  const ids = new Set<string>();
  const accountReservations = new Map<string, number>();
  const deviceReservations = new Map<string, number>();
  for (const entry of value as ScanUsageReservation[]) {
    if (ids.has(entry.scanId)) return false;
    ids.add(entry.scanId);
    if (entry.status === 'RELEASED') continue;
    const accountKey = JSON.stringify([entry.accountId, entry.period]);
    accountReservations.set(accountKey, (accountReservations.get(accountKey) ?? 0) + 1);
    if (entry.deviceHash !== undefined) {
      const deviceKey = JSON.stringify([entry.deviceHash, entry.period]);
      deviceReservations.set(deviceKey, (deviceReservations.get(deviceKey) ?? 0) + 1);
    }
  }
  for (const [key, count] of accountReservations) {
    const [owner, period] = JSON.parse(key) as [string, string];
    if ((accounts[owner]?.[period] ?? 0) < count) return false;
  }
  for (const [key, count] of deviceReservations) {
    const [owner, period] = JSON.parse(key) as [string, string];
    if ((devices[owner]?.[period] ?? 0) < count) return false;
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
    !isCountsByOwner((parsed as Record<string, unknown>)['devices']) ||
    !validReservations((parsed as Record<string, unknown>)['reservations'], (parsed as StoreDocument).accounts, (parsed as StoreDocument).devices)
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
  // Object.fromEntries defines special prototype-like keys as own
  // properties instead of invoking an inherited legacy setter.
  return Object.fromEntries([...map].map(([key, periods]) => [key, Object.fromEntries(periods)]));
}

interface StoreInternals {
  accounts: Map<string, Map<string, number>>;
  devices: Map<string, Map<string, number>>;
  reservations: Map<string, ScanUsageReservation>;
  persistWith(accounts: Map<string, Map<string, number>>, devices: Map<string, Map<string, number>>, reservations: Map<string, ScanUsageReservation>): void;
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

  const bumped = (
    map: Map<string, Map<string, number>>,
    key: string,
    period: string,
  ): Map<string, Map<string, number>> => {
    // Copy both the outer map and the affected period map. Unchanged
    // owners can safely share their maps because they are not mutated.
    const next = new Map(map);
    const periods = new Map(map.get(key));
    periods.set(period, (periods.get(period) ?? 0) + 1);
    next.set(key, periods);
    return next;
  };

  const decremented = (
    map: Map<string, Map<string, number>>,
    key: string,
    period: string,
  ): Map<string, Map<string, number>> => {
    const current = map.get(key)?.get(period) ?? 0;
    if (current < 1) throw new Error('Cannot compensate an absent usage consumption.');
    const next = new Map(map);
    const periods = new Map(map.get(key));
    if (current === 1) periods.delete(period);
    else periods.set(period, current - 1);
    if (periods.size === 0) next.delete(key);
    else next.set(key, periods);
    return next;
  };

  return {
    pendingScanReservations: () => [...internals.reservations.values()].filter((item) => item.status === 'RESERVED').map((item) => ({ ...item })),
    reserveScan: (options) => runExclusive(() => {
      const { scanId, projectId, accountId, period, deviceHash, at } = options;
      const candidate: ScanUsageReservation = { scanId, projectId, accountId, period, ...(deviceHash === undefined ? {} : { deviceHash }), status: 'RESERVED', createdAt: at, updatedAt: at };
      if (!validReservation(candidate)) throw new Error('Invalid scan quota reservation.');
      const existing = internals.reservations.get(scanId);
      if (existing !== undefined) {
        if (existing.projectId !== projectId || existing.accountId !== accountId || existing.period !== period || existing.deviceHash !== deviceHash || existing.status === 'RELEASED') throw new Error('Conflicting scan quota reservation.');
        return 'OK' as const;
      }
      if (internals.reservations.size >= RESERVATIONS_MAX) throw new Error('Scan quota reservation audit capacity reached.');
      if (deviceHash !== undefined) {
        if (!Number.isInteger(options.accountLimit) || !Number.isInteger(options.deviceLimit) || (options.accountLimit ?? 0) < 1 || (options.deviceLimit ?? 0) < 1) throw new Error('Invalid scan quota limits.');
        if (accountCount(accountId, period) >= options.accountLimit!) return 'ACCOUNT_LIMIT' as const;
        if (deviceCount(deviceHash, period) >= options.deviceLimit!) return 'DEVICE_LIMIT' as const;
      }
      const nextAccounts = bumped(internals.accounts, accountId, period);
      const nextDevices = deviceHash === undefined ? internals.devices : bumped(internals.devices, deviceHash, period);
      const reservations = new Map(internals.reservations).set(scanId, candidate);
      internals.persistWith(nextAccounts, nextDevices, reservations);
      internals.accounts = nextAccounts; internals.devices = nextDevices; internals.reservations = reservations;
      return 'OK' as const;
    }),
    settleScan: (scanId, status, reason, at) => runExclusive(() => {
      const existing = internals.reservations.get(scanId);
      if (existing === undefined) throw new Error('Scan quota reservation is missing.');
      if (existing.status === status) return;
      if (existing.status !== 'RESERVED') throw new Error('Scan quota reservation is already finalized.');
      const updated: ScanUsageReservation = { ...existing, status, reason, updatedAt: at };
      if (!validReservation(updated)) throw new Error('Invalid scan quota reconciliation.');
      const nextAccounts = status === 'RELEASED' ? decremented(internals.accounts, existing.accountId, existing.period) : internals.accounts;
      const nextDevices = status === 'RELEASED' && existing.deviceHash !== undefined ? decremented(internals.devices, existing.deviceHash, existing.period) : internals.devices;
      const reservations = new Map(internals.reservations).set(scanId, updated);
      internals.persistWith(nextAccounts, nextDevices, reservations);
      internals.accounts = nextAccounts; internals.devices = nextDevices; internals.reservations = reservations;
    }),
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
        const nextAccounts = bumped(internals.accounts, accountId, period);
        const nextDevices = bumped(internals.devices, deviceHash, period);
        // Commit memory only after persistence succeeds. A failed write
        // leaves both counters unchanged and retryable.
        internals.persistWith(nextAccounts, nextDevices, internals.reservations);
        internals.accounts = nextAccounts;
        internals.devices = nextDevices;
        return 'OK' as const;
      }),
    consumeExempt: ({ accountId, period }) =>
      runExclusive(() => {
        // Exempt consumption counts on the account only — never against
        // the shared FREE device allowance.
        const nextAccounts = bumped(internals.accounts, accountId, period);
        internals.persistWith(nextAccounts, internals.devices, internals.reservations);
        internals.accounts = nextAccounts;
      }),
    releaseFree: ({ accountId, deviceHash, period }) =>
      runExclusive(() => {
        const nextAccounts = decremented(internals.accounts, accountId, period);
        const nextDevices = decremented(internals.devices, deviceHash, period);
        internals.persistWith(nextAccounts, nextDevices, internals.reservations);
        internals.accounts = nextAccounts;
        internals.devices = nextDevices;
      }),
    releaseExempt: ({ accountId, period }) =>
      runExclusive(() => {
        const nextAccounts = decremented(internals.accounts, accountId, period);
        internals.persistWith(nextAccounts, internals.devices, internals.reservations);
        internals.accounts = nextAccounts;
      }),
  };
}

/** Durable usage store: one JSON document, atomic writes (see file docs). */
export function createUsageFileStore(path: string): UsageStore {
  const document = loadDocument(path);
  const accounts = toMap(document.accounts);
  const devices = toMap(document.devices);
  const reservations = new Map((document.reservations ?? []).map((item) => [item.scanId, item]));
  const persistWith = (nextAccounts: typeof accounts, nextDevices: typeof devices, nextReservations: typeof reservations): void => {
    const payload: StoreDocument = {
      version: 1,
      accounts: toRecord(nextAccounts),
      devices: toRecord(nextDevices),
      reservations: [...nextReservations.values()],
    };
    writePrivateJson(path, `${JSON.stringify(payload, null, 2)}\n`);
  };
  return createUsageStoreFrom({ accounts, devices, reservations, persistWith });
}

/** Process-local usage store (tests + explicit `:memory:` setups — rejected in production by config). */
export function createMemoryUsageStore(): UsageStore {
  return createUsageStoreFrom({
    accounts: new Map(),
    devices: new Map(),
    reservations: new Map(),
    persistWith: () => undefined,
  });
}

/** Exposed for tests: the empty-document constant is stable. */
export const emptyUsageDocument = EMPTY_DOCUMENT;
