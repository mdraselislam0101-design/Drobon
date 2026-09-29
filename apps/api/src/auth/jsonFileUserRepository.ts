import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { parseStoredUser, type UserRepository, type UserRecord } from './repositories.js';
import { buildAdminAccountCounts, buildAdminAccountPage } from './adminProjection.js';

/**
 * Durable user repository backed by a single JSON document.
 *
 * WHY THIS EXISTS (Pump 2 scope note): persistent authentication is
 * impossible without durable accounts, and Pump 2 forbids starting the
 * broader database phase. This file is therefore the *minimum persistence
 * boundary* — one document, one writer, isolated behind `UserRepository` —
 * designed so the future database phase swaps this module for a real
 * database implementation with zero changes to routes, middleware or
 * shared contracts.
 *
 * Guarantees and honest limits:
 * - accounts survive process restarts (read at startup, fail fast on a
 *   corrupt document);
 * - writes are atomic (temp file + rename in the same directory), so a
 *   crash mid-write cannot tear the store;
 * - create is serialized in-process and persists BEFORE it is observable:
 *   duplicate emails cannot race and memory never diverges from disk;
 * - it is explicitly single-process/single-writer and intended for
 *   foundation-scale data (thousands of accounts, not millions). Scaling
 *   beyond that is the database phase, not this file.
 */

interface StoreDocument {
  version: 1;
  users: UserRecord[];
}

function loadDocument(path: string): StoreDocument {
  let raw: string;
  try {
    raw = readFileSync(path, 'utf8');
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') {
      return { version: 1, users: [] };
    }
    throw new Error(`Cannot read auth store at ${path}: ${String(code ?? error)}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw) as unknown;
  } catch {
    throw new Error(
      `Auth store at ${path} is not valid JSON — refusing to start with corrupt account data.`,
    );
  }
  if (
    typeof parsed !== 'object' ||
    parsed === null ||
    (parsed as Record<string, unknown>)['version'] !== 1 ||
    !Array.isArray((parsed as Record<string, unknown>)['users'])
  ) {
    throw new Error(`Auth store at ${path} has an unexpected shape — refusing to start.`);
  }
  const rawUsers = (parsed as StoreDocument).users;
  const seenEmails = new Set<string>();
  const seenIds = new Set<string>();
  const users: UserRecord[] = [];
  rawUsers.forEach((entry, index) => {
    const record = parseStoredUser(entry);
    if (record === undefined) {
      throw new Error(
        `Auth store at ${path} has an invalid record at index ${index} — refusing to start.`,
      );
    }
    if (seenEmails.has(record.email) || seenIds.has(record.id)) {
      throw new Error(`Auth store at ${path} contains duplicate records — refusing to start.`);
    }
    seenEmails.add(record.email);
    seenIds.add(record.id);
    users.push(record);
  });
  return { version: 1, users };
}

export function createJsonFileUserRepository(path: string): UserRepository {
  const document = loadDocument(path);
  const byEmail = new Map<string, UserRecord>();
  const byId = new Map<string, UserRecord>();
  for (const record of document.users) {
    byEmail.set(record.email, record);
    byId.set(record.id, record);
  }

  let queue: Promise<unknown> = Promise.resolve();

  const persist = (users: UserRecord[]): void => {
    mkdirSync(dirname(path), { recursive: true });
    const payload: StoreDocument = { version: 1, users };
    const tempPath = join(dirname(path), `.${randomBytes(6).toString('hex')}.tmp`);
    writeFileSync(tempPath, `${JSON.stringify(payload, null, 2)}\n`, { mode: 0o600 });
    renameSync(tempPath, path);
  };

  return {
    create: (record) => {
      const run = queue.then(() => {
        if (byEmail.has(record.email)) {
          return false;
        }
        // Persist first: if the write fails the caller gets an error and
        // in-memory state stays consistent with disk (record absent).
        persist([...byEmail.values(), record]);
        byEmail.set(record.email, record);
        byId.set(record.id, record);
        return true;
      });
      queue = run.catch(() => undefined);
      return run;
    },
    findByEmail: (email) => Promise.resolve(byEmail.get(email)),
    findById: (id) => Promise.resolve(byId.get(id)),
    activatePro: (id, at) => {
      const run = queue.then(() => {
        const current = byId.get(id);
        if (current === undefined) return 'NOT_FOUND' as const;
        if (current.subscription?.plan === 'PRO' && current.subscription.status === 'ACTIVE') return 'ALREADY_ACTIVE' as const;
        const updated: UserRecord = {
          ...current,
          subscription: { plan: 'PRO', status: 'ACTIVE', createdAt: at, updatedAt: at },
        };
        const nextUsers = [...byEmail.values()].map((record) => record.id === id ? updated : record);
        persist(nextUsers);
        byId.set(id, updated);
        byEmail.set(updated.email, updated);
        return 'ACTIVATED' as const;
      });
      queue = run.catch(() => undefined);
      return run;
    },
    adminPage: (filters, page, pageSize) => Promise.resolve(buildAdminAccountPage(byId.values(), filters, page, pageSize)),
    adminCounts: () => Promise.resolve(buildAdminAccountCounts(byId.values())),
  };
}
