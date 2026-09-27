import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { ApiConfig } from '../src/config.js';
import { createJsonFileUserRepository } from '../src/auth/jsonFileUserRepository.js';
import { createMemoryUserRepository } from '../src/auth/memoryUserRepository.js';
import type { UserRepository } from '../src/auth/repositories.js';
import { createSessionStore, type SessionStore } from '../src/auth/sessions.js';
import type { Route } from '../src/http.js';
import { createLogger } from '../src/logger.js';
import { startServer, type StartedServer } from '../src/server.js';
import type { UsageStore } from '../src/usage/store.js';
import {
  createJsonFileProjectStore,
  type ProjectStore,
} from '../src/projects/store.js';

export interface TestServer {
  baseUrl: string;
  config: ApiConfig;
  logs: string[];
  /** Account repository backing this server (seeding/inspection in tests). */
  users: UserRepository;
  /** Session store backing this server (expiry/revocation in tests). */
  sessions: SessionStore;
  /**
   * The injected usage/quota store, when one was provided (Pump 5).
   * Tests that need to inspect/seed usage counters inject their own.
   */
  usageStore?: UsageStore;
  /**
   * The injected project store, when one was provided (Pump 6).
   * Tests that need to inspect/seed projects inject their own.
   */
  projects?: ProjectStore;
  resetRateLimit: () => void;
  stop: () => Promise<void>;
}

export type TestServerOverrides = Partial<ApiConfig> & {
  extraRoutes?: Route[];
  users?: UserRepository;
  sessions?: SessionStore;
  /** Use a real JSON file store at a temp path instead of memory. */
  authStoreDir?: string;
  /** Use a real JSON usage store at a temp path instead of memory (Pump 5). */
  usageStoreDir?: string;
  /** Inject a usage store directly (defaults: memory or usageStoreDir). */
  usageStore?: UsageStore;
  /** Injected clock for usage period math (deterministic month boundaries). */
  usageNow?: () => number;
  /** Use a real JSON project store at a temp path instead of memory (Pump 6). */
  projectStoreDir?: string;
  /** Inject a project store directly (defaults: memory or projectStoreDir). */
  projectStore?: ProjectStore;
};

/**
 * Start an ephemeral API instance on 127.0.0.1 with an OS-assigned port.
 *
 * Auth defaults are intentionally fast for tests: scrypt cost 1024 (the
 * same code path as production, cheaper parameters — see docs/TESTING.md)
 * and the memory account store unless `authStoreDir` opts into the real
 * JSON file repository. Usage stores follow the same pattern
 * (`usageStore`/`usageStoreDir`).
 */
export async function startTestServer(overrides: TestServerOverrides = {}): Promise<TestServer> {
  const logs: string[] = [];
  const {
    extraRoutes,
    users,
    sessions,
    authStoreDir,
    usageStoreDir,
    usageStore,
    usageNow,
    projectStoreDir,
    projectStore,
    ...configOverrides
  } = overrides;
  const config: ApiConfig = {
    env: 'test',
    host: '127.0.0.1',
    port: 0,
    logLevel: 'error',
    corsAllowedOrigins: [],
    rateLimitMaxRequests: 1000,
    rateLimitWindowMs: 60_000,
    bodyMaxBytes: 1_048_576,
    version: '0.0.0-test',
    authStorePath: ':memory:',
    authScryptCost: 1024,
    authSessionTtlSeconds: 3600,
    authRateLimitMaxRequests: 1000,
    authRateLimitWindowMs: 60_000,
    cookieSecure: false,
    authzProbeRoutes: true,
    usageStorePath: ':memory:',
    usageConsumeRoutes: true,
    projectStorePath: ':memory:',
    ...configOverrides,
  };
  const effectiveStorePath =
    authStoreDir === undefined ? config.authStorePath : join(authStoreDir, 'users.json');
  const effectiveUsageStorePath =
    usageStoreDir === undefined ? config.usageStorePath : join(usageStoreDir, 'usage.json');
  const effectiveProjectStorePath =
    projectStoreDir === undefined ? config.projectStorePath : join(projectStoreDir, 'projects.json');
  const configWithStore: ApiConfig =
    authStoreDir === undefined && usageStoreDir === undefined && projectStoreDir === undefined
      ? config
      : {
          ...config,
          ...(authStoreDir === undefined ? {} : { authStorePath: effectiveStorePath }),
          ...(usageStoreDir === undefined ? {} : { usageStorePath: effectiveUsageStorePath }),
          ...(projectStoreDir === undefined ? {} : { projectStorePath: effectiveProjectStorePath }),
        };
  // A single resolved project-store instance: the app AND the returned
  // TestServer must share it (inject-or-default, never two stores).
  const resolvedProjectStore =
    projectStore ??
    (projectStoreDir === undefined
      ? undefined
      : createJsonFileProjectStore(effectiveProjectStorePath));
  const resolvedUsers =
    users ??
    (authStoreDir === undefined
      ? createMemoryUserRepository()
      : createJsonFileUserRepository(effectiveStorePath));
  const resolvedSessions =
    sessions ?? createSessionStore({ ttlSeconds: configWithStore.authSessionTtlSeconds });
  const logger = createLogger({
    // Mirrors config: the default test config logs at `error` (silent),
    // suites asserting log hygiene opt into `info` via overrides.
    level: configWithStore.logLevel,
    service: 'test',
    env: 'test',
    out: (line) => {
      logs.push(line);
    },
  });
  const started: StartedServer = await startServer({
    config: configWithStore,
    logger,
    users: resolvedUsers,
    sessions: resolvedSessions,
    ...(usageStore === undefined ? {} : { usageStore }),
    ...(usageNow === undefined ? {} : { usageNow }),
    ...(resolvedProjectStore === undefined ? {} : { projectStore: resolvedProjectStore }),
    ...(extraRoutes === undefined ? {} : { extraRoutes }),
  });
  return {
    baseUrl: started.url,
    config: configWithStore,
    logs,
    users: resolvedUsers,
    sessions: resolvedSessions,
    ...(usageStore === undefined ? {} : { usageStore }),
    ...(resolvedProjectStore === undefined ? {} : { projects: resolvedProjectStore }),
    resetRateLimit: started.resetRateLimit,
    stop: started.stop,
  };
}

/** Read a fetch Response as unknown JSON. */
export async function readJson(res: Response): Promise<unknown> {
  return (await res.json()) as unknown;
}

/** Create a throwaway directory for durable-store tests; cleaned by the caller. */
export function makeTempStoreDir(prefix: string): string {
  return mkdtempSync(join(tmpdir(), `${prefix}-`));
}

/** Remove a directory created by {@link makeTempStoreDir}. */
export function cleanupTempStoreDir(dir: string): void {
  rmSync(dir, { recursive: true, force: true });
}

/**
 * Extract the session cookie as a header-ready `drobon_session=<token>`
 * pair (attributes stripped). Fails loudly when the header is missing or
 * the cookie is empty — a silent miss would just look like a 401.
 */
export function sessionCookieFrom(res: Response): string {
  const raw = res.headers.getSetCookie().find((entry) => entry.startsWith('drobon_session='));
  if (raw === undefined) {
    throw new Error('Expected a drobon_session Set-Cookie header.');
  }
  const pair = raw.split(';')[0] ?? '';
  if (pair.length <= 'drobon_session='.length) {
    throw new Error('Session cookie was empty.');
  }
  return pair;
}
