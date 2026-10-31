import type { DatasetService } from '../src/external/service.js';
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
import {
  createJsonFileScanStore,
  createMemoryScanStore,
  type ScanStore,
} from '../src/scans/store.js';
import {
  createJsonFileSourceStore,
  createMemorySourceStore,
  type SourceSnapshotStore,
} from '../src/scans/sources.js';
import type { ScanEngine } from '../src/scans/engines.js';
import type { ScanProcessor } from '../src/scans/processor.js';
import { createDastTargetPolicy } from '../src/scans/dast/target.js';
import type { DastProbeResponse, DastTransport } from '../src/scans/dast/http.js';
import { createSastEngine } from '../src/scans/sast/engine.js';
import { createScaEngine } from '../src/scans/sca/engine.js';
import { createSecretsEngine } from '../src/scans/secrets/engine.js';
import { createDastEngine } from '../src/scans/dast/engine.js';
import { createAssessmentDastAuthorizer } from '../src/scans/dast/authorization.js';
import { createNullIntelligenceProvider } from '../src/scans/sca/provider.js';
import { TEST_SAST_RULES, TEST_SECRETS_RULES, TEST_DAST_RULES } from './fixtures/testData.js';
import type { AdvisoryService } from '../src/external/advisory.js';
import type { DastTargetPolicy } from '../src/scans/dast/target.js';
import { createJsonFilePaymentStore, createMemoryPaymentStore, type PaymentStore } from '../src/payments/store.js';
import type { EntitlementStore } from '../src/entitlements/store.js';
import type { PartnerStore } from '../src/partners/store.js';
import { createJsonFileAssessmentStore, createMemoryAssessmentStore, type AssessmentStore } from '../src/assessments/store.js';

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
  /**
   * The scan-job store backing this server (Pump 7) — always resolved
   * to ONE shared instance (injected or created), so tests can inspect
   * durable scan state directly.
   */
  scans: ScanStore;
  assessments: AssessmentStore;
  /**
   * The source-snapshot store backing this server (Pump 8) — always
   * resolved to ONE shared instance (injected or created), so tests can
   * inspect/seed scan targets directly.
   */
  sources: SourceSnapshotStore;
  /** Durable or in-memory payment store under test. */
  payments: PaymentStore;
  /**
   * The scan processor (Pump 7). Auto-start is DISABLED in tests:
   * suites drive drain() explicitly for deterministic lifecycle
   * assertions.
   */
  scanProcessor: ScanProcessor;
  resetRateLimit: () => void;
  stop: () => Promise<void>;
}

export type TestServerOverrides = Partial<ApiConfig> & {
  extraRoutes?: Route[];
  /** Inject a generic advisory service (Pump 15); defaults to NOT_CONFIGURED. */
  advisory?: AdvisoryService;
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
  /** Inject app/assessment/agent clock for local lifecycle tests. */
  appNow?: () => number;
  /** Use a real JSON project store at a temp path instead of memory (Pump 6). */
  projectStoreDir?: string;
  /** Inject a project store directly (defaults: memory or projectStoreDir). */
  projectStore?: ProjectStore;
  /** Use a real JSON scan store at a temp path instead of memory (Pump 7). */
  scanStoreDir?: string;
  /** Inject a scan store directly (defaults: memory or scanStoreDir). */
  scanStore?: ScanStore;
  /** Use a real JSON assessment store at a temp path for restart proofs. */
  assessmentStoreDir?: string;
  studentStoreDir?: string;
  datasetService?: DatasetService;
  /** Inject an assessment store directly (defaults: memory or assessmentStoreDir). */
  assessmentStore?: AssessmentStore;
  /** Use a real JSON source store at a temp path instead of memory (Pump 8). */
  sourceStoreDir?: string;
  /** Inject a source store directly (defaults: memory or sourceStoreDir). */
  sourceStore?: SourceSnapshotStore;
  /** Use a real JSON payment store at a temp path for restart proofs. */
  paymentStoreDir?: string;
  /** Inject a payment store directly (defaults: memory or paymentStoreDir). */
  paymentStore?: PaymentStore;
  /** Inject the admin PRO entitlement store directly (restart proofs). */
  entitlementStore?: EntitlementStore;
  /** Injectable partner persistence boundary for failure/recovery tests. */
  partnerStore?: PartnerStore;
  /** Deterministic payment timestamps. */
  paymentNow?: () => number;
  partnerNow?: () => number;
  /**
   * Inject scanner engines (Pump 8 default: the REAL SAST engine —
   * SAST scans analyze the project's uploaded source snapshot and
   * produce real findings). Pass an explicit list (or `[]`) to control
   * the registry exactly.
   */
  scanEngines?: readonly ScanEngine[];
  /** Safe deterministic resolver; never probes arbitrary/public targets. */
  dastTargetPolicy?: DastTargetPolicy;
  /** Controlled fixture transport; no real HTTP exchange by default. */
  dastTransport?: DastTransport;
  /** Scan processor sweep interval (rarely needed in tests). */
  scanProcessorIntervalMs?: number;
};

const FIXTURE_DAST_RESPONSE: DastProbeResponse = {
  status: 200,
  headers: {
    'content-type': 'text/html; charset=utf-8',
    'access-control-allow-origin': 'https://drobon-aegis.invalid',
    'access-control-allow-credentials': 'true',
    'set-cookie': ['session=FIXTURE_COOKIE_SECRET_DO_NOT_LEAK; Path=/'],
    server: 'fixture-only/1.0',
  },
  body: '<!doctype html><script src="http://fixture.example.org/app.js"></script>',
  bodyTruncated: false,
  elapsedMs: 7,
};

const FIXTURE_DAST_TRANSPORT: DastTransport = {
  probe: async () => ({
    ...FIXTURE_DAST_RESPONSE,
    headers: { ...FIXTURE_DAST_RESPONSE.headers },
  }),
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
    advisory,
    users,
    sessions,
    authStoreDir,
    usageStoreDir,
    usageStore,
    usageNow,
    appNow,
    projectStoreDir,
    projectStore,
    scanStoreDir,
    scanStore,
    assessmentStoreDir,
    assessmentStore,
    studentStoreDir,
    datasetService,
    sourceStoreDir,
    sourceStore,
    paymentStoreDir,
    paymentStore,
    entitlementStore,
    partnerStore,
    paymentNow,
    partnerNow,
    scanEngines,
    dastTargetPolicy,
    dastTransport,
    scanProcessorIntervalMs,
    vulnIntelProvider,
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
    scanStorePath: ':memory:',
    assessmentStorePath: ':memory:',
    studentStorePath: ':memory:',
    sourceStorePath: ':memory:',
    vulnIntelProvider: vulnIntelProvider ?? 'none',
    paymentStorePath: ':memory:',
    entitlementStorePath: ':memory:',
    partnerStorePath: ':memory:',
    paymentConfigStorePath: ':memory:',
    proPriceMinorUnits: 100_000,
    paymentReviewerIds: [],
    manualPaymentMethods: ['MANUAL_TRANSFER'],
    manualPaymentInstructions: 'Payment instructions are not configured. Contact support before sending funds. A submitted reference is user-provided evidence and is not payment verification.',
    paymentRateLimitMaxRequests: 1000,
    paymentRateLimitWindowMs: 60_000,
    platformAdminIds: [],
    adminRateLimitMaxRequests: 1000,
    adminRateLimitWindowMs: 60_000,
    ...configOverrides,
  };
  const effectiveStorePath =
    authStoreDir === undefined ? config.authStorePath : join(authStoreDir, 'users.json');
  const effectiveUsageStorePath =
    usageStoreDir === undefined ? config.usageStorePath : join(usageStoreDir, 'usage.json');
  const effectiveProjectStorePath =
    projectStoreDir === undefined ? config.projectStorePath : join(projectStoreDir, 'projects.json');
  const effectiveScanStorePath =
    scanStoreDir === undefined ? config.scanStorePath : join(scanStoreDir, 'scans.json');
  const effectiveAssessmentStorePath =
    assessmentStoreDir === undefined ? config.assessmentStorePath : join(assessmentStoreDir, 'assessments.json');
  const effectiveStudentStorePath =
    studentStoreDir === undefined ? config.studentStorePath : join(studentStoreDir, 'student-progress.json');
  const effectiveSourceStorePath =
    sourceStoreDir === undefined ? config.sourceStorePath : join(sourceStoreDir, 'sources.json');
  const effectivePaymentStorePath =
    paymentStoreDir === undefined ? config.paymentStorePath : join(paymentStoreDir, 'payments.json');
  const configWithStore: ApiConfig =
    authStoreDir === undefined &&
    usageStoreDir === undefined &&
    projectStoreDir === undefined &&
    scanStoreDir === undefined &&
    assessmentStoreDir === undefined &&
    sourceStoreDir === undefined &&
    paymentStoreDir === undefined &&
    studentStoreDir === undefined
      ? config
      : {
          ...config,
          ...(authStoreDir === undefined ? {} : { authStorePath: effectiveStorePath }),
          ...(usageStoreDir === undefined ? {} : { usageStorePath: effectiveUsageStorePath }),
          ...(projectStoreDir === undefined ? {} : { projectStorePath: effectiveProjectStorePath }),
          ...(scanStoreDir === undefined ? {} : { scanStorePath: effectiveScanStorePath }),
          ...(assessmentStoreDir === undefined ? {} : { assessmentStorePath: effectiveAssessmentStorePath }),
          ...(studentStoreDir === undefined ? {} : { studentStorePath: effectiveStudentStorePath }),
          ...(sourceStoreDir === undefined ? {} : { sourceStorePath: effectiveSourceStorePath }),
          ...(paymentStoreDir === undefined ? {} : { paymentStorePath: effectivePaymentStorePath }),
        };
  // A single resolved project-store instance: the app AND the returned
  // TestServer must share it (inject-or-default, never two stores).
  const resolvedProjectStore =
    projectStore ??
    (projectStoreDir === undefined
      ? undefined
      : createJsonFileProjectStore(effectiveProjectStorePath));
  // Same rule for the scan store (Pump 7): exactly ONE instance shared
  // by the app and the test — always resolved and injected (memory by
  // default, so the test can inspect durable scan state directly).
  const resolvedScanStore =
    scanStore ??
    (scanStoreDir === undefined
      ? createMemoryScanStore()
      : createJsonFileScanStore(effectiveScanStorePath));
  // Same rule for the source store (Pump 8): exactly ONE instance
  // shared by the app and the test.
  const resolvedAssessmentStore =
    assessmentStore ??
    (assessmentStoreDir === undefined
      ? createMemoryAssessmentStore()
      : createJsonFileAssessmentStore(effectiveAssessmentStorePath));
  const resolvedSourceStore =
    sourceStore ??
    (sourceStoreDir === undefined
      ? createMemorySourceStore()
      : createJsonFileSourceStore(effectiveSourceStorePath));
  const resolvedPaymentStore =
    paymentStore ??
    (paymentStoreDir === undefined
      ? createMemoryPaymentStore()
      : createJsonFilePaymentStore(effectivePaymentStorePath));
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
  // Test default: inject minimal test rule fixtures so SAST/secrets
  // produce findings without needing a full Drobon-Dataset. Production
  // src has 0 embedded rules (paid-tool parity); test fixtures live
  // in test/fixtures/testData.ts (not in src/). When a real dataset
  // is configured (vulnIntelProvider=filesystem + datasetPath), we
  // let the app's dataset service provide DPK rules instead.
  const effectiveDastTargetPolicy = dastTargetPolicy ?? createDastTargetPolicy({ resolve: async () => ['93.184.216.34'] });
  const effectiveDastTransport = dastTransport ?? FIXTURE_DAST_TRANSPORT;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- legacy untyped boundary; new modules use unknown.
  const hasRealDataset = (configOverrides as any).datasetPath !== undefined || overrides.vulnIntelProvider === 'filesystem';
  const effectiveScanEngines = scanEngines ?? (hasRealDataset ? undefined : [
    createSastEngine({ sources: resolvedSourceStore, rules: TEST_SAST_RULES }),
    createScaEngine({ sources: resolvedSourceStore, provider: createNullIntelligenceProvider() }),
    createSecretsEngine({ sources: resolvedSourceStore, rules: TEST_SECRETS_RULES }),
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- legacy untyped boundary; new modules use unknown.
    createDastEngine({ targetPolicy: effectiveDastTargetPolicy, transport: effectiveDastTransport, authorize: createAssessmentDastAuthorizer(resolvedAssessmentStore, Date.now, { requireEngagement: configWithStore.dastRequireEngagement === true }), packRules: TEST_DAST_RULES as any }),
  ]);
  const started: StartedServer = await startServer({
    config: configWithStore,
    logger,
    users: resolvedUsers,
    sessions: resolvedSessions,
    paymentStore: resolvedPaymentStore,
    ...(paymentNow === undefined ? {} : { paymentNow }),
    ...(partnerNow === undefined ? {} : { partnerNow }),
    ...(usageStore === undefined ? {} : { usageStore }),
    ...(usageNow === undefined ? {} : { usageNow }),
    ...(appNow === undefined ? {} : { now: appNow }),
    ...(resolvedProjectStore === undefined ? {} : { projectStore: resolvedProjectStore }),
    scanStore: resolvedScanStore,
    ...(datasetService === undefined ? {} : { datasetService }),
    assessmentStore: resolvedAssessmentStore,
    sourceStore: resolvedSourceStore,
    ...(effectiveScanEngines === undefined ? {} : { scanEngines: effectiveScanEngines }),
    ...(entitlementStore === undefined ? {} : { entitlementStore }),
    ...(partnerStore === undefined ? {} : { partnerStore }),
    dastTargetPolicy: effectiveDastTargetPolicy,
    dastTransport: effectiveDastTransport,
    ...(scanProcessorIntervalMs === undefined ? {} : { scanProcessorIntervalMs }),
    // Deterministic tests: no background processing unless a suite
    // starts the processor itself.
    scanProcessorAutoStart: false,
    ...(extraRoutes === undefined ? {} : { extraRoutes }),
    ...(advisory === undefined ? {} : { advisory }),
  });
  return {
    baseUrl: started.url,
    config: configWithStore,
    logs,
    users: resolvedUsers,
    sessions: resolvedSessions,
    ...(usageStore === undefined ? {} : { usageStore }),
    ...(resolvedProjectStore === undefined ? {} : { projects: resolvedProjectStore }),
    scans: resolvedScanStore,
    assessments: resolvedAssessmentStore,
    sources: resolvedSourceStore,
    payments: resolvedPaymentStore,
    scanProcessor: started.app.scanProcessor,
    resetRateLimit: started.resetRateLimit,
    stop: started.stop,
  };
}

/** Read a fetch Response as unknown JSON. */
export async function readJson(res: Response): Promise<unknown> {
  return (await res.json()) as unknown;
}

/** Configure only a synthetic fixture hostname through the real owner-only route. */
export async function configureFixtureDastTarget(
  server: TestServer,
  cookie: string,
  projectId: string,
): Promise<void> {
  const response = await fetch(`${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/dast-target`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify({ targetUrl: 'https://fixture.example.org/' }),
  });
  if (response.status !== 200) {
    throw new Error(`Fixture DAST target configuration failed with status ${response.status}.`);
  }
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
