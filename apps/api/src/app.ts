import type { IncomingMessage, ServerResponse } from 'node:http';
import type { ApiConfig } from './config.js';
import {
  badRequest,
  forbidden,
  internal,
  isAppError,
  methodNotAllowed,
  notFound,
  unauthorized,
} from './errors.js';
import { matchRoutePath, type Middleware, type RequestContext, type Route } from './http.js';
import { createJsonFileUserRepository } from './auth/jsonFileUserRepository.js';
import { createMemoryUserRepository } from './auth/memoryUserRepository.js';
import type { UserRepository } from './auth/repositories.js';
import { createSessionStore, type SessionStore } from './auth/sessions.js';
import { corsMiddleware } from './middleware/cors.js';
import { createAuthRateLimiter } from './middleware/authRateLimit.js';
import { originGuardMiddleware } from './middleware/originGuard.js';
import { createRateLimiter } from './middleware/rateLimit.js';
import { requestIdMiddleware } from './middleware/requestId.js';
import { securityHeadersMiddleware } from './middleware/securityHeaders.js';
import { sessionMiddleware } from './middleware/session.js';
import { deviceMiddleware } from './middleware/device.js';
import { sendFailure } from './respond.js';
import { AUTHZ_DENIED_MESSAGE } from './auth/authorization.js';
import { hasPermission, roleAtLeast } from '@drobon/shared';
import { createAuthRoutes } from './routes/auth.js';
import { createAuthzRoutes } from './routes/authz.js';
import { createEchoRoutes } from './routes/echo.js';
import { createHealthRoutes } from './routes/health.js';
import { createStatusRoutes } from './routes/status.js';
import { createSubscriptionRoutes } from './routes/subscription.js';
import { createUsageRoutes } from './routes/usage.js';
import { createProjectRoutes } from './routes/projects.js';
import { createUsageService, type UsageService } from './usage/service.js';
import { createMemoryUsageStore, createUsageFileStore } from './usage/store.js';
import {
  createJsonFileProjectStore,
  createMemoryProjectStore,
  type ProjectStore,
} from './projects/store.js';
import {
  createJsonFileScanStore,
  createMemoryScanStore,
  type ScanStore,
} from './scans/store.js';
import {
  createJsonFileSourceStore,
  createMemorySourceStore,
  type SourceSnapshotStore,
} from './scans/sources.js';
import { createSastEngine } from './scans/sast/engine.js';
import { createScaEngine } from './scans/sca/engine.js';
import { createSecretsEngine } from './scans/secrets/engine.js';
import { createNullIntelligenceProvider } from './scans/sca/provider.js';
import { createEngineRegistry, type ScanEngine, type ScanEngineRegistry } from './scans/engines.js';
import { createScanProcessor, type ScanProcessor } from './scans/processor.js';
import { createScanRoutes } from './routes/scans.js';
import { createSourceRoutes } from './routes/sources.js';
import { createReportsRoutes } from './routes/reports.js';
import { createAssistantRoutes } from './routes/assistant.js';
import { createPaymentRoutes } from './routes/payments.js';
import { createPartnerRoutes } from './routes/partners.js';
import { createAdminRoutes } from './routes/admin.js';
import { createWorkspaceRoutes } from './routes/workspace.js';
import { createJsonFilePaymentStore, createMemoryPaymentStore, type PaymentStore } from './payments/store.js';
import { createJsonFilePartnerStore, createMemoryPartnerStore, type PartnerStore } from './partners/store.js';
import { createJsonFilePaymentConfigStore, createMemoryPaymentConfigStore, type PaymentConfigStore } from './payments/configStore.js';
import { createPartnerService, type PartnerService } from './partners/service.js';
import { createPaymentService, type PaymentService } from './payments/service.js';
import type { UsageStore } from './usage/store.js';
import type { Logger } from './logger.js';
import { createDastTargetPolicy, type DastTargetPolicy } from './scans/dast/target.js';
import type { DastTransport } from './scans/dast/http.js';
import { createDastEngine } from './scans/dast/engine.js';
import { createJsonFileAssessmentStore, createMemoryAssessmentStore, type AssessmentStore } from './assessments/store.js';
import { createAssessmentRoutes } from './routes/assessments.js';

export interface AppDeps {
  config: ApiConfig;
  logger: Logger;
  /**
   * Extension point for future modules (scanning, admin, ...).
   * Also used by tests to inject fault routes without touching prod code.
   */
  extraRoutes?: Route[];
  /** Clock for request timing (injectable for tests). */
  now?: () => number;
  /** Clock for the rate limiter (injectable for tests). */
  rateLimitNow?: () => number;
  /**
   * Account repository. Defaults to the durable JSON store at
   * `config.authStorePath` (`:memory:` for explicitly ephemeral setups).
   * Tests inject their own instance to control persistence.
   */
  users?: UserRepository;
  /** Session store. Defaults to a fresh in-memory store (Pump 2). */
  sessions?: SessionStore;
  /**
   * Usage/quota store (Pump 5). Defaults to the durable JSON store at
   * `config.usageStorePath` (`:memory:` for explicitly ephemeral setups).
   * Tests inject their own instance to control persistence.
   */
  usageStore?: UsageStore;
  /**
   * Clock for usage period math (epoch ms, injectable so tests exercise
   * UTC month boundaries deterministically).
   */
  usageNow?: () => number;
  /**
   * Project store (Pump 6). Defaults to the durable JSON store at
   * `config.projectStorePath` (`:memory:` for explicitly ephemeral
   * setups). Tests inject their own instance to control persistence.
   */
  projectStore?: ProjectStore;
  /**
   * Scan-job store (Pump 7). Defaults to the durable JSON store at
   * `config.scanStorePath` (`:memory:` for explicitly ephemeral
   * setups). Tests inject their own instance to control persistence.
   */
  scanStore?: ScanStore;
  /** Structured owner/project-bound Security Professional assessment records. */
  assessmentStore?: AssessmentStore;
  /**
   * Source-snapshot store (Pump 8) — the SAST scan target. Defaults to
   * the durable JSON store at `config.sourceStorePath` (`:memory:` for
   * explicitly ephemeral setups). Tests inject their own instance to
   * control persistence.
   */
  sourceStore?: SourceSnapshotStore;
  /**
   * Scanner engines. DEFAULT (Pump 8): the REAL SAST engine is
   * registered — SAST scans actually analyze the project's source
   * snapshot and produce real findings. SCA/SECRETS/DAST remain
   * unimplemented (SCAN_ENGINE_NOT_IMPLEMENTED). Pass an explicit list
   * (including `[]`) to control the registry exactly — tests do.
   */
  scanEngines?: readonly ScanEngine[];
  /** Production-default policy; injectable with deterministic DNS fixtures in tests. */
  dastTargetPolicy?: DastTargetPolicy;
  /** Test-only network seam; production uses the bounded pinned Node HTTP transport. */
  dastTransport?: DastTransport;
  /**
   * Scan processor interval (Pump 7; default 5s, injectable for tests).
   */
  scanProcessorIntervalMs?: number;
  /**
   * Auto-start the scan processor (default true — the server runtime
   * calls start() on boot: recover interrupted scans, drain QUEUED
   * work, run the sweep). Tests disable it for deterministic control.
   */
  scanProcessorAutoStart?: boolean;
  /** Durable payment + audit JSON store; tests may inject a local fixture. */
  paymentStore?: PaymentStore;
  partnerStore?: PartnerStore;
  paymentConfigStore?: PaymentConfigStore;
  /** Clock for partner/coupon/commission timestamps (injectable for tests). */
  partnerNow?: () => number;
  /** Payment-service clock (epoch ms), injectable for deterministic tests. */
  paymentNow?: () => number;
}

export interface App {
  handle: (req: IncomingMessage, res: ServerResponse) => Promise<void>;
  routes: Route[];
  resetRateLimit: () => void;
  /**
   * The scan processor (Pump 7): recovery + worker loop + periodic
   * sweep. The server runtime starts it on boot; tests drive it
   * explicitly.
   */
  scanProcessor: ScanProcessor;
  /** Startup recovery for interrupted cross-store payment approval sagas. */
  ready: Promise<void>;
}

/** Direct peer address only — proxy headers (`X-Forwarded-For`) are never trusted. */
function clientIp(req: IncomingMessage): string {
  return req.socket.remoteAddress ?? 'unknown';
}

/** Parse and normalize the request target to a bare pathname. */
function getPathname(req: IncomingMessage): string {
  const target = req.url ?? '/';
  let pathname: string;
  try {
    pathname = new URL(target, 'http://localhost').pathname;
  } catch {
    throw badRequest('Malformed request URL.');
  }
  if (pathname.length > 1 && pathname.endsWith('/')) {
    pathname = pathname.slice(0, -1);
  }
  return pathname;
}

/**
 * Compose middleware + router into a single request handler with centralized
 * error mapping and structured access logging.
 */
export function createApp(deps: AppDeps): App {
  const { config, logger } = deps;
  const clock = deps.now ?? Date.now;

  // Account store: durable by default (fail-fast on a corrupt document —
  // createApp throws, the process refuses to start). Tests inject their
  // own repository; `:memory:` is the explicitly-ephemeral dev opt-in.
  const users: UserRepository =
    deps.users ??
    (config.authStorePath === ':memory:'
      ? createMemoryUserRepository()
      : createJsonFileUserRepository(config.authStorePath));
  const sessions: SessionStore =
    deps.sessions ?? createSessionStore({ ttlSeconds: config.authSessionTtlSeconds });
  // Usage/quota store (Pump 5): durable by default (fail-fast on a
  // corrupt document — the process refuses to start, quotas never
  // silently reset); tests inject their own store.
  const usageStore: UsageStore =
    deps.usageStore ??
    (config.usageStorePath === ':memory:'
      ? createMemoryUsageStore()
      : createUsageFileStore(config.usageStorePath));
  const projectStore: ProjectStore =
    deps.projectStore ??
    (config.projectStorePath === ':memory:'
      ? createMemoryProjectStore()
      : createJsonFileProjectStore(config.projectStorePath));
  // Scan-job store (Pump 7): durable by default (fail-fast on a corrupt
  // document — createApp throws, the process refuses to start). Tests
  // inject their own store; `:memory:` is the ephemeral dev opt-in.
  const scanStore: ScanStore =
    deps.scanStore ??
    (config.scanStorePath === ':memory:'
      ? createMemoryScanStore()
      : createJsonFileScanStore(config.scanStorePath));
  const assessmentStore: AssessmentStore =
    deps.assessmentStore ??
    (config.assessmentStorePath === ':memory:'
      ? createMemoryAssessmentStore()
      : createJsonFileAssessmentStore(config.assessmentStorePath));
  // Source-snapshot store (Pump 8): durable by default (fail-fast on a
  // corrupt document — the process refuses to start). Tests inject
  // their own store; `:memory:` is the ephemeral dev opt-in.
  const sourceStore: SourceSnapshotStore =
    deps.sourceStore ??
    (config.sourceStorePath === ':memory:'
      ? createMemorySourceStore()
      : createJsonFileSourceStore(config.sourceStorePath));
  // Payment requests and their audit events share one atomic JSON document.
  // The configured store is durable outside explicitly ephemeral development.
  const paymentStore: PaymentStore =
    deps.paymentStore ??
    (config.paymentStorePath === ':memory:'
      ? createMemoryPaymentStore()
      : createJsonFilePaymentStore(config.paymentStorePath));
  // Partner/coupon/commission share one atomic JSON document ( Pump 7 ). Durable
  // outside explicitly ephemeral development; production forbids ':memory:'.
  const partnerStore: PartnerStore =
    deps.partnerStore ??
    (config.partnerStorePath === ':memory:'
      ? createMemoryPartnerStore()
      : createJsonFilePartnerStore(config.partnerStorePath));
  // Runtime admin-managed payment configuration (Phase 20): PRO price and
  // manual-transfer destinations. Seeded from the boot-time environment until
  // the first platform-admin change; durable outside ephemeral development.
  const paymentConfig: PaymentConfigStore =
    deps.paymentConfigStore ??
    (config.paymentConfigStorePath === ':memory:'
      ? createMemoryPaymentConfigStore(config.proPriceMinorUnits)
      : createJsonFilePaymentConfigStore(config.paymentConfigStorePath, config.proPriceMinorUnits));
  const partners: PartnerService = createPartnerService({
    store: partnerStore,
    users,
    payments: paymentStore,
    ...(deps.partnerNow === undefined ? {} : { now: deps.partnerNow }),
  });
  const payments: PaymentService = createPaymentService({
    config,
    store: paymentStore,
    users,
    paymentConfig,
    ...(deps.paymentNow === undefined ? {} : { now: deps.paymentNow }),
    partners,
  });
  const ready = payments
    .recoverInterruptedApprovals()
    .then(() => partners.recoverUnsettledCommissions());
  // One policy instance is shared by configuration preflight, scan
  // preflight and engine execution. The engine re-resolves and pins
  // every request independently, so saved configuration is never
  // treated as authorization to reach a stale/private address.
  const dastTargetPolicy = deps.dastTargetPolicy ?? createDastTargetPolicy();
  // The engine registry (server-side composition ONLY). Pump 8: REAL
  // SAST; Pump 9: REAL SCA; Pump 10: REAL Secrets; Pump 11: bounded,
  // passive, single-target DAST. No browser or exploit capabilities.
  const intelligenceProvider = createNullIntelligenceProvider();
  const scanEngines: ScanEngineRegistry = createEngineRegistry(
    deps.scanEngines ?? [
      createSastEngine({ sources: sourceStore }),
      createScaEngine({ sources: sourceStore, provider: intelligenceProvider }),
      createSecretsEngine({ sources: sourceStore }),
      createDastEngine({
        targetPolicy: dastTargetPolicy,
        ...(deps.dastTransport === undefined ? {} : { transport: deps.dastTransport }),
      }),
    ],
  );
  const scanProcessor: ScanProcessor = createScanProcessor({
    store: scanStore,
    engines: scanEngines,
    logger,
    ...(deps.scanProcessorIntervalMs === undefined
      ? {}
      : { intervalMs: deps.scanProcessorIntervalMs }),
  });
  const usage: UsageService = createUsageService({
    store: usageStore,
    ...(deps.usageNow === undefined ? {} : { now: deps.usageNow }),
  });

  const routes: Route[] = [
    ...createHealthRoutes({ config }),
    ...createStatusRoutes({ config }),
    ...createEchoRoutes({ config }),
    ...createAuthRoutes({ config, users, sessions }),
    ...createAuthzRoutes({ config, users }),
    ...createSubscriptionRoutes(),
    ...createPaymentRoutes({ config, users, payments }),
    ...createPartnerRoutes({ config, partners }),
    ...createAdminRoutes({ config, users, projects: projectStore, scans: scanStore, payments, scanProcessor, paymentConfig }),
    ...createUsageRoutes({ config, users, usage }),
    ...createWorkspaceRoutes({ projects: projectStore, scans: scanStore, now: clock }),
    ...createProjectRoutes({ config, projects: projectStore, dastTargetPolicy }),
    ...createAssessmentRoutes({ config, projects: projectStore, assessments: assessmentStore, scans: scanStore, now: clock }),
    ...createScanRoutes({
      config,
      users,
      projects: projectStore,
      assessments: assessmentStore,
      scans: scanStore,
      sources: sourceStore,
      usage,
      processor: scanProcessor,
      dastTargetPolicy,
    }),
    ...createSourceRoutes({ config, projects: projectStore, sources: sourceStore }),
    ...createReportsRoutes({ config, projects: projectStore, scans: scanStore, now: clock }),
    ...createAssistantRoutes({ config, projects: projectStore, scans: scanStore }),
    ...(deps.extraRoutes ?? []),
  ];

  const rateLimiter = createRateLimiter(
    deps.rateLimitNow === undefined
      ? {
          maxRequests: config.rateLimitMaxRequests,
          windowMs: config.rateLimitWindowMs,
        }
      : {
          maxRequests: config.rateLimitMaxRequests,
          windowMs: config.rateLimitWindowMs,
          now: deps.rateLimitNow,
        },
  );

  const authRateLimiter = createAuthRateLimiter(
    deps.rateLimitNow === undefined
      ? {
          maxRequests: config.authRateLimitMaxRequests,
          windowMs: config.authRateLimitWindowMs,
        }
      : {
          maxRequests: config.authRateLimitMaxRequests,
          windowMs: config.authRateLimitWindowMs,
          now: deps.rateLimitNow,
        },
  );

  const paymentRateLimiter = createRateLimiter(
    deps.rateLimitNow === undefined
      ? { maxRequests: config.paymentRateLimitMaxRequests, windowMs: config.paymentRateLimitWindowMs }
      : { maxRequests: config.paymentRateLimitMaxRequests, windowMs: config.paymentRateLimitWindowMs, now: deps.rateLimitNow },
  );
  const paymentMutationRateLimit: Middleware = async (req, res, ctx, next) => {
    const paymentMutation = (ctx.method === 'POST' || ctx.method === 'PATCH') &&
      (ctx.pathname === '/api/v1/payments' || ctx.pathname.startsWith('/api/v1/payments/') ||
        ctx.pathname.startsWith('/api/v1/admin/payments/') || ctx.pathname.startsWith('/api/v1/admin/partners/') ||
        ctx.pathname === '/api/v1/admin/partners' || ctx.pathname.startsWith('/api/v1/admin/commissions/') ||
        ctx.pathname === '/api/v1/admin/payment-config' || ctx.pathname.startsWith('/api/v1/admin/payment-config/'));
    if (paymentMutation) await paymentRateLimiter.middleware(req, res, ctx, next);
    else await next();
  };

  const adminRateLimiter = createRateLimiter(
    deps.rateLimitNow === undefined
      ? { maxRequests: config.adminRateLimitMaxRequests, windowMs: config.adminRateLimitWindowMs }
      : { maxRequests: config.adminRateLimitMaxRequests, windowMs: config.adminRateLimitWindowMs, now: deps.rateLimitNow },
  );
  const adminEndpointRateLimit: Middleware = async (req, res, ctx, next) => {
    if (ctx.pathname === '/api/v1/admin' || ctx.pathname.startsWith('/api/v1/admin/')) {
      await adminRateLimiter.middleware(req, res, ctx, next);
    } else await next();
  };

  // Pipeline order: request ID → security headers → CORS → global rate limit
  // → credential + payment mutation + admin-read limits → CSRF origin guard → session →
  // device resolution → routing (with the existing authentication boundary).
  const middlewares: Middleware[] = [
    requestIdMiddleware(),
    securityHeadersMiddleware(),
    corsMiddleware({ allowedOrigins: config.corsAllowedOrigins }),
    rateLimiter.middleware,
    authRateLimiter.middleware,
    paymentMutationRateLimit,
    adminEndpointRateLimit,
    originGuardMiddleware({ allowedOrigins: config.corsAllowedOrigins }),
    sessionMiddleware({ sessions, users, cookieSecure: config.cookieSecure }),
    deviceMiddleware({ cookieSecure: config.cookieSecure }),
  ];

  const routeRequest = async (
    req: IncomingMessage,
    res: ServerResponse,
    ctx: RequestContext,
  ): Promise<void> => {
    // Pump 6: routes may be parameterized (`:segment`); exact-match
    // routes keep their original semantics (see matchRoutePath).
    let matchParams: Record<string, string> | undefined;
    const match = routes.find((route) => {
      if (route.method !== ctx.method) {
        return false;
      }
      const params = matchRoutePath(route.path, ctx.pathname);
      if (params === undefined) {
        return false;
      }
      matchParams = params;
      return true;
    });
    if (match !== undefined && matchParams !== undefined) {
      ctx.params = matchParams;
      // Authentication first (401), then authorization (403) — one choke
      // point for every protected route, in the pipeline's documented
      // order. Handlers behind these flags can trust `ctx.user`/`ctx.authz`.
      const needsAuth =
        match.requireAuth === true ||
        match.requireRole !== undefined ||
        match.requirePermission !== undefined;
      if (needsAuth && ctx.user === undefined) {
        throw unauthorized();
      }
      if (ctx.user !== undefined) {
        if (
          match.requirePermission !== undefined &&
          !hasPermission(ctx.user.role, match.requirePermission)
        ) {
          throw forbidden(AUTHZ_DENIED_MESSAGE);
        }
        if (
          match.requireRole !== undefined &&
          !roleAtLeast(ctx.user.role, match.requireRole)
        ) {
          throw forbidden(AUTHZ_DENIED_MESSAGE);
        }
      }
      await match.handler(req, res, ctx);
      return;
    }
    const allowed = routes
      .filter((route) => matchRoutePath(route.path, ctx.pathname) !== undefined)
      .map((route) => route.method);
    if (allowed.length > 0) {
      throw methodNotAllowed(allowed);
    }
    throw notFound();
  };

  const handle = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const ctx: RequestContext = {
      id: '',
      method: req.method ?? 'GET',
      pathname: '/',
      ip: clientIp(req),
      startedAtMs: clock(),
      logger,
      params: {},
    };
    // A dead client socket must never crash the process: a write to an
    // aborted response emits 'error' on the response stream.
    res.once('error', () => {
      logger.debug('Response stream error', { requestId: ctx.id });
    });
    try {
      ctx.pathname = getPathname(req);
      let index = -1;
      const dispatch = async (position: number): Promise<void> => {
        if (position <= index) {
          throw internal('next() called multiple times.');
        }
        index = position;
        const current = middlewares[position];
        if (current === undefined) {
          await routeRequest(req, res, ctx);
          return;
        }
        await current(req, res, ctx, () => dispatch(position + 1));
      };
      await dispatch(0);
    } catch (error) {
      if (res.headersSent) {
        logger.error('Error after response started', {
          requestId: ctx.id,
          err: error,
        });
        res.end();
      } else {
        sendFailure(res, ctx, error, config.env);
        const status = isAppError(error) ? error.statusCode : 500;
        if (status >= 500) {
          logger.error('Request failed', {
            requestId: ctx.id,
            method: ctx.method,
            path: ctx.pathname,
            status,
            err: error,
          });
        } else if (status === 429) {
          // Two distinct 429 causes with different meanings: transport
          // rate limiting vs. plan quota exhaustion (Pump 5).
          if (isAppError(error) && error.code === 'QUOTA_EXCEEDED') {
            logger.warn('Scan quota exceeded', {
              requestId: ctx.id,
              method: ctx.method,
              path: ctx.pathname,
              status,
            });
          } else {
            logger.warn('Request rate limited', {
              requestId: ctx.id,
              method: ctx.method,
              path: ctx.pathname,
              status,
            });
          }
        } else {
          logger.info('Request rejected', {
            requestId: ctx.id,
            method: ctx.method,
            path: ctx.pathname,
            status,
          });
        }
      }
    } finally {
      logger.info('Request completed', {
        requestId: ctx.id,
        method: ctx.method,
        path: ctx.pathname,
        status: res.statusCode,
        durationMs: clock() - ctx.startedAtMs,
      });
    }
  };

  // Pump 7: the server runtime starts the scan processor on boot
  // (recovery + drain + sweep). Tests disable auto-start for
  // deterministic control (they call scanProcessor.drain() explicitly).
  if (deps.scanProcessorAutoStart !== false) {
    void scanProcessor.start().catch((error: unknown) => {
      logger.error('Scan processor failed to start', { err: error });
    });
  }

  return {
    handle,
    routes,
    scanProcessor,
    ready,
    resetRateLimit: (): void => {
      rateLimiter.reset();
      authRateLimiter.reset();
      paymentRateLimiter.reset();
      adminRateLimiter.reset();
    },
  };
}
