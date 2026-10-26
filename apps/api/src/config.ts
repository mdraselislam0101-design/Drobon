import { createRequire } from 'node:module';
import {
  ENVIRONMENTS,
  LOG_LEVELS,
  type EnvironmentName,
  type LogLevel,
} from '@drobon/shared';

/**
 * Validated API configuration. This is the ONLY module allowed to read
 * `process.env` (enforced by `test/static-safety.test.ts`).
 */
export interface ApiConfig {
  env: EnvironmentName;
  host: string;
  port: number;
  logLevel: LogLevel;
  /** Normalized exact origins (`scheme://host[:port]`), no credentials. */
  corsAllowedOrigins: string[];
  rateLimitMaxRequests: number;
  rateLimitWindowMs: number;
  bodyMaxBytes: number;
  version: string;
  /**
   * Where durable user accounts live. A filesystem path (the minimum auth
   * persistence boundary) or the literal `:memory:` for explicitly
   * ephemeral setups — rejected in production by {@link loadConfig}.
   */
  authStorePath: string;
  /** scrypt cost parameter N (power of two). */
  authScryptCost: number;
  /** Absolute session lifetime in seconds. */
  authSessionTtlSeconds: number;
  /** Dedicated rate limit for credential endpoints (per client IP). */
  authRateLimitMaxRequests: number;
  authRateLimitWindowMs: number;
  /**
   * `Secure` attribute for the session cookie. Derived from the
   * environment (production only) so plain-HTTP localhost keeps working.
   */
  cookieSecure: boolean;
  /**
   * Whether the authorization capability probes
   * (`GET /api/v1/authz/capabilities/*`) are registered. Derived:
   * enabled outside production so they can never accidentally ship as
   * public production surface — in production those paths simply 404.
   * The ownership route (`GET /api/v1/users`) is always registered.
   */
  authzProbeRoutes: boolean;
  /**
   * Where durable usage/quota counters live (Pump 5): a filesystem path
   * (same minimum-persistence pattern as the account store) or the
   * literal `:memory:` for explicitly ephemeral setups — rejected in
   * production by {@link loadConfig} (quota state must survive restarts,
   * otherwise a restart would reset allowances).
   */
  usageStorePath: string;
  /**
   * Whether the scan-consumption probe (`POST /api/v1/usage/consume`) is
   * registered. Derived: enabled outside production only — it exists so
   * the usage boundary is observable and E2E-testable before the real
   * Scan/Job system lands. In production it 404s; production scan
   * consumption will happen inside the future scan workflow, never
   * through a user-callable endpoint. `GET /api/v1/usage` is always
   * registered (it is a real user-facing feature).
   */
  usageConsumeRoutes: boolean;
  /**
   * Where durable project records live (Pump 6): a filesystem path
   * (same minimum-persistence pattern as the account and usage stores)
   * or the literal `:memory:` for explicitly ephemeral setups — rejected
   * in production by {@link loadConfig} (projects must survive restarts).
   */
  projectStorePath: string;
  /**
   * Durable scan-job store path (Pump 7). `:memory:` is the explicitly
   * ephemeral dev/test opt-in — rejected in production (scan state must
   * survive restarts).
   */
  scanStorePath: string;
  /** Durable project-scoped Security Professional assessment records. */
  assessmentStorePath: string;
  studentStorePath: string;
  /**
   * Durable source-snapshot store path (Pump 8 — the SAST scan
   * target). `:memory:` is the explicitly ephemeral dev/test opt-in —
   * rejected in production (scan targets must survive restarts).
   */
  sourceStorePath: string;
  /**
   * The vulnerability-intelligence provider selector (Pump 9).
   * `none` — the locked Null provider (no dataset; assessments are
   * honestly NOT_ASSESSED / NO_DATA_LOADED). `filesystem` — loads
   * the external Drobon-Dataset corpus from DATASET_PATH (separate
   * repo, never committed to the app repo). Anything unknown fails
   * fast at startup.
   */
  vulnIntelProvider: 'none' | 'filesystem';
  /** Filesystem path to the external Drobon-Dataset repo (when provider is filesystem). */
  datasetPath?: string | undefined;
  /**
   * Optional path to an operator-supplied GENERIC advisory pack (Pump 15).
   * This is runtime configuration, not a bundled dataset: the file lives
   * outside the repo and drives version/advisory checks for ANY ecosystem.
   * When absent, advisory analysis reports honest NOT_CONFIGURED.
   */
  advisoryPath?: string | undefined;
  /** Durable Pump 15 payment + audit JSON document. */
  paymentStorePath: string;
  /** Admin complimentary PRO entitlement store (persistent by default). */
  entitlementStorePath: string;
  /** Durable Pump 7 partner/coupon/commission JSON document. */
  partnerStorePath: string;
  /** Durable Phase 20 runtime payment-configuration JSON document. */
  paymentConfigStorePath: string;
  /** Server-authoritative PRO price in BDT poisha (minor units). */
  proPriceMinorUnits: number;
  /** Explicit platform payment-reviewer user-id allowlist; account roles are insufficient. */
  paymentReviewerIds: string[];
  /** Manual-only methods currently offered; never online gateway integrations. */
  manualPaymentMethods: Array<'MANUAL_TRANSFER'>;
  /** Safe user-visible instructions, bounded and server-configured. */
  manualPaymentInstructions: string;
  paymentRateLimitMaxRequests: number;
  paymentRateLimitWindowMs: number;
  /** Server-side platform-admin user ID allowlist; live account role must also be ADMIN. */
  platformAdminIds: string[];
  /** Dedicated per-IP limiter for high-cost platform-admin reads. */
  adminRateLimitMaxRequests: number;
  adminRateLimitWindowMs: number;
}

export class ConfigError extends Error {
  readonly issues: string[];

  constructor(issues: string[]) {
    super(`Invalid configuration: ${issues.join('; ')}`);
    this.name = 'ConfigError';
    this.issues = [...issues];
  }
}

function hasControlCharacter(value: string): boolean {
  for (const character of value) {
    const code = character.charCodeAt(0);
    if (code < 32 || code === 127) return true;
  }
  return false;
}

function parseInteger(raw: string | undefined, name: string, issues: string[]): number | undefined {
  if (raw === undefined || raw.trim().length === 0) {
    return undefined;
  }
  if (!/^-?\d+$/.test(raw.trim())) {
    issues.push(`${name} must be an integer`);
    return undefined;
  }
  return Number.parseInt(raw.trim(), 10);
}

function normalizeOrigin(raw: string): string | undefined {
  const trimmed = raw.trim();
  if (trimmed.length === 0 || trimmed.includes('@') || /[\s]/.test(trimmed)) {
    return undefined;
  }
  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    return undefined;
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return undefined;
  }
  if (url.username.length > 0 || url.password.length > 0) {
    return undefined;
  }
  if (url.search.length > 0 || url.hash.length > 0) {
    return undefined;
  }
  if (url.pathname.length > 0 && url.pathname !== '/') {
    return undefined;
  }
  return url.origin;
}

function readServiceVersion(): string {
  try {
    const require = createRequire(import.meta.url);
    const pkg = require('../package.json') as { version?: unknown };
    if (typeof pkg.version === 'string' && pkg.version.length > 0) {
      return pkg.version;
    }
  } catch {
    // Fall through to the fallback below.
  }
  return '0.0.0-dev';
}

/**
 * Parse and validate environment into {@link ApiConfig}. Collects every
 * problem and throws a single {@link ConfigError} — fail fast, fail loudly.
 */
export function loadConfig(env: Record<string, string | undefined> = process.env): ApiConfig {
  const issues: string[] = [];

  const rawEnv = env['NODE_ENV'];
  const environment: EnvironmentName =
    rawEnv === undefined || rawEnv === '' ? 'development' : (rawEnv as EnvironmentName);
  if (!(ENVIRONMENTS as readonly string[]).includes(environment)) {
    issues.push(`NODE_ENV must be one of ${ENVIRONMENTS.join(', ')}`);
  }

  const host = env['HOST'] ?? '127.0.0.1';
  if (host.trim().length === 0 || host.length > 255 || /[\s]/.test(host)) {
    issues.push('HOST must be a non-empty hostname or IP without whitespace');
  }

  const port = parseInteger(env['PORT'], 'PORT', issues) ?? 3001;
  if (port < 1 || port > 65535) {
    issues.push('PORT must be an integer between 1 and 65535');
  }

  const rawLevel = env['LOG_LEVEL'];
  const logLevel: LogLevel = rawLevel === undefined || rawLevel === '' ? 'info' : (rawLevel as LogLevel);
  if (!(LOG_LEVELS as readonly string[]).includes(logLevel)) {
    issues.push(`LOG_LEVEL must be one of ${LOG_LEVELS.join(', ')}`);
  }

  const corsAllowedOrigins: string[] = [];
  const rawOrigins = env['CORS_ALLOWED_ORIGINS'] ?? '';
  for (const piece of rawOrigins.split(',')) {
    if (piece.trim().length === 0) {
      continue;
    }
    const normalized = normalizeOrigin(piece);
    if (normalized === undefined) {
      issues.push(
        `CORS_ALLOWED_ORIGINS entry "${piece.trim()}" must be an exact http(s) origin without credentials, path, query or fragment`,
      );
    } else if (!corsAllowedOrigins.includes(normalized)) {
      corsAllowedOrigins.push(normalized);
    }
  }

  const rateLimitMaxRequests =
    parseInteger(env['RATE_LIMIT_MAX_REQUESTS'], 'RATE_LIMIT_MAX_REQUESTS', issues) ?? 100;
  if (rateLimitMaxRequests < 1 || rateLimitMaxRequests > 1_000_000) {
    issues.push('RATE_LIMIT_MAX_REQUESTS must be an integer between 1 and 1000000');
  }

  const rateLimitWindowMs =
    parseInteger(env['RATE_LIMIT_WINDOW_MS'], 'RATE_LIMIT_WINDOW_MS', issues) ?? 60_000;
  if (rateLimitWindowMs < 1000 || rateLimitWindowMs > 3_600_000) {
    issues.push('RATE_LIMIT_WINDOW_MS must be an integer between 1000 and 3600000');
  }

  const bodyMaxBytes = parseInteger(env['BODY_MAX_BYTES'], 'BODY_MAX_BYTES', issues) ?? 1_048_576;
  if (bodyMaxBytes < 1024 || bodyMaxBytes > 10_485_760) {
    issues.push('BODY_MAX_BYTES must be an integer between 1024 and 10485760');
  }

  // --- Authentication (Pump 2) -------------------------------------------
  const authStorePath = (env['AUTH_STORE_PATH'] ?? '.data/users.json').trim();
  const memoryStore = authStorePath === ':memory:';
  if (authStorePath.length === 0) {
    issues.push('AUTH_STORE_PATH must be a non-empty filesystem path or ":memory:"');
  } else if (memoryStore && environment === 'production') {
    issues.push('AUTH_STORE_PATH=":memory:" is not allowed in production (accounts would not persist)');
  }

  const authScryptCost =
    parseInteger(env['AUTH_SCRYPT_COST'], 'AUTH_SCRYPT_COST', issues) ?? 32_768;
  if (
    authScryptCost < 1024 ||
    authScryptCost > 1_048_576 ||
    (authScryptCost & (authScryptCost - 1)) !== 0
  ) {
    issues.push('AUTH_SCRYPT_COST must be a power of two between 1024 and 1048576');
  }

  const authSessionTtlSeconds =
    parseInteger(env['AUTH_SESSION_TTL_SECONDS'], 'AUTH_SESSION_TTL_SECONDS', issues) ?? 604_800;
  if (authSessionTtlSeconds < 60 || authSessionTtlSeconds > 2_592_000) {
    issues.push('AUTH_SESSION_TTL_SECONDS must be an integer between 60 and 2592000');
  }

  const authRateLimitMaxRequests =
    parseInteger(env['AUTH_RATE_LIMIT_MAX_REQUESTS'], 'AUTH_RATE_LIMIT_MAX_REQUESTS', issues) ?? 30;
  if (authRateLimitMaxRequests < 1 || authRateLimitMaxRequests > 1_000_000) {
    issues.push('AUTH_RATE_LIMIT_MAX_REQUESTS must be an integer between 1 and 1000000');
  }

  const authRateLimitWindowMs =
    parseInteger(env['AUTH_RATE_LIMIT_WINDOW_MS'], 'AUTH_RATE_LIMIT_WINDOW_MS', issues) ?? 60_000;
  if (authRateLimitWindowMs < 1000 || authRateLimitWindowMs > 3_600_000) {
    issues.push('AUTH_RATE_LIMIT_WINDOW_MS must be an integer between 1000 and 3600000');
  }

  // --- Usage / quota (Pump 5) --------------------------------------------
  const usageStorePath = (env['USAGE_STORE_PATH'] ?? '.data/usage.json').trim();
  const usageMemoryStore = usageStorePath === ':memory:';
  if (usageStorePath.length === 0) {
    issues.push('USAGE_STORE_PATH must be a non-empty filesystem path or ":memory:"');
  } else if (usageMemoryStore && environment === 'production') {
    issues.push(
      'USAGE_STORE_PATH=":memory:" is not allowed in production (quota state would not persist)',
    );
  }

  // --- Scans (Pump 7) -------------------------------------------------------
  const scanStorePath = (env['SCAN_STORE_PATH'] ?? '.data/scans.json').trim();
  const scanMemoryStore = scanStorePath === ':memory:';
  if (scanStorePath.length === 0) {
    issues.push('SCAN_STORE_PATH must be a non-empty filesystem path or ":memory:"');
  } else if (scanMemoryStore && environment === 'production') {
    issues.push(
      'SCAN_STORE_PATH=":memory:" is not allowed in production (scan jobs would not persist)',
    );
  }

  // --- Structured assessments (Pump 22) ------------------------------------
  const assessmentStorePath = (env['ASSESSMENT_STORE_PATH'] ?? '.data/assessments.json').trim();
  const assessmentMemoryStore = assessmentStorePath === ':memory:';
  if (assessmentStorePath.length === 0) {
    issues.push('ASSESSMENT_STORE_PATH must be a non-empty filesystem path or ":memory:"');
  } else if (assessmentMemoryStore && environment === 'production') {
    issues.push('ASSESSMENT_STORE_PATH=":memory:" is not allowed in production (assessment records would not persist)');
  }

  // --- Student progress (Phase 22 Pump 2) -----------------------------------
  const studentStorePath = (env['STUDENT_STORE_PATH'] ?? '.data/student-progress.json').trim();
  const studentMemoryStore = studentStorePath === ':memory:';
  if (studentStorePath.length === 0) {
    issues.push('STUDENT_STORE_PATH must be a non-empty filesystem path or ":memory:"');
  } else if (studentMemoryStore && environment === 'production') {
    issues.push('STUDENT_STORE_PATH=":memory:" is not allowed in production (student progress would not persist)');
  }

  // --- Sources (Pump 8) -----------------------------------------------------
  // VULN_INTEL_PROVIDER (Pump 9): the dataset lock in config form —
  // 'none' is the locked default (no dataset); 'filesystem' loads the
  // external Drobon-Dataset corpus from DATASET_PATH (separate repo,
  // never committed to the app repo).
  const vulnIntelProviderRaw = (env['VULN_INTEL_PROVIDER'] ?? 'none').trim().toLowerCase();
  let vulnIntelProvider: 'none' | 'filesystem' = 'none';
  if (vulnIntelProviderRaw === 'none' || vulnIntelProviderRaw === 'filesystem') {
    vulnIntelProvider = vulnIntelProviderRaw as 'none' | 'filesystem';
  } else {
    issues.push(`VULN_INTEL_PROVIDER must be one of none, filesystem`);
  }
  const datasetPathRaw = (env['DATASET_PATH'] ?? '').trim();
  let datasetPath: string | undefined;
  if (vulnIntelProvider === 'filesystem') {
    if (datasetPathRaw.length === 0) {
      issues.push('DATASET_PATH must be set when VULN_INTEL_PROVIDER=filesystem (path to Drobon-Dataset checkout)');
    } else if (datasetPathRaw.length > 500 || hasControlCharacter(datasetPathRaw)) {
      issues.push('DATASET_PATH must be 1-500 printable characters');
    } else {
      datasetPath = datasetPathRaw;
    }
  } else if (datasetPathRaw.length > 0) {
    issues.push('DATASET_PATH is only allowed when VULN_INTEL_PROVIDER=filesystem');
  }
  // ADVISORY_PATH (Pump 15): optional, independent of the dataset provider.
  const advisoryPathRaw = (env['ADVISORY_PATH'] ?? '').trim();
  let advisoryPath: string | undefined;
  if (advisoryPathRaw.length > 0) {
    if (advisoryPathRaw.length > 500 || hasControlCharacter(advisoryPathRaw)) {
      issues.push('ADVISORY_PATH must be 1-500 printable characters');
    } else {
      advisoryPath = advisoryPathRaw;
    }
  }

  const sourceStorePath = (env['SOURCE_STORE_PATH'] ?? '.data/sources.json').trim();
  const sourceMemoryStore = sourceStorePath === ':memory:';
  if (sourceStorePath.length === 0) {
    issues.push('SOURCE_STORE_PATH must be a non-empty filesystem path or ":memory:"');
  } else if (sourceMemoryStore && environment === 'production') {
    issues.push(
      'SOURCE_STORE_PATH=":memory:" is not allowed in production (scan targets would not persist)',
    );
  }

  // --- Projects (Pump 6) ----------------------------------------------------
  const projectStorePath = (env['PROJECT_STORE_PATH'] ?? '.data/projects.json').trim();
  const projectMemoryStore = projectStorePath === ':memory:';
  if (projectStorePath.length === 0) {
    issues.push('PROJECT_STORE_PATH must be a non-empty filesystem path or ":memory:"');
  } else if (projectMemoryStore && environment === 'production') {
    issues.push(
      'PROJECT_STORE_PATH=":memory:" is not allowed in production (projects would not persist)',
    );
  }

  // --- Payment foundation (Pump 15) ---------------------------------------
  const paymentStorePath = (env['PAYMENT_STORE_PATH'] ?? '.data/payments.json').trim();
  if (paymentStorePath.length === 0) {
    issues.push('PAYMENT_STORE_PATH must be a non-empty filesystem path or ":memory:"');
  } else if (paymentStorePath === ':memory:' && environment === 'production') {
    issues.push('PAYMENT_STORE_PATH=":memory:" is not allowed in production (payment records must persist)');
  }
  const partnerStorePath = (env['PARTNER_STORE_PATH'] ?? '.data/partners.json').trim();
  if (partnerStorePath.length === 0) {
    issues.push('PARTNER_STORE_PATH must be a non-empty filesystem path or ":memory:"');
  } else if (partnerStorePath === ':memory:' && environment === 'production') {
    issues.push('PARTNER_STORE_PATH=":memory:" is not allowed in production (partner/commission records must persist)');
  }
  const paymentConfigStorePath = (env['PAYMENT_CONFIG_STORE_PATH'] ?? '.data/payment-config.json').trim();
  if (paymentConfigStorePath.length === 0) {
    issues.push('PAYMENT_CONFIG_STORE_PATH must be a non-empty filesystem path or ":memory:"');
  } else if (paymentConfigStorePath === ':memory:' && environment === 'production') {
    issues.push('PAYMENT_CONFIG_STORE_PATH=":memory:" is not allowed in production (admin payment configuration must persist)');
  }
  // --- Admin complimentary PRO entitlements (persistent by default) -------
  const entitlementStorePath = (env['ENTITLEMENT_STORE_PATH'] ?? '.data/entitlements.json').trim();
  if (entitlementStorePath.length === 0) {
    issues.push('ENTITLEMENT_STORE_PATH must be a non-empty filesystem path or ":memory:"');
  } else if (entitlementStorePath === ':memory:' && environment === 'production') {
    issues.push('ENTITLEMENT_STORE_PATH=":memory:" is not allowed in production (granted entitlements must persist)');
  }
  const proPriceMinorUnits = parseInteger(env['PRO_PRICE_MINOR_UNITS'], 'PRO_PRICE_MINOR_UNITS', issues) ?? 100_000;
  if (!Number.isSafeInteger(proPriceMinorUnits) || proPriceMinorUnits < 1 || proPriceMinorUnits > 100_000_000) {
    issues.push('PRO_PRICE_MINOR_UNITS must be an integer between 1 and 100000000');
  }
  const paymentReviewerIds: string[] = [];
  for (const id of (env['PAYMENT_REVIEWER_IDS'] ?? '').split(',')) {
    const normalized = id.trim();
    if (normalized.length === 0) continue;
    if (!/^usr_[A-Za-z0-9_-]{1,128}$/.test(normalized)) {
      issues.push('PAYMENT_REVIEWER_IDS entries must be bounded server-assigned user ids');
    } else if (!paymentReviewerIds.includes(normalized)) {
      paymentReviewerIds.push(normalized);
    }
  }
  const manualPaymentMethods: Array<'MANUAL_TRANSFER'> = [];
  const rawPaymentMethods = env['PAYMENT_MANUAL_METHODS'] ?? 'MANUAL_TRANSFER';
  for (const method of rawPaymentMethods.split(',')) {
    const normalized = method.trim().toUpperCase();
    if (normalized.length === 0) continue;
    if (normalized !== 'MANUAL_TRANSFER') {
      issues.push('PAYMENT_MANUAL_METHODS currently supports only MANUAL_TRANSFER');
    } else if (!manualPaymentMethods.includes('MANUAL_TRANSFER')) {
      manualPaymentMethods.push('MANUAL_TRANSFER');
    }
  }
  const manualPaymentInstructions = (env['PAYMENT_MANUAL_INSTRUCTIONS'] ??
    'Payment instructions are not configured. Contact support before sending funds. A submitted reference is user-provided evidence and is not payment verification.').trim();
  if (manualPaymentInstructions.length === 0 || manualPaymentInstructions.length > 500 || hasControlCharacter(manualPaymentInstructions)) {
    issues.push('PAYMENT_MANUAL_INSTRUCTIONS must be 1–500 printable characters');
  }
  const paymentRateLimitMaxRequests = parseInteger(env['PAYMENT_RATE_LIMIT_MAX_REQUESTS'], 'PAYMENT_RATE_LIMIT_MAX_REQUESTS', issues) ?? 10;
  if (paymentRateLimitMaxRequests < 1 || paymentRateLimitMaxRequests > 100_000) {
    issues.push('PAYMENT_RATE_LIMIT_MAX_REQUESTS must be an integer between 1 and 100000');
  }
  const paymentRateLimitWindowMs = parseInteger(env['PAYMENT_RATE_LIMIT_WINDOW_MS'], 'PAYMENT_RATE_LIMIT_WINDOW_MS', issues) ?? 60_000;
  if (paymentRateLimitWindowMs < 1000 || paymentRateLimitWindowMs > 3_600_000) {
    issues.push('PAYMENT_RATE_LIMIT_WINDOW_MS must be an integer between 1000 and 3600000');
  }

  // Platform authority is separate from account ADMIN and payment-reviewer
  // authority. Only operator-provisioned IDs in this server environment can
  // be platform admins; the route also requires a fresh live ADMIN role.
  const platformAdminIds: string[] = [];
  for (const id of (env['PLATFORM_ADMIN_IDS'] ?? '').split(',')) {
    const normalized = id.trim();
    if (normalized.length === 0) continue;
    if (!/^usr_[A-Za-z0-9_-]{1,128}$/.test(normalized)) {
      issues.push('PLATFORM_ADMIN_IDS entries must be bounded server-assigned user ids');
    } else if (!platformAdminIds.includes(normalized)) {
      platformAdminIds.push(normalized);
    }
  }
  const adminRateLimitMaxRequests = parseInteger(env['ADMIN_RATE_LIMIT_MAX_REQUESTS'], 'ADMIN_RATE_LIMIT_MAX_REQUESTS', issues) ?? 60;
  if (adminRateLimitMaxRequests < 1 || adminRateLimitMaxRequests > 100_000) {
    issues.push('ADMIN_RATE_LIMIT_MAX_REQUESTS must be an integer between 1 and 100000');
  }
  const adminRateLimitWindowMs = parseInteger(env['ADMIN_RATE_LIMIT_WINDOW_MS'], 'ADMIN_RATE_LIMIT_WINDOW_MS', issues) ?? 60_000;
  if (adminRateLimitWindowMs < 1000 || adminRateLimitWindowMs > 3_600_000) {
    issues.push('ADMIN_RATE_LIMIT_WINDOW_MS must be an integer between 1000 and 3600000');
  }

  if (issues.length > 0) {
    throw new ConfigError(issues);
  }

  return {
    env: environment,
    host,
    port,
    logLevel,
    corsAllowedOrigins,
    rateLimitMaxRequests,
    rateLimitWindowMs,
    bodyMaxBytes,
    version: readServiceVersion(),
    authStorePath,
    authScryptCost,
    authSessionTtlSeconds,
    authRateLimitMaxRequests,
    authRateLimitWindowMs,
    cookieSecure: environment === 'production',
    authzProbeRoutes: environment !== 'production',
    usageStorePath,
    usageConsumeRoutes: environment !== 'production',
    projectStorePath,
    scanStorePath,
    assessmentStorePath,
    studentStorePath,
    sourceStorePath,
    vulnIntelProvider,
    datasetPath,
    advisoryPath,
    paymentStorePath,
    entitlementStorePath,
    partnerStorePath,
    paymentConfigStorePath,
    proPriceMinorUnits,
    paymentReviewerIds,
    manualPaymentMethods,
    manualPaymentInstructions,
    paymentRateLimitMaxRequests,
    paymentRateLimitWindowMs,
    platformAdminIds,
    adminRateLimitMaxRequests,
    adminRateLimitWindowMs,
  };
}
