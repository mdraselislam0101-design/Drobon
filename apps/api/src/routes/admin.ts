import {
  ADMIN_ACCOUNT_PAGE_MAX,
  ADMIN_ACCOUNT_PAGE_SIZE_MAX,
  ADMIN_SCAN_PAGE_MAX,
  ADMIN_SCAN_PAGE_SIZE_MAX,
  ADMIN_FINDING_PAGE_MAX,
  ADMIN_FINDING_PAGE_SIZE_MAX,
  FINDING_LIFECYCLE_STATES,
  isFindingSeverity,
  isScanStatus,
  isScanType,
  ADMIN_AUDIT_PAGE_MAX,
  ADMIN_AUDIT_PAGE_SIZE_MAX,
  ADMIN_AUDIT_RANGE_MAX_DAYS,
  ADMIN_SEARCH_MAX_LENGTH,
  isAccountRole,
  isPaymentAuditAction,
  isPlan,
  isUserType,
  type AdminAccountSummary,
  type AdminAuditRecord,
  type AdminDashboardResponse,
  type AdminScansResponse,
  type AdminFindingsResponse,
  type PaymentAuditAction,
  type FindingSeverity,
  type ScanStatus,
  type ScanType,
  type FindingLifecycleState,
  type Plan,
  type UserType,
} from '@drobon/shared';
import type { ApiConfig } from '../config.js';
import { forbidden, unauthorized, validationError } from '../errors.js';
import type { RequestContext, Route } from '../http.js';
import type { UserRepository } from '../auth/repositories.js';
import { normalizeSubscription } from '../auth/subscriptions.js';
import type { PaymentService } from '../payments/service.js';
import type { ProjectStore } from '../projects/store.js';
import type { ScanStore } from '../scans/store.js';
import type { ScanProcessor } from '../scans/processor.js';
import { sendSuccess } from '../respond.js';

export interface AdminRouteDeps {
  config: ApiConfig;
  users: UserRepository;
  projects: ProjectStore;
  scans: ScanStore;
  payments: PaymentService;
  scanProcessor: ScanProcessor;
}

function actorFrom(ctx: RequestContext) {
  if (ctx.user === undefined) throw unauthorized();
  return ctx.user;
}

/** Platform control is operator-provisioned ID allowlist AND live ADMIN role. */
export function assertPlatformAdmin(ctx: RequestContext, config: ApiConfig) {
  const actor = actorFrom(ctx);
  if (actor.role !== 'ADMIN' || !config.platformAdminIds.includes(actor.id)) {
    throw forbidden('You do not have access to this resource.');
  }
  return actor;
}

function query(req: { url?: string | undefined }, allowed: readonly string[]): URLSearchParams {
  const params = new URL(req.url ?? '/', 'http://drobon.invalid').searchParams;
  for (const key of params.keys()) {
    if (!allowed.includes(key) || params.getAll(key).length !== 1) {
      throw validationError([{ path: key, message: 'Unexpected or repeated query parameter.' }]);
    }
  }
  return params;
}

function positiveInt(raw: string | null, fallback: number, max: number, name: string): number {
  if (raw === null) return fallback;
  if (!/^\d{1,6}$/.test(raw)) throw validationError([{ path: name, message: 'Must be a bounded positive integer.' }]);
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < 1 || value > max) {
    throw validationError([{ path: name, message: `Must be between 1 and ${max}.` }]);
  }
  return value;
}

function isoDateBound(raw: string | null, name: string, endOfDay = false): string | undefined {
  if (raw === null) return undefined;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(raw)) throw validationError([{ path: name, message: 'Use an ISO calendar date (YYYY-MM-DD).' }]);
  const parsed = new Date(`${raw}T${endOfDay ? '23:59:59.999' : '00:00:00.000'}Z`);
  if (Number.isNaN(parsed.getTime()) || parsed.toISOString().slice(0, 10) !== raw) {
    throw validationError([{ path: name, message: 'Date is invalid.' }]);
  }
  return parsed.toISOString();
}

function dateRange(from: string | undefined, to: string | undefined): void {
  if ((from === undefined) !== (to === undefined)) {
    throw validationError([{ path: 'from', message: 'Supply both from and to dates, or neither.' }]);
  }
  if (from !== undefined && to !== undefined) {
    const span = Date.parse(to) - Date.parse(from);
    if (span < 0 || span > ADMIN_AUDIT_RANGE_MAX_DAYS * 24 * 60 * 60 * 1000) {
      throw validationError([{ path: 'from', message: 'Date range must be ordered and at most 366 days.' }]);
    }
  }
}

function accountFilters(params: URLSearchParams) {
  const roleRaw = params.get('role');
  const typeRaw = params.get('userType');
  const planRaw = params.get('plan');
  const rawSearch = params.get('search');
  if (roleRaw !== null && !isAccountRole(roleRaw)) throw validationError([{ path: 'role', message: 'Unsupported account role.' }]);
  if (typeRaw !== null && typeRaw !== 'NONE' && !isUserType(typeRaw)) throw validationError([{ path: 'userType', message: 'Unsupported UserType.' }]);
  if (planRaw !== null && !isPlan(planRaw)) throw validationError([{ path: 'plan', message: 'Unsupported plan.' }]);
  let search: string | undefined;
  if (rawSearch !== null) {
    search = rawSearch.trim().toLowerCase();
    // eslint-disable-next-line no-control-regex -- reject control chars in untrusted search input.
    if (search.length < 1 || search.length > ADMIN_SEARCH_MAX_LENGTH || /[\u0000-\u001f\u007f]/.test(search)) {
      throw validationError([{ path: 'search', message: `Search must be 1–${ADMIN_SEARCH_MAX_LENGTH} printable characters.` }]);
    }
  }
  return {
    ...(roleRaw === null ? {} : { role: roleRaw }),
    ...(typeRaw === null ? {} : { userType: typeRaw as UserType | 'NONE' }),
    ...(planRaw === null ? {} : { plan: planRaw as Plan }),
    ...(search === undefined ? {} : { search }),
  };
}

export function createAdminRoutes(deps: AdminRouteDeps): Route[] {
  const { config, users, projects, scans, payments, scanProcessor } = deps;
  return [
    {
      method: 'GET', path: '/api/v1/admin/dashboard', requireAuth: true,
      handler: async (req, res, ctx) => {
        assertPlatformAdmin(ctx, config);
        if (query(req, []).size !== 0) throw validationError([{ path: 'query', message: 'Dashboard does not accept query parameters.' }]);
        const [accountResult, projectResult, scanResult, paymentResult] = await Promise.allSettled([
          Promise.resolve().then(() => users.adminCounts()),
          Promise.resolve().then(() => projects.adminCounts()),
          Promise.resolve().then(() => scans.adminSummary(Date.now())),
          Promise.resolve().then(() => payments.adminCounts()),
        ]);
        const accountCounts = accountResult.status === 'fulfilled' ? accountResult.value : undefined;
        const projectCounts = projectResult.status === 'fulfilled' ? projectResult.value : undefined;
        const scanCounts = scanResult.status === 'fulfilled' ? scanResult.value : undefined;
        const paymentCounts = paymentResult.status === 'fulfilled' ? paymentResult.value : undefined;
        const body: AdminDashboardResponse = {
          asOf: new Date().toISOString(),
          accounts: accountCounts === undefined ? { state: 'UNAVAILABLE' } : {
            state: 'AVAILABLE', total: accountCounts.total,
            free: accountCounts.byPlan.FREE, pro: accountCounts.byPlan.PRO,
            subscriptionByStatus: accountCounts.bySubscriptionStatus,
          },
          projects: projectCounts === undefined ? { state: 'UNAVAILABLE' } : { state: 'AVAILABLE', ...projectCounts },
          scans: scanCounts === undefined ? { state: 'UNAVAILABLE' } : { state: 'AVAILABLE', total: scanCounts.total, byStatus: scanCounts.byStatus, byType: scanCounts.byType, recentlyCompleted: scanCounts.recentlyCompleted },
          payments: paymentCounts === undefined ? { state: 'UNAVAILABLE' } : { state: 'AVAILABLE', total: paymentCounts.total, byStatus: paymentCounts.byStatus, submittedAmountMinorUnits: paymentCounts.submittedAmountMinorUnits, approvedAmountMinorUnits: paymentCounts.approvedAmountMinorUnits, currency: 'BDT' },
          findings: scanCounts === undefined ? { state: 'UNAVAILABLE' } : { state: 'AVAILABLE', bySeverity: scanCounts.findingsBySeverity, byLifecycleState: scanCounts.findingsByLifecycleState, unresolved: scanCounts.unresolvedFindings, dastObservations: scanCounts.dastObservations, scaNotAssessed: scanCounts.scaNotAssessed },
          system: {
            api: 'SERVING', web: 'NOT_ASSESSED',
            accountPersistence: config.authStorePath === ':memory:' ? 'EPHEMERAL' : 'LOADED_AT_STARTUP',
            paymentPersistence: config.paymentStorePath === ':memory:' ? 'EPHEMERAL' : 'LOADED_AT_STARTUP',
            apiAttachedScanProcessor: scanProcessor.started ? 'RUNNING' : 'NOT_STARTED', separateWorker: 'NOT_INTEGRATED',
            assistantFeature: 'DETERMINISTIC_READ_ONLY', aiProvider: 'NONE', paymentGateway: 'UNAVAILABLE',
            vulnerabilityDataset: 'NO_DATA_LOADED', securityDataset: 'SEPARATE_NOT_LOADED',
          },
        };
        sendSuccess(res, ctx, body);
      },
    },
    {
      method: 'GET', path: '/api/v1/admin/accounts', requireAuth: true,
      handler: async (req, res, ctx) => {
        assertPlatformAdmin(ctx, config);
        const params = query(req, ['page', 'pageSize', 'role', 'userType', 'plan', 'search']);
        const page = positiveInt(params.get('page'), 1, ADMIN_ACCOUNT_PAGE_MAX, 'page');
        const pageSize = positiveInt(params.get('pageSize'), 25, ADMIN_ACCOUNT_PAGE_SIZE_MAX, 'pageSize');
        const filters = accountFilters(params);
        const result = await users.adminPage(filters, page, pageSize);
        const paymentStats = payments.accountStats(result.accounts.map((account) => account.id));
        const accounts: AdminAccountSummary[] = result.accounts.map((account) => {
          const subscription = normalizeSubscription(account.subscription);
          const payment = paymentStats.get(account.id);
          return {
            accountId: account.id, email: account.email, role: account.role, userType: account.userType,
            plan: subscription.plan, subscriptionStatus: subscription.status, createdAt: account.createdAt,
            accountStatus: 'UNAVAILABLE', paymentRequestCount: payment?.requestCount ?? 0,
            latestPaymentStatus: payment?.latestPaymentStatus ?? null,
          };
        });
        sendSuccess(res, ctx, { accounts, page, pageSize, total: result.total });
      },
    },
    {
      method: 'GET', path: '/api/v1/admin/scans', requireAuth: true,
      handler: async (req, res, ctx) => {
        assertPlatformAdmin(ctx, config);
        const params = query(req, ['page', 'pageSize', 'status', 'type', 'accountId', 'projectId', 'from', 'to']);
        const page = positiveInt(params.get('page'), 1, ADMIN_SCAN_PAGE_MAX, 'page');
        const pageSize = positiveInt(params.get('pageSize'), 25, ADMIN_SCAN_PAGE_SIZE_MAX, 'pageSize');
        const statusRaw = params.get('status');
        const typeRaw = params.get('type');
        if (statusRaw !== null && !isScanStatus(statusRaw)) throw validationError([{ path: 'status', message: 'Unsupported scan status.' }]);
        if (typeRaw !== null && !isScanType(typeRaw)) throw validationError([{ path: 'type', message: 'Unsupported scan type.' }]);
        const accountId = params.get('accountId') ?? undefined;
        if (accountId !== undefined && !/^usr_[A-Za-z0-9_-]{1,128}$/.test(accountId)) throw validationError([{ path: 'accountId', message: 'Account ID is invalid.' }]);
        const projectId = params.get('projectId') ?? undefined;
        if (projectId !== undefined && !/^prj_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(projectId)) throw validationError([{ path: 'projectId', message: 'Project ID is invalid.' }]);
        const from = isoDateBound(params.get('from'), 'from');
        const to = isoDateBound(params.get('to'), 'to', true);
        dateRange(from, to);
        const result = await scans.adminScanPage({
          ...(statusRaw === null ? {} : { status: statusRaw as ScanStatus }),
          ...(typeRaw === null ? {} : { scanType: typeRaw as ScanType }),
          ...(accountId === undefined ? {} : { accountId }), ...(projectId === undefined ? {} : { projectId }),
          ...(from === undefined ? {} : { from }), ...(to === undefined ? {} : { to }),
        }, page, pageSize);
        const body: AdminScansResponse = { scans: result.scans, page, pageSize, total: result.total };
        sendSuccess(res, ctx, body);
      },
    },
    {
      method: 'GET', path: '/api/v1/admin/findings', requireAuth: true,
      handler: async (req, res, ctx) => {
        assertPlatformAdmin(ctx, config);
        const params = query(req, ['page', 'pageSize', 'severity', 'scanner', 'state', 'projectId', 'from', 'to']);
        const page = positiveInt(params.get('page'), 1, ADMIN_FINDING_PAGE_MAX, 'page');
        const pageSize = positiveInt(params.get('pageSize'), 25, ADMIN_FINDING_PAGE_SIZE_MAX, 'pageSize');
        const severityRaw = params.get('severity');
        const scannerRaw = params.get('scanner');
        const stateRaw = params.get('state');
        if (severityRaw !== null && !isFindingSeverity(severityRaw)) throw validationError([{ path: 'severity', message: 'Unsupported finding severity.' }]);
        if (scannerRaw !== null && !isScanType(scannerRaw)) throw validationError([{ path: 'scanner', message: 'Unsupported scanner.' }]);
        if (stateRaw !== null && !(FINDING_LIFECYCLE_STATES as readonly string[]).includes(stateRaw)) throw validationError([{ path: 'state', message: 'Unsupported finding lifecycle state.' }]);
        const projectId = params.get('projectId') ?? undefined;
        if (projectId !== undefined && !/^prj_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(projectId)) throw validationError([{ path: 'projectId', message: 'Project ID is invalid.' }]);
        const from = isoDateBound(params.get('from'), 'from');
        const to = isoDateBound(params.get('to'), 'to', true);
        dateRange(from, to);
        const result = await scans.adminFindingPage({
          ...(severityRaw === null ? {} : { severity: severityRaw as FindingSeverity }),
          ...(scannerRaw === null ? {} : { scanner: scannerRaw as ScanType }),
          ...(stateRaw === null ? {} : { lifecycleState: stateRaw as FindingLifecycleState }),
          ...(projectId === undefined ? {} : { projectId }),
          ...(from === undefined ? {} : { from }), ...(to === undefined ? {} : { to }),
        }, page, pageSize);
        const body: AdminFindingsResponse = { findings: result.findings, page, pageSize, total: result.total };
        sendSuccess(res, ctx, body);
      },
    },
    {
      method: 'GET', path: '/api/v1/admin/audit', requireAuth: true,
      handler: async (req, res, ctx) => {
        assertPlatformAdmin(ctx, config);
        const params = query(req, ['page', 'pageSize', 'action', 'accountId', 'paymentId', 'from', 'to']);
        const page = positiveInt(params.get('page'), 1, ADMIN_AUDIT_PAGE_MAX, 'page');
        const pageSize = positiveInt(params.get('pageSize'), 50, ADMIN_AUDIT_PAGE_SIZE_MAX, 'pageSize');
        const actionRaw = params.get('action');
        if (actionRaw !== null && !isPaymentAuditAction(actionRaw)) throw validationError([{ path: 'action', message: 'Unsupported audit action.' }]);
        const accountId = params.get('accountId') ?? undefined;
        if (accountId !== undefined && !/^usr_[A-Za-z0-9_-]{1,128}$/.test(accountId)) throw validationError([{ path: 'accountId', message: 'Account ID is invalid.' }]);
        const paymentId = params.get('paymentId') ?? undefined;
        if (paymentId !== undefined && !/^pay_[0-9a-f-]{36}$/i.test(paymentId)) throw validationError([{ path: 'paymentId', message: 'Payment ID is invalid.' }]);
        const from = isoDateBound(params.get('from'), 'from');
        const to = isoDateBound(params.get('to'), 'to', true);
        dateRange(from, to);
        const result = payments.adminAudit(page, pageSize, {
          ...(actionRaw === null ? {} : { action: actionRaw as PaymentAuditAction }),
          ...(accountId === undefined ? {} : { accountId }), ...(paymentId === undefined ? {} : { paymentId }),
          ...(from === undefined ? {} : { from }), ...(to === undefined ? {} : { to }),
        });
        const events: AdminAuditRecord[] = result.events.map((event) => ({ source: 'PAYMENT', ...event }));
        sendSuccess(res, ctx, { events, page, pageSize, total: result.total, coverage: 'PAYMENT_EVENTS_ONLY' });
      },
    },

  ];
}
