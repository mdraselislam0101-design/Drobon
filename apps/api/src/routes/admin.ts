import {
  ADMIN_ACCOUNT_PAGE_MAX,
  ADMIN_ENTITLEMENT_PAGE_MAX,
  ADMIN_ENTITLEMENT_PAGE_SIZE_MAX,
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
  isAdminProGrantAuditAction,
  isAdminProGrantStatus,
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
import { conflict, forbidden, internal, notFound, unauthorized, validationError } from '../errors.js';
import type { RequestContext, Route } from '../http.js';
import type { UserRepository } from '../auth/repositories.js';
import { normalizeSubscription } from '../auth/subscriptions.js';
import {
  PRICE_MAX_MINOR_UNITS,
  PRICE_MIN_MINOR_UNITS,
  type PaymentConfigState,
  type PaymentConfigStore,
} from '../payments/configStore.js';
import type { PaymentService } from '../payments/service.js';
import type { EntitlementService } from '../entitlements/service.js';
import type { ProjectStore } from '../projects/store.js';
import type { ScanStore } from '../scans/store.js';
import type { ScanProcessor } from '../scans/processor.js';
import { readJsonBody } from '../lib/body.js';
import * as v from '../lib/validate.js';
import { sendSuccess } from '../respond.js';

export interface AdminRouteDeps {
  config: ApiConfig;
  users: UserRepository;
  projects: ProjectStore;
  scans: ScanStore;
  payments: PaymentService;
  scanProcessor: ScanProcessor;
  /** Runtime admin-managed payment configuration (Phase 20). */
  paymentConfig: PaymentConfigStore;
  /** Admin complimentary PRO entitlements (grants are NEVER payments). */
  entitlements?: EntitlementService;
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

/** Phase 20: closed admin schemas for the payment configuration surface. */
const paymentConfigPriceSchema = v.object({
  proPriceMinorUnits: v.number({ integer: true, min: PRICE_MIN_MINOR_UNITS, max: PRICE_MAX_MINOR_UNITS }),
});
const paymentConfigMethodAddSchema = v.object({
  displayName: v.string({ minLength: 1, maxLength: 80, trim: true }),
  accountNumber: v.string({ minLength: 4, maxLength: 40, trim: true }),
  instructions: v.optional(v.string({ maxLength: 300, trim: true })),
});
/** Closed schemas for the admin complimentary PRO surface (grants ≠ payments). */
const proGrantSchema = v.object({
  accountId: v.string({ minLength: 5, maxLength: 128, trim: true, pattern: /^usr_[A-Za-z0-9_-]{1,128}$/ }),
  expiresAt: v.optional(v.string({ maxLength: 40 })),
  reason: v.optional(v.string({ maxLength: 300, trim: true })),
});
const proGrantRevokeSchema = v.object({
  reason: v.optional(v.string({ minLength: 3, maxLength: 300, trim: true })),
});

const paymentConfigMethodPatchSchema = v.object({
  displayName: v.optional(v.string({ minLength: 1, maxLength: 80, trim: true })),
  accountNumber: v.optional(v.string({ minLength: 4, maxLength: 40, trim: true })),
  instructions: v.optional(v.string({ maxLength: 300, trim: true })),
  enabled: v.optional(v.boolean()),
});

function toAdminConfigResponse(state: PaymentConfigState) {
  return {
    proPriceMinorUnits: state.proPriceMinorUnits,
    currency: 'BDT' as const,
    destinations: state.destinations.map(({ methodId, method, displayName, accountNumber, instructions, enabled }) => ({
      methodId, method, displayName, accountNumber, instructions, enabled,
    })),
    updatedAt: state.updatedAt,
    audit: state.audit.map((entry) => ({ ...entry })),
  };
}

export function createAdminRoutes(deps: AdminRouteDeps): Route[] {
  const { config, users, projects, scans, payments, scanProcessor, paymentConfig, entitlements } = deps;
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
          const grant = entitlements?.getActiveGrant(account.id) ?? undefined;
          const source = grant !== undefined ? 'ADMIN_GRANT' : entitlements?.proEntitlementSourceForSubscription(account.id, subscription);
          return {
            accountId: account.id, email: account.email, role: account.role, userType: account.userType,
            plan: subscription.plan, subscriptionStatus: subscription.status, createdAt: account.createdAt,
            effectivePlan: grant !== undefined ? 'PRO' : subscription.plan,
            proEntitlementSource: source ?? null,
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

    // ---- Phase 20: platform-admin payment configuration -------------------
    // Server-authoritative runtime configuration: PRO price + manual-transfer
    // destinations. Only the dual-gated platform admin (live ADMIN role AND
    // operator-provisioned ID allowlist) may read or mutate it. Changes apply
    // to NEW quotes/payments only; historical payment records snapshot their
    // own amounts and are never rewritten. Account numbers appear raw only
    // here (the admin manages them); audit details store masked values.
    {
      method: 'GET', path: '/api/v1/admin/payment-config', requireAuth: true,
      handler: async (req, res, ctx): Promise<void> => {
        assertPlatformAdmin(ctx, config);
        if (query(req, []).size !== 0) throw validationError([{ path: 'query', message: 'Payment configuration does not accept query parameters.' }]);
        sendSuccess(res, ctx, toAdminConfigResponse(paymentConfig.current()));
      },
    },
    {
      method: 'PATCH', path: '/api/v1/admin/payment-config', requireAuth: true,
      handler: async (req, res, ctx): Promise<void> => {
        const actor = assertPlatformAdmin(ctx, config);
        v.rejectUnexpectedQuery(req);
        const raw = await readJsonBody(req, { maxBytes: Math.min(config.bodyMaxBytes, 4096) });
        const parsed = paymentConfigPriceSchema.parse(raw);
        if (!parsed.ok) throw validationError(parsed.issues);
        const updated = await paymentConfig.setPrice(actor.id, parsed.value.proPriceMinorUnits, new Date().toISOString());
        ctx.logger.info('Payment config price updated', { requestId: ctx.logId, actorId: actor.id });
        sendSuccess(res, ctx, toAdminConfigResponse(updated));
      },
    },
    {
      method: 'POST', path: '/api/v1/admin/payment-config/methods', requireAuth: true,
      handler: async (req, res, ctx): Promise<void> => {
        const actor = assertPlatformAdmin(ctx, config);
        v.rejectUnexpectedQuery(req);
        const keyHeader = req.headers['idempotency-key'];
        if (typeof keyHeader !== 'string' || !/^[A-Za-z0-9_-]{8,128}$/.test(keyHeader)) {
          throw validationError([{ path: 'Idempotency-Key', message: 'Supply an 8–128 character idempotency key.' }]);
        }
        const raw = await readJsonBody(req, { maxBytes: Math.min(config.bodyMaxBytes, 4096) });
        const parsed = paymentConfigMethodAddSchema.parse(raw);
        if (!parsed.ok) throw validationError(parsed.issues);
        const result = await paymentConfig.addMethod(
          actor.id,
          {
            displayName: parsed.value.displayName,
            accountNumber: parsed.value.accountNumber,
            instructions: parsed.value.instructions ?? '',
          },
          new Date().toISOString(),
          keyHeader,
        );
        if (result.kind === 'DUPLICATE_DISPLAY_NAME') throw conflict('A payment destination with this display name already exists.');
        ctx.logger.info('Payment config destination added', { requestId: ctx.logId, actorId: actor.id, replay: result.kind === 'REPLAY' });
        sendSuccess(res, ctx, { destination: { methodId: result.destination.methodId, method: result.destination.method, displayName: result.destination.displayName, accountNumber: result.destination.accountNumber, instructions: result.destination.instructions, enabled: result.destination.enabled } }, result.kind === 'CREATED' ? 201 : 200);
      },
    },
    {
      method: 'PATCH', path: '/api/v1/admin/payment-config/methods/:methodId', requireAuth: true,
      handler: async (req, res, ctx): Promise<void> => {
        const actor = assertPlatformAdmin(ctx, config);
        v.rejectUnexpectedQuery(req);
        const methodId = ctx.params['methodId'];
        if (typeof methodId !== 'string' || !/^pmd_[0-9a-f-]{36}$/i.test(methodId)) throw notFound();
        const raw = await readJsonBody(req, { maxBytes: Math.min(config.bodyMaxBytes, 4096) });
        const parsed = paymentConfigMethodPatchSchema.parse(raw);
        if (!parsed.ok) throw validationError(parsed.issues);
        const patch: { displayName?: string; accountNumber?: string; instructions?: string; enabled?: boolean } = {};
        if (parsed.value.displayName !== undefined) patch.displayName = parsed.value.displayName;
        if (parsed.value.accountNumber !== undefined) patch.accountNumber = parsed.value.accountNumber;
        if (parsed.value.instructions !== undefined) patch.instructions = parsed.value.instructions;
        if (parsed.value.enabled !== undefined) patch.enabled = parsed.value.enabled;
        // `v.optional` materializes every shape key as `undefined`, so the
        // emptiness check must look at the mapped patch, not the parse output.
        if (patch.displayName === undefined && patch.accountNumber === undefined && patch.instructions === undefined && patch.enabled === undefined) {
          throw validationError([{ path: 'body', message: 'Supply at least one destination field to update.' }]);
        }
        const result = await paymentConfig.updateMethod(actor.id, methodId, patch, new Date().toISOString());
        if (result.kind === 'NOT_FOUND') throw notFound();
        if (result.kind === 'DUPLICATE_DISPLAY_NAME') throw conflict('Another payment destination already uses this display name.');
        ctx.logger.info('Payment config destination updated', { requestId: ctx.logId, actorId: actor.id, methodId });
        sendSuccess(res, ctx, toAdminConfigResponse(result.state));
      },
    },

    // ---- Admin complimentary PRO entitlements (grants are NOT payments) ----
    // A grant is a persistent entitlement record with its own lifecycle and
    // audit trail. It NEVER creates a payment, never touches the payment
    // ledger/revenue/commissions/coupons, and NEVER mutates the account's
    // persisted subscription — paid PRO always survives a revoke/expiry.
    {
      method: 'POST', path: '/api/v1/admin/entitlements/pro', requireAuth: true,
      handler: async (req, res, ctx): Promise<void> => {
        const actor = assertPlatformAdmin(ctx, config);
        if (entitlements === undefined) throw internal('Entitlement service is not available.');
        v.rejectUnexpectedQuery(req);
        const raw = await readJsonBody(req, { maxBytes: Math.min(config.bodyMaxBytes, 4096) });
        const parsed = proGrantSchema.parse(raw);
        if (!parsed.ok) throw validationError(parsed.issues);
        const { grant, created } = await entitlements.grantPro(actor.id, {
          accountId: parsed.value.accountId,
          ...(parsed.value.expiresAt === undefined ? {} : { expiresAt: parsed.value.expiresAt }),
          ...(parsed.value.reason === undefined ? {} : { reason: parsed.value.reason }),
        });
        ctx.logger.info('Admin PRO grant submitted', { requestId: ctx.logId, actorId: actor.id, grantId: grant.grantId, created, targetAccountId: grant.accountId });
        sendSuccess(res, ctx, { grant }, created ? 201 : 200);
      },
    },
    {
      method: 'GET', path: '/api/v1/admin/entitlements/pro', requireAuth: true,
      handler: async (req, res, ctx): Promise<void> => {
        assertPlatformAdmin(ctx, config);
        if (entitlements === undefined) throw internal('Entitlement service is not available.');
        const params = query(req, ['page', 'pageSize', 'accountId', 'status']);
        const page = positiveInt(params.get('page'), 1, ADMIN_ENTITLEMENT_PAGE_MAX, 'page');
        const pageSize = positiveInt(params.get('pageSize'), 25, ADMIN_ENTITLEMENT_PAGE_SIZE_MAX, 'pageSize');
        const accountId = params.get('accountId') ?? undefined;
        if (accountId !== undefined && !/^usr_[A-Za-z0-9_-]{1,128}$/.test(accountId)) throw validationError([{ path: 'accountId', message: 'Account ID is invalid.' }]);
        const statusRaw = params.get('status');
        if (statusRaw !== null && !isAdminProGrantStatus(statusRaw)) throw validationError([{ path: 'status', message: 'Unsupported grant status.' }]);
        const result = entitlements.listGrants({
          ...(accountId === undefined ? {} : { accountId }),
          ...(statusRaw === null ? {} : { status: statusRaw as 'ACTIVE' | 'REVOKED' }),
        }, page, pageSize);
        sendSuccess(res, ctx, result);
      },
    },
    {
      method: 'GET', path: '/api/v1/admin/entitlements/pro/audit', requireAuth: true,
      handler: async (req, res, ctx): Promise<void> => {
        assertPlatformAdmin(ctx, config);
        if (entitlements === undefined) throw internal('Entitlement service is not available.');
        const params = query(req, ['page', 'pageSize', 'accountId', 'action', 'grantId', 'from', 'to']);
        const page = positiveInt(params.get('page'), 1, ADMIN_AUDIT_PAGE_MAX, 'page');
        const pageSize = positiveInt(params.get('pageSize'), 50, ADMIN_AUDIT_PAGE_SIZE_MAX, 'pageSize');
        const actionRaw = params.get('action');
        if (actionRaw !== null && !isAdminProGrantAuditAction(actionRaw)) throw validationError([{ path: 'action', message: 'Unsupported audit action.' }]);
        const accountId = params.get('accountId') ?? undefined;
        if (accountId !== undefined && !/^usr_[A-Za-z0-9_-]{1,128}$/.test(accountId)) throw validationError([{ path: 'accountId', message: 'Account ID is invalid.' }]);
        const grantId = params.get('grantId') ?? undefined;
        if (grantId !== undefined && !/^apg_[0-9a-f-]{36}$/i.test(grantId)) throw validationError([{ path: 'grantId', message: 'Grant ID is invalid.' }]);
        const from = isoDateBound(params.get('from'), 'from');
        const to = isoDateBound(params.get('to'), 'to', true);
        dateRange(from, to);
        const result = entitlements.listAudit({
          ...(actionRaw === null ? {} : { action: actionRaw as 'ADMIN_PRO_GRANT' | 'ADMIN_PRO_REVOKE' }),
          ...(accountId === undefined ? {} : { accountId }),
          ...(grantId === undefined ? {} : { grantId }),
        }, page, pageSize);
        const body = { events: result.events, page, pageSize, total: result.total, coverage: 'ENTITLEMENT_EVENTS_ONLY' as const };
        sendSuccess(res, ctx, body);
      },
    },
    {
      method: 'POST', path: '/api/v1/admin/entitlements/pro/:grantId/revoke', requireAuth: true,
      handler: async (req, res, ctx): Promise<void> => {
        const actor = assertPlatformAdmin(ctx, config);
        if (entitlements === undefined) throw internal('Entitlement service is not available.');
        v.rejectUnexpectedQuery(req);
        const grantId = ctx.params['grantId'];
        if (typeof grantId !== 'string' || !/^apg_[0-9a-f-]{36}$/i.test(grantId)) throw notFound();
        const raw = await readJsonBody(req, { maxBytes: Math.min(config.bodyMaxBytes, 4096) });
        const parsed = proGrantRevokeSchema.parse(raw);
        if (!parsed.ok) throw validationError(parsed.issues);
        const { grant } = await entitlements.revokePro(grantId, actor.id, {
          ...(parsed.value.reason === undefined ? {} : { reason: parsed.value.reason }),
        });
        ctx.logger.info('Admin PRO grant revoked', { requestId: ctx.logId, actorId: actor.id, grantId });
        sendSuccess(res, ctx, { grant });
      },
    },

  ];
}
