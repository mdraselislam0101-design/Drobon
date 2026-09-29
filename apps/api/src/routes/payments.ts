import type { PaymentMethod, PaymentStatus } from '@drobon/shared';
import { isPaymentMethod, isPaymentStatus } from '@drobon/shared';
import type { ApiConfig } from '../config.js';
import { forbidden, notFound, unauthorized, validationError } from '../errors.js';
import type { RequestContext, Route } from '../http.js';
import type { UserRepository } from '../auth/repositories.js';
import { resolveSubscription } from '../auth/subscriptions.js';
import { readJsonBody } from '../lib/body.js';
import * as v from '../lib/validate.js';
import { sendSuccess } from '../respond.js';
import type { PaymentService } from '../payments/service.js';
import type { PaymentAdminFilters } from '../payments/store.js';

export interface PaymentRouteDeps {
  config: ApiConfig;
  users: UserRepository;
  payments: PaymentService;
}

const createSchema = v.object({
  plan: v.literal('PRO'),
  amountMinorUnits: v.number({ integer: true, min: 1, max: 100_000_000 }),
  currency: v.literal('BDT'),
  paymentMethod: v.literal('MANUAL_TRANSFER'),
  reference: v.string({ minLength: 6, maxLength: 64, trim: true, pattern: /^[A-Za-z0-9][A-Za-z0-9._-]{5,63}$/ }),
});
const emptySchema = v.object({});
const rejectSchema = v.object({ reason: v.string({ minLength: 3, maxLength: 300, trim: true }) });

function actorFrom(ctx: RequestContext) {
  if (ctx.user === undefined) throw unauthorized();
  return ctx.user;
}

function assertPaymentReviewer(ctx: RequestContext, config: ApiConfig) {
  const actor = actorFrom(ctx);
  // Platform payment authority requires both server-side ADMIN role and an
  // explicit platform reviewer allowlist entry; account ADMIN alone is not enough.
  if (actor.role !== 'ADMIN' || !config.paymentReviewerIds.includes(actor.id)) {
    throw forbidden('You do not have access to this resource.');
  }
  return actor;
}

function parsePagination(req: { url?: string | undefined }, allowed: readonly string[] = ['page', 'pageSize']): { page: number; pageSize: number; status?: PaymentStatus; paymentMethod?: PaymentMethod; accountId?: string; from?: string; to?: string } {
  const url = new URL(req.url ?? '/', 'http://drobon.invalid');
  for (const key of url.searchParams.keys()) {
    if (!allowed.includes(key) || url.searchParams.getAll(key).length !== 1) throw validationError([{ path: key, message: 'Unexpected or repeated query parameter.' }]);
  }
  const parsePositive = (raw: string | null, fallback: number, max: number, name: string): number => {
    if (raw === null) return fallback;
    if (!/^\d{1,6}$/.test(raw)) throw validationError([{ path: name, message: 'Must be a bounded positive integer.' }]);
    const parsed = Number(raw);
    if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > max) throw validationError([{ path: name, message: `Must be between 1 and ${max}.` }]);
    return parsed;
  };
  const dateBound = (name: 'from' | 'to', end: boolean): string | undefined => {
    const raw = url.searchParams.get(name);
    if (raw === null) return undefined;
    if (!/^\d{4}-\d{2}-\d{2}$/.test(raw)) throw validationError([{ path: name, message: 'Use an ISO calendar date (YYYY-MM-DD).' }]);
    const parsed = new Date(`${raw}T${end ? '23:59:59.999' : '00:00:00.000'}Z`);
    if (Number.isNaN(parsed.getTime()) || parsed.toISOString().slice(0, 10) !== raw) throw validationError([{ path: name, message: 'Date is invalid.' }]);
    return parsed.toISOString();
  };
  const page = parsePositive(url.searchParams.get('page'), 1, 1000, 'page');
  const pageSize = parsePositive(url.searchParams.get('pageSize'), 20, 50, 'pageSize');
  const rawStatus = url.searchParams.get('status');
  if (rawStatus !== null && !isPaymentStatus(rawStatus)) throw validationError([{ path: 'status', message: 'Unsupported payment status.' }]);
  const rawMethod = url.searchParams.get('paymentMethod');
  if (rawMethod !== null && !isPaymentMethod(rawMethod)) throw validationError([{ path: 'paymentMethod', message: 'Unsupported payment method.' }]);
  const accountId = url.searchParams.get('accountId') ?? undefined;
  if (accountId !== undefined && !/^usr_[A-Za-z0-9_-]{1,128}$/.test(accountId)) throw validationError([{ path: 'accountId', message: 'Account ID is invalid.' }]);
  const from = dateBound('from', false);
  const to = dateBound('to', true);
  if ((from === undefined) !== (to === undefined)) throw validationError([{ path: 'from', message: 'Supply both from and to dates, or neither.' }]);
  if (from !== undefined && to !== undefined && (Date.parse(to) < Date.parse(from) || Date.parse(to) - Date.parse(from) > 366 * 24 * 60 * 60 * 1000)) throw validationError([{ path: 'from', message: 'Date range must be ordered and at most 366 days.' }]);
  return {
    page, pageSize,
    ...(rawStatus === null ? {} : { status: rawStatus }),
    ...(rawMethod === null ? {} : { paymentMethod: rawMethod }),
    ...(accountId === undefined ? {} : { accountId }),
    ...(from === undefined ? {} : { from }),
    ...(to === undefined ? {} : { to }),
  };
}

async function parseBody<T>(req: Parameters<NonNullable<Route['handler']>>[0], config: ApiConfig, schema: { parse(value: unknown): { ok: true; value: T } | { ok: false; issues: unknown[] } }): Promise<T> {
  const raw = await readJsonBody(req, { maxBytes: Math.min(config.bodyMaxBytes, 4096) });
  const parsed = schema.parse(raw);
  if (!parsed.ok) throw validationError(parsed.issues);
  return parsed.value;
}

function requireIdempotencyKey(header: string | string[] | undefined): string {
  if (typeof header !== 'string' || !/^[A-Za-z0-9_-]{8,128}$/.test(header)) {
    throw validationError([{ path: 'Idempotency-Key', message: 'Supply an 8–128 character idempotency key.' }]);
  }
  return header;
}

function rejectBodyFields(body: unknown): void {
  const parsed = emptySchema.parse(body);
  if (!parsed.ok) throw validationError(parsed.issues);
}

function rejectUnexpectedQuery(req: { url?: string | undefined }): void {
  const params = new URL(req.url ?? '/', 'http://drobon.invalid').searchParams;
  const keys = [...new Set(params.keys())];
  if (keys.length > 0) {
    throw validationError(keys.map((path) => ({ path, message: 'Unexpected query parameter.' })));
  }
}

function requirePaymentId(raw: string | undefined): string {
  if (typeof raw !== 'string' || raw.length > 64 || !/^pay_[0-9a-f-]{36}$/i.test(raw)) {
    throw notFound();
  }
  return raw;
}

export function createPaymentRoutes(deps: PaymentRouteDeps): Route[] {
  const { config, users, payments } = deps;
  return [
    {
      method: 'GET', path: '/api/v1/payments/config', requireAuth: true,
      handler: async (req, res, ctx) => {
        const actor = actorFrom(ctx);
        rejectUnexpectedQuery(req);
        const record = await users.findById(actor.id);
        if (record === undefined) throw unauthorized();
        sendSuccess(res, ctx, payments.config(resolveSubscription(record).plan));
      },
    },
    {
      method: 'GET', path: '/api/v1/payments', requireAuth: true,
      handler: async (req, res, ctx) => {
        const actor = actorFrom(ctx);
        const { page, pageSize } = parsePagination(req);
        sendSuccess(res, ctx, payments.history(actor.id, page, pageSize));
      },
    },
    {
      method: 'POST', path: '/api/v1/payments', requireAuth: true,
      handler: async (req, res, ctx) => {
        const actor = actorFrom(ctx);
        rejectUnexpectedQuery(req);
        const record = await users.findById(actor.id);
        if (record === undefined) throw unauthorized();
        const subscription = resolveSubscription(record);
        const input = await parseBody(req, config, createSchema);
        const idempotencyKey = requireIdempotencyKey(req.headers['idempotency-key']);
        const result = await payments.create({
          accountId: record.id,
          userId: actor.id,
          currentPlan: subscription.plan,
          plan: input.plan,
          amountMinorUnits: input.amountMinorUnits,
          currency: input.currency,
          paymentMethod: input.paymentMethod as PaymentMethod,
          reference: input.reference,
          idempotencyKey,
        });
        sendSuccess(res, ctx, { payment: result.payment }, result.created ? 201 : 200);
      },
    },
    {
      method: 'GET', path: '/api/v1/payments/:paymentId', requireAuth: true,
      handler: async (req, res, ctx) => {
        const actor = actorFrom(ctx);
        rejectUnexpectedQuery(req);
        const paymentId = requirePaymentId(ctx.params['paymentId']);
        sendSuccess(res, ctx, payments.getForAccount(paymentId, actor.id));
      },
    },
    {
      method: 'POST', path: '/api/v1/payments/:paymentId/cancel', requireAuth: true,
      handler: async (req, res, ctx) => {
        const actor = actorFrom(ctx);
        rejectUnexpectedQuery(req);
        const paymentId = requirePaymentId(ctx.params['paymentId']);
        payments.getForAccount(paymentId, actor.id);
        if (req.headers['content-type'] !== undefined) rejectBodyFields(await parseBody(req, config, emptySchema));
        sendSuccess(res, ctx, { payment: await payments.cancel(paymentId, actor.id, actor.id) });
      },
    },
    {
      method: 'GET', path: '/api/v1/admin/payments', requireAuth: true,
      handler: async (req, res, ctx) => {
        assertPaymentReviewer(ctx, config);
        const { page, pageSize, status, paymentMethod, accountId, from, to } = parsePagination(req, ['page', 'pageSize', 'status', 'paymentMethod', 'accountId', 'from', 'to']);
        const filters: PaymentAdminFilters = {
          ...(status === undefined ? {} : { status }),
          ...(paymentMethod === undefined ? {} : { paymentMethod }),
          ...(accountId === undefined ? {} : { accountId }),
          ...(from === undefined ? {} : { from }),
          ...(to === undefined ? {} : { to }),
        };
        sendSuccess(res, ctx, payments.adminList(page, pageSize, filters));
      },
    },
    {
      method: 'GET', path: '/api/v1/admin/payments/:paymentId/audit', requireAuth: true,
      handler: async (req, res, ctx) => {
        assertPaymentReviewer(ctx, config);
        rejectUnexpectedQuery(req);
        const paymentId = requirePaymentId(ctx.params['paymentId']);
        sendSuccess(res, ctx, payments.audit(paymentId));
      },
    },
    {
      method: 'POST', path: '/api/v1/admin/payments/:paymentId/review', requireAuth: true,
      handler: async (req, res, ctx) => {
        const reviewer = assertPaymentReviewer(ctx, config);
        rejectUnexpectedQuery(req);
        const paymentId = requirePaymentId(ctx.params['paymentId']);
        const payment = payments.getForAdmin(paymentId);
        if (payment.submittedByUserId === reviewer.id) throw forbidden('You cannot review your own payment request.');
        if (req.headers['content-type'] !== undefined) rejectBodyFields(await parseBody(req, config, emptySchema));
        sendSuccess(res, ctx, { payment: await payments.review(paymentId, reviewer.id) });
      },
    },
    {
      method: 'POST', path: '/api/v1/admin/payments/:paymentId/approve', requireAuth: true,
      handler: async (req, res, ctx) => {
        const reviewer = assertPaymentReviewer(ctx, config);
        rejectUnexpectedQuery(req);
        const paymentId = requirePaymentId(ctx.params['paymentId']);
        const payment = payments.getForAdmin(paymentId);
        if (payment.submittedByUserId === reviewer.id) throw forbidden('You cannot approve your own payment request.');
        if (req.headers['content-type'] !== undefined) rejectBodyFields(await parseBody(req, config, emptySchema));
        sendSuccess(res, ctx, { payment: await payments.approve(paymentId, reviewer.id) });
      },
    },
    {
      method: 'POST', path: '/api/v1/admin/payments/:paymentId/reject', requireAuth: true,
      handler: async (req, res, ctx) => {
        const reviewer = assertPaymentReviewer(ctx, config);
        rejectUnexpectedQuery(req);
        const paymentId = requirePaymentId(ctx.params['paymentId']);
        const payment = payments.getForAdmin(paymentId);
        if (payment.submittedByUserId === reviewer.id) throw forbidden('You cannot reject your own payment request.');
        const input = await parseBody(req, config, rejectSchema);
        sendSuccess(res, ctx, { payment: await payments.reject(paymentId, reviewer.id, input.reason) });
      },
    },
  ];
}
