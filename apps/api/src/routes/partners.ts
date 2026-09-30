import {
  COMMISSION_ID_PATTERN,
  COUPON_CODE_PATTERN,
  PARTNER_ID_PATTERN,
  isCommissionStatus,
  isPartnerStatus,
} from '@drobon/shared';
import type { ApiConfig } from '../config.js';
import { notFound, unauthorized, validationError } from '../errors.js';
import type { RequestContext, Route } from '../http.js';
import { readJsonBody } from '../lib/body.js';
import * as v from '../lib/validate.js';
import { sendSuccess } from '../respond.js';
import type { PartnerService } from '../partners/service.js';
import type { CommissionListFilters, PartnerListFilters } from '../partners/store.js';
import { assertPlatformAdmin } from './admin.js';

export interface PartnerRouteDeps {
  config: ApiConfig;
  partners: PartnerService;
}

const emptySchema = v.object({});
const activateSchema = v.object({
  userId: v.string({ minLength: 3, maxLength: 140, trim: true, pattern: /^usr_[A-Za-z0-9_-]{1,128}$/ }),
  couponCode: v.string({ minLength: 3, maxLength: 40, trim: true }),
  discountPercent: v.number({ integer: true, min: 0, max: 90 }),
  commissionPercent: v.number({ integer: true, min: 0, max: 50 }),
});
/**
 * Coupon reconfiguration: each field optional, at least one required;
 * expiresAt is an ISO timestamp or explicit null (clear).
 */
const couponPatchSchema = {
  parse(value: unknown): { ok: true; value: { status?: 'ACTIVE' | 'INACTIVE'; discountPercent?: number; commissionPercent?: number; expiresAt?: string | null } } | { ok: false; issues: unknown[] } {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
      return { ok: false as const, issues: [{ path: 'body', message: 'Expected a JSON object.' }] };
    }
    const record = value as Record<string, unknown>;
    const allowed = new Set(['status', 'discountPercent', 'commissionPercent', 'expiresAt']);
    const issues: Array<{ path: string; message: string }> = [];
    for (const key of Object.keys(record)) {
      if (!allowed.has(key)) issues.push({ path: key, message: 'Unexpected field.' });
    }
    const out: { status?: 'ACTIVE' | 'INACTIVE'; discountPercent?: number; commissionPercent?: number; expiresAt?: string | null } = {};
    if ('status' in record) {
      if (record['status'] !== 'ACTIVE' && record['status'] !== 'INACTIVE') issues.push({ path: 'status', message: 'Status must be ACTIVE or INACTIVE.' });
      else out.status = record['status'];
    }
    if ('discountPercent' in record) {
      const val = record['discountPercent'];
      if (typeof val !== 'number' || !Number.isSafeInteger(val) || val < 0 || val > 90) issues.push({ path: 'discountPercent', message: 'Discount must be an integer percent between 0 and 90.' });
      else out.discountPercent = val;
    }
    if ('commissionPercent' in record) {
      const val = record['commissionPercent'];
      if (typeof val !== 'number' || !Number.isSafeInteger(val) || val < 0 || val > 50) issues.push({ path: 'commissionPercent', message: 'Commission must be an integer percent between 0 and 50.' });
      else out.commissionPercent = val;
    }
    if ('expiresAt' in record) {
      const val = record['expiresAt'];
      if (val !== null && (typeof val !== 'string' || Number.isNaN(Date.parse(val)))) issues.push({ path: 'expiresAt', message: 'Expiry must be an ISO 8601 timestamp or null.' });
      else out.expiresAt = val as string | null;
    }
    if (Object.keys(out).length === 0 && issues.length === 0) issues.push({ path: 'body', message: 'Provide at least one coupon field to update.' });
    return issues.length > 0 ? { ok: false as const, issues } : { ok: true as const, value: out };
  },
};

function actorFrom(ctx: RequestContext) {
  if (ctx.user === undefined) throw unauthorized();
  return ctx.user;
}

function requirePartnerId(raw: string | undefined): string {
  if (typeof raw !== 'string' || !PARTNER_ID_PATTERN.test(raw)) throw notFound();
  return raw;
}

function requireCommissionId(raw: string | undefined): string {
  if (typeof raw !== 'string' || !COMMISSION_ID_PATTERN.test(raw)) throw notFound();
  return raw;
}

function parseBoundedPage(raw: string | null, fallback: number, max: number, name: string): number {
  if (raw === null) return fallback;
  if (!/^\d{1,6}$/.test(raw)) throw validationError([{ path: name, message: 'Must be a bounded positive integer.' }]);
  const parsed = Number(raw);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > max) throw validationError([{ path: name, message: `Must be between 1 and ${max}.` }]);
  return parsed;
}

function parseListQuery(req: { url?: string | undefined }, allowed: readonly string[]): { page: number; pageSize: number; params: URLSearchParams } {
  const url = new URL(req.url ?? '/', 'http://drobon.invalid');
  for (const key of url.searchParams.keys()) {
    if (!allowed.includes(key) || url.searchParams.getAll(key).length !== 1) {
      throw validationError([{ path: key, message: 'Unexpected or repeated query parameter.' }]);
    }
  }
  return {
    page: parseBoundedPage(url.searchParams.get('page'), 1, 1000, 'page'),
    pageSize: parseBoundedPage(url.searchParams.get('pageSize'), 20, 50, 'pageSize'),
    params: url.searchParams,
  };
}

async function parseBody<T>(req: Parameters<NonNullable<Route['handler']>>[0], config: ApiConfig, schema: { parse(value: unknown): { ok: true; value: T } | { ok: false; issues: unknown[] } }): Promise<T> {
  const raw = await readJsonBody(req, { maxBytes: Math.min(config.bodyMaxBytes, 4096) });
  const parsed = schema.parse(raw);
  if (!parsed.ok) throw validationError(parsed.issues);
  return parsed.value;
}

export function createPartnerRoutes(deps: PartnerRouteDeps): Route[] {
  const { config, partners } = deps;
  return [
    {
      method: 'GET', path: '/api/v1/partners/me/dashboard', requireAuth: true,
      handler: async (req, res, ctx) => {
        const actor = actorFrom(ctx);
        v.rejectUnexpectedQuery(req);
        // Aggregate projection only — customer-level data is unreachable here by design.
        sendSuccess(res, ctx, partners.dashboard(actor.id));
      },
    },
    {
      method: 'GET', path: '/api/v1/admin/partners', requireAuth: true,
      handler: async (req, res, ctx) => {
        assertPlatformAdmin(ctx, config);
        const { page, pageSize, params } = parseListQuery(req, ['page', 'pageSize', 'status']);
        const rawStatus = params.get('status');
        if (rawStatus !== null && !isPartnerStatus(rawStatus)) throw validationError([{ path: 'status', message: 'Unsupported partner status.' }]);
        const filters: PartnerListFilters = rawStatus === null ? {} : { status: rawStatus };
        sendSuccess(res, ctx, partners.listPartners(filters, page, pageSize));
      },
    },
    {
      method: 'POST', path: '/api/v1/admin/partners', requireAuth: true,
      handler: async (req, res, ctx) => {
        const admin = assertPlatformAdmin(ctx, config);
        v.rejectUnexpectedQuery(req);
        const input = await parseBody(req, config, activateSchema);
        const couponCode = input.couponCode.trim().toUpperCase();
        if (!COUPON_CODE_PATTERN.test(couponCode)) throw validationError([{ path: 'couponCode', message: 'Coupon codes are 3–40 characters of A–Z, 0–9 and dashes.' }]);
        sendSuccess(res, ctx, await partners.activatePartner(admin.id, { ...input, couponCode }), 201);
      },
    },
    {
      method: 'GET', path: '/api/v1/admin/partners/:partnerId', requireAuth: true,
      handler: async (req, res, ctx) => {
        assertPlatformAdmin(ctx, config);
        v.rejectUnexpectedQuery(req);
        sendSuccess(res, ctx, partners.getPartnerDetail(requirePartnerId(ctx.params['partnerId'])));
      },
    },
    {
      method: 'POST', path: '/api/v1/admin/partners/:partnerId/deactivate', requireAuth: true,
      handler: async (req, res, ctx) => {
        const admin = assertPlatformAdmin(ctx, config);
        v.rejectUnexpectedQuery(req);
        const partnerId = requirePartnerId(ctx.params['partnerId']);
        if (req.headers['content-type'] !== undefined) await parseBody(req, config, emptySchema);
        sendSuccess(res, ctx, await partners.setPartnerStatus(partnerId, 'DEACTIVATED', admin.id));
      },
    },
    {
      method: 'POST', path: '/api/v1/admin/partners/:partnerId/reactivate', requireAuth: true,
      handler: async (req, res, ctx) => {
        const admin = assertPlatformAdmin(ctx, config);
        v.rejectUnexpectedQuery(req);
        const partnerId = requirePartnerId(ctx.params['partnerId']);
        if (req.headers['content-type'] !== undefined) await parseBody(req, config, emptySchema);
        sendSuccess(res, ctx, await partners.setPartnerStatus(partnerId, 'ACTIVE', admin.id));
      },
    },
    {
      method: 'PATCH', path: '/api/v1/admin/partners/:partnerId/coupon', requireAuth: true,
      handler: async (req, res, ctx) => {
        const admin = assertPlatformAdmin(ctx, config);
        v.rejectUnexpectedQuery(req);
        const partnerId = requirePartnerId(ctx.params['partnerId']);
        const patch = await parseBody(req, config, couponPatchSchema);
        sendSuccess(res, ctx, await partners.updateCoupon(partnerId, patch, admin.id));
      },
    },
    {
      method: 'GET', path: '/api/v1/admin/partners/:partnerId/payments', requireAuth: true,
      handler: async (req, res, ctx) => {
        assertPlatformAdmin(ctx, config);
        const { page, pageSize } = parseListQuery(req, ['page', 'pageSize']);
        sendSuccess(res, ctx, partners.listPartnerPayments(requirePartnerId(ctx.params['partnerId']), page, pageSize));
      },
    },
    {
      method: 'GET', path: '/api/v1/admin/commissions', requireAuth: true,
      handler: async (req, res, ctx) => {
        assertPlatformAdmin(ctx, config);
        const { page, pageSize, params } = parseListQuery(req, ['page', 'pageSize', 'partnerId', 'status']);
        const rawStatus = params.get('status');
        if (rawStatus !== null && !isCommissionStatus(rawStatus)) throw validationError([{ path: 'status', message: 'Unsupported commission status.' }]);
        const partnerId = params.get('partnerId');
        if (partnerId !== null && !PARTNER_ID_PATTERN.test(partnerId)) throw validationError([{ path: 'partnerId', message: 'Partner ID is invalid.' }]);
        const filters: CommissionListFilters = {
          ...(rawStatus === null ? {} : { status: rawStatus as import('@drobon/shared').CommissionStatus }),
          ...(partnerId === null ? {} : { partnerId }),
        };
        sendSuccess(res, ctx, partners.listCommissions(filters, page, pageSize));
      },
    },
    {
      method: 'POST', path: '/api/v1/admin/commissions/:commissionId/available', requireAuth: true,
      handler: async (req, res, ctx) => {
        const admin = assertPlatformAdmin(ctx, config);
        v.rejectUnexpectedQuery(req);
        const commissionId = requireCommissionId(ctx.params['commissionId']);
        if (req.headers['content-type'] !== undefined) await parseBody(req, config, emptySchema);
        sendSuccess(res, ctx, await partners.transitionCommission(commissionId, 'AVAILABLE', admin.id));
      },
    },
    {
      method: 'POST', path: '/api/v1/admin/commissions/:commissionId/paid', requireAuth: true,
      handler: async (req, res, ctx) => {
        const admin = assertPlatformAdmin(ctx, config);
        v.rejectUnexpectedQuery(req);
        const commissionId = requireCommissionId(ctx.params['commissionId']);
        if (req.headers['content-type'] !== undefined) await parseBody(req, config, emptySchema);
        sendSuccess(res, ctx, await partners.transitionCommission(commissionId, 'PAID', admin.id));
      },
    },
  ];
}
