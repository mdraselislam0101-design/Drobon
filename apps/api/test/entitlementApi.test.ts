import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, test } from 'vitest';
import { hashPassword } from '../src/auth/passwords.js';
import type { UserRecord } from '../src/auth/repositories.js';
import { createMemoryUserRepository } from '../src/auth/memoryUserRepository.js';
import { createJsonFileUserRepository } from '../src/auth/jsonFileUserRepository.js';
import {
  createJsonFileEntitlementStore,
  createMemoryEntitlementStore,
} from '../src/entitlements/store.js';
import { createEntitlementService } from '../src/entitlements/service.js';
import { sessionCookieFrom, startTestServer, type TestServer } from './helpers.js';
import { login } from './authFixtures.js';

/**
 * Admin Complimentary PRO grant suite.
 *
 * BUSINESS RULE under test everywhere below: a grant is an ENTITLEMENT,
 * never a payment. It must persist, be admin-only, be idempotent and
 * concurrency-safe, support revoke/expiry, leave the payment ledger /
 * balance / revenue / commission / coupon state byte-identical, never
 * mutate the paid subscription underneath, integrate with quota honestly
 * and write an unforgable audit trail.
 */

const LOGIN_FIXTURE = 'grant-synthetic-login-1';
const PLATFORM_ID = 'usr_grant_platform';
const ADMIN_ID = PLATFORM_ID;
const MEMBER_ID = 'usr_grant_member';
const TARGET_ID = 'usr_grant_target';
const OTHER_ID = 'usr_grant_other';
const servers: TestServer[] = [];

afterEach(async () => { while (servers.length > 0) await servers.pop()?.stop(); });

async function seed(server: TestServer, id: string, role: UserRecord['role'], email = `${id}@example.test`): Promise<void> {
  const record: UserRecord = {
    id, email, passwordHash: await hashPassword(LOGIN_FIXTURE, 1024), createdAt: '2026-09-01T00:00:00.000Z',
    role, userType: null, subscription: { plan: 'FREE', status: 'ACTIVE', createdAt: '2026-09-01T00:00:00.000Z', updatedAt: '2026-09-01T00:00:00.000Z' },
  };
  if (!(await server.users.create(record))) throw new Error('Synthetic account collision.');
}

async function cookie(server: TestServer, email: string): Promise<string> {
  return sessionCookieFrom((await login(server, email, LOGIN_FIXTURE)).res);
}

type Json = { ok: boolean; data: unknown; error?: { code: string } };
async function call(method: string, url: string, options: { cookieHeader?: string; body?: unknown; idempotencyKey?: string } = {}): Promise<{ status: number; body: Json; headers: Headers }> {
  const headers: Record<string, string> = {};
  if (options.cookieHeader !== undefined) headers.cookie = options.cookieHeader;
  if (options.idempotencyKey !== undefined) headers['idempotency-key'] = options.idempotencyKey;
  const init: RequestInit = { method, headers };
  if (options.body !== undefined) { headers['content-type'] = 'application/json'; init.body = JSON.stringify(options.body); }
  const res = await fetch(url, init);
  let body: Json;
  try { body = await res.json() as Json; } catch { body = { ok: false, data: null }; }
  return { status: res.status, body, headers: res.headers };
}

function grantUrl(server: TestServer): string { return `${server.baseUrl}/api/v1/admin/entitlements/pro`; }

async function grant(server: TestServer, cookieHeader: string, body: { accountId: string; expiresAt?: string; reason?: string }): Promise<{ status: number; body: Json }> {
  return call('POST', grantUrl(server), { cookieHeader, body });
}

async function subscriptionOf(server: TestServer, cookieHeader: string): Promise<{ plan: string; status: string; source?: string | undefined }> {
  const res = await call('GET', `${server.baseUrl}/api/v1/subscription`, { cookieHeader });
  const data = res.body.data as { subscription: { plan: string; status: string }; proEntitlementSource?: string | undefined };
  return { plan: data.subscription.plan, status: data.subscription.status, source: data.proEntitlementSource };
}

describe('admin complimentary PRO — authorization (Phase 3 / Phase 12 #1-5)', () => {
  test('#1 platform admin grant succeeds (201, ACTIVE, paymentRequired=false)', async () => {
    const server = await startTestServer({ platformAdminIds: [PLATFORM_ID] });
    servers.push(server);
    await seed(server, PLATFORM_ID, 'ADMIN');
    await seed(server, TARGET_ID, 'MEMBER');
    const adminCookie = await cookie(server, `${PLATFORM_ID}@example.test`);
    const result = await grant(server, adminCookie, { accountId: TARGET_ID, reason: 'Launch assistance' });
    expect(result.status).toBe(201);
    const grantData = result.body.data as { grant: { status: string; plan: string; source: string; paymentRequired: boolean; grantedBy: string; expiresAt: string | null; reason: string | null } };
    expect(grantData.grant.status).toBe('ACTIVE');
    expect(grantData.grant.plan).toBe('PRO');
    expect(grantData.grant.source).toBe('ADMIN_GRANT');
    expect(grantData.grant.paymentRequired).toBe(false);
    expect(grantData.grant.grantedBy).toBe(PLATFORM_ID);
    expect(grantData.grant.reason).toBe('Launch assistance');
    // Effective plan flips for the TARGET user only.
    const targetCookie = await cookie(server, `${TARGET_ID}@example.test`);
    await expect(subscriptionOf(server, targetCookie)).resolves.toEqual({ plan: 'PRO', status: 'ACTIVE', source: 'ADMIN_GRANT' });
  });

  test('#2/#3/#4 MEMBER, anonymous, ordinary ADMIN, and forged identity fields are all denied', async () => {
    const server = await startTestServer({ platformAdminIds: [PLATFORM_ID] });
    servers.push(server);
    await seed(server, PLATFORM_ID, 'ADMIN');
    await seed(server, MEMBER_ID, 'MEMBER');
    await seed(server, 'usr_unlisted_admin', 'ADMIN');
    await seed(server, TARGET_ID, 'MEMBER');
    const memberCookie = await cookie(server, `${MEMBER_ID}@example.test`);
    const ordinaryAdminCookie = await cookie(server, 'usr_unlisted_admin@example.test');
    // #3 anonymous
    expect((await fetch(grantUrl(server), { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ accountId: TARGET_ID }) })).status).toBe(401);
    // #2 authenticated non-admin
    expect((await grant(server, memberCookie, { accountId: TARGET_ID })).status).toBe(403);
    // #4 live ADMIN role WITHOUT the platform allowlist
    expect((await grant(server, ordinaryAdminCookie, { accountId: TARGET_ID })).status).toBe(403);
    // #4 client-side identity forgery: a member supplying admin actor
    // fields is denied on AUTHORIZATION first (403 before any body parse).
    const spoof = await call('POST', grantUrl(server), {
      cookieHeader: memberCookie,
      body: { accountId: TARGET_ID, grantedBy: PLATFORM_ID, actorId: PLATFORM_ID },
    });
    expect(spoof.status).toBe(403);
    // Closed schema: even the PLATFORM ADMIN cannot smuggle identity,
    // price or plan fields through the grant body (fail closed).
    const adminSpoof = await call('POST', grantUrl(server), {
      cookieHeader: await cookie(server, `${PLATFORM_ID}@example.test`),
      body: { accountId: TARGET_ID, grantedBy: PLATFORM_ID, actorId: PLATFORM_ID },
    });
    expect(adminSpoof.status).toBe(422);
  });

  test('#5 malformed/mismatched targets fail closed; admin may grant across accounts by design', async () => {
    const server = await startTestServer({ platformAdminIds: [PLATFORM_ID] });
    servers.push(server);
    await seed(server, PLATFORM_ID, 'ADMIN');
    const adminCookie = await cookie(server, `${PLATFORM_ID}@example.test`);
    // bad id shape
    expect((await grant(server, adminCookie, { accountId: 'not-an-id' })).status).toBe(422);
    // nonexistent account: uniform validation failure
    expect((await grant(server, adminCookie, { accountId: 'usr_does_not_exist' })).status).toBe(422);
    // malformed expiry fails closed
    expect((await grant(server, adminCookie, { accountId: TARGET_ID, expiresAt: 'not-a-date' })).status).toBe(422);
    // past expiry fails closed
    expect((await grant(server, adminCookie, { accountId: TARGET_ID, expiresAt: '2001-01-01T00:00:00.000Z' })).status).toBe(422);
    // unbounded horizon fails closed
    expect((await grant(server, adminCookie, { accountId: TARGET_ID, expiresAt: '4999-01-01T00:00:00.000Z' })).status).toBe(422);
    // cross-account grant (admin → other account) is the intended function:
    await seed(server, OTHER_ID, 'MEMBER');
    expect((await grant(server, adminCookie, { accountId: OTHER_ID })).status).toBe(201);
    // HPP: repeated query parameters rejected on the list surface
    const listHpp = await fetch(`${grantUrl(server)}?page=1&page=2`, { headers: { cookie: adminCookie } });
    expect(listHpp.status).toBe(422);
  });
});

describe('admin complimentary PRO — persistence (Phase 2 / Phase 12 #6-8)', () => {
  test('#6 grant persists across logout/login', async () => {
    const server = await startTestServer({ platformAdminIds: [PLATFORM_ID] });
    servers.push(server);
    await seed(server, PLATFORM_ID, 'ADMIN');
    await seed(server, TARGET_ID, 'MEMBER');
    const adminCookie = await cookie(server, `${PLATFORM_ID}@example.test`);
    expect((await grant(server, adminCookie, { accountId: TARGET_ID })).status).toBe(201);
    // Fresh sessions (logout + login equivalent) still see the entitlement.
    const first = await cookie(server, `${TARGET_ID}@example.test`);
    await expect(subscriptionOf(server, first)).resolves.toEqual({ plan: 'PRO', status: 'ACTIVE', source: 'ADMIN_GRANT' });
    const second = await cookie(server, `${TARGET_ID}@example.test`);
    await expect(subscriptionOf(server, second)).resolves.toEqual({ plan: 'PRO', status: 'ACTIVE', source: 'ADMIN_GRANT' });
  });

  test('#7/#8 grant persists after full API restart (durable JSON stores)', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'drobon-grant-restart-'));
    try {
      const users = createJsonFileUserRepository(`${dir}/users.json`);
      const entitlementStore = createJsonFileEntitlementStore(`${dir}/entitlements.json`);
      const first = await startTestServer({ users, entitlementStore, platformAdminIds: [PLATFORM_ID] });
      servers.push(first);
      await seed(first, PLATFORM_ID, 'ADMIN');
      await seed(first, TARGET_ID, 'MEMBER');
      const adminCookie = await cookie(first, `${PLATFORM_ID}@example.test`);
      const created = await grant(first, adminCookie, { accountId: TARGET_ID, expiresAt: '2035-01-01T00:00:00.000Z' });
      expect(created.status).toBe(201);
      const grantId = (created.body.data as { grant: { grantId: string } }).grant.grantId;
      await first.stop();
      servers.pop();
      // NEW server process over the SAME durable stores.
      const second = await startTestServer({
        users: createJsonFileUserRepository(`${dir}/users.json`),
        entitlementStore: createJsonFileEntitlementStore(`${dir}/entitlements.json`),
        platformAdminIds: [PLATFORM_ID],
      });
      servers.push(second);
      const targetCookie = await cookie(second, `${TARGET_ID}@example.test`);
      await expect(subscriptionOf(second, targetCookie)).resolves.toEqual({ plan: 'PRO', status: 'ACTIVE', source: 'ADMIN_GRANT' });
      // Admin surface still lists the grant with its full lifecycle.
      const platformCookie = await cookie(second, `${PLATFORM_ID}@example.test`);
      const list = await call('GET', `${grantUrl(second)}?accountId=${TARGET_ID}`, { cookieHeader: platformCookie });
      const grants = (list.body.data as { grants: Array<{ grantId: string; status: string }> }).grants;
      expect(grants).toHaveLength(1);
      expect(grants[0]?.grantId).toBe(grantId);
      expect(grants[0]?.status).toBe('ACTIVE');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('admin complimentary PRO — idempotency + lifecycle (Phase 4/5 / Phase 12 #9-12)', () => {
  test('#9/#10 duplicate and concurrent grants are idempotent (one active grant, one audit event)', async () => {
    const server = await startTestServer({ platformAdminIds: [PLATFORM_ID] });
    servers.push(server);
    await seed(server, PLATFORM_ID, 'ADMIN');
    await seed(server, TARGET_ID, 'MEMBER');
    const adminCookie = await cookie(server, `${PLATFORM_ID}@example.test`);
    const first = await grant(server, adminCookie, { accountId: TARGET_ID });
    expect(first.status).toBe(201);
    const grantId = (first.body.data as { grant: { grantId: string } }).grant.grantId;
    // Sequential duplicate → replay of the SAME grant, 200 (not 201).
    const second = await grant(server, adminCookie, { accountId: TARGET_ID });
    expect(second.status).toBe(200);
    expect((second.body.data as typeof first.body.data extends null ? never : { grant: { grantId: string } }).grant.grantId).toBe(grantId);
    // Concurrent duplicates → exactly one CREATED, the rest replays.
    const results = await Promise.all(Array.from({ length: 5 }, () => grant(server, adminCookie, { accountId: TARGET_ID })));
    expect(results.filter((r) => r.status === 201)).toHaveLength(0); // the grant already existed
    for (const result of results) {
      expect(result.status).toBe(200);
      expect((result.body.data as { grant: { grantId: string } }).grant.grantId).toBe(grantId);
    }
    // Exactly ONE grant record and ONE audit event ever.
    const list = await call('GET', grantUrl(server), { cookieHeader: adminCookie });
    expect((list.body.data as { total: number }).total).toBe(1);
    const audit = await call('GET', `${grantUrl(server)}/audit?action=ADMIN_PRO_GRANT`, { cookieHeader: adminCookie });
    expect((audit.body.data as { total: number }).total).toBe(1);
  });

  test('#11 revoke works: effective PRO disappears, paid state untouched, re-revoke conflicts', async () => {
    const server = await startTestServer({ platformAdminIds: [PLATFORM_ID] });
    servers.push(server);
    await seed(server, PLATFORM_ID, 'ADMIN');
    await seed(server, TARGET_ID, 'MEMBER');
    const adminCookie = await cookie(server, `${PLATFORM_ID}@example.test`);
    const created = await grant(server, adminCookie, { accountId: TARGET_ID });
    const grantId = (created.body.data as { grant: { grantId: string } }).grant.grantId;
    const targetCookie = await cookie(server, `${TARGET_ID}@example.test`);
    await expect(subscriptionOf(server, targetCookie)).resolves.toEqual({ plan: 'PRO', status: 'ACTIVE', source: 'ADMIN_GRANT' });
    const revoked = await call('POST', `${grantUrl(server)}/${grantId}/revoke`, { cookieHeader: adminCookie, body: { reason: 'Grant period ended' } });
    expect(revoked.status).toBe(200);
    expect((revoked.body.data as { grant: { status: string; revokedBy: string | null } }).grant.status).toBe('REVOKED');
    expect((revoked.body.data as { grant: { revokedBy: string | null } }).grant.revokedBy).toBe(PLATFORM_ID);
    // Rule B: revoked + no other PRO → FREE (and the source key disappears).
    const after = await subscriptionOf(server, targetCookie);
    expect(after.plan).toBe('FREE');
    expect(after.source).toBeUndefined();
    // Re-revoke conflicts (uniform, no double audit).
    expect((await call('POST', `${grantUrl(server)}/${grantId}/revoke`, { cookieHeader: adminCookie, body: {} })).status).toBe(409);
    const audit = await call('GET', `${grantUrl(server)}/audit?grantId=${grantId}`, { cookieHeader: adminCookie });
    const actions = (audit.body.data as { events: Array<{ action: string }> }).events.map((event) => event.action).sort();
    expect(actions).toEqual(['ADMIN_PRO_GRANT', 'ADMIN_PRO_REVOKE']);
    // Unknown grant id → uniform 404.
    expect((await call('POST', `${grantUrl(server)}/apg_00000000-0000-4000-8000-000000000000/revoke`, { cookieHeader: adminCookie, body: {} })).status).toBe(404);
  });

  test('#12 expiry works (derived at read time; rule D)', async () => {
    // Unit-level with an injected clock: expiry must be read-time derived
    // and must flip the effective plan without any stored mutation.
    const now = { ms: Date.parse('2026-01-01T00:00:00.000Z') };
    const base = createMemoryUserRepository();
    const target: UserRecord = {
      id: TARGET_ID, email: `${TARGET_ID}@example.test`, passwordHash: 'x', createdAt: '2026-01-01T00:00:00.000Z',
      role: 'MEMBER', userType: null, subscription: { plan: 'FREE', status: 'ACTIVE', createdAt: null, updatedAt: null },
    };
    await base.create(target);
    const service = createEntitlementService({ store: createMemoryEntitlementStore(), users: base, now: () => now.ms });
    const { grant: created } = await service.grantPro(ADMIN_ID, { accountId: TARGET_ID, expiresAt: '2026-01-02T00:00:00.000Z' });
    expect(service.hasActivePro(TARGET_ID)).toBe(true);
    expect(service.proEntitlementSourceFor(target)).toBe('ADMIN_GRANT');
    now.ms = Date.parse('2026-01-03T00:00:00.000Z'); // past expiry
    expect(service.hasActivePro(TARGET_ID)).toBe(false);
    expect(service.proEntitlementSourceFor(target)).toBeUndefined();
    // Expired grant no longer blocks a NEW grant (no duplicate-active deadlock).
    const again = await service.grantPro(ADMIN_ID, { accountId: TARGET_ID });
    expect(again.created).toBe(true);
    expect(again.grant.grantId).not.toBe(created.grantId);
    expect(service.hasActivePro(TARGET_ID)).toBe(true);
  });
});

describe('admin complimentary PRO — payment isolation (Phase 6/7 / Phase 12 #13-19)', () => {
  test('#13-19 grant+revoke leave the payment ledger, history, commissions and coupons byte-identical; paid PRO survives (#13)', async () => {
    const server = await startTestServer({ platformAdminIds: [PLATFORM_ID], paymentReviewerIds: [PLATFORM_ID] });
    servers.push(server);
    await seed(server, PLATFORM_ID, 'ADMIN');
    await seed(server, TARGET_ID, 'MEMBER');
    const adminCookie = await cookie(server, `${PLATFORM_ID}@example.test`);
    const targetCookie = await cookie(server, `${TARGET_ID}@example.test`);

    // Baseline snapshot of every financial surface.
    const financialSnapshot = async (): Promise<{ paymentsTotal: number; submitted: number; approved: number; historyTotal: number; statuses: string[]; byStatusTotal: number }> => {
      const counts = await call('GET', `${server.baseUrl}/api/v1/admin/dashboard`, { cookieHeader: adminCookie });
      const paymentsBlock = (counts.body.data as { payments: { total: number; byStatus: Record<string, number>; submittedAmountMinorUnits: number; approvedAmountMinorUnits: number } }).payments;
      const history = await call('GET', `${server.baseUrl}/api/v1/payments?page=1&pageSize=50`, { cookieHeader: targetCookie });
      const historyData = history.body.data as { payments: Array<{ status: string }>; total: number };
      return {
        paymentsTotal: paymentsBlock.total,
        submitted: paymentsBlock.submittedAmountMinorUnits,
        approved: paymentsBlock.approvedAmountMinorUnits,
        historyTotal: historyData.total,
        statuses: historyData.payments.map((payment) => payment.status),
        byStatusTotal: Object.values(paymentsBlock.byStatus).reduce((sum, value) => sum + value, 0),
      };
    };

    // A GENUINE paid PRO exists first (real payment state machine, end to end).
    const price = 100_000;
    const create = await call('POST', `${server.baseUrl}/api/v1/payments`, {
      cookieHeader: targetCookie,
      idempotencyKey: 'grant-test-key-0001',
      body: { plan: 'PRO', amountMinorUnits: price, currency: 'BDT', paymentMethod: 'MANUAL_TRANSFER', reference: 'GRANT-PROOF-001' },
    });
    expect(create.status).toBe(201);
    const paymentId = (create.body.data as { payment: { paymentId: string } }).payment.paymentId;
    expect((await call('POST', `${server.baseUrl}/api/v1/admin/payments/${paymentId}/approve`, { cookieHeader: adminCookie, body: {} })).status).toBe(200);
    const before = await financialSnapshot();
    expect(before.approved).toBe(price);
    // Paid PRO is active (subscription-sourced).
    await expect(subscriptionOf(server, targetCookie)).resolves.toEqual({ plan: 'PRO', status: 'ACTIVE', source: 'PAID' });

    // Grant on top, then revoke.
    const created = await grant(server, adminCookie, { accountId: TARGET_ID });
    expect(created.status).toBe(201);
    const grantId = (created.body.data as { grant: { grantId: string } }).grant.grantId;
    await expect(subscriptionOf(server, targetCookie)).resolves.toEqual({ plan: 'PRO', status: 'ACTIVE', source: 'ADMIN_GRANT' });
    expect((await call('POST', `${grantUrl(server)}/${grantId}/revoke`, { cookieHeader: adminCookie, body: { reason: 'Audit drill' } })).status).toBe(200);

    // Rule C: paid PRO SURVIVES the revoke.
    await expect(subscriptionOf(server, targetCookie)).resolves.toEqual({ plan: 'PRO', status: 'ACTIVE', source: 'PAID' });
    // #14-19: every financial number is UNCHANGED.
    const after = await financialSnapshot();
    expect(after).toEqual(before);
    // No commissions and no coupon attribution anywhere.
    const commissions = await call('GET', `${server.baseUrl}/api/v1/admin/commissions`, { cookieHeader: adminCookie });
    expect((commissions.body.data as { total: number }).total).toBe(0);
    const auditTrail = await call('GET', `${grantUrl(server)}/audit`, { cookieHeader: adminCookie });
    const blob = JSON.stringify(auditTrail.body);
    expect(blob).not.toContain('amountMinorUnits');
    expect(blob).not.toContain('commission');
    // #26 stale client data cannot forge a price/plan through the grant surface.
    expect((await grant(server, adminCookie, { accountId: OTHER_ID, ...({ amountMinorUnits: 1, plan: 'PRO' } as object) } as { accountId: string })).status).toBe(422);
  });
});

describe('admin complimentary PRO — quota + UserType (Phase 11 / Phase 12 #20-22)', () => {
  test('#21/#22 FREE quota before, EXEMPT during grant, authoritative accounting after revoke', async () => {
    const server = await startTestServer({ platformAdminIds: [PLATFORM_ID], rateLimitMaxRequests: 1000 });
    servers.push(server);
    await seed(server, PLATFORM_ID, 'ADMIN');
    await seed(server, TARGET_ID, 'MEMBER');
    const adminCookie = await cookie(server, `${PLATFORM_ID}@example.test`);
    const targetCookie = await cookie(server, `${TARGET_ID}@example.test`);
    const projectCreate = await call('POST', `${server.baseUrl}/api/v1/projects`, { cookieHeader: targetCookie, body: { name: 'Grant quota proof', description: 'synthetic project' } });
    expect(projectCreate.status).toBe(201);
    const projectId = (projectCreate.body.data as { project: { id: string } }).project.id;
    const put = async (): Promise<Response> => fetch(`${server.baseUrl}/api/v1/projects/${projectId}/sources`, {
      method: 'PUT', headers: { cookie: targetCookie, 'content-type': 'application/json' },
      body: JSON.stringify({ files: [{ path: 'main.js', content: 'const x = 1;\n' }] }),
    });
    expect((await put()).status).toBe(200);
    const scan = async (): Promise<Response> => fetch(`${server.baseUrl}/api/v1/projects/${projectId}/scans`, {
      method: 'POST', headers: { cookie: targetCookie, 'content-type': 'application/json' }, body: JSON.stringify({ scanType: 'SAST' }),
    });
    const usage = async (): Promise<{ plan: string; used: number; limit: number | null; remaining: number | null; quotaStatus: string }> => {
      const res = await call('GET', `${server.baseUrl}/api/v1/usage`, { cookieHeader: targetCookie });
      return res.body.data as { plan: string; used: number; limit: number | null; remaining: number | null; quotaStatus: string };
    };
    // FREE: exactly 3 scans, then 429.
    for (let index = 0; index < 3; index += 1) expect((await scan()).status).toBe(201);
    expect((await scan()).status).toBe(429);
    expect(await usage()).toMatchObject({ plan: 'FREE', used: 3, limit: 3, remaining: 0, quotaStatus: 'EXHAUSTED' });

    // GRANT: effective PRO → exempt, further scans succeed.
    const created = await grant(server, adminCookie, { accountId: TARGET_ID });
    const grantId = (created.body.data as { grant: { grantId: string } }).grant.grantId;
    expect(await usage()).toMatchObject({ plan: 'PRO', limit: null, remaining: null, quotaStatus: 'EXEMPT' });
    expect((await scan()).status).toBe(201);
    expect((await scan()).status).toBe(201);

    // #20 UserType switching never creates or removes the entitlement.
    const switched = await call('PATCH', `${server.baseUrl}/api/v1/me/user-type`, { cookieHeader: targetCookie, body: { userType: 'STUDENT' } });
    expect(switched.status).toBe(200);
    await expect(subscriptionOf(server, targetCookie)).resolves.toEqual({ plan: 'PRO', status: 'ACTIVE', source: 'ADMIN_GRANT' });

    // REVOKE: back to FREE; the authoritative account counter (3 FREE +
    // exempt consumption, per the store's documented accounting) decides
    // the verdict — no reset, no corruption.
    expect((await call('POST', `${grantUrl(server)}/${grantId}/revoke`, { cookieHeader: adminCookie, body: {} })).status).toBe(200);
    const finalUsage = await usage();
    expect(finalUsage.plan).toBe('FREE');
    expect(finalUsage.used).toBeGreaterThanOrEqual(3);
    expect(finalUsage.quotaStatus).toBe('EXHAUSTED');
    expect((await scan()).status).toBe(429);
  });
});
