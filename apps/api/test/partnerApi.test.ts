import { afterEach, describe, expect, test } from 'vitest';
import { hashPassword } from '../src/auth/passwords.js';
import type { UserRecord } from '../src/auth/repositories.js';
import { cleanupTempStoreDir, makeTempStoreDir, readJson, sessionCookieFrom, startTestServer, type TestServer } from './helpers.js';
import { login, register } from './authFixtures.js';

/**
 * Pump 7 partner/coupon/commission integration suite. Admin-controlled partner
 * activation, coupon-as-attribution, server-authoritative discount/commission
 * math, idempotent settlement, cross-partner privacy and authorization matrix —
 * exercised through the real HTTP surface.
 */

const PW = 'partner-fixture-password-1';
const PRICE = 100_000;
const REFERENCE = 'TXN-PARTNER-01';
const servers: TestServer[] = [];

afterEach(async () => {
  while (servers.length > 0) await servers.pop()?.stop();
});

async function seededUser(server: TestServer, id: string, role: UserRecord['role'] = 'MEMBER'): Promise<string> {
  const record: UserRecord = {
    id,
    email: `${id}@example.test`,
    passwordHash: await hashPassword(PW, 1024),
    createdAt: '2026-09-01T00:00:00.000Z',
    role,
    userType: null,
    subscription: { plan: 'FREE', status: 'ACTIVE', createdAt: '2026-09-01T00:00:00.000Z', updatedAt: '2026-09-01T00:00:00.000Z' },
  };
  if (!(await server.users.create(record))) throw new Error('Seed account collision.');
  return `${id}@example.test`;
}

async function setup(extra: Partial<Parameters<typeof startTestServer>[0]> = {}): Promise<{
  server: TestServer;
  adminCookie: string;
  reviewerCookie: string;
  memberCookie: string;
}> {
  const server = await startTestServer({
    platformAdminIds: ['usr_platform_admin'],
    paymentReviewerIds: ['usr_platform_reviewer'],
    ...extra,
  });
  servers.push(server);
  await seededUser(server, 'usr_platform_admin', 'ADMIN');
  await seededUser(server, 'usr_platform_reviewer', 'ADMIN');
  const adminCookie = sessionCookieFrom((await login(server, 'usr_platform_admin@example.test', PW)).res);
  const reviewerCookie = sessionCookieFrom((await login(server, 'usr_platform_reviewer@example.test', PW)).res);
  const memberReg = await register(server, 'member@example.test', PW);
  const memberCookie = sessionCookieFrom(memberReg.res);
  return { server, adminCookie, reviewerCookie, memberCookie };
}

async function jsonData<T>(response: Response): Promise<T> {
  const body = await readJson(response) as { data: T };
  return body.data;
}

async function seedPartner(server: TestServer, id: string): Promise<string> {
  await seededUser(server, id);
  return id;
}

interface PartnerSummaryShape { partnerId: string; userId: string; email: string; status: string; coupon: { couponCode: string; discountPercent: number; commissionPercent: number; status: string } }

async function activatePartner(
  server: TestServer,
  adminCookie: string,
  input: { userId: string; couponCode: string; discountPercent?: number; commissionPercent?: number },
): Promise<Response> {
  return fetch(`${server.baseUrl}/api/v1/admin/partners`, {
    method: 'POST',
    headers: { cookie: adminCookie, 'content-type': 'application/json' },
    body: JSON.stringify({ discountPercent: 10, commissionPercent: 5, ...input }),
  });
}

async function createPayment(
  server: TestServer,
  cookie: string,
  body: Record<string, unknown>,
  key = 'idem-partner-0001',
): Promise<Response> {
  return fetch(`${server.baseUrl}/api/v1/payments`, {
    method: 'POST',
    headers: { cookie, 'content-type': 'application/json', 'idempotency-key': key },
    body: JSON.stringify(body),
  });
}

function paymentBody(reference = REFERENCE, additions: Record<string, unknown> = {}): Record<string, unknown> {
  return { plan: 'PRO', amountMinorUnits: PRICE, currency: 'BDT', paymentMethod: 'MANUAL_TRANSFER', reference, ...additions };
}

async function approvePayment(server: TestServer, reviewerCookie: string, paymentId: string): Promise<Response> {
  return fetch(`${server.baseUrl}/api/v1/admin/payments/${paymentId}/approve`, { method: 'POST', headers: { cookie: reviewerCookie } });
}

interface PaymentSummaryShape { paymentId: string; status: string; amountMinorUnits: number; attribution?: { couponCode: string; discountAmountMinorUnits: number; baseAmountMinorUnits: number } }
interface CommissionShape { commissionId: string; partnerId: string; paymentId: string; couponCode: string; status: string; baseAmountMinorUnits: number; discountAmountMinorUnits: number; collectedAmountMinorUnits: number; commissionPercent: number; commissionAmountMinorUnits: number }

describe('partner activation (admin-only, one identity per user)', () => {
  test('admin activates an existing user as partner; activation is server-persisted and grants complimentary PRO', async () => {
    const { server, adminCookie } = await setup();
    await seedPartner(server, 'usr_partner_alpha');
    const res = await activatePartner(server, adminCookie, { userId: 'usr_partner_alpha', couponCode: 'AEGIS-ALPHA' });
    expect(res.status).toBe(201);
    const { partner } = await jsonData<{ partner: PartnerSummaryShape }>(res);
    expect(partner).toMatchObject({ userId: 'usr_partner_alpha', email: 'usr_partner_alpha@example.test', status: 'ACTIVE' });
    expect(partner.coupon).toMatchObject({ couponCode: 'AEGIS-ALPHA', discountPercent: 10, commissionPercent: 5, status: 'ACTIVE' });
    // Complimentary PRO was granted directly on the account, without any payment record.
    const partnerCookie = sessionCookieFrom((await login(server, 'usr_partner_alpha@example.test', PW)).res);
    const subRes = await fetch(`${server.baseUrl}/api/v1/subscription`, { headers: { cookie: partnerCookie } });
    expect(subRes.status).toBe(200);
    const sub = await jsonData<{ subscription: { plan: string; status: string }; proEntitlementSource?: string }>(subRes);
    expect(sub.subscription).toMatchObject({ plan: 'PRO', status: 'ACTIVE' });
    expect(sub.proEntitlementSource).toBeUndefined(); // never call a complimentary grant paid
    const accountsRes = await fetch(`${server.baseUrl}/api/v1/admin/accounts?search=usr_partner_alpha`, { headers: { cookie: adminCookie } });
    const accounts = await jsonData<{ accounts: Array<{ accountId: string; proEntitlementSource: string | null }> }>(accountsRes);
    expect(accounts.accounts.find((entry) => entry.accountId === 'usr_partner_alpha')?.proEntitlementSource).toBeNull();
    const history = await fetch(`${server.baseUrl}/api/v1/payments`, { headers: { cookie: partnerCookie } });
    const payments = await jsonData<{ payments: unknown[]; total: number }>(history);
    expect(payments.total).toBe(0); // complimentary PRO never fabricates payment history
  });

  test('a payment approved after partner PRO was already active is not misattributed as its paid source', async () => {
    const { server, adminCookie, reviewerCookie } = await setup();
    await seedPartner(server, 'usr_partner_pending');
    const partnerCookie = sessionCookieFrom((await login(server, 'usr_partner_pending@example.test', PW)).res);
    const created = await createPayment(server, partnerCookie, paymentBody('TXN-PENDING-PARTNER'), 'idem-pending-partner');
    expect(created.status).toBe(201);
    const { payment } = await jsonData<{ payment: PaymentSummaryShape }>(created);
    expect((await activatePartner(server, adminCookie, { userId: 'usr_partner_pending', couponCode: 'AEGIS-PENDING' })).status).toBe(201);
    expect((await approvePayment(server, reviewerCookie, payment.paymentId)).status).toBe(200);
    const sub = await jsonData<{ subscription: { plan: string }; proEntitlementSource?: string }>(
      await fetch(`${server.baseUrl}/api/v1/subscription`, { headers: { cookie: partnerCookie } }),
    );
    expect(sub.subscription.plan).toBe('PRO');
    expect(sub.proEntitlementSource).toBeUndefined();
    expect(server.payments.hasConfirmedProActivation('usr_partner_pending', (await server.users.findById('usr_partner_pending'))?.subscription?.createdAt ?? null)).toBe(false);
  });

  test('normal MEMBER cannot activate, list, detail, mutate or settle partner resources', async () => {
    const { server, adminCookie, memberCookie } = await setup();
    await seedPartner(server, 'usr_partner_beta');
    const created = await activatePartner(server, adminCookie, { userId: 'usr_partner_beta', couponCode: 'AEGIS-BETA' });
    const { partner } = await jsonData<{ partner: PartnerSummaryShape }>(created);
    const attempts: Array<[string, string, Record<string, unknown> | undefined]> = [
      ['POST', '/api/v1/admin/partners', { userId: 'x', couponCode: 'AEGIS-ZZZZ' }],
      ['GET', '/api/v1/admin/partners', undefined],
      ['GET', `/api/v1/admin/partners/${partner.partnerId}`, undefined],
      ['GET', `/api/v1/admin/partners/${partner.partnerId}/payments`, undefined],
      ['POST', `/api/v1/admin/partners/${partner.partnerId}/deactivate`, undefined],
      ['POST', `/api/v1/admin/partners/${partner.partnerId}/reactivate`, undefined],
      ['PATCH', `/api/v1/admin/partners/${partner.partnerId}/coupon`, { status: 'INACTIVE' }],
      ['GET', '/api/v1/admin/commissions', undefined],
    ];
    for (const [method, path, body] of attempts) {
      const res = await fetch(`${server.baseUrl}${path}`, {
        method,
        headers: { cookie: memberCookie, ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
      expect(res.status, `${method} ${path}`).toBe(403);
    }
  });

  test('ADMIN without the platform allowlist cannot manage partners (dual gate)', async () => {
    const { server } = await setup({ platformAdminIds: [] });
    const outsiderAdmin = sessionCookieFrom((await login(server, 'usr_platform_admin@example.test', PW)).res);
    const res = await fetch(`${server.baseUrl}/api/v1/admin/partners`, { headers: { cookie: outsiderAdmin } });
    expect(res.status).toBe(403);
  });

  test('duplicate partner identity and duplicate coupon code are both rejected', async () => {
    const { server, adminCookie } = await setup();
    await seedPartner(server, 'usr_partner_one');
    await seedPartner(server, 'usr_partner_two');
    expect((await activatePartner(server, adminCookie, { userId: 'usr_partner_one', couponCode: 'AEGIS-ONE' })).status).toBe(201);
    expect((await activatePartner(server, adminCookie, { userId: 'usr_partner_one', couponCode: 'AEGIS-ONE-B' })).status).toBe(409); // same user second identity
    expect((await activatePartner(server, adminCookie, { userId: 'usr_partner_two', couponCode: 'aegis-one' })).status).toBe(409); // normalized collision
    expect((await activatePartner(server, adminCookie, { userId: 'usr_partner_two', couponCode: 'AEGIS-TWO' })).status).toBe(201);
    const list = await fetch(`${server.baseUrl}/api/v1/admin/partners`, { headers: { cookie: adminCookie } });
    const partners = await jsonData<{ partners: PartnerSummaryShape[]; total: number }>(list);
    expect(partners.total).toBe(2);
    expect(partners.partners.map((p) => p.coupon.couponCode).sort()).toEqual(['AEGIS-ONE', 'AEGIS-TWO']);
  });

  test('activation rejects unknown user, malformed coupon and out-of-range percents', async () => {
    const { server, adminCookie } = await setup();
    await seedPartner(server, 'usr_partner_gamma');
    expect((await activatePartner(server, adminCookie, { userId: 'usr_missing_account', couponCode: 'AEGIS-GAMMA' })).status).toBe(422);
    expect((await activatePartner(server, adminCookie, { userId: 'usr_partner_gamma', couponCode: '!!bad!!' })).status).toBe(422);
    expect((await activatePartner(server, adminCookie, { userId: 'usr_partner_gamma', couponCode: 'AEGIS-GAMMA', discountPercent: 101 })).status).toBe(422);
    expect((await activatePartner(server, adminCookie, { userId: 'usr_partner_gamma', couponCode: 'AEGIS-GAMMA', commissionPercent: 99 })).status).toBe(422);
  });
});

describe('coupon redemption and server-authoritative pricing', () => {
  async function partnerActivated(): Promise<{ server: TestServer; adminCookie: string; reviewerCookie: string; buyerCookie: string }> {
    const { server, adminCookie, reviewerCookie } = await setup();
    await seedPartner(server, 'usr_partner_delta');
    const created = await activatePartner(server, adminCookie, { userId: 'usr_partner_delta', couponCode: 'AEGIS-DELTA' });
    expect(created.status).toBe(201);
    const buyer = await register(server, 'buyer@example.test', PW);
    return { server, adminCookie, reviewerCookie, buyerCookie: sessionCookieFrom(buyer.res) };
  }

  test('quote returns server-computed discount; invalid/unknown coupons quote nothing', async () => {
    const { server, buyerCookie } = await partnerActivated();
    const ok = await fetch(`${server.baseUrl}/api/v1/payments/quote?couponCode=aegis-delta`, { headers: { cookie: buyerCookie } });
    expect(ok.status).toBe(200); // normalized case-insensitive
    const quote = await jsonData<{ baseAmountMinorUnits: number; coupon: { code: string; discountPercent: number; discountAmountMinorUnits: number; finalAmountMinorUnits: number } | null }>(ok);
    expect(quote.baseAmountMinorUnits).toBe(PRICE);
    expect(quote.coupon).toMatchObject({ code: 'AEGIS-DELTA', discountPercent: 10, discountAmountMinorUnits: 10_000, finalAmountMinorUnits: 90_000 });
    expect((await fetch(`${server.baseUrl}/api/v1/payments/quote?couponCode=NOPE-UNKNOWN`, { headers: { cookie: buyerCookie } })).status).toBe(422);
    expect((await fetch(`${server.baseUrl}/api/v1/payments/quote?couponCode=AEGIS-DELTA&couponCode=AEGIS-DELTA`, { headers: { cookie: buyerCookie } })).status).toBe(422); // HPP
    expect((await fetch(`${server.baseUrl}/api/v1/payments/quote?coupon=AEGIS-DELTA`, { headers: { cookie: buyerCookie } })).status).toBe(422); // wrong key
    expect((await fetch(`${server.baseUrl}/api/v1/payments/quote`, { headers: { cookie: buyerCookie } })).status).toBe(200); // no coupon → base only
  });

  test('payment with valid coupon records attribution and the discounted amount; client cannot override price/discount/partner', async () => {
    const { server, buyerCookie } = await partnerActivated();
    const fullPriceAttempt = await createPayment(server, buyerCookie, paymentBody(REFERENCE, { couponCode: 'AEGIS-DELTA' }));
    expect(fullPriceAttempt.status).toBe(422); // client quoted the pre-discount price — tampered
    const discounted = await createPayment(server, buyerCookie, paymentBody(REFERENCE, { amountMinorUnits: 90_000, couponCode: 'AEGIS-DELTA' }));
    expect(discounted.status).toBe(201);
    const { payment } = await jsonData<{ payment: PaymentSummaryShape }>(discounted);
    expect(payment.amountMinorUnits).toBe(90_000);
    expect(payment.attribution).toMatchObject({ couponCode: 'AEGIS-DELTA', baseAmountMinorUnits: PRICE, discountAmountMinorUnits: 10_000 });
    // Client-supplied partner/discount manipulation fields are top-level schema violations.
    const forged = await createPayment(server, buyerCookie, paymentBody('TXN-FORGED-01', { amountMinorUnits: 90_000, couponCode: 'AEGIS-DELTA', partnerId: 'ptr_evil', discountPercent: 99, commissionPercent: 1 }), 'idem-forged-01');
    expect(forged.status).toBe(422);
  });

  test('unknown, inactive or expired coupons are rejected uniformly', async () => {
    const { server, adminCookie, buyerCookie } = await partnerActivated();
    expect((await createPayment(server, buyerCookie, paymentBody(REFERENCE, { amountMinorUnits: 90_000, couponCode: 'NOPE-12345' }), 'idem-unknown-coupon')).status).toBe(422);
    // Inactive: patch the coupon off, then redemption must fail.
    const list = await fetch(`${server.baseUrl}/api/v1/admin/partners`, { headers: { cookie: adminCookie } });
    const partners = await jsonData<{ partners: PartnerSummaryShape[] }>(list);
    const partnerId = partners.partners[0]!.partnerId;
    const off = await fetch(`${server.baseUrl}/api/v1/admin/partners/${partnerId}/coupon`, { method: 'PATCH', headers: { cookie: adminCookie, 'content-type': 'application/json' }, body: JSON.stringify({ status: 'INACTIVE' }) });
    expect(off.status).toBe(200);
    expect((await createPayment(server, buyerCookie, paymentBody(REFERENCE, { amountMinorUnits: 90_000, couponCode: 'AEGIS-DELTA' }), 'idem-inactive-coupon')).status).toBe(422);
    // Expired: past expiry makes an ACTIVE coupon non-redeemable.
    const expired = await fetch(`${server.baseUrl}/api/v1/admin/partners/${partnerId}/coupon`, { method: 'PATCH', headers: { cookie: adminCookie, 'content-type': 'application/json' }, body: JSON.stringify({ status: 'ACTIVE', expiresAt: '2020-01-01T00:00:00.000Z' }) });
    expect(expired.status).toBe(200);
    expect((await createPayment(server, buyerCookie, paymentBody(REFERENCE, { amountMinorUnits: 90_000, couponCode: 'AEGIS-DELTA' }), 'idem-expired-coupon')).status).toBe(422);
  });

  test('idempotent replay keeps coupon identity; key reuse with a different coupon conflicts', async () => {
    const { server, buyerCookie } = await partnerActivated();
    const first = await createPayment(server, buyerCookie, paymentBody(REFERENCE, { amountMinorUnits: 90_000, couponCode: 'AEGIS-DELTA' }), 'idem-coupon-replay');
    expect(first.status).toBe(201);
    const replay = await createPayment(server, buyerCookie, paymentBody(REFERENCE, { amountMinorUnits: 90_000, couponCode: 'AEGIS-DELTA' }), 'idem-coupon-replay');
    expect(replay.status).toBe(200);
    const without = await createPayment(server, buyerCookie, paymentBody(REFERENCE), 'idem-coupon-replay');
    expect(without.status).toBe(409);
  });
});

describe('approval → PRO + idempotent commission; reject/cancel produce none', () => {
  test('approved coupon payment activates PRO and creates exactly one commission with correct accounting', async () => {
    const { server, adminCookie, reviewerCookie } = await setup();
    await seedPartner(server, 'usr_partner_epsilon');
    await activatePartner(server, adminCookie, { userId: 'usr_partner_epsilon', couponCode: 'AEGIS-EPS' });
    const buyer = await register(server, 'buyer2@example.test', PW);
    const buyerCookie = sessionCookieFrom(buyer.res);
    const created = await createPayment(server, buyerCookie, paymentBody(REFERENCE, { amountMinorUnits: 90_000, couponCode: 'AEGIS-EPS' }));
    const { payment } = await jsonData<{ payment: PaymentSummaryShape }>(created);
    const approved = await approvePayment(server, reviewerCookie, payment.paymentId);
    expect(approved.status).toBe(200);
    const subscription = await jsonData<{ subscription: { plan: string } }>(await fetch(`${server.baseUrl}/api/v1/subscription`, { headers: { cookie: buyerCookie } }));
    expect(subscription.subscription.plan).toBe('PRO');
    const listRes = await fetch(`${server.baseUrl}/api/v1/admin/commissions`, { headers: { cookie: adminCookie } });
    expect(listRes.status).toBe(200);
    const commissions = await jsonData<{ commissions: CommissionShape[]; total: number }>(listRes);
    expect(commissions.total).toBe(1);
    const commission = commissions.commissions[0]!;
    expect(commission).toMatchObject({
      paymentId: payment.paymentId,
      status: 'PENDING',
      baseAmountMinorUnits: PRICE,
      discountAmountMinorUnits: 10_000,
      collectedAmountMinorUnits: 90_000,
      commissionPercent: 5,
      commissionAmountMinorUnits: 4_500, // 5% of collected 90_000 — the remaining 85_500 is business revenue
    });
    // Duplicate approval replay must not duplicate the commission.
    expect((await approvePayment(server, reviewerCookie, payment.paymentId)).status).toBe(200);
    const afterReplay = await jsonData<{ total: number }>(await fetch(`${server.baseUrl}/api/v1/admin/commissions`, { headers: { cookie: adminCookie } }));
    expect(afterReplay.total).toBe(1);
  });

  test('rejected and cancelled coupon payments create no commission', async () => {
    const { server, adminCookie, reviewerCookie } = await setup();
    await seedPartner(server, 'usr_partner_zeta');
    await activatePartner(server, adminCookie, { userId: 'usr_partner_zeta', couponCode: 'AEGIS-ZETA' });
    const buyerA = await register(server, 'buyerc@example.test', PW);
    const buyerACookie = sessionCookieFrom(buyerA.res);
    const rejectedPayment = await jsonData<{ payment: PaymentSummaryShape }>(await createPayment(server, buyerACookie, paymentBody('TXN-REJ-0001', { amountMinorUnits: 90_000, couponCode: 'AEGIS-ZETA' }), 'idem-reject'));
    const rejected = await fetch(`${server.baseUrl}/api/v1/admin/payments/${rejectedPayment.payment.paymentId}/reject`, {
      method: 'POST', headers: { cookie: reviewerCookie, 'content-type': 'application/json' }, body: JSON.stringify({ reason: 'Receipt could not be matched to any transfer.' }),
    });
    expect(rejected.status).toBe(200);
    const buyerB = await register(server, 'buyerd@example.test', PW);
    const buyerBCookie = sessionCookieFrom(buyerB.res);
    const cancelledPayment = await jsonData<{ payment: PaymentSummaryShape }>(await createPayment(server, buyerBCookie, paymentBody('TXN-CXL-0001', { amountMinorUnits: 90_000, couponCode: 'AEGIS-ZETA' }), 'idem-cancel'));
    const cancelled = await fetch(`${server.baseUrl}/api/v1/payments/${cancelledPayment.payment.paymentId}/cancel`, { method: 'POST', headers: { cookie: buyerBCookie } });
    expect(cancelled.status).toBe(200);
    const commissions = await jsonData<{ total: number }>(await fetch(`${server.baseUrl}/api/v1/admin/commissions`, { headers: { cookie: adminCookie } }));
    expect(commissions.total).toBe(0);
  });

  test('commission lifecycle PENDING → AVAILABLE → PAID is admin-gated, strictly ordered and idempotent', async () => {
    const { server, adminCookie, reviewerCookie, memberCookie } = await setup();
    await seedPartner(server, 'usr_partner_eta');
    await activatePartner(server, adminCookie, { userId: 'usr_partner_eta', couponCode: 'AEGIS-ETA' });
    const buyer = await register(server, 'buyere@example.test', PW);
    const created = await jsonData<{ payment: PaymentSummaryShape }>(await createPayment(server, sessionCookieFrom(buyer.res), paymentBody(REFERENCE, { amountMinorUnits: 90_000, couponCode: 'AEGIS-ETA' }), 'idem-lifecycle'));
    await approvePayment(server, reviewerCookie, created.payment.paymentId);
    const commissions = await jsonData<{ commissions: CommissionShape[] }>(await fetch(`${server.baseUrl}/api/v1/admin/commissions`, { headers: { cookie: adminCookie } }));
    const commission = commissions.commissions[0]!;
    expect((await fetch(`${server.baseUrl}/api/v1/admin/commissions/${commission.commissionId}/paid`, { method: 'POST', headers: { cookie: adminCookie } })).status).toBe(409); // cannot skip AVAILABLE
    expect((await fetch(`${server.baseUrl}/api/v1/admin/commissions/${commission.commissionId}/available`, { method: 'POST', headers: { cookie: memberCookie } })).status).toBe(403);
    expect((await fetch(`${server.baseUrl}/api/v1/admin/commissions/${commission.commissionId}/available`, { method: 'POST', headers: { cookie: memberCookie } })).status).toBe(403);
    const available = await fetch(`${server.baseUrl}/api/v1/admin/commissions/${commission.commissionId}/available`, { method: 'POST', headers: { cookie: adminCookie } });
    expect(available.status).toBe(200);
    expect((await jsonData<{ commission: CommissionShape }>(available)).commission.status).toBe('AVAILABLE');
    expect((await fetch(`${server.baseUrl}/api/v1/admin/commissions/${commission.commissionId}/available`, { method: 'POST', headers: { cookie: adminCookie } })).status).toBe(200); // idempotent
    const paid = await fetch(`${server.baseUrl}/api/v1/admin/commissions/${commission.commissionId}/paid`, { method: 'POST', headers: { cookie: adminCookie } });
    expect(paid.status).toBe(200);
    expect((await jsonData<{ commission: CommissionShape }>(paid)).commission.status).toBe('PAID');
    expect((await fetch(`${server.baseUrl}/api/v1/admin/commissions/${commission.commissionId}/available`, { method: 'POST', headers: { cookie: adminCookie } })).status).toBe(409); // never reverses
  });
});

describe('multiple partners, multiple paid accounts, partner deactivation', () => {
  test('two independent partners keep separate coupons, aggregates and commissions', async () => {
    const { server, adminCookie, reviewerCookie } = await setup();
    await seedPartner(server, 'usr_partner_a7');
    await seedPartner(server, 'usr_partner_b7');
    await activatePartner(server, adminCookie, { userId: 'usr_partner_a7', couponCode: 'AEGIS-A7' });
    await activatePartner(server, adminCookie, { userId: 'usr_partner_b7', couponCode: 'AEGIS-B7', discountPercent: 20, commissionPercent: 10 });
    const buyerA = await register(server, 'buyery@example.test', PW);
    const buyerB = await register(server, 'buyerz@example.test', PW);
    const paymentA = await jsonData<{ payment: PaymentSummaryShape }>(await createPayment(server, sessionCookieFrom(buyerA.res), paymentBody('TXN-PA-00001', { amountMinorUnits: 90_000, couponCode: 'AEGIS-A7' }), 'idem-two-a'));
    expect((await jsonData<{ payment: PaymentSummaryShape }>(await createPayment(server, sessionCookieFrom(buyerB.res), paymentBody('TXN-PB-00001', { amountMinorUnits: 80_000, couponCode: 'AEGIS-B7' }), 'idem-two-b'))).payment.amountMinorUnits).toBe(80_000);
    await approvePayment(server, reviewerCookie, paymentA.payment.paymentId);
    const commissions = await jsonData<{ commissions: CommissionShape[] }>(await fetch(`${server.baseUrl}/api/v1/admin/commissions`, { headers: { cookie: adminCookie } }));
    expect(commissions.commissions).toHaveLength(1);
    expect(commissions.commissions[0]!.couponCode).toBe('AEGIS-A7');
  });

  test('one person may hold several paid accounts; each independent approved payment earns its own commission via the same coupon', async () => {
    const { server, adminCookie, reviewerCookie } = await setup();
    await seedPartner(server, 'usr_partner_theta');
    await activatePartner(server, adminCookie, { userId: 'usr_partner_theta', couponCode: 'AEGIS-THETA' });
    const accountOne = await register(server, 'multi1@example.test', PW);
    const accountTwo = await register(server, 'multi2@example.test', PW);
    const first = await jsonData<{ payment: PaymentSummaryShape }>(await createPayment(server, sessionCookieFrom(accountOne.res), paymentBody('TXN-M1-00001', { amountMinorUnits: 90_000, couponCode: 'AEGIS-THETA' }), 'idem-multi-1'));
    const second = await jsonData<{ payment: PaymentSummaryShape }>(await createPayment(server, sessionCookieFrom(accountTwo.res), paymentBody('TXN-M2-00001', { amountMinorUnits: 90_000, couponCode: 'AEGIS-THETA' }), 'idem-multi-2'));
    expect((await approvePayment(server, reviewerCookie, first.payment.paymentId)).status).toBe(200);
    expect((await approvePayment(server, reviewerCookie, second.payment.paymentId)).status).toBe(200);
    const subOne = await jsonData<{ subscription: { plan: string } }>(await fetch(`${server.baseUrl}/api/v1/subscription`, { headers: { cookie: sessionCookieFrom(accountOne.res) } }));
    expect(subOne.subscription.plan).toBe('PRO'); // both accounts upgraded independently
    const commissions = await jsonData<{ total: number }>(await fetch(`${server.baseUrl}/api/v1/admin/commissions`, { headers: { cookie: adminCookie } }));
    expect(commissions.total).toBe(2);
  });

  test('deactivation stops new redemptions but preserves business rules for attributed payments and dashboard honesty', async () => {
    const { server, adminCookie, reviewerCookie } = await setup();
    await seedPartner(server, 'usr_partner_iota');
    const created = await activatePartner(server, adminCookie, { userId: 'usr_partner_iota', couponCode: 'AEGIS-IOTA' });
    const { partner } = await jsonData<{ partner: PartnerSummaryShape }>(created);
    const buyer = await register(server, 'buyeri@example.test', PW);
    const payment = await jsonData<{ payment: PaymentSummaryShape }>(await createPayment(server, sessionCookieFrom(buyer.res), paymentBody(REFERENCE, { amountMinorUnits: 90_000, couponCode: 'AEGIS-IOTA' }), 'idem-deactivate'));
    const off = await fetch(`${server.baseUrl}/api/v1/admin/partners/${partner.partnerId}/deactivate`, { method: 'POST', headers: { cookie: adminCookie } });
    expect(off.status).toBe(200);
    // New redemptions fail closed while the attributed pending payment still settles on approval.
    const freshBuyer = await register(server, 'buyerj@example.test', PW);
    expect((await createPayment(server, sessionCookieFrom(freshBuyer.res), paymentBody('TXN-IOTA2-01', { amountMinorUnits: 90_000, couponCode: 'AEGIS-IOTA' }), 'idem-deactivated')).status).toBe(422);
    expect((await approvePayment(server, reviewerCookie, payment.payment.paymentId)).status).toBe(200);
    const commissions = await jsonData<{ total: number }>(await fetch(`${server.baseUrl}/api/v1/admin/commissions`, { headers: { cookie: adminCookie } }));
    expect(commissions.total).toBe(1);
    const reactivated = await fetch(`${server.baseUrl}/api/v1/admin/partners/${partner.partnerId}/reactivate`, { method: 'POST', headers: { cookie: adminCookie } });
    expect(reactivated.status).toBe(200);
    expect((await createPayment(server, sessionCookieFrom(freshBuyer.res), paymentBody('TXN-IOTA3-01', { amountMinorUnits: 90_000, couponCode: 'AEGIS-IOTA' }), 'idem-reactivated')).status).toBe(201);
  });
});

describe('partner dashboard — aggregate projection and privacy boundary', () => {
  test('dashboard returns self aggregates only, with no customer-level data anywhere in the payload', async () => {
    const { server, adminCookie, reviewerCookie } = await setup();
    await seedPartner(server, 'usr_partner_kappa');
    await activatePartner(server, adminCookie, { userId: 'usr_partner_kappa', couponCode: 'AEGIS-KAPPA' });
    const partnerCookie = sessionCookieFrom((await login(server, 'usr_partner_kappa@example.test', PW)).res);
    const buyer = await register(server, 'secretdonor@example.test', PW);
    const buyerCookie = sessionCookieFrom(buyer.res);
    const payment = await jsonData<{ payment: PaymentSummaryShape }>(await createPayment(server, buyerCookie, paymentBody('SECRET-REF-1234', { amountMinorUnits: 90_000, couponCode: 'AEGIS-KAPPA' }), 'idem-privacy'));
    await approvePayment(server, reviewerCookie, payment.payment.paymentId);
    const otherBuyer = await register(server, 'otherbuyer@example.test', PW);
    await createPayment(server, sessionCookieFrom(otherBuyer.res), paymentBody('TXN-REJ-9999', { amountMinorUnits: 90_000, couponCode: 'AEGIS-KAPPA' }), 'idem-privacy-rej');
    const rejectedList = await fetch(`${server.baseUrl}/api/v1/admin/payments`, { headers: { cookie: reviewerCookie } });
    const listed = await jsonData<{ payments: PaymentSummaryShape[] }>(rejectedList);
    const toReject = listed.payments.find((row) => row.paymentId !== payment.payment.paymentId)!;
    await fetch(`${server.baseUrl}/api/v1/admin/payments/${toReject.paymentId}/reject`, { method: 'POST', headers: { cookie: reviewerCookie, 'content-type': 'application/json' }, body: JSON.stringify({ reason: 'No matching transfer located for this reference.' }) });
    const dashboard = await fetch(`${server.baseUrl}/api/v1/partners/me/dashboard`, { headers: { cookie: partnerCookie } });
    expect(dashboard.status).toBe(200);
    const body = await dashboard.text();
    const parsed = JSON.parse(body) as { data: { aggregates: { attributedPayments: number; approvedPayments: number; rejectedPayments: number; collectedAmountMinorUnits: number; commission: { pendingAmountMinorUnits: number; earnedAmountMinorUnits: number } } } };
    expect(parsed.data.aggregates).toMatchObject({ attributedPayments: 2, approvedPayments: 1, rejectedPayments: 1, collectedAmountMinorUnits: 90_000 });
    expect(parsed.data.aggregates.commission).toMatchObject({ pendingAmountMinorUnits: 4_500, earnedAmountMinorUnits: 4_500 });
    // Privacy: nothing customer-shaped may leak through the partner projection.
    for (const forbidden of ['secretdonor', 'SECRET-REF-1234', 'otherbuyer', 'accountId', 'submittedByUserId', 'reference', 'paymentId', 'rejectionReason']) {
      expect(body, `payload must not contain ${forbidden}`).not.toContain(forbidden);
    }
  });

  test('partner A cannot read partner B aggregates; a dashboard exposes only the caller identity', async () => {
    const { server, adminCookie, reviewerCookie } = await setup();
    await seedPartner(server, 'usr_partner_lambda');
    await seedPartner(server, 'usr_partner_mu');
    await activatePartner(server, adminCookie, { userId: 'usr_partner_lambda', couponCode: 'AEGIS-LAMBDA' });
    await activatePartner(server, adminCookie, { userId: 'usr_partner_mu', couponCode: 'AEGIS-MU' });
    const buyer = await register(server, 'buyerx@example.test', PW);
    const payment = await jsonData<{ payment: PaymentSummaryShape }>(await createPayment(server, sessionCookieFrom(buyer.res), paymentBody(REFERENCE, { amountMinorUnits: 90_000, couponCode: 'AEGIS-LAMBDA' }), 'idem-cross'));
    await approvePayment(server, reviewerCookie, payment.payment.paymentId);
    const muCookie = sessionCookieFrom((await login(server, 'usr_partner_mu@example.test', PW)).res);
    const dashboard = await jsonData<{ aggregates: { attributedPayments: number; commission: { earnedAmountMinorUnits: number } } }>(await fetch(`${server.baseUrl}/api/v1/partners/me/dashboard`, { headers: { cookie: muCookie } }));
    expect(dashboard.aggregates.attributedPayments).toBe(0); // B sees none of A's attribution
    expect(dashboard.aggregates.commission.earnedAmountMinorUnits).toBe(0);
    const lambdaCookie = sessionCookieFrom((await login(server, 'usr_partner_lambda@example.test', PW)).res);
    const own = await jsonData<{ aggregates: { attributedPayments: number } }>(await fetch(`${server.baseUrl}/api/v1/partners/me/dashboard`, { headers: { cookie: lambdaCookie } }));
    expect(own.aggregates.attributedPayments).toBe(1);
  });

  test('non-partner receives the uniform not-found on the self dashboard; dashboard rejects queries', async () => {
    const { server, memberCookie } = await setup();
    expect((await fetch(`${server.baseUrl}/api/v1/partners/me/dashboard`, { headers: { cookie: memberCookie } })).status).toBe(404);
    expect((await fetch(`${server.baseUrl}/api/v1/partners/me/dashboard?view=all`, { headers: { cookie: memberCookie } })).status).toBe(422);
  });

  test('partners cannot reach admin partner mutations or platform commission control', async () => {
    const { server, adminCookie } = await setup();
    await seedPartner(server, 'usr_partner_nu');
    const created = await activatePartner(server, adminCookie, { userId: 'usr_partner_nu', couponCode: 'AEGIS-NU' });
    const { partner } = await jsonData<{ partner: PartnerSummaryShape }>(created);
    const partnerCookie = sessionCookieFrom((await login(server, 'usr_partner_nu@example.test', PW)).res);
    const attempts: Array<[string, string, Record<string, unknown> | undefined]> = [
      ['GET', '/api/v1/admin/partners', undefined],
      ['PATCH', `/api/v1/admin/partners/${partner.partnerId}/coupon`, { discountPercent: 100 }],
      ['POST', '/api/v1/admin/partners', { userId: 'usr_partner_nu', couponCode: 'AEGIS-ESELF' }],
      ['GET', '/api/v1/admin/commissions', undefined],
      ['GET', `/api/v1/admin/partners/${partner.partnerId}/payments`, undefined],
    ];
    for (const [method, path, body] of attempts) {
      const res = await fetch(`${server.baseUrl}${path}`, { method, headers: { cookie: partnerCookie, ...(body === undefined ? {} : { 'content-type': 'application/json' }) }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
      expect(res.status, `${method} ${path}`).toBe(403);
    }
  });
});

describe('free anti-abuse + paid freedom coexistence (Pump 2 device rule preserved)', () => {
  test('two FREE accounts on one device still share one allowance, while paid upgrades remain unrestricted', async () => {
    const { server, adminCookie, reviewerCookie } = await setup();
    await seedPartner(server, 'usr_partner_xi');
    await activatePartner(server, adminCookie, { userId: 'usr_partner_xi', couponCode: 'AEGIS-XI' });
    // Shared device jar: both registrations reuse the device cookie.
    const regOne = await fetch(`${server.baseUrl}/api/v1/auth/register`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: 'share1@example.test', password: PW }) });
    const devicePair = (regOne.headers.getSetCookie?.() ?? []).map((c) => c.split(';')[0] ?? '').filter((c) => c !== '').find((c) => c.startsWith('drobon_device='));
    const cookieOne = sessionCookieFrom(regOne);
    const regTwo = await fetch(`${server.baseUrl}/api/v1/auth/register`, { method: 'POST', headers: { 'content-type': 'application/json', cookie: devicePair ?? '' }, body: JSON.stringify({ email: 'share2@example.test', password: PW }) });
    const cookieTwo = sessionCookieFrom(regTwo);
    const deviceCookies = [devicePair ?? ''].filter(Boolean);
    const usageHeaders = (cookie: string) => ({ cookie: [cookie, ...deviceCookies].join('; ') });
    const viewOne = await jsonData<{ plan: string; remaining: number | null; limit: number | null }>(await fetch(`${server.baseUrl}/api/v1/usage`, { headers: usageHeaders(cookieOne) }));
    const viewTwo = await jsonData<{ plan: string; remaining: number | null }>(await fetch(`${server.baseUrl}/api/v1/usage`, { headers: usageHeaders(cookieTwo) }));
    expect(viewOne.plan).toBe('FREE');
    expect(viewTwo.remaining).toBe(viewOne.remaining); // shared device allowance — no fresh benefit per account
    // Paid freedom: both accounts upgrade independently with the same coupon.
    const first = await jsonData<{ payment: PaymentSummaryShape }>(await createPayment(server, cookieOne, paymentBody('TXN-SHARE-01', { amountMinorUnits: 90_000, couponCode: 'AEGIS-XI' }), 'idem-share-1'));
    const second = await jsonData<{ payment: PaymentSummaryShape }>(await createPayment(server, cookieTwo, paymentBody('TXN-SHARE-02', { amountMinorUnits: 90_000, couponCode: 'AEGIS-XI' }), 'idem-share-2'));
    expect(first.payment.status).toBe('PENDING');
    expect(second.payment.status).toBe('PENDING');
    expect((await approvePayment(server, reviewerCookie, first.payment.paymentId)).status).toBe(200);
    expect((await approvePayment(server, reviewerCookie, second.payment.paymentId)).status).toBe(200);
    const commissions = await jsonData<{ total: number }>(await fetch(`${server.baseUrl}/api/v1/admin/commissions`, { headers: { cookie: adminCookie } }));
    expect(commissions.total).toBe(2);
  });
});

describe('admin oversight surface discipline', () => {
  test('partner list/detail/payments endpoints enforce allowlisted queries, patterns and projection redaction', async () => {
    const { server, adminCookie } = await setup();
    await seedPartner(server, 'usr_partner_omicron');
    const created = await activatePartner(server, adminCookie, { userId: 'usr_partner_omicron', couponCode: 'AEGIS-OMICRON' });
    const { partner } = await jsonData<{ partner: PartnerSummaryShape }>(created);
    expect((await fetch(`${server.baseUrl}/api/v1/admin/partners?role=ADMIN`, { headers: { cookie: adminCookie } })).status).toBe(422);
    expect((await fetch(`${server.baseUrl}/api/v1/admin/partners?status=ADMIN`, { headers: { cookie: adminCookie } })).status).toBe(422);
    expect((await fetch(`${server.baseUrl}/api/v1/admin/partners?page=1&page=1`, { headers: { cookie: adminCookie } })).status).toBe(422);
    expect((await fetch(`${server.baseUrl}/api/v1/admin/partners/ptr_not-a-real-id`, { headers: { cookie: adminCookie } })).status).toBe(404);
    expect((await fetch(`${server.baseUrl}/api/v1/admin/partners/ptr_00000000-0000-0000-0000-000000000000`, { headers: { cookie: adminCookie } })).status).toBe(404); // absent — same shape as malformed
    expect((await fetch(`${server.baseUrl}/api/v1/admin/commissions?status=APPROVED`, { headers: { cookie: adminCookie } })).status).toBe(422);
    const detail = await fetch(`${server.baseUrl}/api/v1/admin/partners/${partner.partnerId}`, { headers: { cookie: adminCookie } });
    expect(detail.status).toBe(200);
    const body = await detail.text();
    expect(body).toContain('PARTNER_ACTIVATED');
    const patchUnknown = await fetch(`${server.baseUrl}/api/v1/admin/partners/${partner.partnerId}/coupon`, { method: 'PATCH', headers: { cookie: adminCookie, 'content-type': 'application/json' }, body: JSON.stringify({ partnerId: 'ptr_overlap' }) });
    expect(patchUnknown.status).toBe(422);
    const patchEmpty = await fetch(`${server.baseUrl}/api/v1/admin/partners/${partner.partnerId}/coupon`, { method: 'PATCH', headers: { cookie: adminCookie, 'content-type': 'application/json' }, body: JSON.stringify({}) });
    expect(patchEmpty.status).toBe(422);
  });

  test('durable restart keeps partners, commissions and prevents commission double-settlement after recovery', async () => {
    const dir = makeTempStoreDir('drobon-partner-restart-');
    const paymentDir = dir;
    try {
      const base = {
        authStoreDir: dir,
        partnerStorePath: `${dir}/partners.json`,
        paymentStoreDir: paymentDir,
        platformAdminIds: ['usr_platform_admin'] as string[],
        paymentReviewerIds: ['usr_platform_reviewer'] as string[],
      };
      const first = await startTestServer(base);
      servers.push(first);
      await seededUser(first, 'usr_platform_admin', 'ADMIN');
      await seededUser(first, 'usr_platform_reviewer', 'ADMIN');
      await seedPartner(first, 'usr_partner_pi');
      const adminCookie = sessionCookieFrom((await login(first, 'usr_platform_admin@example.test', PW)).res);
      const reviewerCookie = sessionCookieFrom((await login(first, 'usr_platform_reviewer@example.test', PW)).res);
      await activatePartner(first, adminCookie, { userId: 'usr_partner_pi', couponCode: 'AEGIS-PI' });
      const buyer = await register(first, 'buyerpi@example.test', PW);
      const created = await jsonData<{ payment: PaymentSummaryShape }>(await createPayment(first, sessionCookieFrom(buyer.res), paymentBody(REFERENCE, { amountMinorUnits: 90_000, couponCode: 'AEGIS-PI' }), 'idem-restart'));
      await approvePayment(first, reviewerCookie, created.payment.paymentId);
      await first.stop();
      servers.pop();
      const second = await startTestServer(base);
      servers.push(second);
      const adminCookie2 = sessionCookieFrom((await login(second, 'usr_platform_admin@example.test', PW)).res);
      const partners = await jsonData<{ partners: PartnerSummaryShape[]; total: number }>(await fetch(`${second.baseUrl}/api/v1/admin/partners`, { headers: { cookie: adminCookie2 } }));
      expect(partners.total).toBe(1);
      expect(partners.partners[0]!.coupon.couponCode).toBe('AEGIS-PI');
      const commissions = await jsonData<{ total: number }>(await fetch(`${second.baseUrl}/api/v1/admin/commissions`, { headers: { cookie: adminCookie2 } }));
      expect(commissions.total).toBe(1); // recovery replay settled nothing twice
    } finally {
      cleanupTempStoreDir(dir);
    }
  });
});
