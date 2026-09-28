import { randomUUID } from 'node:crypto';
import { afterEach, describe, expect, test } from 'vitest';
import { hashPassword } from '../src/auth/passwords.js';
import type { UserRecord } from '../src/auth/repositories.js';
import { cleanupTempStoreDir, makeTempStoreDir, readJson, sessionCookieFrom, startTestServer, type TestServer } from './helpers.js';
import { login, register, sessionFor } from './authFixtures.js';

const PW = 'payment-fixture-password-1';
const PRICE = 100_000;
const REFERENCE = 'TXN-12345678';
const servers: TestServer[] = [];

afterEach(async () => {
  while (servers.length > 0) await servers.pop()?.stop();
});

async function seededUser(server: TestServer, id: string, role: UserRecord['role'] = 'MEMBER', subscription: UserRecord['subscription'] = { plan: 'FREE', status: 'ACTIVE', createdAt: '2026-09-01T00:00:00.000Z', updatedAt: '2026-09-01T00:00:00.000Z' }, userType: UserRecord['userType'] = null): Promise<void> {
  const record: UserRecord = { id, email: `${id}@example.test`, passwordHash: await hashPassword(PW, 1024), createdAt: '2026-09-01T00:00:00.000Z', role, userType, ...(subscription === undefined ? {} : { subscription }) };
  if (!(await server.users.create(record))) throw new Error('Seed account collision.');
}

async function setup(extra: Partial<Parameters<typeof startTestServer>[0]> = {}): Promise<{ server: TestServer; userCookie: string; userId: string; reviewerCookie: string }> {
  const server = await startTestServer({ paymentReviewerIds: ['usr_platform_reviewer'], ...extra });
  servers.push(server);
  await seededUser(server, 'usr_platform_reviewer', 'ADMIN');
  const reviewerCookie = sessionCookieFrom((await login(server, 'usr_platform_reviewer@example.test', PW)).res);
  const created = await register(server, 'free@example.test', PW);
  const userCookie = sessionCookieFrom(created.res);
  return { server, userCookie, userId: created.user.id, reviewerCookie };
}

function requestBody(reference = REFERENCE, additions: Record<string, unknown> = {}): Record<string, unknown> {
  return { plan: 'PRO', amountMinorUnits: PRICE, currency: 'BDT', paymentMethod: 'MANUAL_TRANSFER', reference, ...additions };
}

async function create(server: TestServer, cookie: string, body = requestBody(), key = 'idem-key-0001'): Promise<Response> {
  return fetch(`${server.baseUrl}/api/v1/payments`, { method: 'POST', headers: { cookie, 'content-type': 'application/json', 'idempotency-key': key }, body: JSON.stringify(body) });
}

async function jsonData<T>(response: Response): Promise<T> {
  const body = await readJson(response) as { data: T };
  return body.data;
}

async function approve(server: TestServer, cookie: string, paymentId: string): Promise<Response> {
  return fetch(`${server.baseUrl}/api/v1/admin/payments/${paymentId}/approve`, { method: 'POST', headers: { cookie } });
}

async function reject(server: TestServer, cookie: string, paymentId: string, reason: string): Promise<Response> {
  return fetch(`${server.baseUrl}/api/v1/admin/payments/${paymentId}/reject`, { method: 'POST', headers: { cookie, 'content-type': 'application/json' }, body: JSON.stringify({ reason }) });
}

describe('Pump 15 payment request, ownership and validation', () => {
  test('FREE user sees server pricing and submits a bounded manual request; gateway stays unavailable', async () => {
    const { server, userCookie } = await setup();
    const configRes = await fetch(`${server.baseUrl}/api/v1/payments/config`, { headers: { cookie: userCookie } });
    expect(configRes.status).toBe(200);
    const config = await jsonData<{ proPriceMinorUnits: number; currency: string; onlineGateway: string; manualPaymentInstructions: string }>(configRes);
    expect(config).toMatchObject({ proPriceMinorUnits: PRICE, currency: 'BDT', onlineGateway: 'UNAVAILABLE' });
    expect(config.manualPaymentInstructions).toContain('not payment verification');

    const created = await create(server, userCookie);
    expect(created.status).toBe(201);
    const data = await jsonData<{ payment: { paymentId: string; status: string; amountMinorUnits: number; reference: string } }>(created);
    expect(data.payment).toMatchObject({ status: 'PENDING', amountMinorUnits: PRICE, reference: REFERENCE });
    expect(data.payment.paymentId).toMatch(/^pay_/);
    expect(JSON.stringify(await readJson(await fetch(`${server.baseUrl}/api/v1/payments`, { headers: { cookie: userCookie } })))).not.toContain('idempotencyKey');
  });

  test('authentication, self-only history/detail, payment IDOR and account query tampering', async () => {
    const { server, userCookie } = await setup();
    expect((await fetch(`${server.baseUrl}/api/v1/payments`)).status).toBe(401);
    const made = await jsonData<{ payment: { paymentId: string } }>(await create(server, userCookie));
    const other = await sessionFor(server, 'other@example.test', PW);
    expect((await fetch(`${server.baseUrl}/api/v1/payments/${made.payment.paymentId}`, { headers: { cookie: other } })).status).toBe(404);
    expect((await fetch(`${server.baseUrl}/api/v1/payments?accountId=${encodeURIComponent((await register(server, 'third@example.test', PW)).user.id)}`, { headers: { cookie: userCookie } })).status).toBe(422);
    const own = await jsonData<{ payments: Array<{ paymentId: string }>; total: number }>(await fetch(`${server.baseUrl}/api/v1/payments`, { headers: { cookie: userCookie } }));
    expect(own.total).toBe(1);
    expect(own.payments[0]?.paymentId).toBe(made.payment.paymentId);
  });

  test.each([
    ['zero price', { amountMinorUnits: 0 }],
    ['negative price', { amountMinorUnits: -1 }],
    ['client-chosen price', { amountMinorUnits: 1 }],
    ['arbitrary currency', { currency: 'USD' }],
    ['FREE requested plan', { plan: 'FREE' }],
    ['fake success claim', { paymentStatus: 'SUCCESS' }],
    ['client account authority', { accountId: 'usr_other', ownerId: 'usr_other', subscriptionId: 'sub_other' }],
    ['discount authority', { discountPercent: 100, finalAmount: 0 }],
    ['oversized reference', { reference: 'A'.repeat(65) }],
    ['malformed reference', { reference: 'bad reference' }],
  ])('rejects %s without creating a record', async (_label, extra) => {
    const { server, userCookie } = await setup();
    const response = await create(server, userCookie, requestBody(REFERENCE, extra), 'idem-invalid-01');
    expect(response.status).toBe(422);
    expect(server.payments.listAll()).toHaveLength(0);
  });

  test('missing key, duplicate active requests/references and idempotent replay controls', async () => {
    const { server, userCookie } = await setup();
    const missing = await fetch(`${server.baseUrl}/api/v1/payments`, { method: 'POST', headers: { cookie: userCookie, 'content-type': 'application/json' }, body: JSON.stringify(requestBody()) });
    expect(missing.status).toBe(422);
    const first = await create(server, userCookie, requestBody(), 'idem-replay-001');
    const second = await create(server, userCookie, requestBody(), 'idem-replay-001');
    expect(first.status).toBe(201);
    expect(second.status).toBe(200);
    const firstData = await jsonData<{ payment: { paymentId: string } }>(first);
    const secondData = await jsonData<{ payment: { paymentId: string } }>(second);
    expect(secondData.payment.paymentId).toBe(firstData.payment.paymentId);
    expect((await create(server, userCookie, requestBody('TXN-87654321'), 'idem-different-02')).status).toBe(409);
    const other = await sessionFor(server, 'other-ref@example.test', PW);
    expect((await create(server, other, requestBody(), 'idem-other-0001')).status).toBe(409);
    const sameAccountNewReference = await create(server, userCookie, requestBody('TXN-87654321'), 'idem-active-0002');
    expect(sameAccountNewReference.status).toBe(409);
    expect(server.payments.listAll()).toHaveLength(1);
  });

  test('free-form rejection reasons redact credential-like material before persistence and delivery', async () => {
    const { server, userCookie, reviewerCookie } = await setup();
    const made = await jsonData<{ payment: { paymentId: string } }>(await create(server, userCookie));
    const response = await reject(server, reviewerCookie, made.payment.paymentId, 'Reference mismatch; api_key=synthetic-secret-value.');
    expect(response.status).toBe(200);
    const result = await jsonData<{ payment: { rejectionReason: string | null } }>(response);
    expect(result.payment.rejectionReason).toContain('[credential omitted]');
    expect(result.payment.rejectionReason).not.toContain('synthetic-secret-value');
    expect(server.payments.get(made.payment.paymentId)?.rejectionReason).not.toContain('synthetic-secret-value');
  });

  test('owner may cancel only a PENDING request; cancellation is idempotent and cannot activate PRO', async () => {
    const { server, userCookie } = await setup();
    const made = await jsonData<{ payment: { paymentId: string } }>(await create(server, userCookie));
    const paymentId = made.payment.paymentId;
    const url = `${server.baseUrl}/api/v1/payments/${paymentId}/cancel`;
    const first = await fetch(url, { method: 'POST', headers: { cookie: userCookie } });
    const second = await fetch(url, { method: 'POST', headers: { cookie: userCookie } });
    expect(first.status).toBe(200);
    expect(second.status).toBe(200);
    expect((await jsonData<{ payment: { status: string } }>(second)).payment.status).toBe('CANCELLED');
    const other = await sessionFor(server, 'cancel-other@example.test', PW);
    expect((await fetch(url, { method: 'POST', headers: { cookie: other } })).status).toBe(404);
    expect(server.payments.listAudit(paymentId).filter((event) => event.action === 'PAYMENT_CANCELLED')).toHaveLength(1);
    expect(server.payments.get(paymentId)?.status).toBe('CANCELLED');
    expect((await server.users.findById((await server.users.findByEmail('free@example.test'))?.id ?? ''))?.subscription?.plan).toBe('FREE');
  });

  test('PRO accounts and UserType cannot bypass plan rules; only FREE accounts request upgrades', async () => {
    const server = await startTestServer();
    servers.push(server);
    await seededUser(server, 'usr_pro_account', 'MEMBER', { plan: 'PRO', status: 'ACTIVE', createdAt: '2026-09-01T00:00:00.000Z', updatedAt: '2026-09-01T00:00:00.000Z' });
    await seededUser(server, 'usr_student_free', 'MEMBER', undefined, 'PENTESTER');
    const proCookie = sessionCookieFrom((await login(server, 'usr_pro_account@example.test', PW)).res);
    const freeCookie = sessionCookieFrom((await login(server, 'usr_student_free@example.test', PW)).res);
    expect((await create(server, proCookie)).status).toBe(409);
    expect((await create(server, freeCookie)).status).toBe(201);
    const sub = await jsonData<{ subscription: { plan: string }; entitlements: string[] }>(await fetch(`${server.baseUrl}/api/v1/subscription`, { headers: { cookie: freeCookie } }));
    expect(sub.subscription.plan).toBe('FREE');
    expect(sub.entitlements).toEqual(['plan:view']);
  });
});

describe('Pump 15 platform review, state transitions and audit', () => {
  test('normal account ADMIN/ACCOUNT_OWNER and submitter cannot review or approve', async () => {
    const { server, userCookie } = await setup();
    const payment = await jsonData<{ payment: { paymentId: string } }>(await create(server, userCookie));
    await seededUser(server, 'usr_regular_admin', 'ADMIN');
    await seededUser(server, 'usr_regular_owner', 'ACCOUNT_OWNER');
    const adminCookie = sessionCookieFrom((await login(server, 'usr_regular_admin@example.test', PW)).res);
    const ownerCookie = sessionCookieFrom((await login(server, 'usr_regular_owner@example.test', PW)).res);
    for (const cookie of [adminCookie, ownerCookie, userCookie]) {
      expect((await fetch(`${server.baseUrl}/api/v1/admin/payments`, { headers: { cookie } })).status).toBe(403);
      expect((await approve(server, cookie, payment.payment.paymentId)).status).toBe(403);
    }
    expect(server.payments.get(payment.payment.paymentId)?.status).toBe('PENDING');
  });

  test('an allowlisted MEMBER still cannot act as a platform payment reviewer', async () => {
    const { server, userCookie } = await setup({ paymentReviewerIds: ['usr_platform_reviewer', 'usr_allowlisted_member'] });
    const made = await jsonData<{ payment: { paymentId: string } }>(await create(server, userCookie));
    await seededUser(server, 'usr_allowlisted_member', 'MEMBER');
    const memberCookie = sessionCookieFrom((await login(server, 'usr_allowlisted_member@example.test', PW)).res);
    expect((await fetch(`${server.baseUrl}/api/v1/admin/payments`, { headers: { cookie: memberCookie } })).status).toBe(403);
    expect((await approve(server, memberCookie, made.payment.paymentId)).status).toBe(403);
    expect(server.payments.get(made.payment.paymentId)?.status).toBe('PENDING');
  });

  test('authorized reviewer approves once, activates existing entitlement and persists audit truth', async () => {
    const { server, userCookie, userId, reviewerCookie } = await setup();
    const made = await jsonData<{ payment: { paymentId: string } }>(await create(server, userCookie));
    const paymentId = made.payment.paymentId;
    const reviewUrl = `${server.baseUrl}/api/v1/admin/payments/${paymentId}/review`;
    expect((await fetch(reviewUrl, { method: 'POST', headers: { cookie: reviewerCookie } })).status).toBe(200);
    expect((await approve(server, reviewerCookie, paymentId)).status).toBe(200);
    expect((await approve(server, reviewerCookie, paymentId)).status).toBe(200);
    expect((await reject(server, reviewerCookie, paymentId, 'late rejection')).status).toBe(409);
    const retry = await create(server, userCookie, requestBody(), 'idem-key-0001');
    expect(retry.status).toBe(200);
    expect((await jsonData<{ payment: { paymentId: string } }>(retry)).payment.paymentId).toBe(paymentId);
    expect((await server.users.findById(userId))?.subscription).toMatchObject({ plan: 'PRO', status: 'ACTIVE' });
    const subscription = await jsonData<{ subscription: { plan: string }; entitlements: string[] }>(await fetch(`${server.baseUrl}/api/v1/subscription`, { headers: { cookie: userCookie } }));
    expect(subscription).toMatchObject({ subscription: { plan: 'PRO', status: 'ACTIVE' }, entitlements: ['plan:view', 'feature:pro'] });
    const own = await jsonData<{ payments: Array<{ status: string }> }>(await fetch(`${server.baseUrl}/api/v1/payments`, { headers: { cookie: userCookie } }));
    expect(own.payments[0]?.status).toBe('APPROVED');
    const events = await jsonData<{ events: Array<{ action: string }> }>(await fetch(`${server.baseUrl}/api/v1/admin/payments/${paymentId}/audit`, { headers: { cookie: reviewerCookie } }));
    expect(events.events.map((event) => event.action)).toEqual(['PAYMENT_CREATED', 'PAYMENT_SUBMITTED', 'PAYMENT_REVIEW_STARTED', 'PAYMENT_APPROVAL_STARTED', 'PAYMENT_APPROVED']);
    expect(events.events.filter((event) => event.action === 'PAYMENT_APPROVED')).toHaveLength(1);
    expect((await fetch(`${server.baseUrl}/api/v1/admin/payments/${paymentId}/audit`, { headers: { cookie: userCookie } })).status).toBe(403);
  });

  test('rejection reason is normalized and owner-visible; rejection is idempotent and never activates PRO', async () => {
    const { server, userCookie, userId, reviewerCookie } = await setup();
    const made = await jsonData<{ payment: { paymentId: string } }>(await create(server, userCookie));
    const paymentId = made.payment.paymentId;
    const first = await reject(server, reviewerCookie, paymentId, '  Reference   does not match.  ');
    const second = await reject(server, reviewerCookie, paymentId, 'A different later reason');
    expect(first.status).toBe(200);
    expect(second.status).toBe(200);
    const rejected = await jsonData<{ payment: { status: string; rejectionReason: string } }>(first);
    expect(rejected.payment).toMatchObject({ status: 'REJECTED', rejectionReason: 'Reference does not match.' });
    expect((await approve(server, reviewerCookie, paymentId)).status).toBe(409);
    const owner = await jsonData<{ payment: { status: string; rejectionReason: string } }>(await fetch(`${server.baseUrl}/api/v1/payments/${paymentId}`, { headers: { cookie: userCookie } }));
    expect(owner.payment).toEqual(rejected.payment);
    expect((await server.users.findById(userId))?.subscription?.plan).toBe('FREE');
    expect(server.payments.listAudit(paymentId).filter((event) => event.action === 'PAYMENT_REJECTED')).toHaveLength(1);
  });

  test('review attempt limiter returns 429 and does not mutate beyond configured cap', async () => {
    const { server, userCookie, reviewerCookie } = await setup({ paymentRateLimitMaxRequests: 1 });
    const made = await jsonData<{ payment: { paymentId: string } }>(await create(server, userCookie));
    // The first mutation above used the same direct peer bucket; clear it to make the assertion precise.
    server.resetRateLimit();
    const url = `${server.baseUrl}/api/v1/admin/payments/${made.payment.paymentId}/review`;
    expect((await fetch(url, { method: 'POST', headers: { cookie: reviewerCookie } })).status).toBe(200);
    const second = await fetch(`${server.baseUrl}/api/v1/admin/payments/${made.payment.paymentId}/approve`, { method: 'POST', headers: { cookie: reviewerCookie } });
    expect(second.status).toBe(429);
    expect(server.payments.listAudit(made.payment.paymentId).filter((event) => event.action === 'PAYMENT_APPROVAL_STARTED')).toHaveLength(0);
  });
});

describe('Pump 15 durable restart and interrupted approval recovery', () => {
  test('same idempotency key returns the persisted request after the configured price changes', async () => {
    const dir = makeTempStoreDir('drobon-payment-idempotency');
    let server: TestServer | undefined;
    try {
      server = await startTestServer({ authStoreDir: dir, paymentStoreDir: dir, proPriceMinorUnits: PRICE });
      servers.push(server);
      const created = await register(server, 'idempotent-price@example.test', PW);
      const userId = created.user.id;
      const first = await create(server, sessionCookieFrom(created.res), requestBody(), 'idem-price-change-001');
      expect(first.status).toBe(201);
      const paymentId = (await jsonData<{ payment: { paymentId: string } }>(first)).payment.paymentId;
      await server.stop();
      servers.splice(servers.indexOf(server), 1);

      server = await startTestServer({ authStoreDir: dir, paymentStoreDir: dir, proPriceMinorUnits: PRICE + 5000 });
      servers.push(server);
      const cookie = sessionCookieFrom((await login(server, 'idempotent-price@example.test', PW)).res);
      const retry = await create(server, cookie, requestBody(), 'idem-price-change-001');
      expect(retry.status).toBe(200);
      expect((await jsonData<{ payment: { paymentId: string; amountMinorUnits: number } }>(retry)).payment).toMatchObject({ paymentId, amountMinorUnits: PRICE });
      expect((await create(server, cookie, requestBody(), 'idem-price-change-002')).status).toBe(422);
      expect(server.payments.listAll()).toHaveLength(1);
      expect(await server.users.findById(userId)).toBeDefined();
    } finally {
      if (server !== undefined) {
        const index = servers.indexOf(server);
        if (index >= 0) servers.splice(index, 1);
        await server.stop();
      }
      cleanupTempStoreDir(dir);
    }
  });

  test('restart reconciles a durable APPROVING state after a simulated crash boundary', async () => {
    const dir = makeTempStoreDir('drobon-payment-recovery');
    let server: TestServer | undefined;
    try {
      server = await startTestServer({ authStoreDir: dir, paymentStoreDir: dir, paymentReviewerIds: ['usr_recovery_reviewer'] });
      servers.push(server);
      await seededUser(server, 'usr_recovery_reviewer', 'ADMIN');
      const created = await register(server, 'recovery-user@example.test', PW);
      const userCookie = sessionCookieFrom(created.res);
      const made = await jsonData<{ payment: { paymentId: string } }>(await create(server, userCookie));
      const pending = server.payments.get(made.payment.paymentId);
      if (pending === undefined) throw new Error('Expected durable payment fixture.');
      const secondCreated = await register(server, 'recovery-after-activation@example.test', PW);
      const secondCookie = sessionCookieFrom(secondCreated.res);
      const secondMade = await jsonData<{ payment: { paymentId: string } }>(await create(server, secondCookie, requestBody('TXN-RECOVERY-B2')));
      const afterActivation = server.payments.get(secondMade.payment.paymentId);
      if (afterActivation === undefined) throw new Error('Expected second durable payment fixture.');
      const startedAt = '2026-09-29T12:00:00.000Z';
      for (const record of [pending, afterActivation]) {
        await server.payments.beginApproval(record.paymentId, 'usr_recovery_reviewer', startedAt, {
          eventId: `evt_${randomUUID()}`, paymentId: record.paymentId, accountId: record.accountId,
          actorId: 'usr_recovery_reviewer', action: 'PAYMENT_APPROVAL_STARTED', previousStatus: 'PENDING',
          newStatus: 'APPROVING', timestamp: startedAt, reason: null,
        });
      }
      // Model a crash after the authoritative account/subscription file was
      // written but before the payment document reached APPROVED.
      expect(await server.users.activatePro(afterActivation.accountId, startedAt)).toBe('ACTIVATED');
      expect(server.payments.get(pending.paymentId)?.status).toBe('APPROVING');
      expect(server.payments.get(afterActivation.paymentId)?.status).toBe('APPROVING');
      await server.stop();
      servers.splice(servers.indexOf(server), 1);
      server = await startTestServer({ authStoreDir: dir, paymentStoreDir: dir, paymentReviewerIds: ['usr_recovery_reviewer'] });
      servers.push(server);
      expect(server.payments.get(pending.paymentId)?.status).toBe('APPROVED');
      expect(server.payments.get(afterActivation.paymentId)?.status).toBe('APPROVED');
      expect(server.payments.listAudit(pending.paymentId).find((event) => event.action === 'PAYMENT_APPROVED')?.actorId).toBe('usr_recovery_reviewer');
      expect(server.payments.listAudit(afterActivation.paymentId).find((event) => event.action === 'PAYMENT_APPROVED')?.actorId).toBe('usr_recovery_reviewer');
      for (const email of ['recovery-user@example.test', 'recovery-after-activation@example.test']) {
        const after = sessionCookieFrom((await login(server, email, PW)).res);
        const subscription = await jsonData<{ subscription: { plan: string }; entitlements: string[] }>(await fetch(`${server.baseUrl}/api/v1/subscription`, { headers: { cookie: after } }));
        expect(subscription.subscription.plan).toBe('PRO');
        expect(subscription.entitlements).toContain('feature:pro');
      }
    } finally {
      if (server !== undefined) {
        const index = servers.indexOf(server);
        if (index >= 0) servers.splice(index, 1);
        await server.stop();
      }
      cleanupTempStoreDir(dir);
    }
  });

  test('payment history, audit and PRO entitlement survive a fresh repository/server instance', async () => {
    const dir = makeTempStoreDir('drobon-payment-e2e');
    let server = await startTestServer({ authStoreDir: dir, paymentStoreDir: dir, paymentReviewerIds: ['usr_durable_reviewer'] });
    servers.push(server);
    await seededUser(server, 'usr_durable_reviewer', 'ADMIN');
    const reviewerCookie = sessionCookieFrom((await login(server, 'usr_durable_reviewer@example.test', PW)).res);
    const created = await register(server, 'durable-free@example.test', PW);
    const userCookie = sessionCookieFrom(created.res);
    const userId = created.user.id;
    const made = await jsonData<{ payment: { paymentId: string } }>(await create(server, userCookie));
    await approve(server, reviewerCookie, made.payment.paymentId);
    await server.stop();
    servers.splice(servers.indexOf(server), 1);
    server = await startTestServer({ authStoreDir: dir, paymentStoreDir: dir, paymentReviewerIds: ['usr_durable_reviewer'] });
    servers.push(server);
    const userAfterRestart = sessionCookieFrom((await login(server, 'durable-free@example.test', PW)).res);
    const reviewerAfterRestart = sessionCookieFrom((await login(server, 'usr_durable_reviewer@example.test', PW)).res);
    const history = await jsonData<{ payments: Array<{ paymentId: string; status: string }> }>(await fetch(`${server.baseUrl}/api/v1/payments`, { headers: { cookie: userAfterRestart } }));
    expect(history.payments).toContainEqual(expect.objectContaining({ paymentId: made.payment.paymentId, status: 'APPROVED' }));
    const subscription = await jsonData<{ subscription: { plan: string }; entitlements: string[] }>(await fetch(`${server.baseUrl}/api/v1/subscription`, { headers: { cookie: userAfterRestart } }));
    expect(subscription.subscription.plan).toBe('PRO');
    expect(subscription.entitlements).toContain('feature:pro');
    const audit = await jsonData<{ events: unknown[] }>(await fetch(`${server.baseUrl}/api/v1/admin/payments/${made.payment.paymentId}/audit`, { headers: { cookie: reviewerAfterRestart } }));
    expect(audit.events.length).toBeGreaterThanOrEqual(4);
    expect((await server.users.findById(userId))?.subscription?.plan).toBe('PRO');
    cleanupTempStoreDir(dir);
  });
});
