import { afterEach, describe, expect, test } from 'vitest';
import { hashPassword } from '../src/auth/passwords.js';
import type { UserRecord } from '../src/auth/repositories.js';
import { makeTempStoreDir, cleanupTempStoreDir, readJson, sessionCookieFrom, startTestServer, type TestServer } from './helpers.js';
import { login, register } from './authFixtures.js';

/**
 * Phase 20 — Admin Payment Configuration security matrix.
 *
 * Covers the mandated live scenarios: add/edit/enable/disable payment
 * destinations, PRO price changes, live user-side reflection, server
 * authority, historical payment integrity, authorization matrix, validation,
 * CSRF/HPP, concurrency, audit masking and replay safety.
 */

const PW = 'paycfg-fixture-password-1';
const PRICE = 100_000;
const servers: TestServer[] = [];

afterEach(async () => {
  while (servers.length > 0) await servers.pop()?.stop();
});

interface AdminConfig {
  proPriceMinorUnits: number;
  destinations: Array<{ methodId: string; displayName: string; accountNumber: string; enabled: boolean }>;
  updatedAt: string;
  audit: Array<{ entryId: string; actorId: string; action: string; detail: string }>;
}

interface UserConfig {
  proPriceMinorUnits: number;
  manualPaymentMethods: string[];
  manualPaymentDestinations: Array<{ methodId: string; displayName: string; accountNumber: string; enabled: boolean }>;
}

async function seededUser(server: TestServer, id: string, role: UserRecord['role'] = 'MEMBER'): Promise<string> {
  const record: UserRecord = {
    id, email: `${id}@example.test`, passwordHash: await hashPassword(PW, 1024),
    createdAt: '2026-09-01T00:00:00.000Z', role, userType: null,
    subscription: { plan: 'FREE', status: 'ACTIVE', createdAt: '2026-09-01T00:00:00.000Z', updatedAt: '2026-09-01T00:00:00.000Z' },
  };
  if (!(await server.users.create(record))) throw new Error('Seed account collision.');
  return `${id}@example.test`;
}

async function setup(): Promise<{ server: TestServer; adminCookie: string; reviewerCookie: string; memberCookie: string; memberEmail: string }> {
  const server = await startTestServer({
    platformAdminIds: ['usr_platform_admin'],
    paymentReviewerIds: ['usr_platform_reviewer'],
  });
  servers.push(server);
  await seededUser(server, 'usr_platform_admin', 'ADMIN');
  await seededUser(server, 'usr_platform_reviewer', 'ADMIN');
  const adminCookie = sessionCookieFrom((await login(server, 'usr_platform_admin@example.test', PW)).res);
  const reviewerCookie = sessionCookieFrom((await login(server, 'usr_platform_reviewer@example.test', PW)).res);
  const memberReg = await register(server, 'member@example.test', PW);
  const memberCookie = sessionCookieFrom(memberReg.res);
  return { server, adminCookie, reviewerCookie, memberCookie, memberEmail: 'member@example.test' };
}

async function jsonData<T>(response: Response): Promise<T> {
  const body = await readJson(response) as { data: T };
  return body.data;
}

async function adminConfig(server: TestServer, cookie: string): Promise<{ status: number; data?: AdminConfig }> {
  const res = await fetch(`${server.baseUrl}/api/v1/admin/payment-config`, { headers: { cookie } });
  if (res.status !== 200) return { status: res.status };
  return { status: 200, data: await jsonData<AdminConfig>(res) };
}

async function userConfig(server: TestServer, cookie: string): Promise<UserConfig> {
  const res = await fetch(`${server.baseUrl}/api/v1/payments/config`, { headers: { cookie } });
  expect(res.status).toBe(200);
  return jsonData<UserConfig>(res);
}

async function patchPrice(server: TestServer, cookie: string, body: unknown, origin?: string): Promise<Response> {
  return fetch(`${server.baseUrl}/api/v1/admin/payment-config`, {
    method: 'PATCH',
    headers: { cookie, 'content-type': 'application/json', ...(origin === undefined ? {} : { origin }) },
    body: JSON.stringify(body),
  });
}

async function addMethod(server: TestServer, cookie: string, body: unknown, key?: string): Promise<Response> {
  return fetch(`${server.baseUrl}/api/v1/admin/payment-config/methods`, {
    method: 'POST',
    headers: { cookie, 'content-type': 'application/json', ...(key === undefined ? {} : { 'idempotency-key': key }) },
    body: JSON.stringify(body),
  });
}

async function patchMethod(server: TestServer, cookie: string, methodId: string, body: unknown): Promise<Response> {
  return fetch(`${server.baseUrl}/api/v1/admin/payment-config/methods/${methodId}`, {
    method: 'PATCH',
    headers: { cookie, 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

async function cancelPayment(server: TestServer, cookie: string, paymentId: string): Promise<void> {
  const res = await fetch(`${server.baseUrl}/api/v1/payments/${paymentId}/cancel`, { method: 'POST', headers: { cookie } });
  expect(res.status).toBe(200);
}

async function createPayment(server: TestServer, cookie: string, amount: number, key: string): Promise<Response> {
  return fetch(`${server.baseUrl}/api/v1/payments`, {
    method: 'POST',
    headers: { cookie, 'content-type': 'application/json', 'idempotency-key': key },
    body: JSON.stringify({ plan: 'PRO', amountMinorUnits: amount, currency: 'BDT', paymentMethod: 'MANUAL_TRANSFER', reference: `CFG${key.replace(/[^A-Za-z0-9]/g, '').slice(0, 24).toUpperCase()}` }),
  });
}

describe('Phase 20 admin payment configuration — authorization matrix', () => {
  test('only the dual-gated platform admin can read or mutate; everyone else is rejected', async () => {
    const { server, adminCookie, reviewerCookie, memberCookie } = await setup();
    const partnerReg = await register(server, 'partner-user@example.test', PW);
    const partnerCookie = sessionCookieFrom(partnerReg.res);

    expect((await fetch(`${server.baseUrl}/api/v1/admin/payment-config`)).status).toBe(401);
    expect((await adminConfig(server, memberCookie)).status).toBe(403);
    expect((await adminConfig(server, partnerCookie)).status).toBe(403);
    // Payment reviewer holds ADMIN role but is NOT in the platform-admin allowlist.
    expect((await adminConfig(server, reviewerCookie)).status).toBe(403);

    for (const cookie of [memberCookie, partnerCookie, reviewerCookie]) {
      expect((await patchPrice(server, cookie, { proPriceMinorUnits: 120_000 })).status).toBe(403);
      expect((await addMethod(server, cookie, { displayName: 'X', accountNumber: '0170000000' }, 'key-abcdefgh')).status).toBe(403);
    }
    // Admin-role user without the allowlist cannot mutate either (fail closed).
    await seededUser(server, 'usr_admin_no_allowlist', 'ADMIN');
    const bareAdmin = sessionCookieFrom((await login(server, 'usr_admin_no_allowlist@example.test', PW)).res);
    expect((await adminConfig(server, bareAdmin)).status).toBe(403);
    expect((await patchPrice(server, bareAdmin, { proPriceMinorUnits: 120_000 })).status).toBe(403);

    expect((await adminConfig(server, adminCookie)).status).toBe(200);
  });

  test('CSRF origin guard and query tampering are rejected on the mutation surface', async () => {
    const { server, adminCookie } = await setup();
    expect((await patchPrice(server, adminCookie, { proPriceMinorUnits: 120_000 }, 'https://evil.example')).status).toBe(403);
    expect((await fetch(`${server.baseUrl}/api/v1/admin/payment-config?proPriceMinorUnits=1`, {
      method: 'PATCH', headers: { cookie: adminCookie, 'content-type': 'application/json' },
      body: JSON.stringify({ proPriceMinorUnits: 120_000 }),
    })).status).toBe(422);
    expect((await fetch(`${server.baseUrl}/api/v1/admin/payment-config?x=1&x=2`, { headers: { cookie: adminCookie } })).status).toBe(422);
    // Nothing changed.
    expect((await adminConfig(server, adminCookie)).data?.proPriceMinorUnits).toBe(PRICE);
  });
});

describe('Phase 20 admin payment configuration — price management', () => {
  test('price bounds and closed schema are enforced', async () => {
    const { server, adminCookie } = await setup();
    for (const bad of [0, -5, 100_000_001, 99.5, '120000', null]) {
      expect((await patchPrice(server, adminCookie, { proPriceMinorUnits: bad })).status).toBe(422);
    }
    expect((await patchPrice(server, adminCookie, { proPriceMinorUnits: 120_000, extra: true })).status).toBe(422);
    expect((await patchPrice(server, adminCookie, {})).status).toBe(422);
    expect((await patchPrice(server, adminCookie, 'nope')).status).toBe(422);
    expect((await adminConfig(server, adminCookie)).data?.proPriceMinorUnits).toBe(PRICE);
  });

  test('admin price change reflects live in the user payment interface and quote (server authority)', async () => {
    const { server, adminCookie, memberCookie } = await setup();
    expect((await userConfig(server, memberCookie)).proPriceMinorUnits).toBe(PRICE);

    const patched = await patchPrice(server, adminCookie, { proPriceMinorUnits: 135_000 });
    expect(patched.status).toBe(200);

    // User reloads → sees the NEW authoritative price immediately (no cache).
    expect((await userConfig(server, memberCookie)).proPriceMinorUnits).toBe(135_000);
    const quote = await jsonData<{ baseAmountMinorUnits: number }>(
      await fetch(`${server.baseUrl}/api/v1/payments/quote`, { headers: { cookie: memberCookie } }),
    );
    expect(quote.baseAmountMinorUnits).toBe(135_000);

    // A client quoting the OLD price is rejected; the NEW price is accepted.
    expect((await createPayment(server, memberCookie, PRICE, 'old-price-key-01')).status).toBe(422);
    expect((await createPayment(server, memberCookie, 135_000, 'new-price-key-01')).status).toBe(201);
  });
});

describe('Phase 20 admin payment configuration — destination management', () => {
  test('add / duplicate / replay / validation behavior', async () => {
    const { server, adminCookie } = await setup();
    // Missing or malformed idempotency key rejected.
    expect((await addMethod(server, adminCookie, { displayName: 'bKash', accountNumber: '01711111111' })).status).toBe(422);
    expect((await addMethod(server, adminCookie, { displayName: 'bKash', accountNumber: '01711111111' }, 'short')).status).toBe(422);
    // Closed schema.
    expect((await addMethod(server, adminCookie, { displayName: 'bKash', accountNumber: '01711111111', enabled: false }, 'key-add-0001')).status).toBe(422);
    expect((await addMethod(server, adminCookie, { displayName: '   ', accountNumber: '01711111111' }, 'key-add-0002')).status).toBe(422);
    expect((await addMethod(server, adminCookie, { displayName: 'bKash', accountNumber: '017' }, 'key-add-0003')).status).toBe(422);

    const created = await addMethod(server, adminCookie, { displayName: 'bKash', accountNumber: '01711111111', instructions: 'Send within 24h' }, 'key-add-0010');
    expect(created.status).toBe(201);
    const made = await jsonData<{ destination: { methodId: string; displayName: string; enabled: boolean } }>(created);
    expect(made.destination.methodId).toMatch(/^pmd_/);
    expect(made.destination).toMatchObject({ displayName: 'bKash', enabled: true });

    // Replay with the same key is safe and returns the SAME destination (no duplicate).
    const replay = await addMethod(server, adminCookie, { displayName: 'bKash', accountNumber: '01711111111', instructions: 'Send within 24h' }, 'key-add-0010');
    expect(replay.status).toBe(200);
    expect((await jsonData<{ destination: { methodId: string } }>(replay)).destination.methodId).toBe(made.destination.methodId);

    // Duplicate display name (case-insensitive) is rejected.
    expect((await addMethod(server, adminCookie, { displayName: 'BKASH', accountNumber: '01999999999' }, 'key-add-0011')).status).toBe(409);
    expect((await adminConfig(server, adminCookie)).data?.destinations.length).toBe(1);
  });

  test('disable removes the method for NEW payments; re-enable restores it; user UI reflects every change', async () => {
    const { server, adminCookie, memberCookie } = await setup();
    const created = await jsonData<{ destination: { methodId: string } }>(
      await addMethod(server, adminCookie, { displayName: 'Nagad', accountNumber: '01822222222' }, 'key-dis-0001'),
    );
    const methodId = created.destination.methodId;

    // Enabled: user sees the destination (account number included — it is where they pay).
    let cfg = await userConfig(server, memberCookie);
    expect(cfg.manualPaymentMethods).toEqual(['MANUAL_TRANSFER']);
    expect(cfg.manualPaymentDestinations.map((d) => d.accountNumber)).toEqual(['01822222222']);
    const firstPayment = await createPayment(server, memberCookie, PRICE, 'dis-key-000001');
    expect(firstPayment.status).toBe(201);
    await cancelPayment(server, memberCookie, (await jsonData<{ payment: { paymentId: string } }>(firstPayment)).payment.paymentId);

    // Admin changes the payment number → user reload sees NEW number (OLD → NEW).
    expect((await patchMethod(server, adminCookie, methodId, { accountNumber: '01833333333' })).status).toBe(200);
    cfg = await userConfig(server, memberCookie);
    expect(cfg.manualPaymentDestinations.map((d) => d.accountNumber)).toEqual(['01833333333']);

    // Disable → method disappears for new payments; creation is refused fail-closed.
    expect((await patchMethod(server, adminCookie, methodId, { enabled: false })).status).toBe(200);
    cfg = await userConfig(server, memberCookie);
    expect(cfg.manualPaymentMethods).toEqual([]);
    expect(cfg.manualPaymentDestinations).toEqual([]);
    expect((await createPayment(server, memberCookie, PRICE, 'dis-key-000002')).status).toBe(422);

    // Re-enable → available again.
    expect((await patchMethod(server, adminCookie, methodId, { enabled: true })).status).toBe(200);
    cfg = await userConfig(server, memberCookie);
    expect(cfg.manualPaymentMethods).toEqual(['MANUAL_TRANSFER']);
    expect(cfg.manualPaymentDestinations.length).toBe(1);
    const restored = await createPayment(server, memberCookie, PRICE, 'dis-key-000003');
    expect(restored.status).toBe(201);
    await cancelPayment(server, memberCookie, (await jsonData<{ payment: { paymentId: string } }>(restored)).payment.paymentId);
  });

  test('destination patch validation: unknown id, malformed id, unknown fields, empty patch', async () => {
    const { server, adminCookie } = await setup();
    const created = await jsonData<{ destination: { methodId: string } }>(
      await addMethod(server, adminCookie, { displayName: 'Rocket', accountNumber: '01944444444' }, 'key-patch-001'),
    );
    expect((await patchMethod(server, adminCookie, 'pmd_00000000-0000-0000-0000-000000000000', { enabled: false })).status).toBe(404);
    expect((await patchMethod(server, adminCookie, 'pmd_not-a-uuid', { enabled: false })).status).toBe(404);
    expect((await patchMethod(server, adminCookie, created.destination.methodId, { enabled: false, evil: true })).status).toBe(422);
    expect((await patchMethod(server, adminCookie, created.destination.methodId, {})).status).toBe(422);
    expect((await patchMethod(server, adminCookie, created.destination.methodId, { displayName: '   ' })).status).toBe(422);
    expect((await patchMethod(server, adminCookie, created.destination.methodId, { accountNumber: '12' })).status).toBe(422);
  });

  test('legacy seed mode: no destinations configured keeps the pre-Phase-20 behavior', async () => {
    const { server, memberCookie } = await setup();
    const cfg = await userConfig(server, memberCookie);
    expect(cfg.manualPaymentMethods).toEqual(['MANUAL_TRANSFER']);
    expect(cfg.manualPaymentDestinations).toEqual([]);
    expect((await createPayment(server, memberCookie, PRICE, 'legacy-key-001')).status).toBe(201);
  });
});

describe('Phase 20 admin payment configuration — historical integrity + audit', () => {
  test('configuration changes never rewrite historical payment records', async () => {
    const { server, adminCookie, memberCookie } = await setup();
    const made = await jsonData<{ payment: { paymentId: string; amountMinorUnits: number; paymentMethod: string } }>(
      await createPayment(server, memberCookie, PRICE, 'hist-key-00001'),
    );
    expect(made.payment.amountMinorUnits).toBe(PRICE);

    await patchPrice(server, adminCookie, { proPriceMinorUnits: 200_000 });
    const created = await jsonData<{ destination: { methodId: string } }>(
      await addMethod(server, adminCookie, { displayName: 'bKash', accountNumber: '01755555555' }, 'hist-add-00001'),
    );
    await patchMethod(server, adminCookie, created.destination.methodId, { enabled: false });

    const detail = await jsonData<{ payment: { paymentId: string; amountMinorUnits: number; paymentMethod: string; status: string } }>(
      await fetch(`${server.baseUrl}/api/v1/payments/${made.payment.paymentId}`, { headers: { cookie: memberCookie } }),
    );
    expect(detail.payment).toMatchObject({ paymentId: made.payment.paymentId, amountMinorUnits: PRICE, paymentMethod: 'MANUAL_TRANSFER', status: 'PENDING' });
  });

  test('every change is audited with masked account numbers (never raw)', async () => {
    const { server, adminCookie } = await setup();
    const account = '01719998887';
    await patchPrice(server, adminCookie, { proPriceMinorUnits: 110_000 });
    const created = await jsonData<{ destination: { methodId: string } }>(
      await addMethod(server, adminCookie, { displayName: 'bKash', accountNumber: account }, 'audit-key-0001'),
    );
    await patchMethod(server, adminCookie, created.destination.methodId, { accountNumber: '01717776665', enabled: false });

    const cfg = await adminConfig(server, adminCookie);
    const actions = cfg.data?.audit.map((entry) => entry.action) ?? [];
    expect(actions).toEqual([
      'PAYMENT_CONFIG_PRICE_UPDATED',
      'PAYMENT_CONFIG_METHOD_ADDED',
      'PAYMENT_CONFIG_METHOD_UPDATED',
    ]);
    const serialized = JSON.stringify(cfg.data?.audit);
    expect(serialized).not.toContain(account);
    expect(serialized).not.toContain('01717776665');
    expect(serialized).toContain('****');
    expect(cfg.data?.audit.every((entry) => entry.actorId === 'usr_platform_admin')).toBe(true);
    // Destinations themselves remain readable to the admin (they manage them).
    expect(cfg.data?.destinations[0]?.accountNumber).toBe('01717776665');
  });

  test('concurrent admin updates stay consistent (no corruption, no torn reads)', async () => {
    const dir = makeTempStoreDir('drobon-paycfg-');
    try {
      const server = await startTestServer({
        platformAdminIds: ['usr_platform_admin'],
        paymentConfigStorePath: `${dir}/payment-config.json`,
      });
      servers.push(server);
      await seededUser(server, 'usr_platform_admin', 'ADMIN');
      const adminCookie = sessionCookieFrom((await login(server, 'usr_platform_admin@example.test', PW)).res);

      const prices = [111_000, 112_000, 113_000, 114_000, 115_000, 116_000, 117_000, 118_000];
      const results = await Promise.all(prices.map((price) => patchPrice(server, adminCookie, { proPriceMinorUnits: price })));
      expect(results.map((res) => res.status)).toEqual(prices.map(() => 200));
      const final = await adminConfig(server, adminCookie);
      expect(prices).toContain(final.data?.proPriceMinorUnits);
      expect(final.data?.audit.length).toBe(8);

      const adds = await Promise.all([1, 2, 3, 4, 5].map((n) =>
        addMethod(server, adminCookie, { displayName: `Method ${n}`, accountNumber: `017000000${n}0` }, `conc-key-000${n}x`)));
      expect(adds.map((res) => res.status)).toEqual([201, 201, 201, 201, 201]);
      const after = await adminConfig(server, adminCookie);
      expect(after.data?.destinations.length).toBe(5);
      expect(new Set(after.data?.destinations.map((d) => d.methodId)).size).toBe(5);
    } finally {
      cleanupTempStoreDir(dir);
    }
  });

  test('payment-config store survives restart (durable) and reflects for users', async () => {
    const dir = makeTempStoreDir('drobon-paycfg-');
    const storePath = `${dir}/payment-config.json`;
    try {
      let server = await startTestServer({ platformAdminIds: ['usr_platform_admin'], paymentConfigStorePath: storePath });
      servers.push(server);
      await seededUser(server, 'usr_platform_admin', 'ADMIN');
      const adminCookie = sessionCookieFrom((await login(server, 'usr_platform_admin@example.test', PW)).res);
      await patchPrice(server, adminCookie, { proPriceMinorUnits: 145_000 });
      await addMethod(server, adminCookie, { displayName: 'Bank', accountNumber: '1234567890' }, 'dur-key-000001');
      await servers.pop()?.stop();

      server = await startTestServer({ platformAdminIds: ['usr_platform_admin'], paymentConfigStorePath: storePath });
      servers.push(server);
      await seededUser(server, 'usr_platform_admin', 'ADMIN');
      const memberReg = await register(server, 'dur-member@example.test', PW);
      const memberCookie = sessionCookieFrom(memberReg.res);
      const cfg = await userConfig(server, memberCookie);
      expect(cfg.proPriceMinorUnits).toBe(145_000);
      expect(cfg.manualPaymentDestinations.map((d) => d.displayName)).toEqual(['Bank']);
    } finally {
      cleanupTempStoreDir(dir);
    }
  });
});
