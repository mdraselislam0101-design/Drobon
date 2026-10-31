import { spawn } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { describe, expect, test } from 'vitest';
import type { UserRecord, UserRepository } from '../src/auth/repositories.js';
import { createJsonFileUserRepository } from '../src/auth/jsonFileUserRepository.js';
import { createJsonFilePartnerStore, type PartnerRecord, type PartnerStore } from '../src/partners/store.js';
import { createPartnerService } from '../src/partners/service.js';
import { createJsonFilePaymentStore, createMemoryPaymentStore, type PaymentRecord } from '../src/payments/store.js';
import { createMemoryPaymentConfigStore } from '../src/payments/configStore.js';
import { createPaymentService } from '../src/payments/service.js';
import { createAccountMutationLock } from '../src/auth/accountMutationLock.js';
import { loadConfig } from '../src/config.js';
import { hashPassword } from '../src/auth/passwords.js';
import { login } from './authFixtures.js';
import { sessionCookieFrom, startTestServer } from './helpers.js';

const stamp = '2026-10-31T00:00:00.000Z';
const now = () => Date.parse(stamp);
const input = { userId: 'usr_partner_recovery', couponCode: 'FIXTURE-RECOVERY', discountPercent: 10, commissionPercent: 5 };
const account: UserRecord = {
  id: input.userId, email: 'partner-recovery@example.test', passwordHash: 'scrypt$fixture',
  createdAt: '2026-01-01T00:00:00.000Z', role: 'MEMBER', userType: null,
  subscription: { plan: 'FREE', status: 'ACTIVE', createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z' },
};

async function setup(dir: string, user: UserRecord = account) {
  const userPath = join(dir, 'users.json');
  const partnerPath = join(dir, 'partners.json');
  const users = createJsonFileUserRepository(userPath);
  await users.create(user);
  const store = createJsonFilePartnerStore(partnerPath);
  const payments = createMemoryPaymentStore();
  const service = createPartnerService({ store, users, payments, now });
  return { userPath, partnerPath, users, store, payments, service };
}

function reopened(userPath: string, partnerPath: string) {
  const users = createJsonFileUserRepository(userPath);
  const store = createJsonFilePartnerStore(partnerPath);
  const payments = createMemoryPaymentStore();
  return { users, store, payments, service: createPartnerService({ store, users, payments, now }) };
}

async function withDir(run: (dir: string) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), 'drobon-partner-recovery-'));
  try { await run(dir); } finally { rmSync(dir, { recursive: true, force: true }); }
}

describe('partner activation: durable intent, compensation and recovery', () => {
  test('partner-store write failure grants nothing; matching retry is idempotent', () => withDir(async (dir) => {
    const { users, store, service, partnerPath, payments } = await setup(dir);
    mkdirSync(partnerPath); // fail atomic rename into a directory
    await expect(service.activatePartner('usr_admin', input)).rejects.toThrow();
    expect((await users.findById(input.userId))?.subscription?.plan).toBe('FREE');
    expect(store.getPartnerByUserId(input.userId)).toBeUndefined();
    expect(service.resolveCoupon(input.couponCode).ok).toBe(false);
    rmSync(partnerPath, { recursive: true });
    const first = await service.activatePartner('usr_admin', input);
    const replay = await service.activatePartner('usr_admin', input);
    expect(replay.partner.partnerId).toBe(first.partner.partnerId);
    expect((await users.findById(input.userId))?.subscription).toMatchObject({ plan: 'PRO', status: 'ACTIVE' });
    expect(service.resolveCoupon(input.couponCode).ok).toBe(true);
    expect(payments.listAll()).toHaveLength(0);
  }));

  test('account write failure persists only an inactive intent; restart and matching retry succeed', () => withDir(async (dir) => {
    const { users, store, payments, userPath, partnerPath } = await setup(dir);
    const failing: UserRepository = { ...users, activatePro: async () => { throw new Error('synthetic account write failure'); } };
    const service = createPartnerService({ store, users: failing, payments, now });
    await expect(service.activatePartner('usr_admin', input)).rejects.toThrow('synthetic account write failure');
    expect((await users.findById(input.userId))?.subscription?.plan).toBe('FREE');
    expect(store.getPartnerByUserId(input.userId)).toMatchObject({ status: 'DEACTIVATED', activationPending: { initiatedAt: stamp } });
    expect(service.resolveCoupon(input.couponCode).ok).toBe(false);
    expect(() => service.dashboard(input.userId)).toThrow();
    const reopenedState = reopened(userPath, partnerPath);
    await reopenedState.service.recoverInterruptedActivations();
    expect((await reopenedState.users.findById(input.userId))?.subscription?.plan).toBe('FREE');
    expect(reopenedState.service.listPartners({}, 1, 20).total).toBe(0);
    await reopenedState.service.activatePartner('usr_admin', input);
    expect((await reopenedState.users.findById(input.userId))?.subscription?.plan).toBe('PRO');
    expect(reopenedState.service.resolveCoupon(input.couponCode).ok).toBe(true);
    expect(reopenedState.store.getPartnerByUserId(input.userId)?.audit.at(-1)?.action).toBe('PARTNER_ACTIVATED');
  }));

  test('an account write that throws after committing is compensated, including a legacy absent subscription', () => withDir(async (dir) => {
    const legacy = { ...account }; delete legacy.subscription;
    const { users, store, payments, userPath, partnerPath } = await setup(dir, legacy);
    const failing: UserRepository = { ...users, activatePro: async (id, at) => { await users.activatePro(id, at); throw new Error('after write'); } };
    const service = createPartnerService({ store, users: failing, payments, now });
    await expect(service.activatePartner('usr_admin', input)).rejects.toThrow('after write');
    expect((await createJsonFileUserRepository(userPath).findById(input.userId))?.subscription).toBeUndefined();
    expect(createJsonFilePartnerStore(partnerPath).getPartnerByUserId(input.userId)?.status).toBe('DEACTIVATED');
    expect(service.isConsistencyBlocked()).toBe(false);
  }));

  test('final partner write failure restores FREE but never changes an already-active paid subscription', async () => {
    for (const paid of [false, true]) await withDir(async (dir) => {
      const prior = paid ? { ...account, subscription: { plan: 'PRO' as const, status: 'ACTIVE' as const, createdAt: '2026-02-01T00:00:00.000Z', updatedAt: '2026-02-01T00:00:00.000Z' } } : account;
      const { users, store, payments, userPath, partnerPath } = await setup(dir, prior);
      const failing: PartnerStore = { ...store, finishActivation: async () => { throw new Error('partner final write failed'); } };
      const service = createPartnerService({ store: failing, users, payments, now });
      await expect(service.activatePartner('usr_admin', input)).rejects.toThrow('partner final write failed');
      expect((await createJsonFileUserRepository(userPath).findById(input.userId))?.subscription).toEqual(prior.subscription);
      expect(createJsonFilePartnerStore(partnerPath).getPartnerByUserId(input.userId)).toMatchObject({ status: 'DEACTIVATED', activationPending: expect.any(Object) });
      expect(service.resolveCoupon(input.couponCode).ok).toBe(false);
      const restart = reopened(userPath, partnerPath);
      await restart.service.recoverInterruptedActivations();
      if (paid) {
        expect(restart.service.resolveCoupon(input.couponCode).ok).toBe(true);
        expect((await restart.users.findById(input.userId))?.subscription).toEqual(prior.subscription);
      } else {
        expect(restart.service.resolveCoupon(input.couponCode).ok).toBe(false);
        await restart.service.activatePartner('usr_admin', input);
        expect((await restart.users.findById(input.userId))?.subscription?.plan).toBe('PRO');
      }
    });
  });

  test('uncertain compensation blocks traffic until restart reconciles the durable intent', () => withDir(async (dir) => {
    const { users, store, payments, userPath, partnerPath } = await setup(dir);
    const failingUsers: UserRepository = { ...users, restorePartnerSubscription: async () => { throw new Error('rollback write failed'); } };
    const failingStore: PartnerStore = { ...store, finishActivation: async () => { throw new Error('final write failed'); } };
    const service = createPartnerService({ store: failingStore, users: failingUsers, payments, now });
    await expect(service.activatePartner('usr_admin', input)).rejects.toThrow();
    expect(service.isConsistencyBlocked()).toBe(true);
    expect(service.resolveCoupon(input.couponCode).ok).toBe(false);
    expect((await users.findById(input.userId))?.subscription?.plan).toBe('PRO'); // unresolved on disk; not presented as a clean failure
    const restart = reopened(userPath, partnerPath);
    await restart.service.recoverInterruptedActivations();
    expect(restart.service.isConsistencyBlocked()).toBe(false);
    expect(restart.service.resolveCoupon(input.couponCode).ok).toBe(true);
    expect((await restart.users.findById(input.userId))?.subscription?.plan).toBe('PRO');
  }));

  test('historical active/FREE record is quarantined without rewriting bytes; explicit matching retry repairs it', () => withDir(async (dir) => {
    const { store, service, partnerPath, users } = await setup(dir);
    const legacy: PartnerRecord = {
      partnerId: 'ptr_00000000-0000-4000-8000-000000000001', userId: input.userId, email: account.email,
      status: 'ACTIVE', coupon: { couponCode: input.couponCode, status: 'ACTIVE', discountPercent: 10, commissionPercent: 5, expiresAt: null, createdAt: stamp, updatedAt: stamp },
      complimentaryProGrantedAt: stamp, createdAt: stamp, updatedAt: stamp, deactivatedAt: null, audit: [],
    };
    await store.createPartner(legacy);
    const before = readFileSync(partnerPath, 'utf8');
    await service.recoverInterruptedActivations();
    expect(readFileSync(partnerPath, 'utf8')).toBe(before);
    expect(service.resolveCoupon(input.couponCode).ok).toBe(false);
    expect(() => service.dashboard(input.userId)).toThrow();
    await service.activatePartner('usr_admin', input);
    expect((await users.findById(input.userId))?.subscription?.plan).toBe('PRO');
    expect(service.resolveCoupon(input.couponCode).ok).toBe(true);
  }));
});

describe('partner activation concurrent with payment approval', () => {
  test('a later paid PRO grant must not silently finalize a compensated partner attempt after restart', () => withDir(async (dir) => {
    const { users, store, userPath, partnerPath } = await setup(dir);
    const paymentPath = join(dir, 'payments.json');
    const payments = createJsonFilePaymentStore(paymentPath);
    const payment: PaymentRecord = {
      paymentId: 'pay_00000000-0000-4000-8000-000000000001', accountId: input.userId, submittedByUserId: input.userId,
      plan: 'PRO', amountMinorUnits: 100_000, currency: 'BDT', paymentMethod: 'MANUAL_TRANSFER',
      reference: 'fixture-reference', referenceKey: 'fixture-reference', idempotencyKey: 'fixture-payment-key', status: 'PENDING',
      createdAt: stamp, submittedAt: stamp, updatedAt: stamp, reviewedAt: null, approvedAt: null, rejectedAt: null,
      reviewerId: null, rejectionReason: null,
    };
    await payments.create(payment, []);
    let finishEntered!: () => void; let releaseFinish!: () => void;
    const entered = new Promise<void>((resolve) => { finishEntered = resolve; });
    const finish = new Promise<void>((resolve) => { releaseFinish = resolve; });
    const failingStore: PartnerStore = { ...store, finishActivation: async () => {
      finishEntered(); await finish; throw new Error('synthetic partner final-write failure');
    } };
    const lock = createAccountMutationLock();
    const partners = createPartnerService({ store: failingStore, users, payments, now, withAccountMutation: lock });
    const paymentService = createPaymentService({ config: loadConfig({ NODE_ENV: 'test' }), store: payments, users,
      paymentConfig: createMemoryPaymentConfigStore(100_000), now: () => now() + 60_000, withAccountMutation: lock });
    const activation = partners.activatePartner('usr_admin', input).then(() => 'success', () => 'failed');
    await entered;
    const approval = paymentService.approve(payment.paymentId, 'usr_reviewer');
    await new Promise<void>((resolve) => setImmediate(resolve));
    expect(payments.get(payment.paymentId)?.status).toBe('APPROVING');
    expect((await users.findById(input.userId))?.subscription?.createdAt).toBe(stamp);
    releaseFinish();
    expect(await activation).toBe('failed');
    expect((await approval).status).toBe('APPROVED');
    const paid = (await users.findById(input.userId))?.subscription;
    expect(paid?.createdAt).toBe('2026-10-31T00:01:00.000Z');
    const partnerBytes = readFileSync(partnerPath, 'utf8');
    const restart = reopened(userPath, partnerPath);
    await restart.service.recoverInterruptedActivations();
    await restart.service.recoverInterruptedActivations();
    expect(restart.service.resolveCoupon(input.couponCode).ok).toBe(false);
    expect(readFileSync(partnerPath, 'utf8')).toBe(partnerBytes);
    expect((await restart.users.findById(input.userId))?.subscription).toEqual(paid);
    expect(createJsonFilePaymentStore(paymentPath).get(payment.paymentId)?.status).toBe('APPROVED');
    await restart.service.activatePartner('usr_admin', input); // explicit matching retry
    expect(restart.service.resolveCoupon(input.couponCode).ok).toBe(true);
    expect((await restart.users.findById(input.userId))?.subscription).toEqual(paid);
  }));
});

describe('partner activation: uncertain final-write inspection', () => {
  test.each([false, true])('unreadable verification after final-write failure (committed=%s) blocks until restart', (committed) => withDir(async (dir) => {
    const { users, store, payments, userPath, partnerPath } = await setup(dir);
    const failing: PartnerStore = { ...store,
      finishActivation: async (...args) => {
        if (committed) await store.finishActivation(...args);
        throw new Error('synthetic final-write uncertainty');
      },
      getPartnerById: () => { throw new Error('synthetic read failure'); },
    };
    const service = createPartnerService({ store: failing, users, payments, now });
    await expect(service.activatePartner('usr_admin', input)).rejects.toMatchObject({ statusCode: 503 });
    expect(service.isConsistencyBlocked()).toBe(true);
    expect((await users.findById(input.userId))?.subscription?.plan).toBe('PRO');
    const restarted = reopened(userPath, partnerPath);
    await restarted.service.recoverInterruptedActivations();
    expect(restarted.service.isConsistencyBlocked()).toBe(false);
    expect(restarted.service.resolveCoupon(input.couponCode).ok).toBe(true);
    expect((await restarted.users.findById(input.userId))?.subscription?.plan).toBe('PRO');
  }));
});

describe('partner activation: HTTP traffic gate', () => {
  const pw = 'partner-recovery-fixture-password';
  const adminId = 'usr_partner_recovery_admin';

  async function seeded(dir: string) {
    const passwordHash = await hashPassword(pw, 1024);
    const initial = await setup(dir, { ...account, passwordHash });
    await initial.users.create({ ...account, id: adminId, email: 'partner-admin@example.test', passwordHash, role: 'ADMIN' });
    return initial;
  }

  test('unreadable final-write verification returns 503 and keeps HTTP traffic blocked until restart', () => withDir(async (dir) => {
    const initial = await seeded(dir);
    const failingStore: PartnerStore = { ...initial.store,
      finishActivation: async () => { throw new Error('synthetic final-write failure'); },
      getPartnerById: () => { throw new Error('synthetic read failure'); },
    };
    const server = await startTestServer({ users: initial.users, partnerStore: failingStore, platformAdminIds: [adminId], partnerNow: now });
    try {
      const admin = sessionCookieFrom((await login(server, 'partner-admin@example.test', pw)).res);
      const response = await fetch(`${server.baseUrl}/api/v1/admin/partners`, {
        method: 'POST', headers: { cookie: admin, 'content-type': 'application/json' }, body: JSON.stringify(input),
      });
      expect(response.status).toBe(503);
      expect((await fetch(`${server.baseUrl}/readyz`)).status).toBe(503);
      expect((await fetch(`${server.baseUrl}/api/v1/subscription`)).status).toBe(503);
    } finally { await server.stop(); }
    const state = reopened(initial.userPath, initial.partnerPath);
    const restart = await startTestServer({ users: state.users, partnerStore: state.store, partnerNow: now });
    try {
      expect((await fetch(`${restart.baseUrl}/readyz`)).status).toBe(200);
      expect(state.store.getPartnerByUserId(input.userId)?.status).toBe('ACTIVE');
      expect((await state.users.findById(input.userId))?.subscription?.plan).toBe('PRO');
    } finally { await restart.stop(); }
  }));

  test('failed compensation returns 503 and blocks traffic until startup recovery', () => withDir(async (dir) => {
    const initial = await seeded(dir);
    const failingUsers: UserRepository = { ...initial.users, restorePartnerSubscription: async () => { throw new Error('synthetic rollback failure'); } };
    const failingStore: PartnerStore = { ...initial.store, finishActivation: async () => { throw new Error('synthetic final write failure'); } };
    const server = await startTestServer({ users: failingUsers, partnerStore: failingStore, platformAdminIds: [adminId], partnerNow: now });
    try {
      const admin = sessionCookieFrom((await login(server, 'partner-admin@example.test', pw)).res);
      const response = await fetch(`${server.baseUrl}/api/v1/admin/partners`, {
        method: 'POST', headers: { cookie: admin, 'content-type': 'application/json' }, body: JSON.stringify(input),
      });
      expect(response.status).toBe(503);
      expect((await fetch(`${server.baseUrl}/readyz`)).status).toBe(503);
      expect((await fetch(`${server.baseUrl}/api/v1/subscription`)).status).toBe(503);
    } finally { await server.stop(); }
    const state = reopened(initial.userPath, initial.partnerPath);
    const restart = await startTestServer({ users: state.users, partnerStore: state.store, partnerNow: now });
    try {
      expect((await fetch(`${restart.baseUrl}/readyz`)).status).toBe(200);
      expect(state.store.getPartnerByUserId(input.userId)?.status).toBe('ACTIVE');
      expect((await state.users.findById(input.userId))?.subscription?.plan).toBe('PRO');
    } finally { await restart.stop(); }
  }));

  test('an already-in-flight session read cannot observe the temporary account PRO state', () => withDir(async (dir) => {
    const initial = await seeded(dir);
    let releaseRead!: () => void; let readEntered!: () => void;
    let releaseFinish!: () => void; let finishEntered!: () => void;
    const readWait = new Promise<void>((resolve) => { releaseRead = resolve; });
    const readStarted = new Promise<void>((resolve) => { readEntered = resolve; });
    const finishWait = new Promise<void>((resolve) => { releaseFinish = resolve; });
    const finishStarted = new Promise<void>((resolve) => { finishEntered = resolve; });
    let delayOneRead = false;
    const users: UserRepository = { ...initial.users, findById: async (id) => {
      if (id === input.userId && delayOneRead) { delayOneRead = false; readEntered(); await readWait; }
      return initial.users.findById(id);
    } };
    const store: PartnerStore = { ...initial.store, finishActivation: async (...args) => {
      finishEntered(); await finishWait; return initial.store.finishActivation(...args);
    } };
    const server = await startTestServer({ users, partnerStore: store, platformAdminIds: [adminId], partnerNow: now });
    try {
      const admin = sessionCookieFrom((await login(server, 'partner-admin@example.test', pw)).res);
      const victim = sessionCookieFrom((await login(server, account.email, pw)).res);
      delayOneRead = true;
      const read = fetch(`${server.baseUrl}/api/v1/subscription`, { headers: { cookie: victim } });
      await readStarted;
      const activation = fetch(`${server.baseUrl}/api/v1/admin/partners`, {
        method: 'POST', headers: { cookie: admin, 'content-type': 'application/json' }, body: JSON.stringify(input),
      });
      await finishStarted;
      expect((await initial.users.findById(input.userId))?.subscription?.plan).toBe('PRO');
      releaseRead();
      expect((await read).status).toBe(503);
      expect((await fetch(`${server.baseUrl}/readyz`)).status).toBe(503);
      releaseFinish();
      expect((await activation).status).toBe(201);
      expect((await fetch(`${server.baseUrl}/api/v1/subscription`, { headers: { cookie: victim } })).status).toBe(200);
    } finally { releaseRead(); releaseFinish(); await server.stop(); }
  }));
});

async function killAtBoundary(dir: string, phase: 'intent' | 'account'): Promise<void> {
  const userUrl = pathToFileURL(resolve('src/auth/jsonFileUserRepository.ts')).href;
  const storeUrl = pathToFileURL(resolve('src/partners/store.ts')).href;
  const serviceUrl = pathToFileURL(resolve('src/partners/service.ts')).href;
  const paymentUrl = pathToFileURL(resolve('src/payments/store.ts')).href;
  const script = `
    import { createJsonFileUserRepository } from ${JSON.stringify(userUrl)};
    import { createJsonFilePartnerStore } from ${JSON.stringify(storeUrl)};
    import { createPartnerService } from ${JSON.stringify(serviceUrl)};
    import { createMemoryPaymentStore } from ${JSON.stringify(paymentUrl)};
    const users = createJsonFileUserRepository(${JSON.stringify(join(dir, 'users.json'))});
    const base = createJsonFilePartnerStore(${JSON.stringify(join(dir, 'partners.json'))});
    const pause = () => new Promise(() => { console.log('PARTNER_CRASH_POINT'); setInterval(() => {}, 1000); });
    const store = { ...base,
      createPartner: async (...args) => { const result = await base.createPartner(...args); if (${JSON.stringify(phase)} === 'intent') await pause(); return result; },
      finishActivation: async (...args) => { if (${JSON.stringify(phase)} === 'account') await pause(); return base.finishActivation(...args); },
    };
    await createPartnerService({ store, users, payments: createMemoryPaymentStore(), now: () => ${now()} }).activatePartner('usr_admin', ${JSON.stringify(input)});
  `;
  await new Promise<void>((resolvePromise, reject) => {
    const child = spawn(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', script], { cwd: process.cwd(), stdio: ['ignore', 'pipe', 'pipe'] });
    let output = ''; let stderr = ''; let killed = false;
    const timeout = setTimeout(() => { child.kill('SIGKILL'); reject(new Error(`crash point not reached: ${stderr}`)); }, 15_000);
    child.stdout.on('data', (chunk: Buffer) => { output += chunk.toString(); if (!killed && output.includes('PARTNER_CRASH_POINT')) { killed = true; child.kill('SIGKILL'); } });
    child.stderr.on('data', (chunk: Buffer) => { stderr += chunk.toString(); });
    child.on('error', (error) => { clearTimeout(timeout); reject(error); });
    child.on('exit', (_code, signal) => { clearTimeout(timeout); if (killed && signal === 'SIGKILL') resolvePromise(); else reject(new Error(`unexpected child exit ${String(signal)}: ${stderr}`)); });
  });
}

describe('partner activation: real process termination', () => {
  test.each(['intent', 'account'] as const)('SIGKILL after %s write is recovered before service use', async (phase) => {
    await withDir(async (dir) => {
      const { userPath, partnerPath } = await setup(dir);
      await killAtBoundary(dir, phase);
      const restart = reopened(userPath, partnerPath);
      expect(restart.store.getPartnerByUserId(input.userId)?.status).toBe('DEACTIVATED');
      expect((await restart.users.findById(input.userId))?.subscription?.plan).toBe(phase === 'account' ? 'PRO' : 'FREE');
      await restart.service.recoverInterruptedActivations();
      await restart.service.recoverInterruptedActivations();
      if (phase === 'intent') {
        expect(restart.service.resolveCoupon(input.couponCode).ok).toBe(false);
        await restart.service.activatePartner('usr_admin', input);
      }
      expect((await restart.users.findById(input.userId))?.subscription?.plan).toBe('PRO');
      expect(restart.service.resolveCoupon(input.couponCode).ok).toBe(true);
      expect(restart.store.getPartnerByUserId(input.userId)?.activationPending).toBeUndefined();
    });
  }, 20_000);
});
