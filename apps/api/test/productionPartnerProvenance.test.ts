import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, test } from 'vitest';
import { createAccountMutationLock } from '../src/auth/accountMutationLock.js';
import { createJsonFileUserRepository } from '../src/auth/jsonFileUserRepository.js';
import type { UserRecord } from '../src/auth/repositories.js';
import { loadConfig } from '../src/config.js';
import { createMemoryPaymentConfigStore } from '../src/payments/configStore.js';
import { createPaymentService } from '../src/payments/service.js';
import { createJsonFilePaymentStore, type PaymentRecord, type PaymentStore } from '../src/payments/store.js';
import { createPartnerService } from '../src/partners/service.js';
import { createJsonFilePartnerStore, type PartnerStore } from '../src/partners/store.js';

// Disposable synthetic records only. No real payment, historical store, or account is touched.
const AT = '2026-10-31T00:00:00.000Z';
const now = () => Date.parse(AT);
const input = { userId: 'usr_partner_provenance_fixture', couponCode: 'FIXTURE-PROVENANCE', discountPercent: 10, commissionPercent: 5 };
const account: UserRecord = { id: input.userId, email: 'provenance@example.test', passwordHash: 'scrypt$fixture', role: 'MEMBER', userType: null,
  createdAt: '2026-01-01T00:00:00.000Z', subscription: { plan: 'FREE', status: 'ACTIVE', createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z' } };
const payment: PaymentRecord = {
  paymentId: 'pay_00000000-0000-4000-8000-000000000001', accountId: input.userId, submittedByUserId: input.userId,
  plan: 'PRO', amountMinorUnits: 100_000, currency: 'BDT', paymentMethod: 'MANUAL_TRANSFER',
  reference: 'synthetic-fixture', referenceKey: 'synthetic-fixture', idempotencyKey: 'synthetic-provenance-key', status: 'PENDING',
  createdAt: AT, submittedAt: AT, updatedAt: AT, reviewedAt: null, approvedAt: null, rejectedAt: null, reviewerId: null, rejectionReason: null,
};

describe('same-millisecond partner/payment recovery provenance', () => {
  test.each(['APPROVED', 'APPROVING'] as const)('a later %s payment cannot be mistaken for the interrupted partner grant', async (status) => {
    const dir = mkdtempSync(join(tmpdir(), 'drobon-provenance-fixture-'));
    try {
      const userPath = join(dir, 'users.json');
      const partnerPath = join(dir, 'partners.json');
      const paymentPath = join(dir, 'payments.json');
      const users = createJsonFileUserRepository(userPath);
      await users.create(account);
      const partners = createJsonFilePartnerStore(partnerPath);
      const payments = createJsonFilePaymentStore(paymentPath);
      await payments.create(payment, []);
      const lock = createAccountMutationLock();
      const failingPartner: PartnerStore = { ...partners, finishActivation: async () => { throw new Error('synthetic final-write failure'); } };
      const partnerService = createPartnerService({ store: failingPartner, users, payments, now, withAccountMutation: lock });
      await expect(partnerService.activatePartner('usr_admin', input)).rejects.toThrow('synthetic final-write failure');
      expect((await users.findById(input.userId))?.subscription?.plan).toBe('FREE');
      const paymentStore: PaymentStore = status === 'APPROVING' ? { ...payments, finishApproval: async () => { throw new Error('synthetic payment final-write failure'); } } : payments;
      const paymentService = createPaymentService({ config: loadConfig({ NODE_ENV: 'test' }), store: paymentStore, users,
        paymentConfig: createMemoryPaymentConfigStore(100_000), now, withAccountMutation: lock });
      if (status === 'APPROVED') expect((await paymentService.approve(payment.paymentId, 'usr_reviewer')).status).toBe('APPROVED');
      else await expect(paymentService.approve(payment.paymentId, 'usr_reviewer')).rejects.toThrow('synthetic payment final-write failure');
      expect(payments.get(payment.paymentId)?.status).toBe(status);
      const paid = (await users.findById(input.userId))?.subscription;
      expect(paid).toMatchObject({ plan: 'PRO', status: 'ACTIVE', createdAt: AT, updatedAt: AT });
      const before = { users: readFileSync(userPath, 'utf8'), partners: readFileSync(partnerPath, 'utf8'), payments: readFileSync(paymentPath, 'utf8') };
      const restartedUsers = createJsonFileUserRepository(userPath);
      const restartedPartners = createJsonFilePartnerStore(partnerPath);
      const restartedPayments = createJsonFilePaymentStore(paymentPath);
      const restarted = createPartnerService({ store: restartedPartners, users: restartedUsers, payments: restartedPayments, now });
      await restarted.recoverInterruptedActivations();
      await restarted.recoverInterruptedActivations();
      expect(restarted.resolveCoupon(input.couponCode).ok).toBe(false);
      expect(readFileSync(userPath, 'utf8')).toBe(before.users);
      expect(readFileSync(partnerPath, 'utf8')).toBe(before.partners);
      expect(readFileSync(paymentPath, 'utf8')).toBe(before.payments);
      expect((await restartedUsers.findById(input.userId))?.subscription).toEqual(paid);
      await restarted.activatePartner('usr_admin', input); // explicit, matching operator retry
      expect(restarted.resolveCoupon(input.couponCode).ok).toBe(true);
      expect((await restartedUsers.findById(input.userId))?.subscription).toEqual(paid);
      expect(restartedPayments.get(payment.paymentId)?.status).toBe(status);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
});
