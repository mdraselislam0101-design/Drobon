import { mkdirSync, mkdtempSync, readFileSync, readdirSync, renameSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, test } from 'vitest';
import type { AdminProGrant } from '@drobon/shared';
import { createJsonFileProjectStore } from '../src/projects/store.js';
import { createJsonFilePaymentStore, type PaymentRecord } from '../src/payments/store.js';
import { createJsonFilePaymentConfigStore } from '../src/payments/configStore.js';
import { createJsonFileEntitlementStore } from '../src/entitlements/store.js';
import { createJsonFileAssessmentStore } from '../src/assessments/store.js';

const at = '2026-10-31T00:00:00.000Z';
const owner = 'usr_synthetic_owner';
const projectId = 'prj_00000000-0000-4000-8000-000000000001';
const id = (n: number): string => `00000000-0000-4000-8000-00000000000${n}`;

interface Fixture {
  mutate(n: number): Promise<unknown>;
  snapshot(): Promise<unknown>;
}
const fixtures: Record<string, (path: string) => Fixture> = {
  projects: (path) => {
    const store = createJsonFileProjectStore(path);
    return { mutate: (n) => store.create({ ownerId: owner, name: `Fixture ${n}`, description: '' }), snapshot: () => store.listByOwner(owner) };
  },
  payments: (path) => {
    const store = createJsonFilePaymentStore(path);
    const payment = (n: number): PaymentRecord => ({
      paymentId: `pay_${id(n)}`, accountId: `${owner}_${n}`, submittedByUserId: owner, plan: 'PRO',
      amountMinorUnits: 100, currency: 'BDT', paymentMethod: 'MANUAL_TRANSFER',
      reference: `fixture-reference-${n}`, referenceKey: `fixture-reference-${n}`, idempotencyKey: `fixture-key-${n}`,
      status: 'PENDING', createdAt: at, submittedAt: at, updatedAt: at,
      reviewedAt: null, approvedAt: null, rejectedAt: null, reviewerId: null, rejectionReason: null,
    });
    return { mutate: (n) => store.create(payment(n), []), snapshot: async () => store.listAll() };
  },
  paymentConfig: (path) => {
    const store = createJsonFilePaymentConfigStore(path, 100);
    return { mutate: (n) => store.setPrice(owner, 100 + n, at), snapshot: async () => store.current() };
  },
  entitlements: (path) => {
    const store = createJsonFileEntitlementStore(path);
    const grant = (n: number): AdminProGrant => ({
      grantId: `apg_${id(n)}`, accountId: `${owner}_${n}`, source: 'ADMIN_GRANT', plan: 'PRO', status: 'ACTIVE',
      paymentRequired: false, grantedBy: owner, grantedAt: at, expiresAt: null, revokedAt: null,
      revokedBy: null, reason: null, updatedAt: at,
    });
    return { mutate: (n) => store.createGrant(grant(n), [], Date.parse(at)), snapshot: async () => store.list({}, 1, 20) };
  },
  assessments: (path) => {
    const store = createJsonFileAssessmentStore(path);
    return { mutate: (n) => store.create({ ownerId: owner, projectId, title: `Fixture ${n}`, objectives: ['Review'],
      scope: { inScopeHosts: ['app.example.org'], outOfScopeHosts: [] }, now: at }), snapshot: () => store.listByProject(owner, projectId) };
  },
};

describe('ordinary rename failure across legacy JSON writers', () => {
  test.each(Object.entries(fixtures))('%s: preserves data and unrelated temp files, then survives retry and restart', async (_name, open) => {
    const dir = mkdtempSync(join(tmpdir(), 'drobon-json-failure-'));
    const path = join(dir, 'store.json');
    const backup = join(dir, 'saved.json');
    try {
      const store = open(path);
      await store.mutate(1);
      const before = await store.snapshot();
      const bytes = readFileSync(path, 'utf8');
      writeFileSync(join(dir, 'existing.tmp'), 'unrelated synthetic data');
      renameSync(path, backup);
      mkdirSync(path); // Force the real same-directory rename to fail after writing the temp file.
      await expect(store.mutate(2)).rejects.toThrow();
      expect(await store.snapshot()).toEqual(before);
      expect(readFileSync(backup, 'utf8')).toBe(bytes);
      expect(readdirSync(dir).filter((name) => name.endsWith('.tmp'))).toEqual(['existing.tmp']);
      expect(readFileSync(join(dir, 'existing.tmp'), 'utf8')).toBe('unrelated synthetic data');
      rmSync(path, { recursive: true });
      renameSync(backup, path);
      expect(await open(path).snapshot()).toEqual(before);
      await store.mutate(2);
      expect(await open(path).snapshot()).toEqual(await store.snapshot());
      expect(statSync(path).mode & 0o777).toBe(0o600);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
});
