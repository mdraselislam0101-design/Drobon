import { describe, expect, test } from 'vitest';
import {
  isAdminAccountsResponse,
  isAdminAuditResponse,
  isAdminDashboardResponse,
  isAdminFindingsResponse,
  isAdminScansResponse,
  type AdminDashboardResponse,
} from '../src/admin.js';

const dashboard: AdminDashboardResponse = {
  asOf: '2026-09-29T12:00:00.000Z',
  accounts: { state: 'AVAILABLE', total: 0, free: 0, pro: 0, subscriptionByStatus: { ACTIVE: 0, INACTIVE: 0, CANCELLED: 0, EXPIRED: 0 } },
  projects: { state: 'AVAILABLE', total: 0, active: 0, archived: 0 },
  scans: { state: 'AVAILABLE', total: 0, byStatus: { QUEUED: 0, RUNNING: 0, COMPLETED: 0, FAILED: 0, TIMED_OUT: 0 }, byType: { SAST: 0, SCA: 0, SECRETS: 0, DAST: 0 }, recentlyCompleted: 0 },
  payments: { state: 'AVAILABLE', total: 0, byStatus: { PENDING: 0, UNDER_REVIEW: 0, APPROVING: 0, APPROVED: 0, REJECTED: 0, CANCELLED: 0 }, submittedAmountMinorUnits: 0, approvedAmountMinorUnits: 0, currency: 'BDT' },
  findings: { state: 'AVAILABLE', bySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }, byLifecycleState: { OPEN: 0, ACKNOWLEDGED: 0, IN_PROGRESS: 0, RESOLVED: 0, FALSE_POSITIVE: 0, REOPENED: 0 }, unresolved: 0, dastObservations: 0, scaNotAssessed: 0 },
  system: { api: 'SERVING', web: 'NOT_ASSESSED', accountPersistence: 'EPHEMERAL', paymentPersistence: 'EPHEMERAL', apiAttachedScanProcessor: 'NOT_STARTED', separateWorker: 'NOT_INTEGRATED', assistantFeature: 'DETERMINISTIC_READ_ONLY', aiProvider: 'NONE', paymentGateway: 'UNAVAILABLE', vulnerabilityDataset: 'NO_DATA_LOADED', securityDataset: 'SEPARATE_NOT_LOADED' },
};

describe('Pump 16 admin response guards', () => {
  test('accepts exact dashboard vocabularies and rejects fabricated/secret fields', () => {
    expect(isAdminDashboardResponse(dashboard)).toBe(true);
    expect(isAdminDashboardResponse({ ...dashboard, accounts: { state: 'UNAVAILABLE' } })).toBe(true);
    expect(isAdminDashboardResponse({ ...dashboard, accounts: { state: 'UNAVAILABLE', total: 0 } })).toBe(false);
    expect(isAdminDashboardResponse({ ...dashboard, unrecognizedField: 'synthetic-value' })).toBe(false);
    expect(isAdminDashboardResponse({ ...dashboard, accounts: { ...dashboard.accounts, passwordHash: 'hash' } })).toBe(false);
    expect(isAdminDashboardResponse({ ...dashboard, system: { ...dashboard.system, separateWorker: 'RUNNING' } })).toBe(false);
  });

  test('account, scan, finding, and audit pages reject over-posted sensitive fields', () => {
    const account = { accountId: 'usr_test', email: 'masked@example.test', role: 'MEMBER', userType: null, plan: 'FREE', subscriptionStatus: 'ACTIVE', effectivePlan: 'FREE', proEntitlementSource: null, createdAt: '2026-09-01T00:00:00.000Z', accountStatus: 'UNAVAILABLE', paymentRequestCount: 0, latestPaymentStatus: null };
    expect(isAdminAccountsResponse({ accounts: [account], page: 1, pageSize: 25, total: 1 })).toBe(true);
    expect(isAdminAccountsResponse({ accounts: [{ ...account, passwordHash: 'scrypt$secret' }], page: 1, pageSize: 25, total: 1 })).toBe(false);

    const scan = { scanId: 'scan_00000000-0000-4000-8000-000000000001', projectId: 'prj_11111111-1111-4111-8111-111111111111', accountId: 'usr_test', scanType: 'SAST', status: 'COMPLETED', createdAt: '2026-09-01T00:00:00.000Z', completedAt: '2026-09-01T00:01:00.000Z', findingsTotal: 1 };
    expect(isAdminScansResponse({ scans: [scan], page: 1, pageSize: 25, total: 1 })).toBe(true);
    expect(isAdminScansResponse({ scans: [{ ...scan, targetUrl: 'https://private.example.test' }], page: 1, pageSize: 25, total: 1 })).toBe(false);

    const finding = { findingNumber: 1, scanId: scan.scanId, projectId: scan.projectId, scanner: 'SAST', ruleId: 'DG-SAST-001', severity: 'HIGH', lifecycleState: 'OPEN', observedAt: '2026-09-01T00:01:00.000Z' };
    expect(isAdminFindingsResponse({ findings: [finding], page: 1, pageSize: 25, total: 1 })).toBe(true);
    expect(isAdminFindingsResponse({ findings: [{ ...finding, evidence: 'secret', fingerprint: 'a'.repeat(64) }], page: 1, pageSize: 25, total: 1 })).toBe(false);

    const audit = { source: 'PAYMENT', eventId: 'evt_00000000-0000-4000-8000-000000000001', paymentId: 'pay_00000000-0000-4000-8000-000000000001', accountId: 'usr_test', actorId: 'usr_operator', action: 'PAYMENT_CREATED', previousStatus: null, newStatus: 'PENDING', timestamp: '2026-09-01T00:00:00.000Z', reason: null };
    expect(isAdminAuditResponse({ events: [audit], page: 1, pageSize: 50, total: 1, coverage: 'PAYMENT_EVENTS_ONLY' })).toBe(true);
    expect(isAdminAuditResponse({ events: [{ ...audit, token: 'secret' }], page: 1, pageSize: 50, total: 1, coverage: 'PAYMENT_EVENTS_ONLY' })).toBe(false);
  });
});
