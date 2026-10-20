import { FINDING_LIFECYCLE_STATES } from './findings.js';
import { PROJECT_ID_PATTERN } from './projects.js';
import { FINDING_SEVERITIES } from './scans.js';
import { isRecord } from './guards.js';
import { ACCOUNT_ROLES, isAccountRole, isUserType, USER_TYPES, type AccountRole, type UserType } from './authz.js';
import { PAYMENT_AUDIT_ACTIONS, PAYMENT_STATUSES, isPaymentAuditAction, isPaymentStatus, type PaymentAuditAction, type PaymentStatus } from './payments.js';
import { SCAN_STATUSES, SCAN_TYPES, isScanStatus, isScanType, type ScanStatus, type ScanType } from './scans.js';
import { isPlan, isSubscriptionStatus, SUBSCRIPTION_STATUSES, type Plan, type SubscriptionStatus } from './plans.js';
import { isProEntitlementSource } from './entitlements.js';

export const ADMIN_ACCOUNT_PAGE_SIZE_MAX = 50;
export const ADMIN_ACCOUNT_PAGE_MAX = 1_000;
export const ADMIN_AUDIT_PAGE_SIZE_MAX = 100;
export const ADMIN_AUDIT_PAGE_MAX = 1_000;
export const ADMIN_SEARCH_MAX_LENGTH = 100;
export const ADMIN_AUDIT_RANGE_MAX_DAYS = 366;

export interface AdminAuditFilters {
  page?: number;
  pageSize?: number;
  action?: PaymentAuditAction;
  accountId?: string;
  paymentId?: string;
  from?: string;
  to?: string;
}

export interface AdminDashboardResponse {
  asOf: string;
  accounts: { state: 'AVAILABLE'; total: number; free: number; pro: number; subscriptionByStatus: Record<SubscriptionStatus, number> } | { state: 'UNAVAILABLE' };
  projects: { state: 'AVAILABLE'; total: number; active: number; archived: number } | { state: 'UNAVAILABLE' };
  scans: { state: 'AVAILABLE'; total: number; byStatus: Record<ScanStatus, number>; byType: Record<ScanType, number>; recentlyCompleted: number } | { state: 'UNAVAILABLE' };
  payments: {
    state: 'AVAILABLE'; total: number; byStatus: Record<PaymentStatus, number>;
    submittedAmountMinorUnits: number; approvedAmountMinorUnits: number; currency: 'BDT';
  } | { state: 'UNAVAILABLE' };
  findings: {
    state: 'AVAILABLE'; bySeverity: Record<(typeof FINDING_SEVERITIES)[number], number>;
    byLifecycleState: Record<(typeof FINDING_LIFECYCLE_STATES)[number], number>;
    unresolved: number; dastObservations: number; scaNotAssessed: number;
  } | { state: 'UNAVAILABLE' };
  system: {
    api: 'SERVING'; web: 'NOT_ASSESSED';
    accountPersistence: 'LOADED_AT_STARTUP' | 'EPHEMERAL'; paymentPersistence: 'LOADED_AT_STARTUP' | 'EPHEMERAL';
    apiAttachedScanProcessor: 'RUNNING' | 'NOT_STARTED'; separateWorker: 'NOT_INTEGRATED';
    assistantFeature: 'DETERMINISTIC_READ_ONLY'; aiProvider: 'NONE';
    paymentGateway: 'UNAVAILABLE'; vulnerabilityDataset: 'NO_DATA_LOADED'; securityDataset: 'SEPARATE_NOT_LOADED';
  };
}

export interface AdminAccountSummary {
  accountId: string;
  email: string;
  role: AccountRole;
  userType: UserType | null;
  /** The account's OWN persisted (paid) subscription plan. */
  plan: Plan;
  subscriptionStatus: SubscriptionStatus;
  /**
   * The server-derived EFFECTIVE plan: PRO when either the persisted
   * subscription is PRO+ACTIVE or an active admin complimentary PRO
   * grant exists; otherwise FREE. Kept beside `plan` so the admin can
   * always distinguish paid state from granted state.
   */
  effectivePlan: Plan;
  /**
   * Where the effective PRO comes from: `'PAID'` (subscription),
   * `'ADMIN_GRANT'` (active complimentary grant), or `null` when the
   * effective plan is FREE.
   */
  proEntitlementSource: 'PAID' | 'ADMIN_GRANT' | null;
  createdAt: string;
  accountStatus: 'UNAVAILABLE';
  paymentRequestCount: number;
  latestPaymentStatus: PaymentStatus | null;
}

export interface AdminAccountsResponse {
  accounts: AdminAccountSummary[];
  page: number;
  pageSize: number;
  total: number;
}

export const ADMIN_SCAN_PAGE_SIZE_MAX = 100;
export const ADMIN_SCAN_PAGE_MAX = 1_000;
export const ADMIN_FINDING_PAGE_SIZE_MAX = 100;
export const ADMIN_FINDING_PAGE_MAX = 1_000;

/** Metadata-only operations projection: no source, target URL, or credentials. */
export interface AdminScanSummary {
  scanId: string;
  projectId: string;
  accountId: string;
  scanType: ScanType;
  status: ScanStatus;
  createdAt: string;
  completedAt: string | null;
  findingsTotal: number;
}

export interface AdminScansResponse {
  scans: AdminScanSummary[];
  page: number;
  pageSize: number;
  total: number;
}

/** Redacted finding index: deliberately excludes content, paths, evidence, and fingerprint hashes. */
export interface AdminFindingSummary {
  findingNumber: number;
  scanId: string;
  projectId: string;
  scanner: ScanType;
  ruleId: string;
  severity: (typeof FINDING_SEVERITIES)[number];
  lifecycleState: (typeof FINDING_LIFECYCLE_STATES)[number];
  observedAt: string;
}

export interface AdminFindingsResponse {
  findings: AdminFindingSummary[];
  page: number;
  pageSize: number;
  total: number;
}

export interface AdminAuditRecord {
  source: 'PAYMENT';
  eventId: string;
  paymentId: string;
  accountId: string;
  actorId: string;
  action: PaymentAuditAction;
  previousStatus: PaymentStatus | null;
  newStatus: PaymentStatus;
  timestamp: string;
  reason: string | null;
}

export interface AdminAuditResponse {
  events: AdminAuditRecord[];
  page: number;
  pageSize: number;
  total: number;
  coverage: 'PAYMENT_EVENTS_ONLY';
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return Object.keys(value).length === keys.length && keys.every((key) => Object.prototype.hasOwnProperty.call(value, key));
}

function nonnegativeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function pageMeta(value: Record<string, unknown>, rows: unknown[], rowKey: string, maximum: number, maxPage: number, extraKeys: readonly string[] = []): boolean {
  return hasExactKeys(value, [rowKey, 'page', 'pageSize', 'total', ...extraKeys]) && typeof value['page'] === 'number' && Number.isSafeInteger(value['page']) && value['page'] >= 1 && value['page'] <= maxPage &&
    typeof value['pageSize'] === 'number' && Number.isSafeInteger(value['pageSize']) && value['pageSize'] >= 1 && value['pageSize'] <= maximum &&
    nonnegativeInteger(value['total']) && rows.length <= value['pageSize'];
}

function isoTime(value: unknown): value is string { return typeof value === 'string' && !Number.isNaN(Date.parse(value)); }

function isCountMap(value: unknown, keys: readonly string[]): boolean {
  return isRecord(value) && hasExactKeys(value, keys) && keys.every((key) => nonnegativeInteger(value[key]));
}

function availableAccounts(value: unknown): boolean {
  return isRecord(value) && value['state'] === 'AVAILABLE' && hasExactKeys(value, ['state', 'total', 'free', 'pro', 'subscriptionByStatus']) &&
    nonnegativeInteger(value['total']) && nonnegativeInteger(value['free']) && nonnegativeInteger(value['pro']) &&
    isCountMap(value['subscriptionByStatus'], SUBSCRIPTION_STATUSES);
}

function availableProjects(value: unknown): boolean {
  return isRecord(value) && value['state'] === 'AVAILABLE' && hasExactKeys(value, ['state', 'total', 'active', 'archived']) &&
    nonnegativeInteger(value['total']) && nonnegativeInteger(value['active']) && nonnegativeInteger(value['archived']);
}

function availableScans(value: unknown): boolean {
  return isRecord(value) && value['state'] === 'AVAILABLE' && hasExactKeys(value, ['state', 'total', 'byStatus', 'byType', 'recentlyCompleted']) &&
    nonnegativeInteger(value['total']) && nonnegativeInteger(value['recentlyCompleted']) &&
    isCountMap(value['byStatus'], SCAN_STATUSES) && isCountMap(value['byType'], SCAN_TYPES);
}

function availablePayments(value: unknown): boolean {
  return isRecord(value) && value['state'] === 'AVAILABLE' && hasExactKeys(value, ['state', 'total', 'byStatus', 'submittedAmountMinorUnits', 'approvedAmountMinorUnits', 'currency']) &&
    nonnegativeInteger(value['total']) && value['currency'] === 'BDT' && nonnegativeInteger(value['submittedAmountMinorUnits']) &&
    nonnegativeInteger(value['approvedAmountMinorUnits']) && isCountMap(value['byStatus'], PAYMENT_STATUSES);
}

function availableFindings(value: unknown): boolean {
  return isRecord(value) && value['state'] === 'AVAILABLE' && hasExactKeys(value, ['state', 'bySeverity', 'byLifecycleState', 'unresolved', 'dastObservations', 'scaNotAssessed']) &&
    nonnegativeInteger(value['unresolved']) && nonnegativeInteger(value['dastObservations']) && nonnegativeInteger(value['scaNotAssessed']) &&
    isCountMap(value['bySeverity'], FINDING_SEVERITIES) && isCountMap(value['byLifecycleState'], FINDING_LIFECYCLE_STATES);
}

function unavailable(value: unknown): boolean {
  return isRecord(value) && hasExactKeys(value, ['state']) && value['state'] === 'UNAVAILABLE';
}

export function isAdminDashboardResponse(value: unknown): value is AdminDashboardResponse {
  if (!isRecord(value) || !hasExactKeys(value, ['asOf', 'accounts', 'projects', 'scans', 'payments', 'findings', 'system']) || !isoTime(value['asOf'])) return false;
  const system = value['system'];
  if (!isRecord(system) || !hasExactKeys(system, ['api', 'web', 'accountPersistence', 'paymentPersistence', 'apiAttachedScanProcessor', 'separateWorker', 'assistantFeature', 'aiProvider', 'paymentGateway', 'vulnerabilityDataset', 'securityDataset'])) return false;
  return (availableAccounts(value['accounts']) || unavailable(value['accounts'])) &&
    (availableProjects(value['projects']) || unavailable(value['projects'])) &&
    (availableScans(value['scans']) || unavailable(value['scans'])) &&
    (availablePayments(value['payments']) || unavailable(value['payments'])) &&
    (availableFindings(value['findings']) || unavailable(value['findings'])) &&
    system['api'] === 'SERVING' && system['web'] === 'NOT_ASSESSED' &&
    (system['accountPersistence'] === 'LOADED_AT_STARTUP' || system['accountPersistence'] === 'EPHEMERAL') &&
    (system['paymentPersistence'] === 'LOADED_AT_STARTUP' || system['paymentPersistence'] === 'EPHEMERAL') &&
    (system['apiAttachedScanProcessor'] === 'RUNNING' || system['apiAttachedScanProcessor'] === 'NOT_STARTED') &&
    system['separateWorker'] === 'NOT_INTEGRATED' && system['assistantFeature'] === 'DETERMINISTIC_READ_ONLY' &&
    system['aiProvider'] === 'NONE' && system['paymentGateway'] === 'UNAVAILABLE' &&
    system['vulnerabilityDataset'] === 'NO_DATA_LOADED' && system['securityDataset'] === 'SEPARATE_NOT_LOADED';
}

export function isAdminAccountSummary(value: unknown): value is AdminAccountSummary {
  return isRecord(value) && hasExactKeys(value, ['accountId', 'email', 'role', 'userType', 'plan', 'subscriptionStatus', 'effectivePlan', 'proEntitlementSource', 'createdAt', 'accountStatus', 'paymentRequestCount', 'latestPaymentStatus']) && typeof value['accountId'] === 'string' && value['accountId'].length > 0 && typeof value['email'] === 'string' && value['email'].length <= 320 && isAccountRole(value['role']) && (value['userType'] === null || isUserType(value['userType'])) && isPlan(value['plan']) && isSubscriptionStatus(value['subscriptionStatus']) && isPlan(value['effectivePlan']) && (value['proEntitlementSource'] === null || isProEntitlementSource(value['proEntitlementSource'])) && isoTime(value['createdAt']) && value['accountStatus'] === 'UNAVAILABLE' && nonnegativeInteger(value['paymentRequestCount']) && (value['latestPaymentStatus'] === null || isPaymentStatus(value['latestPaymentStatus']));
}

export function isAdminAccountsResponse(value: unknown): value is AdminAccountsResponse {
  if (!isRecord(value) || !Array.isArray(value['accounts']) || !value['accounts'].every(isAdminAccountSummary)) return false;
  return pageMeta(value, value['accounts'], 'accounts', ADMIN_ACCOUNT_PAGE_SIZE_MAX, ADMIN_ACCOUNT_PAGE_MAX);
}

export function isAdminScanSummary(value: unknown): value is AdminScanSummary {
  return isRecord(value) && hasExactKeys(value, ['scanId', 'projectId', 'accountId', 'scanType', 'status', 'createdAt', 'completedAt', 'findingsTotal']) && typeof value['scanId'] === 'string' && /^scan_[0-9a-f-]{36}$/.test(value['scanId']) &&
    typeof value['projectId'] === 'string' && PROJECT_ID_PATTERN.test(value['projectId']) &&
    typeof value['accountId'] === 'string' && value['accountId'].length > 0 &&
    isScanType(value['scanType']) && isScanStatus(value['status']) && isoTime(value['createdAt']) &&
    (value['completedAt'] === null || isoTime(value['completedAt'])) && nonnegativeInteger(value['findingsTotal']);
}

export function isAdminScansResponse(value: unknown): value is AdminScansResponse {
  if (!isRecord(value) || !Array.isArray(value['scans']) || !value['scans'].every(isAdminScanSummary)) return false;
  return pageMeta(value, value['scans'], 'scans', ADMIN_SCAN_PAGE_SIZE_MAX, ADMIN_SCAN_PAGE_MAX);
}

export function isAdminFindingSummary(value: unknown): value is AdminFindingSummary {
  return isRecord(value) && hasExactKeys(value, ['findingNumber', 'scanId', 'projectId', 'scanner', 'ruleId', 'severity', 'lifecycleState', 'observedAt']) && typeof value['findingNumber'] === 'number' && Number.isSafeInteger(value['findingNumber']) && value['findingNumber'] >= 1 && value['findingNumber'] <= 200 &&
    typeof value['scanId'] === 'string' && /^scan_[0-9a-f-]{36}$/.test(value['scanId']) &&
    typeof value['projectId'] === 'string' && PROJECT_ID_PATTERN.test(value['projectId']) &&
    isScanType(value['scanner']) && typeof value['ruleId'] === 'string' && /^(?:DG|DPK)-(?:SAST|SEC|DAST)-[0-9]{3,}$/.test(value['ruleId']) &&
    (FINDING_SEVERITIES as readonly unknown[]).includes(value['severity']) &&
    (FINDING_LIFECYCLE_STATES as readonly unknown[]).includes(value['lifecycleState']) && isoTime(value['observedAt']);
}

export function isAdminFindingsResponse(value: unknown): value is AdminFindingsResponse {
  if (!isRecord(value) || !Array.isArray(value['findings']) || !value['findings'].every(isAdminFindingSummary)) return false;
  return pageMeta(value, value['findings'], 'findings', ADMIN_FINDING_PAGE_SIZE_MAX, ADMIN_FINDING_PAGE_MAX);
}

export function isAdminAuditRecord(value: unknown): value is AdminAuditRecord {
  return isRecord(value) && hasExactKeys(value, ['source', 'eventId', 'paymentId', 'accountId', 'actorId', 'action', 'previousStatus', 'newStatus', 'timestamp', 'reason']) && value['source'] === 'PAYMENT' && typeof value['eventId'] === 'string' && typeof value['paymentId'] === 'string' && typeof value['accountId'] === 'string' && typeof value['actorId'] === 'string' && isPaymentAuditAction(value['action']) && (value['previousStatus'] === null || isPaymentStatus(value['previousStatus'])) && isPaymentStatus(value['newStatus']) && isoTime(value['timestamp']) && (value['reason'] === null || (typeof value['reason'] === 'string' && value['reason'].length <= 300));
}

export function isAdminAuditResponse(value: unknown): value is AdminAuditResponse {
  if (!isRecord(value) || value['coverage'] !== 'PAYMENT_EVENTS_ONLY' || !Array.isArray(value['events']) || !value['events'].every(isAdminAuditRecord)) return false;
  return pageMeta(value, value['events'], 'events', ADMIN_AUDIT_PAGE_SIZE_MAX, ADMIN_AUDIT_PAGE_MAX, ['coverage']);
}

export const ADMIN_FILTER_CONTRACT = Object.freeze({ roles: ACCOUNT_ROLES, userTypes: USER_TYPES, scanStatuses: SCAN_STATUSES, paymentStatuses: PAYMENT_STATUSES, auditActions: PAYMENT_AUDIT_ACTIONS });
export function isAdminScanStatus(value: unknown): value is ScanStatus { return isScanStatus(value); }
export function isAdminScanType(value: unknown): value is ScanType { return isScanType(value); }
export function isAdminAuditAction(value: unknown): value is PaymentAuditAction { return isPaymentAuditAction(value); }
