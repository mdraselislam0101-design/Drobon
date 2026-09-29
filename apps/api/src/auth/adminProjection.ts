import type { Plan, SubscriptionStatus } from '@drobon/shared';
import { type AccountRole, type UserType } from '@drobon/shared';
import { resolveSubscription } from './subscriptions.js';
import type { AdminAccountCounts, AdminAccountFilters, AdminAccountPage, AdminUserRecord, UserRecord } from './repositories.js';

function compareAccounts(a: UserRecord, b: UserRecord): number {
  return a.createdAt > b.createdAt ? -1 : a.createdAt < b.createdAt ? 1 : a.id.localeCompare(b.id);
}

function matches(record: UserRecord, filters: AdminAccountFilters): boolean {
  if (filters.role !== undefined && record.role !== filters.role) return false;
  if (filters.userType === 'NONE' && record.userType !== null) return false;
  if (filters.userType !== undefined && filters.userType !== 'NONE' && record.userType !== filters.userType) return false;
  if (filters.plan !== undefined && resolveSubscription(record).plan !== filters.plan) return false;
  if (filters.search !== undefined && !record.email.includes(filters.search)) return false;
  return true;
}

function publicRecord(record: UserRecord): AdminUserRecord {
  return {
    id: record.id,
    email: record.email,
    createdAt: record.createdAt,
    role: record.role,
    userType: record.userType,
    ...(record.subscription === undefined ? {} : { subscription: record.subscription }),
  };
}

export function buildAdminAccountPage(records: Iterable<UserRecord>, filters: AdminAccountFilters, page: number, pageSize: number): AdminAccountPage {
  const offset = (page - 1) * pageSize;
  const retain = offset + pageSize;
  const candidates: UserRecord[] = [];
  let total = 0;
  for (const record of records) {
    if (!matches(record, filters)) continue;
    total += 1;
    candidates.push(record);
    // Bounded retention: inputs are validated at the API boundary (max
    // page 1000 × 50). Periodic pruning avoids copying every matching row.
    if (candidates.length >= retain + 1000) {
      candidates.sort(compareAccounts);
      candidates.length = retain;
    }
  }
  candidates.sort(compareAccounts);
  return { accounts: candidates.slice(offset, offset + pageSize).map(publicRecord), total };
}

export function buildAdminAccountCounts(records: Iterable<UserRecord>): AdminAccountCounts {
  const byPlan: Record<Plan, number> = { FREE: 0, PRO: 0 };
  const bySubscriptionStatus: Record<SubscriptionStatus, number> = { ACTIVE: 0, INACTIVE: 0, CANCELLED: 0, EXPIRED: 0 };
  const byRole: Record<AccountRole, number> = { MEMBER: 0, ADMIN: 0, ACCOUNT_OWNER: 0 };
  const byUserType: Record<UserType | 'NONE', number> = { DEVELOPER: 0, STUDENT: 0, SECURITY_PROFESSIONAL: 0, PENTESTER: 0, NONE: 0 };
  let total = 0;
  for (const record of records) {
    total += 1;
    const subscription = resolveSubscription(record);
    byPlan[subscription.plan] += 1;
    bySubscriptionStatus[subscription.status] += 1;
    byRole[record.role] += 1;
    byUserType[record.userType ?? 'NONE'] += 1;
  }
  return { total, byPlan, bySubscriptionStatus, byRole, byUserType };
}
