import { describe, expect, test } from 'vitest';
import {
  ACCOUNT_ROLES,
  ACCOUNT_ROLE_RANK,
  AUTHZ_CAPABILITY_LEVELS,
  PERMISSIONS,
  USER_TYPES,
  hasPermission,
  isAccountRole,
  isCapabilityResponse,
  isPermission,
  isUserType,
  requiredRoleForPermission,
  roleAtLeast,
  type AccountRole,
  type Permission,
  type UserType,
} from '../src/index.js';

describe('account roles', () => {
  test('exposes exactly the three Pump 3 roles with strict ranks', () => {
    expect(ACCOUNT_ROLES).toEqual(['MEMBER', 'ADMIN', 'ACCOUNT_OWNER']);
    expect(ACCOUNT_ROLE_RANK.MEMBER).toBeLessThan(ACCOUNT_ROLE_RANK.ADMIN);
    expect(ACCOUNT_ROLE_RANK.ADMIN).toBeLessThan(ACCOUNT_ROLE_RANK.ACCOUNT_OWNER);
  });

  test('isAccountRole is exact-match only', () => {
    expect(isAccountRole('MEMBER')).toBe(true);
    expect(isAccountRole('ACCOUNT_OWNER')).toBe(true);
    expect(isAccountRole('member')).toBe(false);
    expect(isAccountRole('SUPERADMIN')).toBe(false);
    expect(isAccountRole('')).toBe(false);
    expect(isAccountRole(0)).toBe(false);
    expect(isAccountRole(null)).toBe(false);
    expect(isAccountRole(undefined)).toBe(false);
    expect(isAccountRole({ role: 'ADMIN' })).toBe(false);
  });

  test('roleAtLeast implements the hierarchy in both directions', () => {
    expect(roleAtLeast('MEMBER', 'MEMBER')).toBe(true);
    expect(roleAtLeast('ADMIN', 'MEMBER')).toBe(true);
    expect(roleAtLeast('ACCOUNT_OWNER', 'ADMIN')).toBe(true);
    expect(roleAtLeast('ACCOUNT_OWNER', 'ACCOUNT_OWNER')).toBe(true);
    expect(roleAtLeast('MEMBER', 'ADMIN')).toBe(false);
    expect(roleAtLeast('MEMBER', 'ACCOUNT_OWNER')).toBe(false);
    expect(roleAtLeast('ADMIN', 'ACCOUNT_OWNER')).toBe(false);
  });
});

describe('user types (classification only)', () => {
  test('exposes exactly the supported values', () => {
    expect(USER_TYPES).toEqual([
      'DEVELOPER',
      'STUDENT',
      'SECURITY_PROFESSIONAL',
      'PENTESTER',
    ]);
  });

  test('isUserType rejects role-like and unknown strings', () => {
    expect(isUserType('DEVELOPER')).toBe(true);
    expect(isUserType('PENTESTER')).toBe(true);
    expect(isUserType('ADMIN')).toBe(false);
    expect(isUserType('MEMBER')).toBe(false);
    expect(isUserType('developer')).toBe(false);
    expect(isUserType('')).toBe(false);
    expect(isUserType(42)).toBe(false);
  });
});

describe('permission table', () => {
  test('every permission declares a known minimum role', () => {
    for (const permission of Object.keys(PERMISSIONS) as Permission[]) {
      expect(isAccountRole(requiredRoleForPermission(permission))).toBe(true);
    }
  });

  test('probe capabilities map onto the documented hierarchy', () => {
    expect(requiredRoleForPermission('authz:capability:member')).toBe('MEMBER');
    expect(requiredRoleForPermission('authz:capability:admin')).toBe('ADMIN');
    expect(requiredRoleForPermission('authz:capability:owner')).toBe('ACCOUNT_OWNER');
    expect(requiredRoleForPermission('users:read:self')).toBe('MEMBER');
    expect(requiredRoleForPermission('users:read:others')).toBe('ADMIN');
  });

  test('hasPermission applies the table through the hierarchy', () => {
    const roles: AccountRole[] = ['MEMBER', 'ADMIN', 'ACCOUNT_OWNER'];
    expect(hasPermission('MEMBER', 'authz:capability:member')).toBe(true);
    expect(hasPermission('ADMIN', 'authz:capability:member')).toBe(true);
    expect(hasPermission('ACCOUNT_OWNER', 'authz:capability:member')).toBe(true);
    expect(hasPermission('MEMBER', 'authz:capability:admin')).toBe(false);
    expect(hasPermission('ADMIN', 'authz:capability:admin')).toBe(true);
    expect(hasPermission('ACCOUNT_OWNER', 'authz:capability:admin')).toBe(true);
    expect(hasPermission('ADMIN', 'authz:capability:owner')).toBe(false);
    expect(hasPermission('ACCOUNT_OWNER', 'authz:capability:owner')).toBe(true);
    // Privileged reads are explicit: ADMIN and above only.
    expect(hasPermission('MEMBER', 'users:read:others')).toBe(false);
    expect(hasPermission('ADMIN', 'users:read:others')).toBe(true);
    expect(hasPermission('ACCOUNT_OWNER', 'users:read:others')).toBe(true);
    expect(roles.every((role) => hasPermission(role, 'users:read:self'))).toBe(true);
  });

  test('isPermission only accepts declared capabilities', () => {
    expect(isPermission('authz:capability:admin')).toBe(true);
    expect(isPermission('users:read:others')).toBe(true);
    expect(isPermission('users:delete:any')).toBe(false);
    expect(isPermission('ADMIN')).toBe(false);
    expect(isPermission('')).toBe(false);
    expect(isPermission(null)).toBe(false);
  });
});

describe('capability probe contract', () => {
  test('exposes exactly the three probe levels', () => {
    expect(AUTHZ_CAPABILITY_LEVELS).toEqual(['member', 'admin', 'owner']);
  });

  test('isCapabilityResponse validates the envelope', () => {
    expect(isCapabilityResponse({ capability: 'member' })).toBe(true);
    expect(isCapabilityResponse({ capability: 'owner' })).toBe(true);
    expect(isCapabilityResponse({ capability: 'root' })).toBe(false);
    expect(isCapabilityResponse({})).toBe(false);
    expect(isCapabilityResponse({ capability: 7 })).toBe(false);
    expect(isCapabilityResponse(null)).toBe(false);
  });
});

describe('user type never intersects role checks', () => {
  test('a privileged userType grants nothing when the role is MEMBER', () => {
    // UserType is absent from every authorization API by construction:
    // hasPermission/roleAtLeast take an AccountRole and nothing else.
    const userType: UserType = 'SECURITY_PROFESSIONAL';
    expect(userType).not.toBe('ADMIN');
    expect(hasPermission('MEMBER', 'authz:capability:admin')).toBe(false);
    expect(hasPermission('MEMBER', 'authz:capability:owner')).toBe(false);
  });
});
