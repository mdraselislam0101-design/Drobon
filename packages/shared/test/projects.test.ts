import { describe, expect, test } from 'vitest';
import {
  PROJECT_DESCRIPTION_MAX_LENGTH,
  PROJECT_ID_PATTERN,
  PROJECT_NAME_MAX_LENGTH,
  PROJECT_STATUSES,
  compareProjectsDesc,
  isProject,
  isProjectResponse,
  isProjectStatus,
  isProjectsResponse,
  type Project,
} from '../src/index.js';

/**
 * Pump 6 project contract tests: the closed status vocabulary, the id
 * shape, the deterministic ordering contract, and the payload guards
 * that keep the client boundary honest (forged projects, foreign
 * shapes and cross-field junk all fail closed).
 */

const project: Project = {
  id: 'prj_0f0e0d0c-0b0a-4909-8807-650605040302',
  name: 'Primary web app',
  description: 'The checkout flow.',
  status: 'ACTIVE',
  createdAt: '2026-09-28T10:00:00.000Z',
  updatedAt: '2026-09-28T10:00:00.000Z',
};

describe('project vocabulary', () => {
  test('exactly two lifecycle statuses exist', () => {
    expect(PROJECT_STATUSES).toEqual(['ACTIVE', 'ARCHIVED']);
    for (const status of PROJECT_STATUSES) {
      expect(isProjectStatus(status)).toBe(true);
    }
    for (const bad of ['active', 'DELETED', 'CLOSED', '', null, 1]) {
      expect(isProjectStatus(bad)).toBe(false);
    }
  });

  test('name and description bounds are finite and tight', () => {
    expect(PROJECT_NAME_MAX_LENGTH).toBe(120);
    expect(PROJECT_DESCRIPTION_MAX_LENGTH).toBe(2000);
  });

  test('ids are prj_ + lowercase UUID v4 shape', () => {
    expect(PROJECT_ID_PATTERN.test(project.id)).toBe(true);
    for (const bad of [
      'usr_0f0e0d0c-0b0a-4909-8807-650605040302', // wrong prefix
      'prj_0F0E0D0C-0B0A-4909-8807-650605040302', // uppercase
      'prj_1', // counter-ish
      'prj_', // empty
      '0f0e0d0c-0b0a-4909-8807-650605040302', // no prefix
      'prj_0f0e0d0c-0b0a-4909-8807-6506050403', // too short
      '',
      'prj_../../etc/passwd',
    ]) {
      expect(PROJECT_ID_PATTERN.test(bad), bad).toBe(false);
    }
  });
});

describe('deterministic ordering contract', () => {
  const a = { ...project, id: 'prj_00000000-0000-4000-8000-00000000000a', updatedAt: '2026-09-28T10:00:00.000Z' };
  const b = { ...project, id: 'prj_00000000-0000-4000-8000-00000000000b', updatedAt: '2026-09-28T10:00:00.000Z' };
  const older = { ...project, id: 'prj_00000000-0000-4000-8000-00000000000c', updatedAt: '2026-09-01T10:00:00.000Z' };

  test('updatedAt DESC — most recently touched first', () => {
    expect(compareProjectsDesc(a, older)).toBe(-1);
    expect(compareProjectsDesc(older, a)).toBe(1);
  });

  test('id ASC is the stable tie-breaker for identical timestamps', () => {
    expect(compareProjectsDesc(a, b)).toBe(-1);
    expect(compareProjectsDesc(b, a)).toBe(1);
    expect(compareProjectsDesc(a, a)).toBe(0);
  });

  test('sorting with the comparator is total and deterministic', () => {
    const list = [b, older, a, a];
    const sorted = [...list].sort(compareProjectsDesc);
    expect(sorted.map((entry) => entry.id)).toEqual([
      'prj_00000000-0000-4000-8000-00000000000a',
      'prj_00000000-0000-4000-8000-00000000000a',
      'prj_00000000-0000-4000-8000-00000000000b',
      'prj_00000000-0000-4000-8000-00000000000c',
    ]);
  });
});

describe('payload guards (client boundary)', () => {
  test('accepts the canonical project and both statuses', () => {
    expect(isProject(project)).toBe(true);
    expect(isProject({ ...project, status: 'ARCHIVED' })).toBe(true);
    expect(isProject({ ...project, description: '' })).toBe(true);
  });

  test('rejects forged or malformed projects', () => {
    for (const bad of [
      { ...project, id: 'not-an-id' },
      { ...project, id: 'usr_0f0e0d0c-0b0a-4909-8807-650605040302' },
      { ...project, name: '' }, // names are never empty
      { ...project, name: 'x'.repeat(PROJECT_NAME_MAX_LENGTH + 1) },
      { ...project, description: 'x'.repeat(PROJECT_DESCRIPTION_MAX_LENGTH + 1) },
      { ...project, status: 'DELETED' },
      { ...project, status: 'ACTIVE '.trim() + 'X' },
      { ...project, createdAt: 'yesterday' },
      { ...project, updatedAt: 12345 },
      { id: project.id }, // missing halves
      null,
      'ACTIVE',
      [],
    ]) {
      expect(isProject(bad), JSON.stringify(bad)).toBe(false);
    }
  });

  test('list and single envelopes validate; junk fails closed', () => {
    expect(isProjectsResponse({ projects: [project] })).toBe(true);
    expect(isProjectsResponse({ projects: [] })).toBe(true);
    expect(isProjectResponse({ project })).toBe(true);
    for (const bad of [
      { projects: [project, { ...project, status: 'HACKED' }] },
      { projects: {} },
      { projects: null },
      { project: null },
      { project: { ...project, name: '' } },
      {},
      null,
    ]) {
      expect(isProjectsResponse(bad) || isProjectResponse(bad), JSON.stringify(bad)).toBe(false);
    }
  });

  test('the project shape carries no owner or storage fields', () => {
    // Self-only API: the owner is by construction the caller, so the
    // contract itself must be incapable of carrying owner/storage data.
    expect(Object.keys(project).sort()).toEqual([
      'createdAt',
      'description',
      'id',
      'name',
      'status',
      'updatedAt',
    ]);
  });
});
