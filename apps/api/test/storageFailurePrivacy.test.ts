import { mkdirSync, mkdtempSync, readFileSync, readdirSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, test } from 'vitest';
import { createJsonFileUserRepository } from '../src/auth/jsonFileUserRepository.js';
import { createJsonFileSourceStore } from '../src/scans/sources.js';
import type { UserRecord } from '../src/auth/repositories.js';

// Tests use disposable synthetic account and source data only.
const at = '2026-10-31T00:00:00.000Z';
const user: UserRecord = { id: 'usr_storage_fixture', email: 'storage-fixture@example.test', passwordHash: 'scrypt$fixture',
  role: 'MEMBER', userType: null, createdAt: at, subscription: { plan: 'FREE', status: 'ACTIVE', createdAt: at, updatedAt: at } };

describe('account and source file failures', () => {
  test('failed account rename leaves no copied account temp file, preserves FREE, and allows an idempotent PRO retry', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'main-app-account-failure-'));
    const path = join(dir, 'users.json');
    const backup = join(dir, 'saved.json');
    try {
      const users = createJsonFileUserRepository(path);
      expect(await users.create(user)).toBe(true);
      const original = readFileSync(path, 'utf8');
      writeFileSync(join(dir, 'history.tmp'), 'preexisting synthetic file');
      renameSync(path, backup);
      mkdirSync(path); // force actual rename failure after the temp write
      await expect(users.activatePro(user.id, at)).rejects.toThrow();
      expect((await users.findById(user.id))?.subscription?.plan).toBe('FREE');
      expect(readFileSync(backup, 'utf8')).toBe(original);
      expect(readdirSync(dir).filter((name) => name.endsWith('.tmp'))).toEqual(['history.tmp']);
      expect(readFileSync(join(dir, 'history.tmp'), 'utf8')).toBe('preexisting synthetic file');
      rmSync(path, { recursive: true });
      renameSync(backup, path);
      expect((await createJsonFileUserRepository(path).findById(user.id))?.subscription?.plan).toBe('FREE');
      expect(await users.activatePro(user.id, at)).toBe('ACTIVATED');
      expect(await users.activatePro(user.id, at)).toBe('ALREADY_ACTIVE');
      expect((await createJsonFileUserRepository(path).findById(user.id))?.subscription?.plan).toBe('PRO');
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  test('failed source rename removes the new raw-source temp file and retains the old snapshot', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'main-app-source-failure-'));
    const path = join(dir, 'sources.json');
    const backup = join(dir, 'saved.json');
    const input = { ownerId: user.id, projectId: 'prj_00000000-0000-4000-8000-000000000001', files: [{ path: 'fixture.js', content: 'const value = "old synthetic";' }] };
    try {
      const sources = createJsonFileSourceStore(path);
      await sources.replace(input);
      const original = readFileSync(path, 'utf8');
      writeFileSync(join(dir, 'history.tmp'), 'preexisting synthetic file');
      renameSync(path, backup);
      mkdirSync(path);
      const changed = { ...input, files: [{ path: 'fixture.js', content: 'const value = "new synthetic";' }] };
      await expect(sources.replace(changed)).rejects.toThrow();
      expect((await sources.findByProject(input.projectId))?.files[0]?.content).toBe(input.files[0]?.content);
      expect(readFileSync(backup, 'utf8')).toBe(original);
      expect(readdirSync(dir).filter((name) => name.endsWith('.tmp'))).toEqual(['history.tmp']);
      expect(readFileSync(join(dir, 'history.tmp'), 'utf8')).toBe('preexisting synthetic file');
      rmSync(path, { recursive: true });
      renameSync(backup, path);
      expect((await createJsonFileSourceStore(path).findByProject(input.projectId))?.files[0]?.content).toBe(input.files[0]?.content);
      await sources.replace(changed);
      expect((await createJsonFileSourceStore(path).findByProject(input.projectId))?.files[0]?.content).toBe(changed.files[0]?.content);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
});
