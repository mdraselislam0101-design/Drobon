import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, test } from 'vitest';
import { createJsonFileUserRepository } from '../src/auth/jsonFileUserRepository.js';
import { createMemoryUserRepository } from '../src/auth/memoryUserRepository.js';
import type { UserRecord } from '../src/auth/repositories.js';
import { cleanupTempStoreDir, makeTempStoreDir } from './helpers.js';

function record(email: string, id = `usr_${email}`): UserRecord {
  return {
    id,
    email,
    passwordHash: 'scrypt$1024$8$1$c2FsdA==$aGFzaA==', // fixture marker: test
    createdAt: '2026-09-27T00:00:00.000Z',
    role: 'MEMBER',
    userType: null,
  };
}

const dirs: string[] = [];
function tempDir(): string {
  const dir = makeTempStoreDir('drobon-repo-test');
  dirs.push(dir);
  return dir;
}

afterEach(() => {
  while (dirs.length > 0) {
    const dir = dirs.pop();
    if (dir !== undefined) {
      cleanupTempStoreDir(dir);
    }
  }
});

describe('memory user repository', () => {
  test('creates, finds and enforces uniqueness', async () => {
    const repo = createMemoryUserRepository();
    expect(await repo.create(record('a@example.test'))).toBe(true);
    expect(await repo.create(record('a@example.test', 'usr_other'))).toBe(false);
    expect((await repo.findByEmail('a@example.test'))?.id).toBe('usr_a@example.test');
    expect(await repo.findByEmail('missing@example.test')).toBeUndefined();
    expect(await repo.findById('usr_a@example.test')).toBeDefined();
    expect(await repo.findById('usr_nope')).toBeUndefined();
  });

  test('racing creates cannot both win', async () => {
    const repo = createMemoryUserRepository();
    const results = await Promise.all([
      repo.create(record('race@example.test', 'usr_1')),
      repo.create(record('race@example.test', 'usr_2')),
    ]);
    expect(results.filter((created) => created)).toHaveLength(1);
  });
});

describe('JSON file user repository', () => {
  test('a missing file starts as an empty store and is created on first write', async () => {
    const dir = tempDir();
    const path = join(dir, 'nested', 'users.json');
    const repo = createJsonFileUserRepository(path);
    expect(await repo.findByEmail('nobody@example.test')).toBeUndefined();
    expect(await repo.create(record('first@example.test'))).toBe(true);
    expect(existsSync(path)).toBe(true);
    const doc = JSON.parse(readFileSync(path, 'utf8')) as {
      version: number;
      users: UserRecord[];
    };
    expect(doc.version).toBe(1);
    expect(doc.users).toHaveLength(1);
    expect(doc.users[0]?.email).toBe('first@example.test');
  });

  test('accounts survive a restart (new repository, same file)', async () => {
    const dir = tempDir();
    const path = join(dir, 'users.json');
    const first = createJsonFileUserRepository(path);
    expect(await first.create(record('persist@example.test'))).toBe(true);

    const second = createJsonFileUserRepository(path);
    const found = await second.findByEmail('persist@example.test');
    expect(found?.id).toBe('usr_persist@example.test');
    expect(await second.findById(found?.id ?? '')).toBeDefined();
    // Uniqueness survives too.
    expect(await second.create(record('persist@example.test', 'usr_late'))).toBe(false);
  });

  test('the file stores only the hash, never a plaintext password', async () => {
    const dir = tempDir();
    const path = join(dir, 'users.json');
    const repo = createJsonFileUserRepository(path);
    await repo.create({
      id: 'usr_hash-check',
      email: 'hash@example.test',
      passwordHash: 'scrypt$1024$8$1$c2FsdA==$aGFzaA==',
      createdAt: '2026-09-27T00:00:00.000Z',
      role: 'MEMBER',
      userType: null,
    });
    const raw = readFileSync(path, 'utf8');
    expect(raw).toContain('scrypt$');
    expect(raw).not.toContain('PlaintextNever-test');
  });

  test('duplicate creates are rejected without rewriting the file', async () => {
    const dir = tempDir();
    const path = join(dir, 'users.json');
    const repo = createJsonFileUserRepository(path);
    await repo.create(record('once@example.test', 'usr_first'));
    const before = readFileSync(path, 'utf8');
    expect(await repo.create(record('once@example.test', 'usr_second'))).toBe(false);
    expect(readFileSync(path, 'utf8')).toBe(before);
    expect((await repo.findByEmail('once@example.test'))?.id).toBe('usr_first');
  });

  test('concurrent creates of different emails all persist', async () => {
    const dir = tempDir();
    const path = join(dir, 'users.json');
    const repo = createJsonFileUserRepository(path);
    const results = await Promise.all(
      Array.from({ length: 5 }, (_unused, index) =>
        repo.create(record(`bulk${index}@example.test`, `usr_bulk${index}`)),
      ),
    );
    expect(results.every((created) => created)).toBe(true);
    const restarted = createJsonFileUserRepository(path);
    for (let index = 0; index < 5; index += 1) {
      expect(await restarted.findByEmail(`bulk${index}@example.test`)).toBeDefined();
    }
  });

  test('corrupt or foreign documents refuse to load', () => {
    const cases: Array<[string, RegExp]> = [
      ['not json at all', /valid JSON/],
      ['{"version":2,"users":[]}', /unexpected shape/],
      ['{"version":1,"users":"nope"}', /unexpected shape/],
      [
        JSON.stringify({
          version: 1,
          users: [{ id: '', email: 'x', passwordHash: 'nope', createdAt: 'x' }],
        }),
        /invalid record/,
      ],
      [
        JSON.stringify({
          version: 1,
          users: [record('dup@example.test'), record('dup@example.test', 'usr_dup2')],
        }),
        /duplicate records/,
      ],
    ];
    for (const [content, pattern] of cases) {
      const dir = tempDir();
      const path = join(dir, 'users.json');
      writeFileSync(path, content, 'utf8');
      expect(() => createJsonFileUserRepository(path)).toThrow(pattern);
    }
  });

  test('Pump 2-era records without role/userType load as MEMBER/null', async () => {
    const dir = tempDir();
    const path = join(dir, 'users.json');
    // Exactly what a Pump 2 store looked like: no authorization fields.
    const pump2Doc = {
      version: 1,
      users: [
        {
          id: 'usr_legacy',
          email: 'legacy@example.test',
          passwordHash: 'scrypt$1024$8$1$c2FsdA==$aGFzaA==',
          createdAt: '2026-09-27T00:00:00.000Z',
        },
      ],
    };
    writeFileSync(path, JSON.stringify(pump2Doc));
    const repo = createJsonFileUserRepository(path);
    const found = await repo.findByEmail('legacy@example.test');
    expect(found).toBeDefined();
    // Migration defaults are safe: never elevated, classification empty.
    expect(found?.role).toBe('MEMBER');
    expect(found?.userType).toBeNull();
  });

  test('invalid authorization fields refuse to load (fail fast)', () => {
    const dir = tempDir();
    const base = {
      id: 'usr_badrole',
      email: 'badrole@example.test',
      passwordHash: 'scrypt$1024$8$1$c2FsdA==$aGFzaA==',
      createdAt: '2026-09-27T00:00:00.000Z',
    };
    for (const bad of [
      { role: 'SUPERADMIN' },
      { role: 'admin' },
      { role: null },
      { role: 7 },
      { userType: 'ADMIN' },
      { userType: 'hacker' },
      { userType: 42 },
    ]) {
      const path = join(dir, `store-${Object.keys(bad).join('-')}-${Object.values(bad).join('')}.json`);
      writeFileSync(
        path,
        JSON.stringify({ version: 1, users: [{ ...base, ...bad }] }),
      );
      expect(() => createJsonFileUserRepository(path)).toThrow(/invalid record/);
    }
  });

  test('valid Pump 3 authorization fields round-trip through the file', async () => {
    const dir = tempDir();
    const path = join(dir, 'users.json');
    const repo = createJsonFileUserRepository(path);
    const created: UserRecord = {
      id: 'usr_roundtrip',
      email: 'roundtrip@example.test',
      passwordHash: 'scrypt$1024$8$1$c2FsdA==$aGFzaA==',
      createdAt: '2026-09-27T00:00:00.000Z',
      role: 'ACCOUNT_OWNER',
      userType: 'SECURITY_PROFESSIONAL',
    };
    expect(await repo.create(created)).toBe(true);
    const reloaded = createJsonFileUserRepository(path);
    const found = await reloaded.findById('usr_roundtrip');
    expect(found).toEqual(created);
  });

  test('reading an unreadable file fails loudly', () => {
    const dir = tempDir();
    const path = join(dir, 'users.json');
    writeFileSync(path, JSON.stringify({ version: 1, users: [] }), 'utf8');
    // Point the repository at a directory instead of a file: EISDIR.
    expect(() => createJsonFileUserRepository(dir)).toThrow(/Cannot read auth store/);
  });
});
