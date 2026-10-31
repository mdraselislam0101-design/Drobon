import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, test, vi } from 'vitest';

const interleaving = vi.hoisted(() => ({ replacement: '' }));
vi.mock('node:fs', async (original) => {
  const fs = await original<typeof import('node:fs')>();
  return { ...fs, renameSync: (from: Parameters<typeof fs.renameSync>[0], to: Parameters<typeof fs.renameSync>[1]) => {
    if (interleaving.replacement !== '') {
      const replacement = interleaving.replacement;
      interleaving.replacement = '';
      fs.renameSync(replacement, from);
      throw new Error('synthetic interleaved rename failure');
    }
    return fs.renameSync(from, to);
  } };
});

// Force a random-name collision with a synthetic file to prove exclusive
// creation neither overwrites nor unlinks a pre-existing writer's temp file.
vi.mock('node:crypto', async (original) => ({
  ...await original<typeof import('node:crypto')>(),
  randomBytes: () => Buffer.alloc(6, 0xab),
}));
import { writePrivateJson } from '../src/lib/writePrivateJson.js';

describe('private JSON writes', () => {
  test('an existing temporary name and destination are left unchanged on collision', () => {
    const dir = mkdtempSync(join(tmpdir(), 'main-app-temp-collision-'));
    try {
      const destination = join(dir, 'store.json');
      const collision = join(dir, '.abababababab.tmp');
      writeFileSync(destination, 'old synthetic destination');
      writeFileSync(collision, 'preexisting synthetic temporary file');
      expect(() => writePrivateJson(destination, 'new synthetic document')).toThrow();
      expect(readFileSync(destination, 'utf8')).toBe('old synthetic destination');
      expect(readFileSync(collision, 'utf8')).toBe('preexisting synthetic temporary file');
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  test('does not clean up a replacement file installed before a failed rename', () => {
    const dir = mkdtempSync(join(tmpdir(), 'main-app-temp-replaced-'));
    try {
      const destination = join(dir, 'store.json');
      const replacement = join(dir, 'other-writer');
      const temp = join(dir, '.abababababab.tmp');
      writeFileSync(destination, 'old synthetic destination');
      writeFileSync(replacement, 'other synthetic writer data');
      interleaving.replacement = replacement;
      expect(() => writePrivateJson(destination, 'new synthetic document')).toThrow();
      expect(readFileSync(destination, 'utf8')).toBe('old synthetic destination');
      expect(readFileSync(temp, 'utf8')).toBe('other synthetic writer data');
    } finally { interleaving.replacement = ''; rmSync(dir, { recursive: true, force: true }); }
  });
});
