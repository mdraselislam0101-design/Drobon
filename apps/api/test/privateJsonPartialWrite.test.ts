import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, test, vi } from 'vitest';

const fixture = vi.hoisted(() => ({ fail: false, tempMode: 0 }));
vi.mock('node:fs', async (original) => {
  const fs = await original<typeof import('node:fs')>();
  return { ...fs, writeFileSync: (path: Parameters<typeof fs.writeFileSync>[0], data: Parameters<typeof fs.writeFileSync>[1], options?: Parameters<typeof fs.writeFileSync>[2]) => {
    if (fixture.fail && typeof path === 'number') {
      fixture.fail = false;
      fs.writeSync(path, 'partial synthetic data');
      fixture.tempMode = fs.fstatSync(path).mode & 0o777;
      throw new Error('synthetic partial write failure');
    }
    return fs.writeFileSync(path, data, options);
  } };
});
import { writePrivateJson } from '../src/lib/writePrivateJson.js';

describe('partial private JSON writes', () => {
  test('an ordinary partial write failure removes only its own private temp and permits retry', () => {
    const dir = mkdtempSync(join(tmpdir(), 'drobon-partial-json-'));
    try {
      const path = join(dir, 'store.json');
      writeFileSync(path, 'old synthetic document');
      writeFileSync(join(dir, 'historical.tmp'), 'unrelated synthetic temp');
      fixture.fail = true;
      expect(() => writePrivateJson(path, 'new synthetic document')).toThrow('synthetic partial write failure');
      expect(fixture.tempMode).toBe(0o600);
      expect(readFileSync(path, 'utf8')).toBe('old synthetic document');
      expect(readdirSync(dir).filter((name) => name.endsWith('.tmp'))).toEqual(['historical.tmp']);
      expect(readFileSync(join(dir, 'historical.tmp'), 'utf8')).toBe('unrelated synthetic temp');
      writePrivateJson(path, 'new synthetic document');
      expect(readFileSync(path, 'utf8')).toBe('new synthetic document');
      expect(statSync(path).mode & 0o777).toBe(0o600);
    } finally { fixture.fail = false; rmSync(dir, { recursive: true, force: true }); }
  });
});
