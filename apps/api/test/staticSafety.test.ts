import { readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, test } from 'vitest';

const SRC_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'src');

function listTsFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      out.push(...listTsFiles(full));
    } else if (entry.endsWith('.ts')) {
      out.push(full);
    }
  }
  return out;
}

const sources = (): Array<{ file: string; content: string }> =>
  listTsFiles(SRC_DIR).map((file) => ({
    file: relative(SRC_DIR, file),
    content: readFileSync(file, 'utf8'),
  }));

describe('static safety', () => {
  test('sources contain no unsafe execution primitives', () => {
    const forbidden: Array<{ pattern: RegExp; reason: string }> = [
      { pattern: /child_process/, reason: 'child processes are forbidden' },
      { pattern: /\bexec(Sync|File)?\s*\(/, reason: 'exec is forbidden' },
      { pattern: /\bspawn(Sync)?\s*\(/, reason: 'spawn is forbidden' },
      { pattern: /\beval\s*\(/, reason: 'eval is forbidden' },
      { pattern: /new\s+Function\s*\(/, reason: 'Function constructor is forbidden' },
      { pattern: /__proto__/, reason: '__proto__ access is forbidden' },
    ];
    const violations: string[] = [];
    for (const { file, content } of sources()) {
      for (const { pattern, reason } of forbidden) {
        if (pattern.test(content)) {
          violations.push(`${file}: ${reason} (${pattern})`);
        }
      }
    }
    expect(violations).toEqual([]);
  });

  test('process.env is read only in config.ts', () => {
    const readers = sources()
      .filter(({ content }) => content.includes('process.env'))
      .map(({ file }) => file);
    expect(readers).toEqual(['config.ts']);
  });

  test('no source imports a database, dataset or shell module', () => {
    const denied = [
      'child_process',
      'node:child_process',
      'pg',
      'postgres',
      'mysql',
      'mysql2',
      'sqlite3',
      'better-sqlite3',
      'prisma',
      '@prisma/client',
      'typeorm',
      'sequelize',
      'mongoose',
      'mongodb',
      'redis',
      'ioredis',
      'knex',
    ];
    const violations: string[] = [];
    for (const { file, content } of sources()) {
      for (const spec of denied) {
        if (
          content.includes(`from '${spec}'`) ||
          content.includes(`from "${spec}"`) ||
          content.includes(`require('${spec}')`) ||
          content.includes(`require("${spec}")`)
        ) {
          violations.push(`${file}: imports ${spec}`);
        }
      }
    }
    expect(violations).toEqual([]);
  });
});
