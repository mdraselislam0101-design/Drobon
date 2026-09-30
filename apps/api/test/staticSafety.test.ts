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
    // The SAST rule definitions (Pump 8) are DETECTION DATA: their
    // regex patterns necessarily NAME the dangerous APIs they detect
    // (`exec(`, `eval(`, …) as text. The file is exempt from the
    // API-NAME patterns below — and covered instead by a structural
    // guarantee in the next test (no imports at all → it cannot invoke
    // anything). Every other file is checked with no exemption, and
    // the `__proto__` check applies everywhere.
    const RULE_DATA_FILE = 'scans/sast/rules.ts';
    // The SCA parsers (Pump 9) carry a prototype-key DENYLIST — the
    // literal `__proto__` string as DATA (skipped, never accessed).
    // Exempt from that one pattern, with a compensating structural
    // control in the test after next.
    const PARSER_DATALIST_FILE = 'scans/sca/parsers.ts';
    // The Student lesson catalog (Phase 22) is EDUCATIONAL DATA: its
    // synthetic fixtures necessarily NAME the APIs they teach (`eval(`,
    // `exec(`, `process.env`) inside string constants. The file is
    // exempt from the API-NAME patterns below and covered instead by a
    // structural guarantee in the lesson-data test after next (pure
    // data module: no runtime imports, forbidden names only inside
    // string literals).
    const LESSON_DATA_FILE = 'student/lessons.ts';
    const forbidden: Array<{
      pattern: RegExp;
      reason: string;
      exemptRuleData?: boolean;
      exemptParserDenylist?: boolean;
      exemptLessonData?: boolean;
    }> = [
      { pattern: /child_process/, reason: 'child processes are forbidden', exemptRuleData: true, exemptLessonData: true },
      { pattern: /\bexec(Sync|File)?\s*\(/, reason: 'exec is forbidden', exemptRuleData: true, exemptLessonData: true },
      { pattern: /\bspawn(Sync)?\s*\(/, reason: 'spawn is forbidden', exemptRuleData: true, exemptLessonData: true },
      { pattern: /\beval\s*\(/, reason: 'eval is forbidden', exemptRuleData: true, exemptLessonData: true },
      {
        pattern: /new\s+Function\s*\(/,
        reason: 'Function constructor is forbidden',
        exemptRuleData: true,
        exemptLessonData: true,
      },
      {
        pattern: /__proto__/,
        reason: '__proto__ access is forbidden',
        exemptParserDenylist: true,
      },
    ];
    const violations: string[] = [];
    for (const { file, content } of sources()) {
      for (const { pattern, reason, exemptRuleData, exemptParserDenylist, exemptLessonData } of forbidden) {
        if (file === RULE_DATA_FILE && exemptRuleData === true) {
          continue;
        }
        if (file === PARSER_DATALIST_FILE && exemptParserDenylist === true) {
          continue;
        }
        if (file === LESSON_DATA_FILE && exemptLessonData === true) {
          continue;
        }
        if (pattern.test(content)) {
          violations.push(`${file}: ${reason} (${pattern})`);
        }
      }
    }
    expect(violations).toEqual([]);
  });

  test('the SAST rule-definition module is pure data (no runtime imports)', () => {
    // Compensating control for the exemption above: the rule module
    // may import TYPES only (erased at compile time) — a module with
    // no runtime imports cannot invoke child processes, engines or
    // evaluators; it only declares regex data and pure helpers over it.
    const rules = sources().find(({ file }) => file === 'scans/sast/rules.ts');
    expect(rules).toBeDefined();
    expect(rules?.content).not.toMatch(/^\s*import\s(?!type\b)/m);
    expect(rules?.content).not.toMatch(/require\s*\(/);
    expect(rules?.content).not.toMatch(/\bprocess\b/);
  });

  test('the Student lesson catalog is pure data (API names only inside string literals)', () => {
    // Compensating control for the exemption above: the lesson module
    // may import TYPES only, must never use require(), and — once every
    // string literal is stripped — must contain none of the forbidden
    // API names at all. The fixtures can therefore only ever be inert
    // text: the module cannot invoke what it depicts.
    const lessons = sources().find(({ file }) => file === 'student/lessons.ts');
    expect(lessons).toBeDefined();
    const content = lessons?.content ?? '';
    expect(content).not.toMatch(/^\s*import\s(?!type\b)/m);
    expect(content).not.toMatch(/require\s*\(/);
    const stripped = content
      .replace(/'(?:[^'\\]|\\.)*'/g, "''")
      .replace(/"(?:[^"\\]|\\.)*"/g, '""')
      .replace(/`(?:[^`\\]|\\.)*`/g, '``');
    for (const pattern of [/child_process/, /\bexec(Sync|File)?\s*\(/, /\bspawn(Sync)?\s*\(/, /\beval\s*\(/, /new\s+Function\s*\(/, /process\.env/]) {
      expect(pattern.test(stripped)).toBe(false);
    }
  });

  test('the SCA parser prototype-key denylist is data, not access', () => {
    // Compensating control for the exemption above: the literal may
    // exist ONLY inside the denylist constant and its documentation —
    // never as an assignment target, a property read or a spread key.
    const parsers = sources().find(({ file }) => file === 'scans/sca/parsers.ts');
    expect(parsers).toBeDefined();
    const content = parsers?.content ?? '';
    expect(content).not.toMatch(/__proto__\s*[:=]/); // no assignment/setter
    expect(content).not.toMatch(/\[\s*'__proto__'\s*\]/); // no property read
    expect(content).not.toMatch(/\.\s*__proto__/); // no dot access
    // And the denylist itself exists (defense in depth is real).
    expect(content).toContain("['__proto__', 'constructor', 'prototype']");
  });

  test('process.env is read only in config.ts', () => {
    // `student/lessons.ts` is the one additional reader of the TEXT
    // `process.env` (Phase 22): its hard-coded-secrets lesson names the
    // remediation inside a fixture string. It is not a runtime read —
    // the lesson-data structural test below proves the module has no
    // runtime imports and that `process.env` occurs only inside string
    // literals.
    const readers = sources()
      .filter(({ content }) => content.includes('process.env'))
      .map(({ file }) => file);
    expect(readers.sort()).toEqual(['config.ts', 'student/lessons.ts']);
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
