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
    const forbidden: Array<{
      pattern: RegExp;
      reason: string;
      exemptRuleData?: boolean;
      exemptParserDenylist?: boolean;
    }> = [
      { pattern: /child_process/, reason: 'child processes are forbidden', exemptRuleData: true },
      { pattern: /\bexec(Sync|File)?\s*\(/, reason: 'exec is forbidden', exemptRuleData: true },
      { pattern: /\bspawn(Sync)?\s*\(/, reason: 'spawn is forbidden', exemptRuleData: true },
      { pattern: /\beval\s*\(/, reason: 'eval is forbidden', exemptRuleData: true },
      {
        pattern: /new\s+Function\s*\(/,
        reason: 'Function constructor is forbidden',
        exemptRuleData: true,
      },
      {
        pattern: /__proto__/,
        reason: '__proto__ access is forbidden',
        exemptParserDenylist: true,
      },
    ];
    const violations: string[] = [];
    for (const { file, content } of sources()) {
      for (const { pattern, reason, exemptRuleData, exemptParserDenylist } of forbidden) {
        if (file === RULE_DATA_FILE && exemptRuleData === true) {
          continue;
        }
        if (file === PARSER_DATALIST_FILE && exemptParserDenylist === true) {
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
