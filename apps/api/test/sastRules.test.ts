import { describe, expect, test } from 'vitest';
import {
  matchRuleLine,
  SAST_RULES,
  sastRuleById,
  type SastRule,
} from '../src/scans/sast/rules.js';

/**
 * SAST rule tests (Pump 8) — every rule needs BOTH a positive case
 * (vulnerable → finding) and negative cases (safe forms → NO finding).
 * The goal is meaningful detection, not finding-count maximization:
 * false positives on known-safe forms are treated as failures.
 */
describe('SAST rule registry', () => {
  test('ships the 47 documented rules with stable, ordered ids', () => {
    expect(SAST_RULES.map((rule) => rule.id)).toEqual(
      SAST_RULES.map((rule) => rule.id).sort((a, b) => Number(a.slice(8)) - Number(b.slice(8))),
    );
    expect(new Set(SAST_RULES.map((rule) => rule.id)).size).toBe(SAST_RULES.length);
    expect(SAST_RULES.length).toBe(47);
    expect(SAST_RULES[0]?.id).toBe('DG-SAST-001');
    expect(SAST_RULES[SAST_RULES.length - 1]?.id).toBe('DG-SAST-047');
  });

  test('CWE mappings are defensible and documented per rule', () => {
    const expected: Record<string, string | undefined> = {
      'DG-SAST-001': 'CWE-78',
      'DG-SAST-002': 'CWE-95',
      'DG-SAST-003': 'CWE-89',
      'DG-SAST-004': 'CWE-79',
      'DG-SAST-005': 'CWE-798',
      'DG-SAST-006': 'CWE-327',
      'DG-SAST-007': 'CWE-95',
      'DG-SAST-008': 'CWE-78',
      'DG-SAST-009': 'CWE-502',
      'DG-SAST-010': 'CWE-327',
      'DG-SAST-011': 'CWE-89',
      'DG-SAST-012': 'CWE-489',
      'DG-SAST-013': 'CWE-78',
      'DG-SAST-014': 'CWE-89',
      'DG-SAST-015': 'CWE-327',
      'DG-SAST-016': 'CWE-732',
      'DG-SAST-017': 'CWE-749',
      'DG-SAST-018': 'CWE-120',
      'DG-SAST-019': 'CWE-78',
      'DG-SAST-020': 'CWE-89',
      'DG-SAST-021': 'CWE-327',
      'DG-SAST-022': 'CWE-78',
      'DG-SAST-023': 'CWE-78',
      'DG-SAST-024': 'CWE-89',
      'DG-SAST-025': 'CWE-78',
      'DG-SAST-026': 'CWE-327',
      'DG-SAST-027': 'CWE-78',
      'DG-SAST-028': 'CWE-78',
      'DG-SAST-029': 'CWE-327',
      'DG-SAST-030': 'CWE-78',
      'DG-SAST-031': 'CWE-78',
      'DG-SAST-032': 'CWE-78',
      'DG-SAST-034': 'CWE-78',
      'DG-SAST-035': 'CWE-95',
      'DG-SAST-036': 'CWE-89',
      'DG-SAST-038': 'CWE-78',
      'DG-SAST-039': 'CWE-78',
      'DG-SAST-040': 'CWE-89',
      'DG-SAST-041': 'CWE-611',
      'DG-SAST-042': 'CWE-250',
      'DG-SAST-043': 'CWE-250',
      'DG-SAST-044': 'CWE-494',
      'DG-SAST-045': 'CWE-284',
      // DG-SAST-033/037/046/047 deliberately omit CWE (mixed or uncertain class — documented).
    };
    for (const rule of SAST_RULES) {
      expect(rule.cwe).toBe(expected[rule.id]);
      if (rule.cwe !== undefined) {
        expect(rule.cwe).toMatch(/^CWE-[1-9][0-9]{0,5}$/);
      }
    }
  });

  test('pattern safety: no stateful flags, no nested quantifiers (ReDoS)', () => {
    for (const rule of SAST_RULES) {
      for (const pattern of rule.patterns) {
        expect(pattern.global).toBe(false);
        expect(pattern.sticky).toBe(false);
        // Nested quantifiers (`(a+)+`, `(.*)*`) are the classic
        // catastrophic-backtracking shape: no quantifier may directly
        // follow a group that itself contains a quantifier.
        const source = pattern.source;
        expect(source).not.toMatch(/\((?:[^()]*[+*][^()]*)\)[+*]/);
        expect(source).not.toMatch(/\((?:[^()]*\{[0-9,]+\}[^()]*)\)[+*]/);
      }
    }
  });

  test('pathological inputs match in bounded time (linear regexes)', () => {
    const pathological = [
      'x'.repeat(100_000),
      `'${'x'.repeat(100_000)}`,
      'exec(' + "'".repeat(100_000),
      'exec(' + '`'.repeat(50_000) + '${',
      'db.query(`' + 'x'.repeat(100_000),
      'el.innerHTML = "' + 'x'.repeat(100_000) + '" +',
      '/'.repeat(100_000),
      '='.repeat(100_000),
    ];
    for (const line of pathological) {
      const started = Date.now();
      for (const rule of SAST_RULES) {
        matchRuleLine(rule, line);
      }
      const elapsed = Date.now() - started;
      // 6 rules over a 100 KB line must stay far below 1s — linear
      // time. A catastrophic backtracker would take minutes.
      expect(elapsed).toBeLessThan(1000);
    }
  });

  test('matching is deterministic: same line → same result, every time', () => {
    const line = 'exec(`deploy ${branch}`);';
    const rule = sastRuleById('DG-SAST-001') as SastRule;
    const first = matchRuleLine(rule, line);
    for (let i = 0; i < 100; i += 1) {
      expect(matchRuleLine(rule, line)).toEqual(first);
    }
    expect(first?.column).toBe(1);
  });
});

describe('DG-SAST-001: OS command execution (command injection)', () => {
  const rule = sastRuleById('DG-SAST-001') as SastRule;
  const vulnerable = [
    'exec(`rm -rf ${dir}`);',
    "execSync('tar czf ' + path);",
    "child.exec('convert ' + fileName + ' out.png');",
    'exec(`curl ${url} | sh`);',
    '  execSync(`mysqldump ${db}`)',
  ];
  const safe = [
    "exec('ls -la');", // constant command
    "execSync('uptime');",
    'exec(cmd);', // identifier pass-through — documented limitation, NOT flagged
    "spawn('ls', ['-la']);", // argument-array spawn without shell
    "execFile('convert', [input, output]);",
    'const executor = null;', // word-boundary check
    'myexec(`x ${y}`);', // not the exec API
    'exec(`static-template`);', // template without interpolation
  ];

  test('vulnerable forms produce a finding', () => {
    for (const line of vulnerable) {
      expect(matchRuleLine(rule, line), line).toBeDefined();
    }
  });

  test('safe forms produce NO finding (no false positives)', () => {
    for (const line of safe) {
      expect(matchRuleLine(rule, line), line).toBeUndefined();
    }
  });
});

describe('DG-SAST-002: dynamic code evaluation', () => {
  const rule = sastRuleById('DG-SAST-002') as SastRule;
  const vulnerable = [
    'eval(`(${expr})`);',
    "eval('var x = ' + userInput);",
    "new Function('return ' + body);",
    'new Function(`return ${payload}`);',
  ];
  const safe = [
    "eval('1 + 1');",
    "new Function('a', 'return a + 1');", // constant body
    'evaluate(expr);', // different identifier
    'eval(code);', // identifier pass-through — documented limitation
    'const evaluation = 1;',
  ];

  test('vulnerable forms produce a finding', () => {
    for (const line of vulnerable) {
      expect(matchRuleLine(rule, line), line).toBeDefined();
    }
  });

  test('safe forms produce NO finding', () => {
    for (const line of safe) {
      expect(matchRuleLine(rule, line), line).toBeUndefined();
    }
  });
});

describe('DG-SAST-003: SQL query construction (SQL injection)', () => {
  const rule = sastRuleById('DG-SAST-003') as SastRule;
  const vulnerable = [
    'db.query(`SELECT * FROM users WHERE id = ${id}`);',
    "db.query('SELECT * FROM t WHERE x = ' + userInput);",
    'connection.execute(`DELETE FROM s WHERE k = "${key}"`);',
    "client.execute('UPDATE t SET a = ' + a);",
  ];
  const safe = [
    "db.query('SELECT * FROM users WHERE id = ?', [id]);", // parameterized
    'db.query(sql);', // identifier — documented limitation
    'db.query(`SELECT 1`);', // constant template
    "const sql = `SELECT ${col}`;", // not a query sink
    'querySelector(`.${cls}`);', // not .query
    "pool.query('SELECT 1');",
  ];

  test('vulnerable forms produce a finding', () => {
    for (const line of vulnerable) {
      expect(matchRuleLine(rule, line), line).toBeDefined();
    }
  });

  test('safe forms produce NO finding (parameterized queries stay clean)', () => {
    for (const line of safe) {
      expect(matchRuleLine(rule, line), line).toBeUndefined();
    }
  });
});

describe('DG-SAST-004: raw HTML output (XSS)', () => {
  const rule = sastRuleById('DG-SAST-004') as SastRule;
  const vulnerable = [
    'el.innerHTML = `<b>${name}</b>`;',
    "el.innerHTML = '<b>' + name + '</b>';",
    'dangerouslySetInnerHTML: { __html: `<div>${user}</div>` }',
    "dangerouslySetInnerHTML: { __html: html + user }",
    "document.write('<p>' + user + '</p>');",
    'document.writeln(`hello ${name}`);',
  ];
  const safe = [
    'el.textContent = `<b>${name}</b>`;', // text sink — escaped
    'el.innerHTML = "<b>static</b>";', // constant markup
    "dangerouslySetInnerHTML: { __html: sanitizer.sanitize(html) }", // no interpolation/concat into __html
    'document.write("static");',
    'const innerHTML = name;', // not an assignment sink
    'el.innerHTML;',
  ];

  test('vulnerable forms produce a finding', () => {
    for (const line of vulnerable) {
      expect(matchRuleLine(rule, line), line).toBeDefined();
    }
  });

  test('safe forms produce NO finding (escaping/text sinks stay clean)', () => {
    for (const line of safe) {
      expect(matchRuleLine(rule, line), line).toBeUndefined();
    }
  });

  test('severity stays MEDIUM — taintedness is unproven without dataflow (no inflation)', () => {
    expect(rule.severity).toBe('MEDIUM');
  });
});

describe('DG-SAST-005: hardcoded credentials', () => {
  const rule = sastRuleById('DG-SAST-005') as SastRule;
  // Every literal below is a FAKE test fixture, never a real credential.
  const vulnerable = [
    "const apiKey = 'sk_live_abcdef123456';", // fake
    'password: "hunter2hunter2",', // fake
    "const DB_PASSWORD = 'p4ssw0rd-exists';", // fake
    'private_key: "AAAAAAAAAAAA";', // fake
    "authToken: 'tok_1234567890abcdef';", // fake
  ];
  const safe = [
    "const password = 'changeme';", // placeholder
    "const password = 'placeholder';",
    'const apiKey = process.env.API_KEY;', // not a literal
    "const password = 'short';", // fake — under the length floor
    "const password = '';", // empty
    'const myPasswordVar = 42;', // not a string
    'const passwordInput = "type-here";', // credential-shaped suffix word-boundary check
    'passwordHash, // no assignment',
  ];

  test('vulnerable forms produce a finding', () => {
    for (const line of vulnerable) {
      expect(matchRuleLine(rule, line), line).toBeDefined();
    }
  });

  test('safe forms produce NO finding', () => {
    for (const line of safe) {
      expect(matchRuleLine(rule, line), line).toBeUndefined();
    }
  });

  test('evidence REDACTS the credential value, preserving the code shape', () => {
    const line = "  const apiKey = 'sk_live_abcdef123456';  // fake";
    const match = matchRuleLine(rule, line);
    expect(match).toBeDefined();
    const evidence = rule.redactEvidence?.(line, match as { column: number });
    expect(evidence).toContain("apiKey = '<redacted>'");
    expect(evidence).not.toContain('sk_live_abcdef123456'); // the secret NEVER survives
    expect(evidence).toContain('// fake'); // surrounding context preserved
  });

  test('short values redact length-neutrally (evidence bound is never exceeded)', () => {
    // 8-char value + '<redacted>' would be +2 chars; the marker must
    // shrink to asterisks so the evidence length stays exact.
    const line = `const token = '${'a'.repeat(8)}';`;
    const match = matchRuleLine(rule, line);
    expect(match).toBeDefined();
    const evidence = rule.redactEvidence?.(line, match as { column: number });
    expect(evidence).toBe("const token = '********';");
    expect(evidence?.length).toBe(line.length);
  });
});

describe('DG-SAST-006: weak hash algorithms', () => {
  const rule = sastRuleById('DG-SAST-006') as SastRule;
  const vulnerable = [
    "createHash('md5')",
    'createHash("sha1")',
    "createHmac('md5', key)",
    'createHmac("sha1", secret)',
  ];
  const safe = [
    "createHash('sha256')",
    "createHash('sha512')",
    'createHash(algorithm)', // not a literal choice
    'mycreateHash("md5")', // word boundary
  ];

  test('vulnerable forms produce a finding', () => {
    for (const line of vulnerable) {
      expect(matchRuleLine(rule, line), line).toBeDefined();
    }
  });

  test('safe forms produce NO finding', () => {
    for (const line of safe) {
      expect(matchRuleLine(rule, line), line).toBeUndefined();
    }
  });

  test('severity stays LOW — non-security checksum uses are legitimate (documented)', () => {
    expect(rule.severity).toBe('LOW');
  });
});
