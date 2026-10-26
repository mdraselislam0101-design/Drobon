import { describe, expect, test } from 'vitest';
import { matchRuleLine, SAST_RULES, sastRuleById } from '../src/scans/sast/rules.js';
import { TEST_SAST_RULES, TEST_SAST_RULE_IDS } from './fixtures/testData.js';

/**
 * SAST rule framework tests — paid-tool parity: production has 0 embedded
 * rules (data lives in Drobon-Dataset), tests use fixtures for verification.
 */
describe('SAST rule registry', () => {
  test('production registry is empty — data lives in dataset (paid-tool parity)', () => {
    expect(SAST_RULES.length).toBe(0);
    expect(sastRuleById('DG-SAST-001')).toBeUndefined();
  });

  test('test fixtures provide the expected DG rules for verification', () => {
    expect(TEST_SAST_RULES.map((r) => r.id).sort()).toEqual(TEST_SAST_RULE_IDS.sort());
    expect(TEST_SAST_RULES.length).toBe(6);
    expect(TEST_SAST_RULES[0]?.id).toBe('DG-SAST-001');
  });

  test('pattern safety: no stateful flags, no nested quantifiers (ReDoS)', () => {
    for (const rule of [...SAST_RULES, ...TEST_SAST_RULES]) {
      for (const pattern of rule.patterns) {
        expect(pattern.global).toBe(false);
        expect(pattern.sticky).toBe(false);
        const source = pattern.source;
        expect(source).not.toMatch(/\((?:[^()]*[+*][^()]*\))[+*]/);
        expect(source).not.toMatch(/\((?:[^()]*\{[0-9,]+\}[^()]*\))[+*]/);
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
      for (const rule of TEST_SAST_RULES) {
        matchRuleLine(rule, line);
      }
      const elapsed = Date.now() - started;
      expect(elapsed).toBeLessThan(1000);
    }
  });

  test('matching is deterministic: same line → same result, every time', () => {
    const line = 'exec(`deploy ${branch}`);';
    const rule = TEST_SAST_RULES.find((r) => r.id === 'DG-SAST-001')!;
    const first = matchRuleLine(rule, line);
    for (let i = 0; i < 100; i += 1) {
      expect(matchRuleLine(rule, line)).toEqual(first);
    }
    expect(first?.column).toBe(1);
  });
});

describe('DG-SAST-001: OS command execution (command injection)', () => {
  const rule = TEST_SAST_RULES.find((r) => r.id === 'DG-SAST-001')!;
  const vulnerable = [
    'exec(`rm -rf ${dir}`);',
    "execSync('tar czf ' + path);",
    "child.exec('convert ' + fileName + ' out.png');",
    'exec(`curl ${url} | sh`);',
    '  execSync(`mysqldump ${db}`)',
  ];
  const safe = [
    "exec('ls -la');",
    "execSync('uptime');",
    'exec(cmd);',
    "spawn('ls', ['-la']);",
    "execFile('convert', [input, output]);",
    'const executor = null;',
    'myexec(`x ${y}`);',
    'exec(`static-template`);',
  ];
  test('vulnerable forms produce a finding', () => {
    for (const line of vulnerable) expect(matchRuleLine(rule, line), line).toBeDefined();
  });
  test('safe forms produce NO finding (no false positives)', () => {
    for (const line of safe) expect(matchRuleLine(rule, line), line).toBeUndefined();
  });
});

describe('DG-SAST-002: dynamic code evaluation', () => {
  const rule = TEST_SAST_RULES.find((r) => r.id === 'DG-SAST-002')!;
  const vulnerable = [
    'eval(`(${expr})`);',
    "eval('var x = ' + userInput);",
    "new Function('return ' + body);",
    'new Function(`return ${payload}`);',
  ];
  const safe = [
    "eval('1 + 1');",
    "new Function('a', 'return a + 1');",
    'evaluate(expr);',
    'eval(code);',
    'const evaluation = 1;',
  ];
  test('vulnerable forms produce a finding', () => {
    for (const line of vulnerable) expect(matchRuleLine(rule, line), line).toBeDefined();
  });
  test('safe forms produce NO finding', () => {
    for (const line of safe) expect(matchRuleLine(rule, line), line).toBeUndefined();
  });
});

describe('DG-SAST-003: SQL query construction (SQL injection)', () => {
  const rule = TEST_SAST_RULES.find((r) => r.id === 'DG-SAST-003')!;
  const vulnerable = [
    'db.query(`SELECT * FROM users WHERE id = ${id}`);',
    "db.query('SELECT * FROM t WHERE x = ' + userInput);",
    'connection.execute(`DELETE FROM s WHERE k = "${key}"`);',
    "client.execute('UPDATE t SET a = ' + a);",
  ];
  const safe = [
    "db.query('SELECT * FROM users WHERE id = ?', [id]);",
    'db.query(sql);',
    'db.query(`SELECT 1`);',
    "const sql = `SELECT ${col}`;",
    'querySelector(`.${cls}`);',
    "pool.query('SELECT 1');",
  ];
  test('vulnerable forms produce a finding', () => {
    for (const line of vulnerable) expect(matchRuleLine(rule, line), line).toBeDefined();
  });
  test('safe forms produce NO finding (parameterized queries stay clean)', () => {
    for (const line of safe) expect(matchRuleLine(rule, line), line).toBeUndefined();
  });
});

describe('DG-SAST-004: raw HTML output (XSS)', () => {
  const rule = TEST_SAST_RULES.find((r) => r.id === 'DG-SAST-004')!;
  const vulnerable = [
    'el.innerHTML = `<b>${name}</b>`;',
    "el.innerHTML = '<b>' + name + '</b>';",
    'dangerouslySetInnerHTML: { __html: `<div>${user}</div>` }',
    "dangerouslySetInnerHTML: { __html: html + user }",
    "document.write('<p>' + user + '</p>');",
    'document.writeln(`hello ${name}`);',
  ];
  const safe = [
    'el.textContent = `<b>${name}</b>`;',
    'el.innerHTML = "<b>static</b>";',
    "dangerouslySetInnerHTML: { __html: sanitizer.sanitize(html) }",
    'document.write("static");',
    'const innerHTML = name;',
    'el.innerHTML;',
  ];
  test('vulnerable forms produce a finding', () => {
    for (const line of vulnerable) expect(matchRuleLine(rule, line), line).toBeDefined();
  });
  test('safe forms produce NO finding (escaping/text sinks stay clean)', () => {
    for (const line of safe) expect(matchRuleLine(rule, line), line).toBeUndefined();
  });
  test('severity stays MEDIUM — taintedness is unproven without dataflow (no inflation)', () => {
    expect(rule.severity).toBe('MEDIUM');
  });
});

describe('DG-SAST-005: hardcoded credentials', () => {
  const rule = TEST_SAST_RULES.find((r) => r.id === 'DG-SAST-005')!;
  const vulnerable = [
    "const apiKey = 'sk_live_abcdef123456';", // fake fixture
    'password: "hunter2hunter2",',
    "const DB_PASSWORD = 'p4ssw0rd-exists';",
    'private_key: "AAAAAAAAAAAA";', // fake fixture
    "authToken: 'tok_1234567890abcdef';", // fake fixture
  ];
  const safe = [
    "const password = 'changeme';",
    "const password = 'placeholder';",
    'const apiKey = process.env.API_KEY;',
    "const password = 'short';", // fake fixture: below the rule length bound
    "const password = '';",
    'const myPasswordVar = 42;',
    'const passwordInput = "type-here";',
    'passwordHash, // no assignment',
  ];
  test('vulnerable forms produce a finding', () => {
    for (const line of vulnerable) expect(matchRuleLine(rule, line), line).toBeDefined();
  });
  test('safe forms produce NO finding', () => {
    for (const line of safe) expect(matchRuleLine(rule, line), line).toBeUndefined();
  });
  test('evidence REDACTS the credential value, preserving the code shape', () => {
    const line = "  const apiKey = 'sk_live_abcdef123456';  // fake";
    const match = matchRuleLine(rule, line);
    expect(match).toBeDefined();
    const evidence = rule.redactEvidence?.(line, match as { column: number });
    expect(evidence).toContain("apiKey = '<redacted>'");
    expect(evidence).not.toContain('sk_live_abcdef123456');
    expect(evidence).toContain('// fake');
  });
  test('short values redact length-neutrally (evidence bound is never exceeded)', () => {
    const line = `const token = '${'a'.repeat(8)}';`;
    const match = matchRuleLine(rule, line);
    expect(match).toBeDefined();
    const evidence = rule.redactEvidence?.(line, match as { column: number });
    expect(evidence).toBe("const token = '********';");
    expect(evidence?.length).toBe(line.length);
  });
});

describe('DG-SAST-006: weak hash algorithms', () => {
  const rule = TEST_SAST_RULES.find((r) => r.id === 'DG-SAST-006')!;
  const vulnerable = [
    "createHash('md5')",
    'createHash("sha1")',
    "createHmac('md5', key)",
    'createHmac("sha1", secret)',
  ];
  const safe = [
    "createHash('sha256')",
    "createHash('sha512')",
    'createHash(algorithm)',
    'mycreateHash("md5")',
  ];
  test('vulnerable forms produce a finding', () => {
    for (const line of vulnerable) expect(matchRuleLine(rule, line), line).toBeDefined();
  });
  test('safe forms produce NO finding', () => {
    for (const line of safe) expect(matchRuleLine(rule, line), line).toBeUndefined();
  });
  test('severity stays LOW — non-security checksum uses are legitimate (documented)', () => {
    expect(rule.severity).toBe('LOW');
  });
});
