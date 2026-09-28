import { describe, expect, test } from 'vitest';
import {
  characterClasses,
  matchSecretsRuleLine,
  SECRETS_RULES,
  secretsRuleById,
  shannonEntropy,
} from '../src/scans/secrets/rules.js';

/**
 * Secrets rule framework tests (Pump 10) — the detection matrix and
 * the FALSE-POSITIVE defenses. Every fixture value is SYNTHETIC
 * (obviously fake, same-line marked) — the DATASET LOCK holds: no
 * real credential material exists in this repository.
 *
 * NO-FAKE contract under test: a rule fires ONLY on a real match of
 * its deterministic pattern; placeholders, UUIDs, plain hashes,
 * public keys and documentation examples NEVER become findings.
 */

// --- synthetic positive fixtures (values chosen to avoid the
// placeholder denylist so detection is exercised honestly) ----------
const SYNTH = {
  awsKey: 'AKIAP10QZ9WM7XK2BR4J', // fake-test fixture
  githubToken: 'ghp_P10aBcDeFgHiJkLmNoPqRsTuVwXyZ123456A', // fake-test fixture
  stripeKey: 'sk_live_P10qZW9xK2mBr4JdN7vH', // fake-test fixture
  slackToken: 'xoxb-P10AbCdEfGhIjKlMnOpQrStUv01', // fake-test fixture
  googleKey: 'AIzaP10gOoQzW9xK2mBr4JdN7vHcTfLpYuIwXeR', // fake-test fixture
  bearer: 'P10AbCdEfGhIjKlMnOpQrStUvWx40', // fake-test fixture
  dbPassword: 'P10-sUp3r-Pg', // fake-test fixture
  apiKeyValue: 'P10ApiKeyZx9Qw8Er7Ty6Uio5Pl', // fake-test fixture
  passwordValue: 'P10-C0rr3ct-Horse-Stapl3-Batt3ry', // fake-test fixture
  keyBody: 'Zml4dHVyZS1zeW50aGV0aWMta2V5LWJvZHktbm90LXJlYWw9PQ==', // fake-test fixture
} as const;

/** PEM fixtures are CONCATENATED so no literal key-block header exists in this file. */
const PEM_PRIVATE_HEADER = ['-----BEGIN RSA ', 'PRIVATE KEY-----'].join(''); // fake-test fixture
const PEM_PRIVATE_FOOTER = ['-----END RSA ', 'PRIVATE KEY-----'].join(''); // fake-test fixture

function fires(ruleId: string, line: string): boolean {
  const rule = secretsRuleById(ruleId);
  if (rule === undefined) {
    throw new Error(`unknown rule ${ruleId}`);
  }
  return matchSecretsRuleLine(rule, line) !== undefined;
}

describe('secrets rules: registry integrity', () => {
  test('closed registry: stable ids, ordered, documented severity AND confidence', () => {
    expect(SECRETS_RULES.map((rule) => rule.id)).toEqual([
      'DG-SEC-001',
      'DG-SEC-002',
      'DG-SEC-003',
      'DG-SEC-004',
      'DG-SEC-005',
      'DG-SEC-006',
    ]);
    for (const rule of SECRETS_RULES) {
      expect(rule.title.length).toBeGreaterThan(0);
      expect(rule.description.length).toBeGreaterThan(0);
      expect(rule.remediation.length).toBeGreaterThan(0);
      expect(rule.limitation.length).toBeGreaterThan(0);
      expect(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).toContain(rule.severity);
      expect(['LOW', 'MEDIUM', 'HIGH']).toContain(rule.confidence);
      expect(rule.category.length).toBeGreaterThan(0);
      // Every rule must declare how its evidence is made safe.
      expect(rule.matchOnlyEvidence === true || rule.valueSpan !== undefined).toBe(true);
    }
    // Severity policy (documented, deterministic — never scary-defaulted):
    expect(secretsRuleById('DG-SEC-001')?.severity).toBe('HIGH'); // no CRITICAL in v1
    expect(secretsRuleById('DG-SEC-006')?.severity).toBe('MEDIUM'); // heuristic stays modest
    expect(secretsRuleById('DG-SEC-006')?.confidence).toBe('LOW'); // labeled uncertainty
  });

  test('patterns are linear-time-safe: no g/y flags, no nested quantifiers', () => {
    for (const rule of SECRETS_RULES) {
      for (const pattern of rule.patterns) {
        expect(pattern.global).toBe(false);
        expect(pattern.sticky).toBe(false);
        expect(pattern.source).not.toMatch(/\{[0-9]+,\}[^(]*\{[0-9]+,\}/); // no nested ranges
        expect(pattern.source).not.toMatch(/\([^)]*[+*][^)]*\)[s+*]{2,}/); // no stacked groups
      }
    }
  });

  test('no rule text ever claims verification or liveness', () => {
    for (const rule of SECRETS_RULES) {
      const text = `${rule.title}\n${rule.description}\n${rule.remediation}`;
      expect(text).not.toMatch(/\b(valid credential|active credential|compromised|has been revoked|is live|verified live)\b/i);
    }
  });

  test('pathological lines stay bounded (ReDoS-shaped inputs)', () => {
    const pathological = [
      'a'.repeat(5000),
      `${'x'.repeat(3000)}${SYNTH.awsKey}`,
      `${SYNTH.awsKey}${'y'.repeat(3000)}`,
      `postgres://${'u'.repeat(2000)}:${'p'.repeat(2000)}@host`,
      `Bearer ${'t'.repeat(4000)}`,
      `${PEM_PRIVATE_HEADER}${'Z'.repeat(4000)}`,
    ];
    const start = Date.now();
    for (const line of pathological) {
      for (const rule of SECRETS_RULES) {
        matchSecretsRuleLine(rule, line);
      }
    }
    expect(Date.now() - start).toBeLessThan(2000); // linear, not exponential
  });
});

describe('DG-SEC-001: private key blocks', () => {
  test('detects supported private-key header kinds', () => {
    for (const kind of ['RSA ', 'EC ', 'DSA ', 'OPENSSH ', 'PGP ', 'ENCRYPTED ', '']) {
      const header = ['-----BEGIN ', kind, 'PRIVATE KEY-----'].join(''); // fake-test fixture
      expect(fires('DG-SEC-001', header)).toBe(true);
    }
    expect(fires('DG-SEC-001', PEM_PRIVATE_HEADER)).toBe(true);
    expect(fires('DG-SEC-001', `const x = \`${PEM_PRIVATE_HEADER}\``)).toBe(true);
  });

  test('public keys, certificates and END lines do NOT fire (false positives)', () => {
    expect(fires('DG-SEC-001', '-----BEGIN PUBLIC KEY-----')).toBe(false);
    expect(fires('DG-SEC-001', '-----BEGIN CERTIFICATE-----')).toBe(false);
    expect(fires('DG-SEC-001', PEM_PRIVATE_FOOTER)).toBe(false);
    expect(fires('DG-SEC-001', 'the private key is on the server')).toBe(false);
    expect(fires('DG-SEC-001', '-----BEGIN OPENSSH PUBLIC KEY-----')).toBe(false);
  });

  test('the evidence is EXACTLY the header — an inlined body cannot leak', () => {
    const rule = secretsRuleById('DG-SEC-001');
    const hostile = `${PEM_PRIVATE_HEADER}${SYNTH.keyBody}`; // body inlined on the SAME line
    const match = matchSecretsRuleLine(rule!, hostile);
    expect(match).toBeDefined();
    expect(match?.text).not.toContain(SYNTH.keyBody); // match = header only
    expect(match?.text).toBe(PEM_PRIVATE_HEADER);
  });
});

describe('DG-SEC-002: known-prefix service credentials', () => {
  test('detects AWS/GitHub/Stripe/Slack/Google formats', () => {
    expect(fires('DG-SEC-002', `aws_key = "${SYNTH.awsKey}"`)).toBe(true);
    expect(fires('DG-SEC-002', SYNTH.githubToken)).toBe(true);
    expect(fires('DG-SEC-002', `token: ${SYNTH.stripeKey}`)).toBe(true);
    expect(fires('DG-SEC-002', SYNTH.slackToken)).toBe(true);
    expect(fires('DG-SEC-002', SYNTH.googleKey)).toBe(true);
  });

  test('documentation examples and clearly-marked values do NOT fire', () => {
    expect(fires('DG-SEC-002', 'AKIAIOSFODNN7EXAMPLE')).toBe(false); // the AWS docs example
    expect(fires('DG-SEC-002', 'ASIAYOURACCOUNTIDHERE0')).toBe(false); // 'your' placeholder
    expect(fires('DG-SEC-002', 'ghp_ThisIsAExampleTokenForDocsAAAAAAAAAAAAAAAAA')).toBe(false);
    expect(fires('DG-SEC-002', 'sk_test_P10qZW9xK2mBr4JdN7vH')).toBe(false); // test-mode key
    expect(fires('DG-SEC-002', 'AKIA')).toBe(false); // too short
    expect(fires('DG-SEC-002', 'aklap10qz9wm7xk2br4j')).toBe(false); // wrong case = wrong format
  });
});

describe('DG-SEC-003: bearer tokens', () => {
  test('detects distinctive bearer tokens in headers and assignments', () => {
    expect(fires('DG-SEC-003', `Authorization: Bearer ${SYNTH.bearer}`)).toBe(true);
    expect(fires('DG-SEC-003', `headers = { Authorization: "Bearer ${SYNTH.bearer}" }`)).toBe(true);
    expect(fires('DG-SEC-003', `bearer_token = '${SYNTH.bearer}'`)).toBe(true);
  });

  test('short/placeholder/interpolated bearers do NOT fire', () => {
    expect(fires('DG-SEC-003', 'Authorization: Bearer short123')).toBe(false);
    expect(fires('DG-SEC-003', 'Authorization: Bearer <YOUR_TOKEN>')).toBe(false);
    expect(fires('DG-SEC-003', "Authorization: Bearer ${process.env.TOKEN}")).toBe(false);
    expect(fires('DG-SEC-003', 'authorization = Bearer changeme12345678')).toBe(false);
    expect(fires('DG-SEC-003', 'bearer_token = null')).toBe(false);
  });
});

describe('DG-SEC-004: credential-bearing connection URLs', () => {
  test('detects user:password URLs across schemes', () => {
    expect(fires('DG-SEC-004', `db = "postgres://svc:${SYNTH.dbPassword}@db.host:5432/app"`)).toBe(true);
    expect(fires('DG-SEC-004', `mongodb+srv://svc:${SYNTH.dbPassword}@cluster.example.net`)).toBe(true);
    expect(fires('DG-SEC-004', `redis://default:${SYNTH.dbPassword}@cache:6379`)).toBe(true);
    expect(fires('DG-SEC-004', `amqp://svc:${SYNTH.dbPassword}@mq:5672/vhost`)).toBe(true);
  });

  test('placeholder passwords and credential-less URLs do NOT fire', () => {
    expect(fires('DG-SEC-004', 'postgres://svc:password@db/app')).toBe(false);
    expect(fires('DG-SEC-004', 'postgres://svc:changeme@db/app')).toBe(false);
    expect(fires('DG-SEC-004', 'postgres://user:${DB_PASS}@db/app')).toBe(false);
    expect(fires('DG-SEC-004', 'postgres://svc@db/app')).toBe(false); // no inline credential
    expect(fires('DG-SEC-004', 'https://user:pass@example.com')).toBe(false); // not a credentialed scheme
  });
});

describe('DG-SEC-005: api-key assignments', () => {
  test('detects long mixed-class literals under api-key names', () => {
    expect(fires('DG-SEC-005', `apiKey = '${SYNTH.apiKeyValue}'`)).toBe(true); // fake
    expect(fires('DG-SEC-005', `"api_key": "${SYNTH.apiKeyValue}"`)).toBe(true); // fake
    expect(fires('DG-SEC-005', `MY_API_KEY = "${SYNTH.apiKeyValue}"`)).toBe(true);
    expect(fires('DG-SEC-005', `x-api-key: ${SYNTH.apiKeyValue}`)).toBe(true);
  });

  test('placeholders, templates, short and single-class values do NOT fire', () => {
    expect(fires('DG-SEC-005', "apiKey = '<YOUR_API_KEY>'")).toBe(false); // fake
    expect(fires('DG-SEC-005', "apiKey = 'your-api-key-here'")).toBe(false);
    expect(fires('DG-SEC-005', "apiKey = 'abcdefghijklmnopqrst'")).toBe(false); // one class // fake
    expect(fires('DG-SEC-005', "apiKey = 'P10abc'")).toBe(false); // too short // fake
    expect(fires('DG-SEC-005', "apiKey = process.env.API_KEY")).toBe(false); // not a literal
    expect(fires('DG-SEC-005', "apiKey = '550e8400-e29b-41d4-a716-446655440000'")).toBe(false); // UUID // fake
    // Bare (unquoted) config values with the right shape DO fire —
    // the quotes are the config file's choice, not the secret's.
    expect(fires('DG-SEC-005', `api_key: ${SYNTH.apiKeyValue}`)).toBe(true);
  });
});

describe('DG-SEC-006: generic password heuristic (structure + entropy)', () => {
  test('fires on strong values under credential-family names', () => {
    expect(fires('DG-SEC-006', `password = '${SYNTH.passwordValue}'`)).toBe(true); // fake
    expect(fires('DG-SEC-006', `DB_PASSWORD: "${SYNTH.passwordValue}"`)).toBe(true);
    expect(fires('DG-SEC-006', `client_secret = '${SYNTH.passwordValue}'`)).toBe(true); // fake
  });

  test('placeholders and weak values do NOT fire', () => {
    expect(fires('DG-SEC-006', "password = 'changeme12345'")).toBe(false);
    expect(fires('DG-SEC-006', "password = 'example-value-here'")).toBe(false);
    expect(fires('DG-SEC-006', 'password = "Str0ng!ButInDocsExample"')).toBe(false); // 'example'
    expect(fires('DG-SEC-006', "password = 'aaaaaaaaaaaaaaaa'")).toBe(false); // low entropy // fake
    expect(fires('DG-SEC-006', 'password = "P10abc"')).toBe(false); // too short // fake
  });

  test('UUIDs and plain hashes are never secrets here (false positives)', () => {
    expect(fires('DG-SEC-006', "password = '550e8400-e29b-41d4-a716-446655440000'")).toBe(false); // fake
    expect(
      fires('DG-SEC-006', "password = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'"), // fake
    ).toBe(false); // sha256 hex
    expect(fires('DG-SEC-006', "token = '098f6bcd4621d373cade4e832627b4f6'")).toBe(false); // md5 hex
  });

  test('entropy and class helpers are deterministic and documented', () => {
    expect(shannonEntropy('')).toBe(0);
    expect(shannonEntropy('aaaa')).toBe(0);
    // 16 distinct chars → exactly 4 bits/char.
    expect(shannonEntropy('0123456789abcdef')).toBe(4);
    expect(characterClasses('aaaa')).toBe(1);
    expect(characterClasses('Aa1!')).toBe(4);
  });
});

describe('cross-rule honesty', () => {
  test('ordinary code with no secrets produces ZERO matches', () => {
    const ordinary = [
      'export function add(a: number, b: number) { return a + b; }',
      "const greeting = 'hello world';",
      'import path from "node:path";',
      'db.query("SELECT * FROM users WHERE id = ?", [id]);',
      'const requestId = "f476b31c-9d00-42e1-89fe-f25a929ae701";', // a UUID is an ID
      'integrity: "sha512-cG9tcDktZTJlLWludGVncml0eS12YWx1ZS1mYWtlPT0=",', // package integrity
      'const PORT = 3001;',
      '# just a comment about tokens in documentation',
    ];
    for (const line of ordinary) {
      for (const rule of SECRETS_RULES) {
        expect(matchSecretsRuleLine(rule, line), `${rule.id} on: ${line}`).toBeUndefined();
      }
    }
  });

  test('the same line can legitimately match multiple rules (ids stay distinct)', () => {
    const line = `password = '${SYNTH.passwordValue}'; api_key = '${SYNTH.apiKeyValue}'`; // fake-test fixture
    const matched = SECRETS_RULES.filter((rule) => matchSecretsRuleLine(rule, line) !== undefined);
    expect(matched.map((rule) => rule.id).sort()).toEqual(['DG-SEC-005', 'DG-SEC-006']);
  });
});
