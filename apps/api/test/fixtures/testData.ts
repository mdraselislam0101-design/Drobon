/**
 * Test fixtures for dataset-decoupled engines.
 * These are TEST-ONLY rule fixtures that mimic the old embedded DG-* rules
 * but live in test code, not in production src/. Production src has 0
 * embedded rules and loads all data from Drobon-Dataset via dataset service.
 * Paid-tool parity: production data is external, test data is fixture.
 */
import type { SastRule } from '../../src/scans/sast/rules.js';
import type { SecretsRule } from '../../src/scans/secrets/rules.js';

// Minimal SAST test rules — 6 rules covering the original v1 catalog
// Patterns copied from the old src/scans/sast/rules.ts for test fidelity
const JS_FAMILY: readonly string[] = ['javascript', 'typescript', 'jsx', 'tsx'];
export const TEST_SAST_RULES: readonly SastRule[] = [
  {
    id: 'DG-SAST-001',
    languages: JS_FAMILY,
    title: 'OS command built from dynamic input',
    description: 'A shell command is constructed with interpolated or concatenated values before being passed to exec/execSync.',
    severity: 'HIGH',
    cwe: 'CWE-78',
    category: 'command-injection',
    remediation: 'Avoid a shell entirely: use execFile/spawn with an argument array and no shell.',
    limitation: 'Lexical, line-based, no dataflow.',
    patterns: [/\bexec(?:Sync)?\s*\(\s*(?:`[^`]*\$\{|(['\"]).*?\1\s*\+)/],
  },
  {
    id: 'DG-SAST-002',
    languages: JS_FAMILY,
    title: 'Code evaluated from a dynamically built string',
    description: 'A string built with interpolated or concatenated values is passed to eval or new Function.',
    severity: 'HIGH',
    cwe: 'CWE-95',
    category: 'code-injection',
    remediation: 'Remove the dynamic evaluation: use data structures, maps or explicit branches.',
    limitation: 'Lexical, line-based, no dataflow.',
    patterns: [/\beval\s*\(\s*(?:`[^`]*\$\{|(['\"]).*?\1\s*\+)/, /\bnew\s+Function\s*\(\s*(?:`[^`]*\$\{|(['\"]).*?\1\s*\+)/],
  },
  {
    id: 'DG-SAST-003',
    languages: JS_FAMILY,
    title: 'SQL query built from dynamic string construction',
    description: 'SQL text is constructed with interpolated or concatenated values and passed to a query/execute call.',
    severity: 'HIGH',
    cwe: 'CWE-89',
    category: 'sql-injection',
    remediation: 'Use parameterized queries: keep the SQL text a constant and pass values as parameters.',
    limitation: 'Lexical, line-based, no dataflow.',
    patterns: [/\.query\s*\(\s*(?:`[^`]*\$\{|(['\"]).*?\1\s*\+)/, /\.execute\s*\(\s*(?:`[^`]*\$\{|(['\"]).*?\1\s*\+)/],
  },
  {
    id: 'DG-SAST-004',
    languages: JS_FAMILY,
    title: 'Raw HTML built from dynamic input',
    description: 'Markup constructed with interpolated or concatenated values is assigned to a raw-HTML sink.',
    severity: 'MEDIUM',
    cwe: 'CWE-79',
    category: 'xss',
    remediation: 'Render dynamic values as TEXT (textContent, React children).',
    limitation: 'Lexical, line-based, no dataflow.',
    patterns: [/\.innerHTML\s*=[^=]*(?:`[^`]*\$\{|(['\"]).*?\1\s*\+)/, /__html\s*:\s*(?:`[^`]*\$\{|(['\"]).*?\1\s*\+|[A-Za-z_$][\w$.]*\s*\+)/, /\bdocument\.write(?:ln)?\s*\(\s*(?:`[^`]*\$\{|(['\"]).*?\1\s*\+)/],
  },
  {
    id: 'DG-SAST-005',
    title: 'Hardcoded credential-like literal',
    description: 'A credential-named variable or property is assigned a literal value.',
    severity: 'MEDIUM',
    cwe: 'CWE-798',
    category: 'hardcoded-credential',
    remediation: 'Move the value out of source code: read it from the environment or a secret manager.',
    limitation: 'Lexical heuristic on credential-shaped names.',
    patterns: [/\b(?:[A-Za-z0-9]+_)?(?:password|passwd|pwd|secret|secrets?_?key|apikey|api_key|token|auth_?token|access_?token|client_?secret|private_?key|credentials?)\b\s*[:=]\s*(['\"])(?!(?:changeme|placeholder|example|dummy|redacted|password|secret|token|undefined|xxx+|your[-_a-z]*)\1)[A-Za-z0-9_+/=.\\-]{8,}\1/i],
    redactEvidence: (line: string, match: { column: number }): string => {
      const literal = /(['\"])[A-Za-z0-9_+/=.\\-]{8,}\1/i.exec(line.slice(match.column - 1));
      if (literal === null) return line;
      const start = match.column - 1 + literal.index;
      const quote = literal[0][0] ?? '"';
      const value = literal[0].slice(1, -1);
      const replacement = value.length >= 10 ? '<redacted>' : '*'.repeat(value.length);
      return `${line.slice(0, start)}${quote}${replacement}${quote}${line.slice(start + literal[0].length)}`;
    },
  },
  {
    id: 'DG-SAST-006',
    languages: JS_FAMILY,
    title: 'Weak hash algorithm (MD5/SHA-1) in a cryptographic API',
    description: 'createHash/createHmac is called with md5 or sha1.',
    severity: 'LOW',
    cwe: 'CWE-327',
    category: 'weak-cryptography',
    remediation: 'Use a modern algorithm (SHA-256 or stronger).',
    limitation: 'Detects the algorithm choice in createHash/createHmac calls only.',
    patterns: [/\bcreate(?:Hash|Hmac)\s*\(\s*(['\"])(?:md5|sha1)\1/],
  },
];

// Minimal secrets test rules — 2 rules for smoke tests
export const TEST_SECRETS_RULES: readonly SecretsRule[] = [
  {
    id: 'DG-SEC-001',
    title: 'Private key block detected in source',
    description: 'A PEM private-key header was found.',
    category: 'private-key',
    severity: 'HIGH',
    confidence: 'HIGH',
    cwe: 'CWE-798',
    remediation: 'Remove the key file from the source snapshot.',
    limitation: 'Matches PEM-style private-key headers only.',
    patterns: [/-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----/],
    matchOnlyEvidence: true,
  },
  {
    id: 'DG-SEC-002',
    title: 'Known-format service credential detected',
    description: 'A credential matching a documented service format was found.',
    category: 'service-credential',
    severity: 'HIGH',
    confidence: 'HIGH',
    cwe: 'CWE-798',
    remediation: 'Move the credential to the environment or a secret manager.',
    limitation: 'Prefix-shaped only.',
    patterns: [/\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/, /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/],
    validate: (matched: string) => !matched.toLowerCase().includes('example'),
    valueSpan: (match) => ({ start: 0, end: match.text.length }),
  },
];

export const TEST_SAST_RULE_IDS = TEST_SAST_RULES.map((r) => r.id);

// Minimal DAST test rules — 8 rules mimicking old hardcoded DG-DAST-* logic
// Each uses a pack check that will match the FIXTURE_DAST_RESPONSE in helpers.ts
export const TEST_DAST_RULES: readonly any[] = [
  {
    id: 'DG-DAST-001',
    title: 'Target uses unencrypted HTTP',
    description: 'The observed target URL uses HTTP.',
    severity: 'MEDIUM',
    cwe: 'CWE-319',
    category: 'transport',
    remediation: 'Serve the application over HTTPS.',
    limitation: 'Only checks URL scheme.',
    check: { type: 'http-url', requireScheme: 'http' },
  },
  {
    id: 'DG-DAST-002',
    title: 'Strict-Transport-Security is missing or ineffective',
    description: 'The HTTPS response did not provide HSTS.',
    severity: 'LOW',
    category: 'headers',
    remediation: 'Configure HSTS.',
    limitation: 'Only checks presence.',
    check: { type: 'missing-response-header', header: 'strict-transport-security' },
  },
  {
    id: 'DG-DAST-003',
    title: 'X-Content-Type-Options is not nosniff',
    description: 'The response did not set X-Content-Type-Options to nosniff.',
    severity: 'LOW',
    category: 'headers',
    remediation: 'Set X-Content-Type-Options: nosniff.',
    limitation: 'Only checks header.',
    check: { type: 'missing-response-header', header: 'x-content-type-options' },
  },
  {
    id: 'DG-DAST-004',
    title: 'No frame-embedding restriction was observed',
    description: 'Neither X-Frame-Options nor CSP frame-ancestors was present.',
    severity: 'LOW',
    category: 'headers',
    remediation: 'Set frame restriction.',
    limitation: 'Only checks X-Frame-Options.',
    check: { type: 'missing-response-header', header: 'x-frame-options' },
  },
  {
    id: 'DG-DAST-005',
    title: 'CORS allows credentials with a broad or reflected origin',
    description: 'CORS headers showed permissive origin.',
    severity: 'MEDIUM',
    category: 'cors',
    remediation: 'Allow only explicit trusted origins.',
    limitation: 'Synthetic origin check.',
    check: { type: 'response-header-matches', header: 'access-control-allow-origin', valuePattern: 'https://drobon-aegis.invalid' },
  },
  {
    id: 'DG-DAST-006',
    title: 'Server implementation headers are exposed',
    description: 'Response exposed implementation header.',
    severity: 'INFO',
    category: 'info-disclosure',
    remediation: 'Remove implementation headers.',
    limitation: 'Only checks presence.',
    check: { type: 'response-header-matches', header: 'server', valuePattern: '.*' },
  },
  {
    id: 'DG-DAST-007',
    title: 'Cookie security attributes are incomplete',
    description: 'Cookie omitted security attributes.',
    severity: 'LOW',
    category: 'cookies',
    remediation: 'Set Secure, HttpOnly, SameSite.',
    limitation: 'Only checks first cookie.',
    check: { type: 'cookie-missing-flag', flag: 'Secure' },
  },
  {
    id: 'DG-DAST-008',
    title: 'HTTPS document references insecure HTTP resources',
    description: 'HTML contained HTTP subresource.',
    severity: 'MEDIUM',
    category: 'mixed-content',
    remediation: 'Serve all subresources over HTTPS.',
    limitation: 'Only checks body for http://',
    check: { type: 'response-body-matches', valuePattern: 'http://' },
  },
];

export const TEST_DAST_RULE_IDS = TEST_DAST_RULES.map((r: any) => r.id);
