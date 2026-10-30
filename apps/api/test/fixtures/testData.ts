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
    patterns: [/\bexec(?:Sync)?\s*\(\s*(?:`[^`]*\$\{|(['"]).*?\1\s*\+)/],
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
    patterns: [/\beval\s*\(\s*(?:`[^`]*\$\{|(['"]).*?\1\s*\+)/, /\bnew\s+Function\s*\(\s*(?:`[^`]*\$\{|(['"]).*?\1\s*\+)/],
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
    patterns: [/\.query\s*\(\s*(?:`[^`]*\$\{|(['"]).*?\1\s*\+)/, /\.execute\s*\(\s*(?:`[^`]*\$\{|(['"]).*?\1\s*\+)/],
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
    patterns: [/\.innerHTML\s*=[^=]*(?:`[^`]*\$\{|(['"]).*?\1\s*\+)/, /__html\s*:\s*(?:`[^`]*\$\{|(['"]).*?\1\s*\+|[A-Za-z_$][\w$.]*\s*\+)/, /\bdocument\.write(?:ln)?\s*\(\s*(?:`[^`]*\$\{|(['"]).*?\1\s*\+)/],
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
    patterns: [/\b(?:[A-Za-z0-9]+_)?(?:password|passwd|pwd|secret|secrets?_?key|apikey|api_key|token|auth_?token|access_?token|client_?secret|private_?key|credentials?)\b\s*[:=]\s*(['"])(?!(?:changeme|placeholder|example|dummy|redacted|password|secret|token|undefined|xxx+|your[-_a-z]*)\1)[A-Za-z0-9_+/=.\\-]{8,}\1/i],
    redactEvidence: (line: string, match: { column: number }): string => {
      const literal = /(['"])[A-Za-z0-9_+/=.\\-]{8,}\1/i.exec(line.slice(match.column - 1));
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
    patterns: [/\bcreate(?:Hash|Hmac)\s*\(\s*(['"])(?:md5|sha1)\1/],
  },
];

/**
 * Flow-enabled SAST test rules (test-only data). The production registry is
 * empty by design; the bounded semantic layer still needs rule metadata to
 * build a finding. These three fixtures mirror the old DG-SAST-048/049/050
 * contracts (command / SQL / HTML flows) WITHOUT shipping detection data in
 * production `src/` — the dataset provides real rules at runtime.
 */
export const TEST_SAST_FLOW_RULES: readonly SastRule[] = [
  {
    id: 'DG-SAST-048',
    title: 'Untrusted value reaches a command sink',
    description: 'A request-derived value flows into a shell command without an allowlisted sanitizer.',
    severity: 'HIGH',
    cwe: 'CWE-78',
    category: 'command-injection',
    remediation: 'Use execFile/spawn with an argument array and no shell; validate and allowlist inputs.',
    limitation: 'Bounded single-pass flow analysis; no interprocedural or cross-file tracking.',
    patterns: [],
    languages: ['javascript', 'typescript', 'jsx', 'tsx', 'python', 'php', 'ruby', 'go', 'java', 'kotlin', 'csharp'],
    flow: 'command',
  },
  {
    id: 'DG-SAST-049',
    title: 'Untrusted value reaches a SQL sink',
    description: 'A request-derived value flows into a dynamically built SQL statement.',
    severity: 'HIGH',
    cwe: 'CWE-89',
    category: 'sql-injection',
    remediation: 'Use parameterized queries and keep the SQL text constant.',
    limitation: 'Bounded single-pass flow analysis; string-masked literals only.',
    patterns: [],
    languages: ['javascript', 'typescript', 'jsx', 'tsx', 'python', 'php', 'ruby', 'go', 'java', 'kotlin', 'csharp'],
    flow: 'sql',
  },
  {
    id: 'DG-SAST-050',
    title: 'Untrusted value reaches a raw-HTML sink',
    description: 'A request-derived value flows into an innerHTML-style raw markup sink.',
    severity: 'MEDIUM',
    cwe: 'CWE-79',
    category: 'xss',
    remediation: 'Render values as text (textContent / framework children), never as raw HTML.',
    limitation: 'Bounded single-pass flow analysis; DOM sanitizer libraries are not modelled.',
    patterns: [],
    languages: ['javascript', 'typescript', 'jsx', 'tsx', 'python', 'php', 'ruby', 'go', 'java', 'kotlin', 'csharp'],
    flow: 'html',
  },
];

/** All test-only SAST rules, including the flow-enabled fixtures. */
export const ALL_TEST_SAST_RULES: readonly SastRule[] = [...TEST_SAST_RULES, ...TEST_SAST_FLOW_RULES];

// Secrets test fixtures — 6 rules covering all categories (paid-tool parity: test data in test/, not src/)
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
    patterns: [/\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/, /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/, /\b[sr]k_live_[A-Za-z0-9]{20,255}\b/, /\bxox[baprs]-[A-Za-z0-9-]{20,255}\b/, /\bAIza[0-9A-Za-z_-]{35}\b/],
    validate: (matched: string) => !matched.toLowerCase().includes('example'),
    valueSpan: (match) => ({ start: 0, end: match.text.length }),
  },
  {
    id: 'DG-SEC-003',
    title: 'Bearer token hardcoded in source',
    description: 'A long, distinctive bearer token is hardcoded in an authorization header or a bearer-token assignment.',
    category: 'bearer-token',
    severity: 'HIGH',
    confidence: 'MEDIUM',
    cwe: 'CWE-798',
    remediation: 'Load the token from the environment or a secret manager at runtime and rotate the exposed value.',
    limitation: 'Requires a 20+ character mixed-class token after `Bearer` (or in a bearer-named assignment); placeholders, templates and short values are excluded.',
    patterns: [/\bAuthorization\b['"]?\s*[:=]\s*['"]?Bearer\s+[A-Za-z0-9+/=_.-]{20,}/i, /\bbearer[_-]?token\b\s*[:=]\s*['"][A-Za-z0-9+/=_.$-]{20,}['"]/i],
    validate: (matched: string) => {
      const token = matched.split(/[\s'":=]+/).filter(Boolean).pop() ?? '';
      return token.length >= 20 && !matched.toLowerCase().includes('example') && !matched.toLowerCase().includes('changeme');
    },
    valueSpan: (match) => {
      const token = match.text.split(/[\s'":=]+/).filter(Boolean).pop() ?? '';
      const index = token.length === 0 ? -1 : match.text.lastIndexOf(token);
      if (index === -1) return undefined;
      return { start: index, end: index + token.length };
    },
  },
  {
    id: 'DG-SEC-004',
    title: 'Connection string with embedded credential',
    description: 'A connection URL contains an inline username:password credential (database, cache, queue or FTP).',
    category: 'connection-string',
    severity: 'HIGH',
    confidence: 'MEDIUM',
    cwe: 'CWE-798',
    remediation: 'Move the credential out of the URL: read the full connection string (or its password part) from the environment or a secret manager, and rotate the exposed password.',
    limitation: 'Known schemes only (postgres/postgresql/mysql/mongodb(+srv)/redis/rediss/amqp/amqps/ftp/ftps), with a non-placeholder password of 4+ characters.',
    patterns: [/\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|rediss|amqp|amqps|ftp|ftps):\/\/[A-Za-z0-9._%-]+:[^@\s/'"]{4,}@/],
    validate: (matched: string) => {
      const separator = matched.lastIndexOf(':');
      const password = matched.slice(separator + 1, -1);
      return !password.toLowerCase().includes('password') && !password.toLowerCase().includes('changeme') && !password.toLowerCase().includes('postgres');
    },
    valueSpan: (match) => {
      const at = match.text.lastIndexOf('@');
      const colon = match.text.lastIndexOf(':', at);
      if (at === -1 || colon === -1 || at - colon < 2) return undefined;
      return { start: colon + 1, end: at };
    },
  },
  {
    id: 'DG-SEC-005',
    title: 'API key hardcoded in source',
    description: 'A long credential-shaped literal is assigned to an API-key-named variable or setting. Hardcoded API keys end up in source control, builds and logs and cannot be rotated safely.',
    category: 'api-key',
    severity: 'HIGH',
    confidence: 'MEDIUM',
    cwe: 'CWE-798',
    remediation: 'Move the key to the environment or a secret manager, load it at runtime, and rotate the exposed value.',
    limitation: 'Requires an api-key-shaped name with a 20+ character, ≥2-class literal; placeholders, templates, UUIDs and plain hex digests are excluded.',
    patterns: [/(?:[A-Za-z0-9]+[-_])?api[_-]?key\b\s*['"]?\s*[:=]\s*['"]?[A-Za-z0-9+/=_.$!-]{20,}['"]?/i],
    validate: (matched: string) => {
      let value = matched.match(/['"]([^'"]+)['"]/)?.[1] ?? '';
      if (!value) {
        const sep = matched.search(/[:=]/);
        if (sep !== -1) value = matched.slice(sep + 1).trim().replace(/^['"]/, '').replace(/['"]$/, '');
      }
      return value.length >= 20 && !value.toLowerCase().includes('example') && !value.toLowerCase().includes('changeme');
    },
    valueSpan: (match) => {
      const quoted = match.text.match(/['"]([^'"]+)['"]/);
      if (quoted !== null && quoted.index !== undefined) {
        const start = quoted.index + 1;
        return { start, end: start + (quoted[1] ?? '').length };
      }
      const separator = match.text.search(/[:=]/);
      if (separator === -1) return undefined;
      const rest = match.text.slice(separator + 1);
      const leading = rest.length - rest.trimStart().length;
      const value = rest.trim().replace(/^['"]/, '').replace(/['"]$/, '');
      if (value.length === 0) return undefined;
      const start = separator + 1 + leading;
      return { start, end: start + value.length };
    },
  },
  {
    id: 'DG-SEC-006',
    title: 'Hardcoded password or secret with a strong value',
    description: 'A password- or secret-named variable is assigned a long, mixed-character literal that looks like a real credential rather than a placeholder.',
    category: 'password',
    severity: 'MEDIUM',
    confidence: 'LOW',
    cwe: 'CWE-798',
    remediation: 'Move the value to the environment or a secret manager and rotate it if it may be real.',
    limitation: 'Heuristic: credential-family names with ≥12 chars, ≥2 character classes and ≥3.5 bits/char entropy; placeholders, templates, UUIDs and plain hex digests are excluded.',
    patterns: [/\b(?:[A-Za-z0-9]+_)?(?:password|passwd|pwd|client_?secret|secret)\b\s*['"]?\s*[:=]\s*['"][^'"]{12,}['"]/i],
    validate: (matched: string) => {
      const literal = matched.match(/['"]([^'"]+)['"]/)?.[1] ?? '';
      if (literal.length < 12) return false;
      // Simplified strong check for test fixtures: mixed class, not placeholder, not UUID/hash
      const lower = literal.toLowerCase();
      if (lower.includes('changeme') || lower.includes('example') || lower.includes('password')) return false;
      // Check at least 2 char classes
      let classes = 0;
      if (/[a-z]/.test(literal)) classes++;
      if (/[A-Z]/.test(literal)) classes++;
      if (/[0-9]/.test(literal)) classes++;
      if (/[^A-Za-z0-9]/.test(literal)) classes++;
      return classes >= 2;
    },
    valueSpan: (match) => {
      const literal = match.text.match(/['"]([^'"]+)['"]/);
      const value = literal?.[1];
      if (literal === null || value === undefined || value.length === 0) return undefined;
      const index = (literal.index ?? match.text.search(/['"]/)) + 1;
      return { start: index, end: index + value.length };
    },
  },
];

export const TEST_SAST_RULE_IDS = TEST_SAST_RULES.map((r) => r.id);

// Minimal DAST test rules — 8 rules mimicking old hardcoded DG-DAST-* logic
// Each uses a pack check that will match the FIXTURE_DAST_RESPONSE in helpers.ts
// eslint-disable-next-line @typescript-eslint/no-explicit-any -- legacy untyped boundary; new modules use unknown.
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

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- legacy untyped boundary; new modules use unknown.
export const TEST_DAST_RULE_IDS = TEST_DAST_RULES.map((r: any) => r.id);
