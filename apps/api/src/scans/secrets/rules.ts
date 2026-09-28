import type { FindingConfidence, FindingSeverity } from '@drobon/shared';

/**
 * THE REAL SECRETS RULE FRAMEWORK (Pump 10).
 *
 * Each rule is a first-class object with a STABLE identifier
 * (`DG-SEC-###`), a FIXED severity and a FIXED confidence — both
 * defined HERE, never guessed at runtime, never influenced by the
 * client or the UI.
 *
 * THE NO-FAKE-SECURITY-REPORT RULE, applied to secrets:
 * - DETECTED_SECRET ≠ VERIFIED_LIVE_CREDENTIAL. A match proves the
 *   STRING has a credential's SHAPE — nothing more. No rule, title,
 *   description or remediation may claim the credential is valid,
 *   active, compromised or revoked. There is NO verification: the
 *   engine performs no network access and never contacts any service.
 * - A finding exists ONLY when a deterministic pattern matched REAL
 *   snapshot content at a real line/column. No match = no finding.
 *   "Unknown" is reported as unknown, never as safe.
 * - Severity is conservative and documented per rule (no CRITICAL in
 *   v1: even a private-key match does not prove the key is real,
 *   current, or authorized for anything).
 *
 * FALSE-POSITIVE DEFENSE (tested):
 * - Value denylist: obvious placeholders/templates never match
 *   (changeme/example/your/…/…, interpolation `${…}`, `<…>`).
 * - Structure gates: minimum length, character-class mix, UUID-shape
 *   and plain-hash exclusions, known-prefix requirements. Entropy is
 *   ONE input among several — "high entropy = secret" alone is never
 *   a rule.
 * - Known documentation values (e.g. the AWS example access key) are
 *   excluded explicitly.
 *
 * REDACTION CONTRACT (critical): every rule that matches credential
 * MATERIAL must redact it from the evidence — the finding shows the
 * context (variable name, scheme, quotes) with the value replaced by
 * `<redacted>`. The raw secret never enters the finding object, so it
 * can never reach the API, UI, logs or stores through it.
 *
 * This module is APPLICATION LOGIC, not a secret database: it
 * contains no real credentials and no external datasets (the dataset
 * lock holds — see docs/SECRETS.md).
 */

/** One deterministic match of a rule on one source line. */
export interface SecretsRuleMatch {
  /** 1-based column of the match start (regex match index). */
  column: number;
  /** The exact matched text (needed for value-level gates/redaction). */
  text: string;
}

/** A rule's line matcher: at most one match per rule per line. */
export type SecretsLineMatcher = (line: string) => SecretsRuleMatch | undefined;

export interface SecretsRule {
  /** Stable identifier (`DG-SEC-###`) — never reused, never changed. */
  readonly id: string;
  /** Short human title (surfaces in findings; NEVER a verification claim). */
  readonly title: string;
  /** What matched and why it matters (surfaces in findings). */
  readonly description: string;
  /** Detection category (documentation/grouping). */
  readonly category: string;
  /** Fixed severity — rule-defined, never client-influenced. */
  readonly severity: FindingSeverity;
  /**
   * Fixed detection confidence — how certain THIS RULE is that the
   * match is credential material (HIGH = structural/known format).
   * Detection confidence only; never a liveness claim.
   */
  readonly confidence: FindingConfidence;
  /** Defensible CWE mapping, or omitted when uncertain. */
  readonly cwe?: string;
  /** Rule-specific remediation guidance (surfaces in findings). */
  readonly remediation: string;
  /** Documented false-positive considerations (docs/SECRETS.md). */
  readonly limitation: string;
  /**
   * Deterministic line patterns (no g/y flags, no nested quantifiers
   * — linear time, asserted by unit tests).
   */
  readonly patterns: readonly RegExp[];
  /**
   * Optional value gate: given the matched text, apply
   * structure/entropy criteria. Returning false drops the match
   * (conservative — an unmatched shape is never reported).
   */
  readonly validate?: (matched: string) => boolean;
  /**
   * REDACTION CONTRACT (the engine enforces it): the span of the
   * SECRET VALUE inside the matched text (start inclusive, end
   * exclusive, relative to match start). The engine blanks exactly
   * this span — positionally, so a value cut by the evidence window
   * can never leak partially. Rules that match only safe text (the
   * private-key HEADER) set `matchOnlyEvidence` instead.
   */
  readonly valueSpan?: (match: SecretsRuleMatch) => { start: number; end: number } | undefined;
  /**
   * True when the matched text itself IS the evidence and contains no
   * secret material (e.g. a PEM header line): the evidence is exactly
   * the match, nothing else from the line can leak.
   */
  readonly matchOnlyEvidence?: boolean;
}

/**
 * Run one rule against one line: the FIRST matching pattern wins, a
 * rule fires at most once per line, and the value gate may veto the
 * match. Pure function of (rule, line).
 */
export function matchSecretsRuleLine(
  rule: SecretsRule,
  line: string,
): SecretsRuleMatch | undefined {
  for (const pattern of rule.patterns) {
    if (pattern.global || pattern.sticky) {
      throw new Error(`Rule pattern must not use the g/y flags: ${rule.id}`);
    }
    // String.match (not RegExp.exec): staticSafety forbids exec-shaped
    // calls outside the SAST rule-data exemption, and this module has
    // no runtime imports at all.
    const match = line.match(pattern);
    if (match !== null) {
      const candidate: SecretsRuleMatch = {
        column: (match.index ?? 0) + 1,
        text: match[0],
      };
      if (rule.validate !== undefined && !rule.validate(candidate.text)) {
        // Vetoed on its merits (e.g. a placeholder) — but a LATER
        // pattern of the same rule may legitimately match DIFFERENT
        // material on this line, so keep trying.
        continue;
      }
      return candidate;
    }
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// Shared value gates (deterministic structure criteria — no randomness)
// ---------------------------------------------------------------------------

/**
 * Placeholder/template values that never constitute findings. Checked
 * case-insensitively as SUBSTRINGS of the value. Real random
 * credentials effectively never contain these words; documentation
 * examples and clearly-marked test values do.
 */
const PLACEHOLDER_MARKERS = [
  'changeme',
  'change-me',
  'change_me',
  'placeholder',
  'example',
  'dummy',
  'sample',
  'your',
  'todo',
  'fixme',
  'xxx',
  'redacted',
  'notaset',
  'not-a-secret',
  'notreal',
  'insert',
  'here',
  'fake',
  'synthetic',
  'demo',
  'test',
  // Self-referential documentation values: a secret whose value is
  // literally the word "password"/"secret"/"token" is documentation.
  'password',
  'secret',
  'token',
] as const;

/** `<YOUR_API_KEY>`, `{{secret}}`, `${TOKEN}` — templates, not literals. */
function isTemplateValue(value: string): boolean {
  return value.includes('<') || value.includes('>') || value.includes('${') || value.includes('{{');
}

/** UUID/GUID shape — identifiers, not credentials (§ false positives). */
const UUID_SHAPE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Plain hex digests (MD5/SHA-1/SHA-256/SHA-512 hex) — checksums and
 * commit ids, not credential material for the generic rules.
 */
const PLAIN_HEX_DIGEST =
  /^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{56}|[0-9a-f]{64}|[0-9a-f]{96}|[0-9a-f]{128})$/i;

function isPlaceholderValue(value: string): boolean {
  const lower = value.toLowerCase();
  return (
    isTemplateValue(value) ||
    PLACEHOLDER_MARKERS.some((marker) => lower.includes(marker))
  );
}

/** Shannon entropy per character (deterministic, no randomness). */
export function shannonEntropy(value: string): number {
  if (value.length === 0) {
    return 0;
  }
  const counts = new Map<string, number>();
  for (const char of value) {
    counts.set(char, (counts.get(char) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/** How many of the four character classes the value uses. */
export function characterClasses(value: string): number {
  let classes = 0;
  if (/[a-z]/.test(value)) {
    classes += 1;
  }
  if (/[A-Z]/.test(value)) {
    classes += 1;
  }
  if (/[0-9]/.test(value)) {
    classes += 1;
  }
  if (/[^A-Za-z0-9]/.test(value)) {
    classes += 1;
  }
  return classes;
}

/**
 * Strong generic-secret criteria (DG-SEC-006): a long, mixed-class,
 * non-trivial-entropy literal that is not a placeholder, UUID or
 * plain hash. Entropy is one input of several — never sufficient
 * alone.
 */
function isStrongSecretValue(value: string): boolean {
  return (
    value.length >= 12 &&
    characterClasses(value) >= 2 &&
    shannonEntropy(value) >= 3.5 &&
    !isPlaceholderValue(value) &&
    !UUID_SHAPE.test(value) &&
    !PLAIN_HEX_DIGEST.test(value)
  );
}

/**
 * Extract the secret VALUE from an assignment/header match: prefer the
 * quoted literal, else the bare text after the first `:`/`=` separator
 * (config/ENV/header shapes). Gating the VALUE — never the whole line,
 * whose variable NAME legitimately contains words like "token".
 */
function assignmentValueOf(matched: string): string {
  const quoted = matched.match(/['"]([^'"]{4,})['"]/);
  if (quoted !== null && quoted[1] !== undefined) {
    return quoted[1];
  }
  const separator = matched.search(/[:=]/);
  if (separator === -1) {
    return '';
  }
  return matched
    .slice(separator + 1)
    .trim()
    .replace(/^['"]/, '')
    .replace(/['"]$/, '');
}

/**
 * Length-neutral `<redacted>` replacement (the SAST-005 precedent):
 * same-length asterisks for short values so redaction can never push
 * evidence past its hard bound; the marker for longer ones.
 */
export function redactLiteral(value: string): string {
  return value.length >= 10 ? '<redacted>' : '*'.repeat(value.length);
}

// ---------------------------------------------------------------------------
// The rules
// ---------------------------------------------------------------------------

/**
 * DG-SEC-001 — Private key block header.
 *
 * Fires on a PEM private-key header line (`-----BEGIN <KIND> PRIVATE
 * KEY-----`). The header itself carries no key material; the evidence
 * is EXACTLY the header (anything else sharing its line — e.g. an
 * inlined body — is dropped), so key material can never leak through
 * evidence. The key body is never parsed, used, or validated anywhere.
 *
 * Severity HIGH (not CRITICAL): the match proves key-SHAPED material
 * exists in source; it does not prove the key is real, current,
 * decryptable, or authorized for anything.
 */
const RULE_PRIVATE_KEY_BLOCK: SecretsRule = {
  id: 'DG-SEC-001',
  title: 'Private key block detected in source',
  description:
    'A PEM private-key header was found in the uploaded source. Private-key material must never live in source control: anyone with repository access obtains the key, and rotation becomes impossible without a history rewrite.',
  category: 'private-key',
  severity: 'HIGH',
  confidence: 'HIGH',
  cwe: 'CWE-798',
  remediation:
    'Remove the key file from the source snapshot and from version control entirely (including history where applicable). Move private keys to a secret manager or key-management system, load them at runtime, and rotate the exposed key. This detection does not attempt to determine whether the key is valid or in use.',
  limitation:
    'Matches PEM-style private-key headers only (RSA/EC/DSA/OPENSSH/PGP/ENCRYPTED/generic). Single-line/inlined non-PEM keys, encrypted keystores (e.g. .p12/.jks binaries) and non-header key formats are not detected. Public keys and certificates deliberately do not match.',
  patterns: [/-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----/],
  // The header carries no key material; the evidence is EXACTLY the
  // header — no surrounding line content, so an inlined key body
  // sharing the line cannot leak through evidence.
  matchOnlyEvidence: true,
};

/**
 * DG-SEC-002 — Known-prefix service credentials.
 *
 * Service credentials with reliable, documented prefixes (AWS access
 * key ids, GitHub/Stripe/Slack/Google tokens). The prefix makes these
 * HIGH confidence SHAPES; the canonical documentation example values
 * are excluded.
 *
 * Severity HIGH: these formats are concrete production credential
 * formats. Still only a SHAPE match — validity/liveness is NOT tested
 * (no network access, no verification, ever).
 */
const RULE_KNOWN_PREFIX_CREDENTIALS: SecretsRule = {
  id: 'DG-SEC-002',
  title: 'Known-format service credential detected',
  description:
    'A credential matching a documented service format (AWS access key id, GitHub, Stripe, Slack or Google token) was found in the source. Hardcoded service credentials end up in source control, builds and logs and cannot be rotated safely.',
  category: 'service-credential',
  severity: 'HIGH',
  confidence: 'HIGH',
  cwe: 'CWE-798',
  remediation:
    'Move the credential to the environment or a secret manager and rotate it: a value that reached source code must be treated as exposed even if it may be a test value. This detection matched the credential format only; it did not contact any service and cannot say whether the credential is valid or active.',
  limitation:
    'Prefix-shaped only: AWS AKIA/ASIA/ABIA/ACCA ids, GitHub ghp_/gho_/ghu_/ghs_/ghr_, Stripe sk_live_/rk_live_ (test-mode keys deliberately excluded), Slack xoxb/xoxp/xoxa/xoxr/xoxs, Google AIza keys. Documentation example values are excluded. Other services and custom formats are not detected.',
  patterns: [
    /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/,
    /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/,
    /\b[sr]k_live_[A-Za-z0-9]{20,255}\b/,
    /\bxox[baprs]-[A-Za-z0-9-]{20,255}\b/,
    /\bAIza[0-9A-Za-z_-]{35}\b/,
  ],
  validate: (matched: string): boolean => !isPlaceholderValue(matched),
  // The entire match is the credential — every character is blanked.
  valueSpan: (match: SecretsRuleMatch) => ({ start: 0, end: match.text.length }),
};

/**
 * DG-SEC-003 — Bearer/authorization token with a distinctive value.
 *
 * Fires on `Authorization … Bearer <token>` (code, config or header
 * assignment) and explicit bearer-token assignments where the token
 * is long enough to be distinctive and not a placeholder.
 */
const RULE_BEARER_TOKEN: SecretsRule = {
  id: 'DG-SEC-003',
  title: 'Bearer token hardcoded in source',
  description:
    'A long, distinctive bearer token is hardcoded in an authorization header or a bearer-token assignment. Anyone with source access obtains the token; it cannot be rotated without a code change.',
  category: 'bearer-token',
  severity: 'HIGH',
  confidence: 'MEDIUM',
  cwe: 'CWE-798',
  remediation:
    'Load the token from the environment or a secret manager at runtime and rotate the exposed value. This detection matched a token-shaped literal only; it did not verify the token against any service.',
  limitation:
    'Requires a 20+ character mixed-class token after `Bearer` (or in a bearer-named assignment); placeholders, templates and short values are excluded. The rule cannot tell an access token from a similarly-shaped opaque string, hence MEDIUM confidence.',
  patterns: [
    /\bAuthorization\b['"]?\s*[:=]\s*['"]?Bearer\s+[A-Za-z0-9+/=_.-]{20,}/i,
    /\bbearer[_-]?token\b\s*[:=]\s*['"][A-Za-z0-9+/=_.$-]{20,}['"]/i,
  ],
  validate: (matched: string): boolean => {
    // The token is the tail after the last separator; gate on it.
    const token = matched.split(/[\s'":=]+/).filter(Boolean).pop() ?? '';
    return token.length >= 20 && characterClasses(token) >= 2 && !isPlaceholderValue(token);
  },
  // The secret is the token tail; the scheme/keyword context stays.
  valueSpan: (match: SecretsRuleMatch): { start: number; end: number } | undefined => {
    const token = match.text.split(/[\s'":=]+/).filter(Boolean).pop() ?? '';
    const index = token.length === 0 ? -1 : match.text.lastIndexOf(token);
    if (index === -1) {
      return undefined; // Engine fails closed if the span is lost.
    }
    return { start: index, end: index + token.length };
  },
};

/**
 * DG-SEC-004 — Credential-bearing connection URL.
 *
 * Fires on `scheme://user:password@…` connection strings (databases,
 * caches, queues, FTP) where the password part is non-trivial and not
 * a placeholder. The password is redacted from the evidence.
 */
const RULE_CREDENTIAL_URL: SecretsRule = {
  id: 'DG-SEC-004',
  title: 'Connection string with embedded credential',
  description:
    'A connection URL contains an inline username:password credential (database, cache, queue or FTP). The credential is stored in plain text in source and transits logs and process listings.',
  category: 'connection-string',
  severity: 'HIGH',
  confidence: 'MEDIUM',
  cwe: 'CWE-798',
  remediation:
    'Move the credential out of the URL: read the full connection string (or its password part) from the environment or a secret manager, and rotate the exposed password. This detection matched the URL shape only; it did not attempt to connect anywhere.',
  limitation:
    'Known schemes only (postgres/postgresql/mysql/mongodb(+srv)/redis/rediss/amqp/amqps/ftp/ftps), with a non-placeholder password of 4+ characters. URL-encoded or separately-configured credentials are not detected, hence MEDIUM confidence.',
  patterns: [
    /\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|rediss|amqp|amqps|ftp|ftps):\/\/[A-Za-z0-9._%-]+:[^@\s/'"]{4,}@/,
  ],
  validate: (matched: string): boolean => {
    const separator = matched.lastIndexOf(':');
    const password = matched.slice(separator + 1, -1);
    // URL documentation defaults (the scheme's own name, common
    // placeholder users/passwords) are never real credentials.
    const urlPlaceholders = [
      'password',
      'pass',
      'secret',
      'username',
      'user',
      'admin',
      'root',
      'postgres',
      'mysql',
      'mongo',
      'redis',
      'guest',
      '1234',
      '12345678',
    ];
    return (
      !isPlaceholderValue(password) &&
      !UUID_SHAPE.test(password) &&
      !urlPlaceholders.includes(password.toLowerCase())
    );
  },
  // The secret is the password segment (between the last ':' and the
  // '@'); scheme/user/host stay visible for context.
  valueSpan: (match: SecretsRuleMatch): { start: number; end: number } | undefined => {
    const at = match.text.lastIndexOf('@');
    const colon = match.text.lastIndexOf(':', at);
    if (at === -1 || colon === -1 || at - colon < 2) {
      return undefined;
    }
    return { start: colon + 1, end: at };
  },
};

/**
 * DG-SEC-005 — API-key-shaped assignment.
 *
 * Fires when an api-key-named variable/property/ENV entry is assigned
 * a long mixed-class literal (the classic `apiKey = '…'` shape).
 * Structure-gated: length ≥ 20, ≥ 2 character classes, not a
 * placeholder/template/UUID/plain hash.
 */
const RULE_API_KEY_ASSIGNMENT: SecretsRule = {
  id: 'DG-SEC-005',
  title: 'API key hardcoded in source',
  description:
    'A long credential-shaped literal is assigned to an API-key-named variable or setting. Hardcoded API keys end up in source control, builds and logs and cannot be rotated safely.',
  category: 'api-key',
  severity: 'HIGH',
  confidence: 'MEDIUM',
  cwe: 'CWE-798',
  remediation:
    'Move the key to the environment or a secret manager, load it at runtime, and rotate the exposed value. This detection matched a key-shaped literal only; it did not contact the API to verify the key.',
  limitation:
    'Requires an api-key-shaped name (api_key/apikey/api-key, incl. SCREAMING_SNAKE forms) with a 20+ character, ≥2-class literal; placeholders, templates, UUIDs and plain hex digests are excluded. Non-literal or composed keys are not detected, hence MEDIUM confidence.',
  patterns: [
    // Name forms: `apiKey`, `api_key`, `api-key`, `MY_API_KEY`,
    // `x-api-key` (an optional word prefix + separator). The value
    // literal may be quoted or bare (config/ENV/header shapes).
    /(?:[A-Za-z0-9]+[-_])?api[_-]?key\b\s*['"]?\s*[:=]\s*['"]?[A-Za-z0-9+/=_.$!-]{20,}['"]?/i,
  ],
  validate: (matched: string): boolean => {
    const value = assignmentValueOf(matched);
    return (
      value.length >= 20 &&
      characterClasses(value) >= 2 &&
      !isPlaceholderValue(value) &&
      !UUID_SHAPE.test(value)
    );
  },
  // The secret is the quoted literal (quotes stay for context).
  valueSpan: (match: SecretsRuleMatch): { start: number; end: number } | undefined => {
    const quoted = match.text.match(/['"]([^'"]+)['"]/);
    if (quoted !== null && quoted.index !== undefined) {
      const start = quoted.index + 1;
      return { start, end: start + (quoted[1] ?? '').length };
    }
    // Bare (unquoted) config value: the trimmed text after the separator.
    const separator = match.text.search(/[:=]/);
    if (separator === -1) {
      return undefined; // Engine fails closed if the span is lost.
    }
    const rest = match.text.slice(separator + 1);
    const leading = rest.length - rest.trimStart().length;
    const value = rest.trim().replace(/^['"]/, '').replace(/['"]$/, '');
    if (value.length === 0) {
      return undefined;
    }
    const start = separator + 1 + leading;
    return { start, end: start + value.length };
  },
};

/**
 * DG-SEC-006 — Generic password/secret assignment (strong-value heuristic).
 *
 * The deliberately conservative catch-all: password/secret-named
 * assignments whose value passes the strong-secret gate (length,
 * classes, entropy; placeholders/UUIDs/plain hashes excluded). MEDIUM
 * severity, LOW confidence: without a known format this is a
 * heuristic, and it is labeled as one.
 */
const RULE_GENERIC_SECRET_ASSIGNMENT: SecretsRule = {
  id: 'DG-SEC-006',
  title: 'Hardcoded password or secret with a strong value',
  description:
    'A password- or secret-named variable is assigned a long, mixed-character literal that looks like a real credential rather than a placeholder. Hardcoded secrets cannot be rotated safely and leak into builds and logs.',
  category: 'password',
  severity: 'MEDIUM',
  confidence: 'LOW',
  cwe: 'CWE-798',
  remediation:
    'Move the value to the environment or a secret manager and rotate it if it may be real. This is a heuristic match on name + value shape; it did not and cannot verify the credential.',
  limitation:
    'Heuristic: credential-family names (password/passwd/pwd/secret/client_secret, incl. SCREAMING_SNAKE) with ≥12 chars, ≥2 character classes and ≥3.5 bits/char entropy; placeholders, templates, UUIDs and plain hex digests are excluded. Entropy alone never triggers a finding — it is one input of several. Detection confidence is LOW by design.',
  patterns: [
    /\b(?:[A-Za-z0-9]+_)?(?:password|passwd|pwd|client_?secret|secret)\b\s*['"]?\s*[:=]\s*['"][^'"]{12,}['"]/i,
  ],
  validate: (matched: string): boolean => {
    const literal = matched.match(/['"]([^'"]+)['"]/)?.[1] ?? '';
    return isStrongSecretValue(literal);
  },
  // The secret is the quoted literal (quotes stay for context).
  valueSpan: (match: SecretsRuleMatch): { start: number; end: number } | undefined => {
    const literal = match.text.match(/['"]([^'"]+)['"]/);
    const value = literal?.[1];
    if (literal === null || value === undefined || value.length === 0) {
      return undefined;
    }
    const index = (literal.index ?? match.text.search(/['"]/)) + 1;
    return { start: index, end: index + value.length };
  },
};

/**
 * The closed rule registry, ordered by id. Adding a rule = appending
 * here with the next stable id (DG-SEC-007…) and documenting it in
 * docs/SECRETS.md. Rules are immutable at runtime — nothing
 * client-facing can add, remove or alter a rule.
 */
export const SECRETS_RULES: readonly SecretsRule[] = [
  RULE_PRIVATE_KEY_BLOCK,
  RULE_KNOWN_PREFIX_CREDENTIALS,
  RULE_BEARER_TOKEN,
  RULE_CREDENTIAL_URL,
  RULE_API_KEY_ASSIGNMENT,
  RULE_GENERIC_SECRET_ASSIGNMENT,
];

export function secretsRuleById(id: string): SecretsRule | undefined {
  return SECRETS_RULES.find((rule) => rule.id === id);
}
