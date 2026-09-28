import type { FindingSeverity } from '@drobon/shared';

/**
 * The SAST rule framework (Pump 8) — small, extensible, deterministic.
 *
 * Each rule is a first-class object with a STABLE identifier, a fixed
 * severity, a defensible CWE mapping (omitted rather than guessed), a
 * documented limitation, remediation guidance separate from evidence,
 * and one or more LINE MATCHERS.
 *
 * Design rules (tested):
 * - DETERMINISTIC: same source line → same findings, every time. No
 *   randomness, no time, no environment, no ordering effects.
 * - CONSERVATIVE: rules fire only on precise triggers (dynamic
 *   construction feeding a dangerous sink). Known-safe forms (constant
 *   literals, parameterized queries, escaped output) do NOT match. The
 *   goal is meaningful detection, not finding-count maximization.
 * - LINEAR TIME: every matcher is a hand-checked regex with NO nested
 *   quantifiers — no catastrophic backtracking (a regression test
 *   feeds pathological lines and asserts bounded analysis time).
 * - READ-ONLY: rules only MATCH. They never rewrite, never auto-fix,
 *   never execute anything.
 *
 * This module is APPLICATION LOGIC, not a vulnerability-database
 * import: it contains no CVE/NVD/GHSA/OSV/KEV/EPSS data (the dataset
 * lock holds — see docs/SAST.md).
 */

/** One deterministic match of a rule on one source line. */
export interface SastRuleMatch {
  /** 1-based column of the match start (the regex match index). */
  column: number;
}

/**
 * A rule's line matcher: given one physical source line, return at most
 * one match (the first). Pure function of the line.
 */
export type SastLineMatcher = (line: string) => SastRuleMatch | undefined;

export interface SastRule {
  /** Stable identifier (`DG-SAST-###`) — never reused, never changed. */
  readonly id: string;
  /** Short human title (surfaces in findings). */
  readonly title: string;
  /** What matched and why it matters (surfaces in findings). */
  readonly description: string;
  /** Fixed severity — rule-defined, never client-influenced. */
  readonly severity: FindingSeverity;
  /** Defensible CWE mapping, or omitted when uncertain. */
  readonly cwe?: string;
  /** Vulnerability class (documentation/grouping). */
  readonly category: string;
  /** Rule-specific remediation guidance (surfaces in findings). */
  readonly remediation: string;
  /** Documented detection limitation (docs/SAST.md; not a finding field). */
  readonly limitation: string;
  /**
   * Deterministic line patterns. CONTRACTS (asserted by unit tests):
   * - no `g`/`y` flags (stateful `lastIndex` bugs are impossible);
   * - hand-reviewed, no nested quantifiers — linear time (the ReDoS
   *   regression test feeds pathological lines and asserts bounded
   *   analysis time).
   */
  readonly patterns: readonly RegExp[];
  /**
   * Optional evidence redaction: given the raw matched line and the
   * match, return the evidence with sensitive parts removed.
   */
  readonly redactEvidence?: (line: string, match: SastRuleMatch) => string;
}

/**
 * Run one rule against one line: the FIRST matching pattern wins, and
 * a rule fires at most once per line. Pure function of (rule, line).
 */
export function matchRuleLine(rule: SastRule, line: string): SastRuleMatch | undefined {
  for (const pattern of rule.patterns) {
    if (pattern.global || pattern.sticky) {
      throw new Error(`Rule pattern must not use the g/y flags: ${rule.id}`);
    }
    const match = pattern.exec(line);
    if (match !== null) {
      return { column: match.index + 1 };
    }
  }
  return undefined;
}

/**
 * DG-SAST-001 — OS command execution with dynamically built commands.
 *
 * Fires when `exec`/`execSync` (the child_process APIs that always
 * invoke a shell) receive a command built with template interpolation
 * or string concatenation — the classic command-injection shape.
 */
const RULE_COMMAND_INJECTION: SastRule = {
  id: 'DG-SAST-001',
  title: 'OS command built from dynamic input',
  description:
    'A shell command is constructed with interpolated or concatenated values before being passed to exec/execSync. If any part of the value is attacker-influenced, arbitrary commands can be injected.',
  severity: 'HIGH',
  cwe: 'CWE-78',
  category: 'command-injection',
  remediation:
    'Avoid a shell entirely: use execFile/spawn with an argument array and no shell. If a shell is unavoidable, pass dynamic values as arguments, never interpolated into the command string.',
  limitation:
    'Lexical, line-based, no dataflow: only template-literal interpolation and concatenation into exec/execSync are flagged; a variable passed through unchanged (exec(cmd)) and spawn with shell:true are not detected in v1.',
  patterns: [
    /\bexec(?:Sync)?\s*\(\s*(?:`[^`]*\$\{|(['"]).*?\1\s*\+)/,
  ],
};

/**
 * DG-SAST-002 — Dynamic code evaluation.
 *
 * Fires when `eval` or `new Function` receives code built with
 * interpolation/concatenation — code injection.
 */
const RULE_CODE_INJECTION: SastRule = {
  id: 'DG-SAST-002',
  title: 'Code evaluated from a dynamically built string',
  description:
    'A string built with interpolated or concatenated values is passed to eval or new Function. If any part of it is attacker-influenced, arbitrary code executes in the application.',
  severity: 'HIGH',
  cwe: 'CWE-95',
  category: 'code-injection',
  remediation:
    'Remove the dynamic evaluation: use data structures, maps or explicit branches instead of building code. If parsing is required, use a dedicated parser for the format, never the JS evaluator.',
  limitation:
    'Lexical, line-based, no dataflow: only interpolated/concatenated arguments are flagged; eval(variable) pass-through and indirect eval (window[\'eval\']) are not detected in v1.',
  patterns: [
    /\beval\s*\(\s*(?:`[^`]*\$\{|(['"]).*?\1\s*\+)/,
    /\bnew\s+Function\s*\(\s*(?:`[^`]*\$\{|(['"]).*?\1\s*\+)/,
  ],
};

/**
 * DG-SAST-003 — SQL query built with dynamic string construction.
 *
 * Fires when a `.query(...)`/`.execute(...)` call receives SQL text
 * built with template interpolation or concatenation, instead of
 * placeholders/parameters.
 */
const RULE_SQL_INJECTION: SastRule = {
  id: 'DG-SAST-003',
  title: 'SQL query built from dynamic string construction',
  description:
    'SQL text is constructed with interpolated or concatenated values and passed to a query/execute call. If any value is attacker-influenced, the query can be rewritten (SQL injection).',
  severity: 'HIGH',
  cwe: 'CWE-89',
  category: 'sql-injection',
  remediation:
    'Use parameterized queries: keep the SQL text a constant and pass values as parameters (e.g. query("… WHERE id = ?", [id])). Never build SQL by string interpolation or concatenation.',
  limitation:
    'Lexical, line-based, no dataflow: only .query/.execute calls with an interpolated or concatenated first argument are flagged; a sql variable passed through unchanged and multi-line statement building are not detected in v1.',
  patterns: [
    /\.query\s*\(\s*(?:`[^`]*\$\{|(['"]).*?\1\s*\+)/,
    /\.execute\s*\(\s*(?:`[^`]*\$\{|(['"]).*?\1\s*\+)/,
  ],
};

/**
 * DG-SAST-004 — Raw HTML output built from dynamic input.
 *
 * Fires when an HTML sink (`innerHTML` assignment, React
 * `dangerouslySetInnerHTML`, `document.write`) receives markup built
 * with interpolation/concatenation — the XSS shape. MEDIUM: without
 * dataflow the taintedness of the value is unproven, so the severity
 * is deliberately not inflated.
 */
const RULE_RAW_HTML: SastRule = {
  id: 'DG-SAST-004',
  title: 'Raw HTML built from dynamic input',
  description:
    'Markup constructed with interpolated or concatenated values is assigned to a raw-HTML sink (innerHTML, dangerouslySetInnerHTML, document.write). If any part of the value is attacker-influenced, script can be injected into the page (XSS).',
  severity: 'MEDIUM',
  cwe: 'CWE-79',
  category: 'xss',
  remediation:
    'Render dynamic values as TEXT (textContent, React children — they escape automatically). If trusted markup is genuinely required, sanitize it with an allowlist-based sanitizer before insertion.',
  limitation:
    'Lexical, line-based, no dataflow: only interpolated/concatenated assignments to innerHTML/dangerouslySetInnerHTML/document.write are flagged; severity stays MEDIUM because taintedness cannot be proven without dataflow.',
  patterns: [
    /\.innerHTML\s*=[^=]*(?:`[^`]*\$\{|(['"]).*?\1\s*\+)/,
    /__html\s*:\s*(?:`[^`]*\$\{|(['"]).*?\1\s*\+|[A-Za-z_$][\w$.]*\s*\+)/,
    /\bdocument\.write(?:ln)?\s*\(\s*(?:`[^`]*\$\{|(['"]).*?\1\s*\+)/,
  ],
};

/**
 * DG-SAST-005 — Hardcoded credential-like literal.
 *
 * Fires when a credential-named variable/property is assigned a
 * non-trivial string literal. The EVIDENCE IS REDACTED: the literal's
 * value never appears in the finding — the value is replaced with
 * `<redacted>` so the finding stays useful without re-exposing the
 * secret through API responses or logs.
 */
const RULE_HARDCODED_CREDENTIAL: SastRule = {
  id: 'DG-SAST-005',
  title: 'Hardcoded credential-like literal',
  description:
    'A credential-named variable or property is assigned a literal value. Hardcoded secrets end up in source control, builds and logs and cannot be rotated safely.',
  severity: 'MEDIUM',
  cwe: 'CWE-798',
  category: 'hardcoded-credential',
  remediation:
    'Move the value out of source code: read it from the environment or a secret manager at startup, and rotate the exposed value. Never commit real credentials, even in tests.',
  limitation:
    'Lexical heuristic on credential-shaped names (password/secret/token/key families, including SCREAMING_SNAKE prefixes like DB_PASSWORD) assigned literals of at least 8 characters, with obvious placeholders excluded. It cannot detect obfuscated, composed or non-literal secrets, and it does not attempt entropy analysis in v1.',
  patterns: [
    // The negative lookahead excludes obvious placeholder values so the
    // rule stays conservative (real hardcoded credentials, not docs).
    /\b(?:[A-Za-z0-9]+_)?(?:password|passwd|pwd|secret|secrets?_?key|apikey|api_key|token|auth_?token|access_?token|client_?secret|private_?key|credentials?)\b\s*[:=]\s*(['"])(?!(?:changeme|placeholder|example|dummy|redacted|password|secret|token|undefined|xxx+|your[-_a-z]*)\1)[A-Za-z0-9_+/=.\\-]{8,}\1/i,
  ],
  redactEvidence: (line: string, match: SastRuleMatch): string => {
    // Replace the literal's VALUE with a marker, keeping the quote
    // characters so the shape of the code stays understandable. The
    // replacement is LENGTH-NEUTRAL ('<redacted>' only when the value
    // is at least that long, same-length asterisks otherwise) so
    // redaction can never push the evidence over its hard bound.
    const literal = /(['"])[A-Za-z0-9_+/=.\\-]{8,}\1/i.exec(
      line.slice(match.column - 1),
    );
    if (literal === null) {
      return line;
    }
    const start = match.column - 1 + literal.index;
    const quote = literal[0][0] ?? '"';
    const value = literal[0].slice(1, -1);
    const replacement = value.length >= 10 ? '<redacted>' : '*'.repeat(value.length);
    return `${line.slice(0, start)}${quote}${replacement}${quote}${line.slice(start + literal[0].length)}`;
  },
};

/**
 * DG-SAST-006 — Weak hash/HMAC algorithm.
 *
 * Fires on `createHash`/`createHmac` with md5 or sha1. LOW severity:
 * broken-for-collision algorithms have legitimate non-security uses
 * (checksums, cache keys), which the limitation states honestly.
 */
const RULE_WEAK_HASH: SastRule = {
  id: 'DG-SAST-006',
  title: 'Weak hash algorithm (MD5/SHA-1) in a cryptographic API',
  description:
    'createHash/createHmac is called with md5 or sha1. These algorithms are cryptographically broken for collision resistance and must not be used where security properties are required.',
  severity: 'LOW',
  cwe: 'CWE-327',
  category: 'weak-cryptography',
  remediation:
    'Use a modern algorithm (SHA-256 or stronger for hashes; SHA-256+ HMACs). If MD5/SHA-1 is used only as a non-security checksum, add a comment saying so.',
  limitation:
    'Detects the algorithm choice in createHash/createHmac calls only. Whether the hash is used for a security purpose requires context the lexical engine does not have — hence LOW severity.',
  patterns: [
    /\bcreate(?:Hash|Hmac)\s*\(\s*(['"])(?:md5|sha1)\1/,
  ],
};

/**
 * The closed rule registry, ordered by id. Adding a rule = appending
 * here with the next stable id (DG-SAST-007…) and documenting it in
 * docs/SAST.md. Rules are never mutated at runtime — nothing
 * client-facing can add, remove or alter a rule.
 */
export const SAST_RULES: readonly SastRule[] = [
  RULE_COMMAND_INJECTION,
  RULE_CODE_INJECTION,
  RULE_SQL_INJECTION,
  RULE_RAW_HTML,
  RULE_HARDCODED_CREDENTIAL,
  RULE_WEAK_HASH,
];

export function sastRuleById(id: string): SastRule | undefined {
  return SAST_RULES.find((rule) => rule.id === id);
}
