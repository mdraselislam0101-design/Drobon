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
   * Language-family gating (SAST v2 universal catalog — see
   * `languages.ts`): the rule runs ONLY on files detected as one of
   * these families. `undefined` = universal (runs on every analyzed
   * file, e.g. the hardcoded-credential heuristic). Family ids always
   * exist in the catalog (asserted by an invariant test).
   */
  readonly languages?: readonly string[];
  /**
   * Optional evidence redaction: given the raw matched line and the
   * match, return the evidence with sensitive parts removed.
   */
  readonly redactEvidence?: (line: string, match: SastRuleMatch) => string;
  /**
   * Flow-participation tag (deep-semantic pump): rules tagged here have
   * an INTENTIONALLY EMPTY `patterns` list (the line matcher never
   * fires) and are instead driven by the bounded flow analyzer in
   * `semantic.ts` (source → assignment → sink within one file, explicit
   * sanitizer allowlist, hard bounds). One registry, one finding model —
   * flow findings are normal SAST findings with the same identity rules.
   */
  readonly flow?: 'command' | 'sql' | 'html';
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

/** Language families sharing the ECMAScript rule shape (v2 gating). */
const JS_FAMILY: readonly string[] = ['javascript', 'typescript', 'jsx', 'tsx'];

/** JVM language families sharing the Java rule shape (v2 gating). */
const JVM_FAMILY: readonly string[] = ['java', 'kotlin', 'groovy', 'scala'];

/**
 * DG-SAST-001 — OS command execution with dynamically built commands.
 *
 * Fires when `exec`/`execSync` (the child_process APIs that always
 * invoke a shell) receive a command built with template interpolation
 * or string concatenation — the classic command-injection shape.
 */
const RULE_COMMAND_INJECTION: SastRule = {
  id: 'DG-SAST-001',
  languages: JS_FAMILY,
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
  languages: JS_FAMILY,
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
  languages: JS_FAMILY,
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
  languages: JS_FAMILY,
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
  languages: JS_FAMILY,
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
 * UNIVERSAL RULE SET (SAST v2) — DG-SAST-007 onward.
 *
 * Same engine, same contracts as v1 (deterministic, conservative,
 * linear-time, read-only — see the module header), extended across the
 * language catalog in `languages.ts`:
 *
 * - every rule declares the families it applies to (`languages`); the
 *   engine gates per file, so a Python rule never runs on a Kotlin file;
 * - `languages: undefined` means universal (credential heuristic);
 * - conservative shapes only: dangerous SINKS receiving interpolated
 *   or concatenated values (or dangerous named operations with no safe
 *   reading, e.g. MODE_WORLD_READABLE, delegatecall);
 * - one positive synthetic fixture per rule in `sastLanguages.test.ts`;
 * - severity stays honest: without dataflow, taintedness is unproven,
 *   so "dynamic value" is the trigger, never "confirmed exploit".
 */

const rule = (config: SastRule): SastRule => config;

const RULE_PY_CODE_EVAL = rule({
  id: 'DG-SAST-007', languages: ['python'],
  title: 'Dynamic code evaluation (eval/exec) from a built string',
  description: 'Python eval/exec receives an f-string or concatenated string. If any part is attacker-influenced, arbitrary code executes.',
  severity: 'HIGH', cwe: 'CWE-95', category: 'code-injection',
  remediation: 'Remove dynamic evaluation: use data structures, mapping or ast.literal_eval for literal data; never build code strings from input.',
  limitation: 'Lexical, line-based: only f-string or quoted-concatenation arguments are flagged; pass-through variables are not detected.',
  patterns: [/\b(?:eval|exec)\s*\(\s*f(['"])/, /\b(?:eval|exec)\s*\(\s*(['"])[^'"]*\1\s*\+/],
});

const RULE_PY_OS_CMD = rule({
  id: 'DG-SAST-008', languages: ['python'],
  title: 'OS command built from a dynamic string (os.system/os.popen)',
  description: 'os.system/os.popen receives an f-string or concatenated command. Attacker-influenced parts allow arbitrary command execution.',
  severity: 'HIGH', cwe: 'CWE-78', category: 'command-injection',
  remediation: 'Use subprocess.run with an argument list and shell=False; never build command strings by interpolation or concatenation.',
  limitation: 'Lexical, line-based: only f-string or quoted-concatenation arguments are flagged.',
  patterns: [/\bos\.(?:system|popen)\s*\(\s*f(['"])/, /\bos\.(?:system|popen)\s*\(\s*(['"])[^'"]*\1\s*\+/],
});

const RULE_PY_UNSAFE_DESERIALIZE = rule({
  id: 'DG-SAST-009', languages: ['python'],
  title: 'Unsafe deserialization (pickle/marshal/yaml.load)',
  description: 'pickle/marshal deserialization or yaml.load without a safe Loader can execute embedded objects — untrusted input becomes code execution.',
  severity: 'HIGH', cwe: 'CWE-502', category: 'unsafe-deserialization',
  remediation: 'Use json (or yaml.safe_load) for untrusted data; reserve pickle for trusted, integrity-protected blobs only.',
  limitation: 'Lexical, line-based: flags the unsafe calls themselves; a yaml.load with an explicit Loader= on the same line is excluded.',
  patterns: [/\bpickle\.loads?\s*\(/, /\byaml\.load(?:_all)?\s*\((?![^)]*\bLoader\s*=)/, /\bmarshal\.loads?\s*\(/],
});

const RULE_PY_WEAK_HASH = rule({
  id: 'DG-SAST-010', languages: ['python'],
  title: 'Weak hash algorithm (hashlib.md5/sha1)',
  description: 'hashlib.md5/sha1 is cryptographically broken for collision resistance; security uses require a modern algorithm.',
  severity: 'LOW', cwe: 'CWE-327', category: 'weak-cryptography',
  remediation: 'Use SHA-256 or stronger for security purposes; comment non-security checksum uses explicitly.',
  limitation: 'Algorithm choice only; the purpose (security vs checksum) needs context the lexical engine lacks.',
  patterns: [/\bhashlib\.(?:md5|sha1)\s*\(/],
});

const RULE_PY_DJANGO_RAW_SQL = rule({
  id: 'DG-SAST-011', languages: ['python'],
  title: 'Django raw SQL built from a dynamic string',
  description: 'A Django .raw() query receives an f-string or concatenated SQL. Attacker-influenced parts rewrite the query (SQL injection).',
  severity: 'MEDIUM', cwe: 'CWE-89', category: 'sql-injection',
  remediation: 'Use the ORM or parameterized raw SQL (raw("… %s …", [param])). Never interpolate input into SQL text.',
  limitation: 'Lexical, line-based; framework-shape heuristic (Django raw). No dataflow: taintedness unproven → MEDIUM.',
  patterns: [/\.raw\s*\(\s*f(['"])/, /\.raw\s*\(\s*(['"])[^'"]*\1\s*\+/],
});

const RULE_PY_FLASK_DEBUG = rule({
  id: 'DG-SAST-012', languages: ['python'],
  title: 'Flask debug mode enabled on app.run',
  description: 'app.run(debug=True) exposes the interactive debugger; in production this leaks source and enables remote code execution.',
  severity: 'MEDIUM', cwe: 'CWE-489', category: 'framework-security',
  remediation: 'Keep debug off in production; drive it from an environment flag and run production behind a WSGI server.',
  limitation: 'Detects the literal debug=True on app.run only; other launch paths are not covered.',
  patterns: [/\bapp\.run\s*\([^)]*\bdebug\s*=\s*True/],
});

const RULE_JVM_CMD = rule({
  id: 'DG-SAST-013', languages: JVM_FAMILY,
  title: 'JVM command execution built from a concatenated string',
  description: 'Runtime.exec / ProcessBuilder receives a concatenated command. Attacker-influenced parts allow arbitrary command execution.',
  severity: 'HIGH', cwe: 'CWE-78', category: 'command-injection',
  remediation: 'Pass the program and each argument as separate array elements (ProcessBuilder with arg list); never build one command string.',
  limitation: 'Lexical, line-based: only quoted-concatenation shapes are flagged.',
  patterns: [/\bRuntime\.getRuntime\s*\(\s*\)\s*\.exec\s*\(\s*(['"])[^'"]*\1\s*\+/, /\bnew\s+ProcessBuilder\s*\([^)]*(['"])[^'"]*\1\s*\+/],
});

const RULE_JVM_SQL = rule({
  id: 'DG-SAST-014', languages: JVM_FAMILY,
  title: 'JDBC statement built from concatenated SQL',
  description: 'executeQuery/executeUpdate/execute receives concatenated SQL text. Attacker-influenced parts rewrite the statement (SQL injection).',
  severity: 'HIGH', cwe: 'CWE-89', category: 'sql-injection',
  remediation: 'Use PreparedStatement with ? placeholders and setXxx parameters; never concatenate input into SQL.',
  limitation: 'Lexical, line-based: only quoted-concatenation first arguments are flagged.',
  patterns: [/\.(?:executeQuery|executeUpdate|execute)\s*\(\s*(['"])[^'"]*\1\s*[+]/],
});

const RULE_JVM_WEAK_HASH = rule({
  id: 'DG-SAST-015', languages: JVM_FAMILY,
  title: 'Weak hash algorithm (MessageDigest MD5/SHA-1)',
  description: 'MessageDigest.getInstance("MD5"/"SHA-1") selects algorithms broken for collision resistance.',
  severity: 'LOW', cwe: 'CWE-327', category: 'weak-cryptography',
  remediation: 'Prefer SHA-256 or stronger; document non-security checksum uses.',
  limitation: 'Algorithm choice only; purpose requires context.',
  patterns: [/\bMessageDigest\.getInstance\s*\(\s*(['"])(?:MD5|SHA-?1)\1/i],
});

const RULE_ANDROID_WORLD_READABLE = rule({
  id: 'DG-SAST-016', languages: ['java', 'kotlin'],
  title: 'World-readable/writable private storage (MODE_WORLD_*)',
  description: 'MODE_WORLD_READABLE/WRITABLE makes app-private files readable or writable by every other app on the device.',
  severity: 'HIGH', cwe: 'CWE-732', category: 'android-insecure-storage',
  remediation: 'Use MODE_PRIVATE (or EncryptedSharedPreferences/.DataStore); share data explicitly via a FileProvider with grants.',
  limitation: 'Flags the constant itself; legacy API removed in modern Android but still compiled against older targets.',
  patterns: [/\bMODE_WORLD_(?:READABLE|WRITABLE)\b/],
});

const RULE_ANDROID_WEBVIEW = rule({
  id: 'DG-SAST-017', languages: ['java', 'kotlin'],
  title: 'WebView risky settings enabled',
  description: 'setJavaScriptEnabled(true) / setAllowFileAccess*(true) widen the WebView attack surface; combined with untrusted content this enables script and file access.',
  severity: 'MEDIUM', cwe: 'CWE-749', category: 'android-webview',
  remediation: 'Enable JavaScript only for trusted origins; keep file access disabled; prefer safe navigation over file URLs in untrusted pages.',
  limitation: 'Flags the literal settings calls; whether untrusted content is loaded requires dataflow the engine lacks.',
  patterns: [/setJavaScriptEnabled\s*\(\s*true\s*\)/, /setAllowFileAccess(?:FromFileURLs)?\s*\(\s*true\s*\)/],
});

const RULE_NATIVE_MEMORY = rule({
  id: 'DG-SAST-018', languages: ['c', 'cpp', 'objc', 'objcpp'],
  title: 'Dangerous C memory function (gets/strcpy/strcat/sprintf)',
  description: 'gets/strcpy/strcat/sprintf/vsprintf perform no bounds checking; with attacker-controlled input they enable buffer overflows.',
  severity: 'MEDIUM', cwe: 'CWE-120', category: 'memory-safety',
  remediation: 'Use bounded variants (fgets, snprintf, strlcpy/strscpy) and length-checked copies; never gets().',
  limitation: 'Call-name heuristic: no taint or length analysis, so risk is signal, not proof → MEDIUM.',
  patterns: [/\b(?:gets|strcpy|strcat|sprintf|vsprintf)\s*\(/],
});

const RULE_CS_CMD = rule({
  id: 'DG-SAST-019', languages: ['csharp'],
  title: 'Process.Start built from a concatenated command',
  description: 'Process.Start receives a concatenated command line. Attacker-influenced parts allow arbitrary program execution.',
  severity: 'HIGH', cwe: 'CWE-78', category: 'command-injection',
  remediation: 'Start a fixed executable with an argument list (ProcessStartInfo.ArgumentList); never concatenate a command line.',
  limitation: 'Lexical, line-based: only quoted-concatenation shapes are flagged.',
  patterns: [/\bProcess\.Start\s*\([^)]*(['"])[^'"]*\1\s*\+/],
});

const RULE_CS_SQL = rule({
  id: 'DG-SAST-020', languages: ['csharp'],
  title: 'SqlCommand built from concatenated SQL',
  description: 'new SqlCommand/SqlDataAdapter receives concatenated SQL. Attacker-influenced parts rewrite the query (SQL injection).',
  severity: 'HIGH', cwe: 'CWE-89', category: 'sql-injection',
  remediation: 'Use SqlCommand with Parameters (@name) and never concatenate input into CommandText.',
  limitation: 'Lexical, line-based: only quoted-concatenation constructor arguments are flagged.',
  patterns: [/\bnew\s+Sql(?:Command|DataAdapter)\s*\([^)]*(['"])[^'"]*\1\s*\+/],
});

const RULE_CS_WEAK_HASH = rule({
  id: 'DG-SAST-021', languages: ['csharp', 'vbnet'],
  title: 'Weak hash algorithm (MD5/SHA-1 providers)',
  description: 'MD5/SHA1 Create or CryptoServiceProvider types select algorithms broken for collision resistance.',
  severity: 'LOW', cwe: 'CWE-327', category: 'weak-cryptography',
  remediation: 'Use SHA-256 or stronger (SHA256.Create); document non-security checksum uses.',
  limitation: 'Type-name heuristic only; purpose requires context.',
  patterns: [/\b(?:MD5\.Create|SHA1\.Create|MD5CryptoServiceProvider|SHA1CryptoServiceProvider)\b/],
});

const RULE_VB_SHELL = rule({
  id: 'DG-SAST-022', languages: ['vbnet'],
  title: 'VB Shell() built from a concatenated command',
  description: 'Shell() receives a concatenated command line. Attacker-influenced parts allow arbitrary program execution.',
  severity: 'HIGH', cwe: 'CWE-78', category: 'command-injection',
  remediation: 'Use ProcessStartInfo with a fixed executable and ArgumentList; never build command strings from input.',
  limitation: 'Lexical, line-based: only quoted concatenation (& or +) is flagged.',
  patterns: [/\bShell\s*\(\s*(['"])[^'"]*\1\s*[+&]/],
});

const RULE_PHP_CMD = rule({
  id: 'DG-SAST-023', languages: ['php'],
  title: 'PHP command execution built from dynamic input',
  description: 'shell_exec/system/passthru or backtick execution receives concatenated/interpolated input — arbitrary command execution.',
  severity: 'HIGH', cwe: 'CWE-78', category: 'command-injection',
  remediation: 'Use escapeshellarg/escapeshellcmd on every dynamic part, or a native PHP implementation without a shell.',
  limitation: 'Lexical, line-based: quoted concat, leading $variable, and backtick interpolation shapes only.',
  patterns: [/\b(?:shell_exec|system|passthru)\s*\(\s*(['"])[^'"]*\1\s*\./, /\b(?:shell_exec|system|passthru)\s*\(\s*\$/, /`[^`]*\$\w+[^`]*`/],
});

const RULE_PHP_SQL = rule({
  id: 'DG-SAST-024', languages: ['php'],
  title: 'PHP SQL query built by concatenation',
  description: 'mysql_query/mysqli_query/->query receives concatenated SQL. Attacker-influenced parts rewrite the query (SQL injection).',
  severity: 'HIGH', cwe: 'CWE-89', category: 'sql-injection',
  remediation: 'Use prepared statements (mysqli prepare/PDO with bound parameters); never concatenate input into SQL.',
  limitation: 'Lexical, line-based: quoted-concatenation shapes only.',
  patterns: [/\b(?:mysql_query|mysqli_query)\s*\([^)]*(['"])[^'"]*\1\s*\.\s*\$/, /->\s*query\s*\(\s*(['"])[^'"]*\1\s*\.\s*\$/],
});

const RULE_GO_CMD = rule({
  id: 'DG-SAST-025', languages: ['go'],
  title: 'Go exec.Command built with fmt.Sprintf',
  description: 'exec.Command/CommandContext built via fmt.Sprintf embeds dynamic values into a command string — command injection risk.',
  severity: 'HIGH', cwe: 'CWE-78', category: 'command-injection',
  remediation: 'Pass fixed binary name plus separate arguments to exec.Command; never format a combined command string.',
  limitation: 'Lexical, line-based: only the fmt.Sprintf shape is flagged.',
  patterns: [/\bexec\.Command(?:Context)?\s*\([^)]*fmt\.Sprintf/],
});

const RULE_GO_WEAK_HASH = rule({
  id: 'DG-SAST-026', languages: ['go'],
  title: 'Weak hash algorithm (crypto/md5, crypto/sha1)',
  description: 'md5.New/sha1.New selects algorithms broken for collision resistance.',
  severity: 'LOW', cwe: 'CWE-327', category: 'weak-cryptography',
  remediation: 'Use crypto/sha256 or stronger; document non-security checksum uses.',
  limitation: 'Package/constructor name only; purpose requires context.',
  patterns: [/\b(?:md5|sha1)\.New\s*\(/],
});

const RULE_RUBY_CMD = rule({
  id: 'DG-SAST-027', languages: ['ruby'],
  title: 'Ruby command execution with #{…} interpolation',
  description: 'system() or backtick execution with string interpolation embeds dynamic values into a shell command.',
  severity: 'HIGH', cwe: 'CWE-78', category: 'command-injection',
  remediation: 'Pass arguments as an array (system(cmd, arg1, arg2)) or use Open3 with explicit argument vectors; never interpolate into a shell string.',
  limitation: 'Lexical, line-based: interpolation shapes only.',
  patterns: [/\bsystem\s*\(\s*(['"])[^'"]*#\{/, /`[^`]*#\{[^`]*`/],
});

const RULE_RUST_CMD = rule({
  id: 'DG-SAST-028', languages: ['rust'],
  title: 'Rust Command built with format!',
  description: 'Command::new/.arg built via format! embeds dynamic values into a command/argument string.',
  severity: 'HIGH', cwe: 'CWE-78', category: 'command-injection',
  remediation: 'Pass program and arguments as separate .arg() values without formatting; when a shell is unavoidable, validate/allowlist the values.',
  limitation: 'Lexical, line-based: only the format! shape is flagged.',
  patterns: [/\bCommand::new\s*\([^)]*format!/, /\.arg\s*\([^)]*format!/],
});

const RULE_SWIFT_WEAK_CRYPTO = rule({
  id: 'DG-SAST-029', languages: ['swift'],
  title: 'Weak Swift/CommonCrypto algorithm (DES/3DES/RC4/MD5/SHA-1)',
  description: 'Legacy CommonCrypto algorithms (kCCAlgorithmDES/3DES/RC4/…) or Insecure.md5/sha1 are broken for modern security needs.',
  severity: 'MEDIUM', cwe: 'CWE-327', category: 'weak-cryptography',
  remediation: 'Use AES-GCM (CryptoKit) and SHA-256+; legacy algorithms only behind an explicitly documented compatibility decision.',
  limitation: 'Algorithm-name heuristic; purpose and key management require context.',
  patterns: [/\bkCCAlgorithm(?:DES|3DES|RC4|RC2|Blowfish)\b/, /\bInsecure\.(?:md5|sha1)\b/i],
});

const RULE_DART_CMD = rule({
  id: 'DG-SAST-030', languages: ['dart'],
  title: 'Dart Process built from a concatenated command',
  description: 'Process.run/start receives a concatenated command. Attacker-influenced parts allow arbitrary program execution.',
  severity: 'HIGH', cwe: 'CWE-78', category: 'command-injection',
  remediation: 'Pass a fixed executable plus an argument list (Process.run(cmd, [args])); never concatenate a command line.',
  limitation: 'Lexical, line-based: quoted-concatenation shapes only.',
  patterns: [/\bProcess\.(?:run|start)\s*\(\s*(['"])[^'"]*\1\s*\+/],
});

const RULE_LUA_CMD = rule({
  id: 'DG-SAST-031', languages: ['lua'],
  title: 'Lua command execution with .. concatenation',
  description: 'os.execute/io.popen receives a concatenated command string — dynamic shell execution.',
  severity: 'HIGH', cwe: 'CWE-78', category: 'command-injection',
  remediation: 'Avoid os.execute/io.popen for dynamic input; validate against an allowlist or use a native binding without a shell.',
  limitation: 'Lexical, line-based: `..` concatenation inside the call only.',
  patterns: [/\bos\.execute\s*\([^)]*\.\./, /\bio\.popen\s*\([^)]*\.\./],
});

const RULE_PERL_CMD = rule({
  id: 'DG-SAST-032', languages: ['perl'],
  title: 'Perl command execution with interpolation',
  description: 'system() or backticks with $variable interpolation embeds dynamic values into a shell command.',
  severity: 'HIGH', cwe: 'CWE-78', category: 'command-injection',
  remediation: 'Use the multi-argument system(LIST) form or IPC::Open3 without a shell; never interpolate into a command string.',
  limitation: 'Lexical, line-based: interpolation shapes only.',
  patterns: [/\bsystem\s*\(\s*(['"])[^'"]*\$/, /`[^`]*\$(?:\w+|\{)[^`]*`/],
});

const RULE_SOLIDITY_DANGEROUS = rule({
  id: 'DG-SAST-033', languages: ['solidity'],
  title: 'Solidity delegatecall/selfdestruct usage',
  description: 'delegatecall executes foreign code in the caller storage context and selfdestruct permanently destroys the contract — both demand explicit review.',
  severity: 'MEDIUM', category: 'dangerous-operation',
  remediation: 'Restrict delegatecall to audited, immutable targets behind access control; remove selfdestruct or gate it behind multisig.',
  limitation: 'Call-name signal only: no control-flow or storage analysis — flagged for review, not proof of exploitability.',
  patterns: [/\.delegatecall\s*\(/, /\bselfdestruct\s*\(/],
});

const RULE_SHELL_EVAL = rule({
  id: 'DG-SAST-034', languages: ['bash', 'shell-posix'],
  title: 'Shell eval with variable expansion',
  description: 'eval re-parses expanded variables as shell syntax; any attacker-influenced value becomes arbitrary command execution.',
  severity: 'HIGH', cwe: 'CWE-78', category: 'command-injection',
  remediation: 'Avoid eval; use arrays ("$@") and case dispatch, or validate against a strict allowlist before evaluation.',
  limitation: 'Lexical, line-based: eval followed by an expansion on the same line.',
  patterns: [/\beval\s+[^#]*\$\{?\w/],
});

const RULE_PS_INVOKE_EXPRESSION = rule({
  id: 'DG-SAST-035', languages: ['powershell'],
  title: 'PowerShell Invoke-Expression with variables',
  description: 'Invoke-Expression executes a built string as PowerShell code — dynamic input becomes code execution.',
  severity: 'HIGH', cwe: 'CWE-95', category: 'code-injection',
  remediation: 'Replace Invoke-Expression with direct cmdlet invocation, splatting or a validated command lookup; never execute built strings.',
  limitation: 'Lexical, line-based: same-line variable usage only.',
  patterns: [/\bInvoke-Expression\s+[^#]*\$/],
});

const RULE_APEX_SOQL = rule({
  id: 'DG-SAST-036', languages: ['apex'],
  title: 'Apex SOQL built with concatenation (Database.query)',
  description: 'Database.query with a concatenated query string allows SOQL injection when user input reaches the string.',
  severity: 'HIGH', cwe: 'CWE-89', category: 'injection',
  remediation: 'Use bind variables in static SOQL or String.escapeSingleQuotes on dynamic fragments; allowlist sortable/filterable fields.',
  limitation: 'Lexical, line-based: quoted-concatenation shapes only.',
  patterns: [/\bDatabase\.query\s*\(\s*(['"])[^'"]*\1\s*\+/],
});

const RULE_BEAM_CODE_EXEC = rule({
  id: 'DG-SAST-037', languages: ['elixir', 'erlang'],
  title: 'Erlang/Elixir dynamic code or shell execution',
  description: 'Code.eval_string/eval_quoted evaluates built strings as code; os:cmd with ++ concatenation builds shell commands dynamically.',
  severity: 'HIGH', category: 'code-execution',
  remediation: 'Avoid eval; use data-driven dispatch. For shells, pass argument lists and validate inputs against an allowlist.',
  limitation: 'Lexical, line-based: the eval call shape and the ++ concatenation shape only.',
  patterns: [/\bCode\.eval_(?:string|quoted)\s*\(/, /\bos\s*:\s*cmd\s*\([^)]*\+\+/],
});

const RULE_R_CMD = rule({
  id: 'DG-SAST-038', languages: ['r'],
  title: 'R system() built from paste/sprintf',
  description: 'system(paste(...)) constructs shell commands from dynamic parts — command injection risk.',
  severity: 'MEDIUM', cwe: 'CWE-78', category: 'command-injection',
  remediation: 'Pass separate arguments (system2(cmd, args)) with shQuote() on every dynamic value.',
  limitation: 'Lexical, line-based: the paste/sprintf construction shape only; taintedness unproven → MEDIUM.',
  patterns: [/\bsystem\s*\(\s*(?:base::)?paste\s*\(/, /\bsystem\s*\(\s*(?:base::)?sprintf\s*\(/],
});

const RULE_JULIA_CMD = rule({
  id: 'DG-SAST-039', languages: ['julia'],
  title: 'Julia run(`…`) with $ interpolation',
  description: 'run with an interpolated backtick command embeds dynamic values into a shell command.',
  severity: 'MEDIUM', cwe: 'CWE-78', category: 'command-injection',
  remediation: 'Use the backtick cmd`prog` form with separate interpolated ARGUMENTS (auto-escaped), never interpolated command text.',
  limitation: 'Lexical, line-based: interpolation inside a run(`…`) literal; taintedness unproven → MEDIUM.',
  patterns: [/\brun\s*\(\s*`[^`]*\$/],
});

const RULE_SQL_DYNAMIC = rule({
  id: 'DG-SAST-040', languages: ['sql'],
  title: 'Dynamic SQL execution (EXEC(@…)/EXECUTE IMMEDIATE … ||)',
  description: 'Dynamic SQL assembled from variables/concatenation defeats plan caching and enables SQL injection when input reaches the string.',
  severity: 'MEDIUM', cwe: 'CWE-89', category: 'sql-injection',
  remediation: 'Prefer static SQL with parameters; when dynamic SQL is unavoidable, sp_executesql with typed parameters and allowlisted identifiers.',
  limitation: 'Configuration-shape heuristic on the SQL text; no taint analysis → MEDIUM.',
  patterns: [/\bEXEC(?:UTE)?\s*\(\s*@/i, /\bEXECUTE\s+IMMEDIATE\b[^;]*\|\|/i],
});

const RULE_XML_XXE = rule({
  id: 'DG-SAST-041', languages: ['xml'],
  title: 'External XML entity declaration (XXE shape)',
  description: 'A DTD <!ENTITY … SYSTEM/PUBLIC> declaration can pull external content (file:// or network) when parsed by a non-hardened parser.',
  severity: 'HIGH', cwe: 'CWE-611', category: 'xxe',
  remediation: 'Disable DTDs/external entities at the parser (feature flags) and treat DTDs in untrusted XML as hostile.',
  limitation: 'Declaration-shape heuristic: whether an unsafe parser consumes the document requires cross-file context.',
  patterns: [/<!ENTITY\s+\w+\s+(?:SYSTEM|PUBLIC)/i],
});

const RULE_YAML_PRIVILEGED = rule({
  id: 'DG-SAST-042', languages: ['yaml'],
  title: 'Privileged container (securityContext privileged: true)',
  description: 'privileged: true grants the container near-host capabilities — a container escape amplifier.',
  severity: 'MEDIUM', cwe: 'CWE-250', category: 'container-security',
  remediation: 'Drop capabilities to the minimum set (run as non-root, readOnlyRootFilesystem); reserve privileged for strictly reviewed system daemons.',
  limitation: 'Key/value heuristic on the YAML text; pod/policy context requires cross-file analysis.',
  patterns: [/\bprivileged:\s*true\b/],
});

const RULE_GHA_PERMISSIONS = rule({
  id: 'DG-SAST-043', languages: ['github-actions'],
  title: 'GitHub Actions workflow grants write-all permissions',
  description: 'permissions: write-all gives every job a full write token — a compromised action can tamper with the repository.',
  severity: 'MEDIUM', cwe: 'CWE-250', category: 'ci-permissions',
  remediation: 'Set the minimum per-job permissions block (contents: read by default); grant write scopes only where a job proves the need.',
  limitation: 'Literal `permissions: write-all` shape only.',
  patterns: [/\bpermissions:\s*write-all\b/],
});

const RULE_DOCKERFILE_PIPE_TO_SHELL = rule({
  id: 'DG-SAST-044', languages: ['dockerfile'],
  title: 'Dockerfile downloads and pipes a script into a shell',
  description: 'curl … | sh executes a remote script without integrity verification inside the image build.',
  severity: 'MEDIUM', cwe: 'CWE-494', category: 'config-security',
  remediation: 'Download a pinned artifact, verify its checksum/signature, then execute; avoid piping unverified scripts into shells.',
  limitation: 'Line-shape heuristic (curl piped to sh); verification steps elsewhere in the file are not correlated.',
  patterns: [/\bcurl[^|]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b/],
});

const RULE_TF_OPEN_INGRESS = rule({
  id: 'DG-SAST-045', languages: ['terraform'],
  title: 'Terraform ingress open to 0.0.0.0/0',
  description: 'cidr_blocks = ["0.0.0.0/0"] exposes the security group to the entire internet (commonly paired with SSH/RDP ports).',
  severity: 'MEDIUM', cwe: 'CWE-284', category: 'infra-security',
  remediation: 'Restrict ingress to explicit source ranges; put administrative ports behind a bastion/SSM path instead of open CIDRs.',
  limitation: 'Literal open-CIDR shape; the port pairing requires cross-attribute analysis the line engine lacks.',
  patterns: [/\bcidr_blocks\s*=\s*\[[^\]]*0\.0\.0\.0\/0/],
});

const RULE_ELECTRON_NODE_INTEGRATION = rule({
  id: 'DG-SAST-046', languages: JS_FAMILY,
  title: 'Electron nodeIntegration enabled / contextIsolation disabled',
  description: 'nodeIntegration: true (or contextIsolation: false) exposes Node capabilities to renderer content; XSS in the renderer becomes RCE.',
  severity: 'HIGH', category: 'framework-security',
  remediation: 'Keep nodeIntegration:false and contextIsolation:true; bridge features through a narrowly preloaded contextBridge API.',
  limitation: 'Literal webPreferences keys on one line; cross-file preload analysis is out of scope.',
  patterns: [/\bnodeIntegration\s*:\s*true/, /\bcontextIsolation\s*:\s*false/],
});

const RULE_ANDROID_EXPORTED = rule({
  id: 'DG-SAST-047', languages: ['android-manifest'],
  title: 'Exported Android component (android:exported="true")',
  description: 'An activity/service/receiver/provider is exported: any other app (or the system) can invoke it, exposing internal entry points.',
  severity: 'MEDIUM', category: 'android-security',
  remediation: 'Keep components non-exported unless they are genuine entry points; exported components must validate callers, permissions and intent contents.',
  limitation: 'Manifest attribute heuristic: intent-filter analysis and caller validation require deeper manifest analysis.',
  patterns: [/<(?:activity|activity-alias|service|receiver|provider)\b[^>]*android:exported="true"/],
});

/**
 * Flow rules (deep-semantic pump) — DG-SAST-048…050. Intentionally
 * pattern-less (`patterns: []`): they never fire from the line matcher
 * and are driven exclusively by the bounded flow analyzer
 * (`semantic.ts`) with per-language source/sink/sanitizer tables and
 * hard propagation bounds. Findings land at the SINK line with the
 * sink column; identity/lifecycle/report/SARIF behavior is identical
 * to every other rule. Maturity stays PARTIAL — this is bounded
 * intra-file reasoning, not a parser/AST/dataflow engine.
 */

const FLOW_LANGUAGES: readonly string[] = [
  'javascript', 'typescript', 'jsx', 'tsx', 'python', 'php', 'ruby', 'go', 'java', 'kotlin', 'csharp',
];

const RULE_FLOW_COMMAND = rule({
  id: 'DG-SAST-048', languages: FLOW_LANGUAGES,
  title: 'Untrusted input flows into command execution (bounded taint flow)',
  description: 'A value originating from a request/argv source reaches a command-execution call through assignments in the same file. Unlike the single-line shapes (DG-SAST-001/008/013/…), source and sink may sit on different lines.',
  severity: 'HIGH', cwe: 'CWE-78', category: 'taint-flow', flow: 'command',
  remediation: 'Do not build command strings from request input. Use argument-vector APIs with fixed command names, or allowlist-validate the exact values before use.',
  limitation: 'Bounded intra-file, single-pass flow: use-before-assignment, loop-carried values, cross-file/helper flows and sanitizers outside the explicit allowlist are not tracked; at most 3 findings per file.',
  patterns: [],
});

const RULE_FLOW_SQL = rule({
  id: 'DG-SAST-049', languages: FLOW_LANGUAGES,
  title: 'Untrusted input flows into SQL execution (bounded taint flow)',
  description: 'A value originating from a request/argv source reaches a SQL-execution call through assignments in the same file — the multi-line form of the SQL-concat shapes.',
  severity: 'HIGH', cwe: 'CWE-89', category: 'taint-flow', flow: 'sql',
  remediation: 'Use parameterized statements (placeholders + bound parameters) for every query that involves request-derived values.',
  limitation: 'Bounded intra-file, single-pass flow; parameterized (`?`/`%s`/bound) forms are treated as sanitized, other sanitizers only from the explicit allowlist; at most 3 findings per file.',
  patterns: [],
});

const RULE_FLOW_HTML = rule({
  id: 'DG-SAST-050', languages: ['javascript', 'typescript', 'jsx', 'tsx', 'python'],
  title: 'Untrusted input flows into HTML rendering (bounded taint flow, XSS)',
  description: 'A value originating from a request/argv source reaches an HTML sink (innerHTML/document.write/dangerouslySetInnerHTML/render_template_string) through assignments in the same file.',
  severity: 'HIGH', cwe: 'CWE-79', category: 'taint-flow', flow: 'html',
  remediation: 'Render text via textContent/template auto-escaping; if HTML must be rendered, sanitize server-side with an allowlist-based sanitizer before assignment.',
  limitation: 'Bounded intra-file, single-pass flow; sanitizer knowledge is an explicit allowlist (DOMPurify/escapeHtml/textContent/html.escape/bleach); at most 3 findings per file.',
  patterns: [],
});

/**
 * The closed rule registry, ordered by id. Adding a rule = appending
 * here with the next stable id (DG-SAST-051…) and documenting it in
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
  RULE_PY_CODE_EVAL,
  RULE_PY_OS_CMD,
  RULE_PY_UNSAFE_DESERIALIZE,
  RULE_PY_WEAK_HASH,
  RULE_PY_DJANGO_RAW_SQL,
  RULE_PY_FLASK_DEBUG,
  RULE_JVM_CMD,
  RULE_JVM_SQL,
  RULE_JVM_WEAK_HASH,
  RULE_ANDROID_WORLD_READABLE,
  RULE_ANDROID_WEBVIEW,
  RULE_NATIVE_MEMORY,
  RULE_CS_CMD,
  RULE_CS_SQL,
  RULE_CS_WEAK_HASH,
  RULE_VB_SHELL,
  RULE_PHP_CMD,
  RULE_PHP_SQL,
  RULE_GO_CMD,
  RULE_GO_WEAK_HASH,
  RULE_RUBY_CMD,
  RULE_RUST_CMD,
  RULE_SWIFT_WEAK_CRYPTO,
  RULE_DART_CMD,
  RULE_LUA_CMD,
  RULE_PERL_CMD,
  RULE_SOLIDITY_DANGEROUS,
  RULE_SHELL_EVAL,
  RULE_PS_INVOKE_EXPRESSION,
  RULE_APEX_SOQL,
  RULE_BEAM_CODE_EXEC,
  RULE_R_CMD,
  RULE_JULIA_CMD,
  RULE_SQL_DYNAMIC,
  RULE_XML_XXE,
  RULE_YAML_PRIVILEGED,
  RULE_GHA_PERMISSIONS,
  RULE_DOCKERFILE_PIPE_TO_SHELL,
  RULE_TF_OPEN_INGRESS,
  RULE_ELECTRON_NODE_INTEGRATION,
  RULE_ANDROID_EXPORTED,
  RULE_FLOW_COMMAND,
  RULE_FLOW_SQL,
  RULE_FLOW_HTML,
];

export function sastRuleById(id: string): SastRule | undefined {
  return SAST_RULES.find((rule) => rule.id === id);
}
