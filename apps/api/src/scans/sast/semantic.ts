import type { SastRule } from './rules.js';

/**
 * BOUNDED SEMANTIC LAYER for the SAST engine (deep-semantic pump).
 *
 * This module is the engine's lightweight structural analyzer: it adds
 * source → sink reasoning on top of the line matcher WITHOUT becoming a
 * second engine or a parser dependency. Everything here is pure,
 * synchronous, deterministic function work over already-validated text
 * (the snapshot store guarantees plain UTF-8 text, ≤256 KiB per file).
 *
 * What it does (honest scope):
 * - LITERAL MASKING: replaces string-literal contents and comments with
 *   spaces, preserving every character offset — so text inside comments
 *   and strings can never produce a finding (a class of false positives
 *   the pure line matcher cannot avoid), and evidence columns stay exact.
 * - INTRA-FILE TAINT FLOW (single forward pass): a small per-language
 *   table of SOURCE expressions (request input, argv, …), SINK calls
 *   (command/SQL/HTML sinks) and SANITIZER calls (an explicit, bounded
 *   list) drives a bounded propagation: `source → variable → sink`
 *   across lines of ONE file produces a flow finding at the sink line.
 * - EXPLICIT BOUNDS (tested): at most MAX_FLOW_VARS tainted variables,
 *   at most MAX_TOKENS_PER_SNIPPET identifier tokens inspected per
 *   snippet, at most MAX_FLOW_FINDINGS_PER_RULE_PER_FILE findings per
 *   rule per file, a bounded sink-argument window, and NO recursion, NO
 *   fixpoint loops, NO cross-file resolution, NO call-graph construction.
 *   Use-before-definition ordering is not tracked (documented
 *   limitation) — the pass is strictly linear in file size.
 *
 * Security boundaries inherited and kept:
 * - READ-ONLY text analysis; the target code is never executed.
 * - The sanitizer model is a small EXPLICIT allowlist — the engine never
 *   claims complete sanitizer knowledge; anything not on the list is
 *   treated as unsanitized (conservative, may over-report, never
 *   silently suppresses).
 * - This is application logic, NOT a vulnerability-database import: no
 *   CVE/NVD/GHSA/OSV/KEV/EPSS data exists anywhere here (the dataset
 *   lock holds). The API names below are generic language surfaces, the
 *   same names the line-matcher rules already carry.
 */

/** Hard propagation bounds (documented in docs/SAST.md, asserted in tests). */
export const MAX_FLOW_VARS = 512;
export const MAX_TOKENS_PER_SNIPPET = 64;
export const MAX_FLOW_FINDINGS_PER_RULE_PER_FILE = 3;
export const MAX_SINK_ARGUMENT_WINDOW = 300;

/** The flow classes the analyzer implements (registry-gated, see rules.ts). */
export type SastFlowKind = 'command' | 'sql' | 'html';

/**
 * One candidate flow finding: the sink rule, the 0-based line of the
 * sink call and the 1-based column of the sink match (in the ORIGINAL
 * line — masking preserves offsets, so the mapping is exact).
 */
export interface SastFlowFinding {
  readonly ruleId: string;
  readonly lineIndex: number;
  readonly column: number;
}

/** One flow-enabled rule as the analyzer sees it. */
export interface FlowRuleRef {
  readonly id: string;
  readonly flow: SastFlowKind;
}

// ---------------------------------------------------------------------------
// Literal masking (comments + string contents → spaces, offsets preserved)
// ---------------------------------------------------------------------------

interface LiteralStyle {
  /** Tokens that start a line comment. */
  readonly lineComments: readonly string[];
  /** Block comment delimiters. */
  readonly blockComments: ReadonlyArray<{ open: string; close: string }>;
  /** Quote characters opening a string literal. */
  readonly quotes: readonly string[];
  /** Triple-quoted string openers (Python). */
  readonly tripleQuotes?: readonly string[];
}

const C_LIKE: LiteralStyle = {
  lineComments: ['//'],
  blockComments: [{ open: '/*', close: '*/' }],
  quotes: ["'", '"', '`'],
};

const HASH_LIKE: LiteralStyle = {
  lineComments: ['#'],
  blockComments: [],
  quotes: ["'", '"'],
};

const PYTHON_STYLE: LiteralStyle = {
  lineComments: ['#'],
  blockComments: [],
  quotes: ["'", '"'],
  tripleQuotes: ['"""', "'''"],
};

const SQL_STYLE: LiteralStyle = {
  lineComments: ['--'],
  blockComments: [{ open: '/*', close: '*/' }],
  quotes: ["'"],
};

const LUA_STYLE: LiteralStyle = {
  lineComments: ['--'],
  blockComments: [{ open: '--[[', close: ']]' }],
  quotes: ["'", '"'],
};

const POWERSHELL_STYLE: LiteralStyle = {
  lineComments: ['#'],
  blockComments: [{ open: '<#', close: '#>' }],
  quotes: ["'", '"'],
};

/** Rust is C-like but single quotes are LIFETIMES/chars — masking them would hide code. */
const RUST_STYLE: LiteralStyle = {
  lineComments: ['//'],
  blockComments: [{ open: '/*', close: '*/' }],
  quotes: ['"'],
};

function literalStyleFor(family: string): LiteralStyle {
  switch (family) {
    case 'python':
      return PYTHON_STYLE;
    case 'rust':
      return RUST_STYLE;
    case 'sql':
      return SQL_STYLE;
    case 'lua':
      return LUA_STYLE;
    case 'powershell':
      return POWERSHELL_STYLE;
    case 'php':
      // PHP accepts both comment styles.
      return { lineComments: ['//', '#'], blockComments: C_LIKE.blockComments, quotes: ["'", '"'] };
    case 'bash':
    case 'shell-posix':
    case 'ruby':
    case 'perl':
      // Command substitutions can contain # characters that are not
      // comments (for example Ruby's `#{expression}` interpolation).
      return { ...HASH_LIKE, quotes: ["'", '"', '`'] };
    case 'r':
    case 'julia':
    case 'elixir':
    case 'yaml':
    case 'github-actions':
    case 'dockerfile':
    case 'terraform':
      return HASH_LIKE;
    default:
      return C_LIKE;
  }
}

/**
 * Masked copy of the content: comment text and string-literal contents
 * become spaces; newlines, line counts and every character offset are
 * preserved exactly. Tolerant of malformed input by construction — the
 * state machine cannot throw on any byte sequence.
 */
function maskSource(content: string, family: string, keepStrings: boolean): string {
  const style = literalStyleFor(family);
  const out = content.split('');
  const n = content.length;
  // Multi-line states persist across the scan.
  let inLineComment = false;
  let blockClose: string | undefined;
  let stringQuote: string | undefined;
  let stringTriple: string | undefined;
  // A backtick template literal can span lines (C-like families).
  for (let i = 0; i < n; i += 1) {
    const ch = content[i] as string;
    if (ch === '\n') {
      inLineComment = false;
      // Only unterminated single-line strings and template literals
      // survive a newline; an OPEN triple-quoted string continues
      // (documented: a malformed unterminated triple swallows the rest
      // of the file into the mask — under-detection, never a finding).
      if (stringQuote !== undefined && stringTriple === undefined && stringQuote !== '`') {
        stringQuote = undefined;
      }
      continue;
    }
    if (inLineComment) {
      out[i] = ' ';
      continue;
    }
    if (blockClose !== undefined) {
      if (content.startsWith(blockClose, i)) {
        out[i] = ' ';
        out[i + 1] = ' ';
        i += blockClose.length - 1;
        blockClose = undefined;
      } else {
        out[i] = ' ';
      }
      continue;
    }
    if (stringQuote !== undefined) {
      // Triple-quoted strings close on their delimiter.
      if (stringTriple !== undefined && content.startsWith(stringTriple, i)) {
        if (!keepStrings) for (let k = 0; k < stringTriple.length; k += 1) out[i + k] = ' ';
        i += stringTriple.length - 1;
        stringQuote = undefined;
        stringTriple = undefined;
        continue;
      }
      if (ch === '\\' && i + 1 < n) {
        if (!keepStrings) { out[i] = ' '; out[i + 1] = ' '; }
        i += 1;
        continue;
      }
      if (ch === stringQuote) {
        // Single-quoted strings close on the first bare quote (triple-
        // quoted strings are handled above by the delimiter check).
        if (!keepStrings) out[i] = ' ';
        stringQuote = undefined;
        continue;
      }
      if (!keepStrings) out[i] = ' ';
      continue;
    }
    // Normal state: try the openers, longest first (triples before quotes,
    // `--[[` before `--`).
    if (style.tripleQuotes !== undefined) {
      let matched = false;
      for (const triple of style.tripleQuotes) {
        if (content.startsWith(triple, i)) {
          if (!keepStrings) for (let k = 0; k < triple.length; k += 1) out[i + k] = ' ';
          i += triple.length - 1;
          stringQuote = triple[0] as string;
          stringTriple = triple;
          matched = true;
          break;
        }
      }
      if (matched) continue;
    }
    let matched = false;
    for (const block of style.blockComments) {
      if (content.startsWith(block.open, i)) {
        for (let k = 0; k < block.open.length; k += 1) out[i + k] = ' ';
        i += block.open.length - 1;
        blockClose = block.close;
        matched = true;
        break;
      }
    }
    if (matched) continue;
    for (const token of style.lineComments) {
      if (content.startsWith(token, i)) {
        for (let k = 0; k < token.length; k += 1) out[i + k] = ' ';
        i += token.length - 1;
        inLineComment = true;
        matched = true;
        break;
      }
    }
    if (matched) continue;
    for (const quote of style.quotes) {
      if (ch === quote) {
        if (!keepStrings) out[i] = ' ';
        stringQuote = quote;
        stringTriple = undefined;
        matched = true;
        break;
      }
    }
    if (matched) continue;
    // Plain code character — copied verbatim.
  }
  return out.join('');
}

/** Mask comments and string literals for the bounded flow analyzer. */
export function maskLiterals(content: string, family: string): string {
  return maskSource(content, family, false);
}

// Only families whose comment syntax the small lexer explicitly models.
// Unknown/config formats stay unchanged rather than guessing their grammar.
const LEXICAL_COMMENT_FAMILIES: ReadonlySet<string> = new Set([
  'javascript', 'typescript', 'jsx', 'tsx', 'java', 'kotlin', 'scala', 'groovy',
  'c', 'cpp', 'objc', 'objcpp', 'csharp', 'go', 'rust', 'php', 'swift', 'dart', 'solidity',
  'python', 'shell-posix', 'bash', 'ruby', 'perl', 'r', 'julia', 'elixir', 'lua', 'powershell', 'sql',
]);

/** Preserve strings and offsets while masking recognized comments for lexical rules. */
export function maskComments(content: string, family: string): string {
  return LEXICAL_COMMENT_FAMILIES.has(family) ? maskSource(content, family, true) : content;
}

// ---------------------------------------------------------------------------
// Bounded per-language data tables (explicit, reviewed, tested)
// ---------------------------------------------------------------------------

/**
 * SOURCE expressions: where untrusted input enters. Kept deliberately
 * small and per-family — an expression that is not listed is NOT a
 * source (documented limitation, honest under-approximation).
 */
const SOURCES: Record<string, RegExp> = {
  javascript: /\b(?:req|request)\s*\.\s*(?:body|query|params|headers|cookies|files)\b|\bprocess\s*\.\s*argv\b/,
  typescript: /\b(?:req|request)\s*\.\s*(?:body|query|params|headers|cookies|files)\b|\bprocess\s*\.\s*argv\b/,
  jsx: /\b(?:req|request)\s*\.\s*(?:body|query|params|headers|cookies|files)\b/,
  tsx: /\b(?:req|request)\s*\.\s*(?:body|query|params|headers|cookies|files)\b/,
  python:
    /\binput\s*\(|\brequest\s*\.\s*(?:args|form|values|json|data|cookies|headers)\b|\bsys\s*\.\s*argv\b/,
  php: /\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\b/,
  ruby: /\bparams\s*\[/,
  go: /\bQuery\s*\(\s*\)\s*\.\s*Get\s*\(|\bFormValue\s*\(|\bHeader\s*\.\s*Get\s*\(/,
  java: /\bgetParameter\s*\(|\bgetHeader\s*\(|\bgetStringExtra\s*\(|\bgetExtras\s*\(/,
  kotlin: /\bgetParameter\s*\(|\bgetHeader\s*\(|\bgetStringExtra\s*\(|\bgetExtras\s*\(/,
  csharp: /\bRequest\s*\[|\bQueryString\s*\[|\bReadLine\s*\(/,
};

/** SANITIZER calls/idioms per family (explicit bounded allowlist). */
const SANITIZERS: Record<string, RegExp> = {
  javascript:
    /\bencodeURIComponent\s*\(|\bparseInt\s*\(|\bNumber\s*\(|\bescapeHtml\w*\s*\(|\bDOMPurify\s*\.\s*sanitize\s*\(|\bsanitizeHtml\w*\s*\(|\bsh\s*\.\s*quote\s*\(|\btextContent\s*=/,
  typescript:
    /\bencodeURIComponent\s*\(|\bparseInt\s*\(|\bNumber\s*\(|\bescapeHtml\w*\s*\(|\bDOMPurify\s*\.\s*sanitize\s*\(|\bsanitizeHtml\w*\s*\(|\bsh\s*\.\s*quote\s*\(|\btextContent\s*=/,
  jsx: /\bencodeURIComponent\s*\(|\bparseInt\s*\(|\bNumber\s*\(|\bescapeHtml\w*\s*\(|\bDOMPurify\s*\.\s*sanitize\s*\(/,
  tsx: /\bencodeURIComponent\s*\(|\bparseInt\s*\(|\bNumber\s*\(|\bescapeHtml\w*\s*\(|\bDOMPurify\s*\.\s*sanitize\s*\(/,
  python:
    /\bshlex\s*\.\s*quote\s*\(|\bpipes\s*\.\s*quote\s*\(|\bint\s*\(|\bhtml\s*\.\s*escape\s*\(|\bbleach\s*\.\s*clean\s*\(|\bmarkupsafe\s*\.\s*escape\s*\(/,
  php: /\bescapeshellarg\s*\(|\bescapeshellcmd\s*\(|\bintval\s*\(|\bpreg_quote\s*\(|\b(?:prepare|bindParam|bindValue)\s*\(/,
  ruby: /\bShellwords\s*\.\s*(?:escape|shellescape|join)\s*\(|\bInteger\s*\(|\bCGI\s*\.\s*escapeHTML\s*\(/,
  go: /\burl\s*\.\s*QueryEscape\s*\(|\bstrconv\s*\.\s*Atoi\s*\(|\bhtml\s*\.\s*EscapeString\s*\(/,
  java: /\bInteger\s*\.\s*(?:parseInt|valueOf)\s*\(|\bLong\s*\.\s*valueOf\s*\(|\bset(?:Int|Long|String|Double)\s*\(/,
  kotlin: /\btoInt\s*\(|\btoLong\s*\(|\bset(?:Int|Long|String|Double)\s*\(/,
  csharp:
    /\bint\s*\.\s*(?:Parse|TryParse)\s*\(|\blong\s*\.\s*(?:Parse|TryParse)\s*\(|\bParameters\s*\.\s*Add(?:WithValue)?\s*\(|\bUri\s*\.\s*EscapeDataString\s*\(|\bHttpUtility\s*\.\s*HtmlEncode\s*\(/,
};

/** SQL placeholder idioms — a query built around `?`/`%s` parameters is parameterized. */
const SQL_PARAMETERIZED = /\?|%s\b/;

/** SINK call patterns per flow kind and family (column = match start). */
const SINKS: Record<SastFlowKind, Record<string, RegExp>> = {
  command: {
    javascript: /\b(?:exec|execSync|spawn|spawnSync)\s*\(/,
    typescript: /\b(?:exec|execSync|spawn|spawnSync)\s*\(/,
    jsx: /\b(?:exec|execSync|spawn|spawnSync)\s*\(/,
    tsx: /\b(?:exec|execSync|spawn|spawnSync)\s*\(/,
    python: /\bos\s*\.\s*(?:system|popen)\s*\(|\bsubprocess\s*\.\s*(?:call|run|Popen|check_output|check_call)\s*\(/,
    php: /\bshell_exec\s*\(|\b(?:system|passthru|proc_open)\s*\(/,
    ruby: /\b(?:system|spawn)\s*\(/,
    go: /\bexec\s*\.\s*Command\s*\(/,
    java: /\bgetRuntime\s*\(\s*\)\s*\.\s*exec\b|\bnew\s+ProcessBuilder\s*\(/,
    kotlin: /\bgetRuntime\s*\(\s*\)\s*\.\s*exec\b|\bnew\s+ProcessBuilder\s*\(/,
    csharp: /\bProcess\s*\.\s*Start\s*\(/,
  },
  sql: {
    javascript: /\.\s*(?:query|execute)\s*\(/,
    typescript: /\.\s*(?:query|execute)\s*\(/,
    python: /\.\s*(?:execute|executemany)\s*\(/,
    php: /\bmysqli_query\s*\(|->\s*query\s*\(/,
    ruby: /\.\s*execute\s*\(/,
    go: /\.\s*(?:Query|Exec)\s*\(/,
    java: /\b(?:executeQuery|executeUpdate|execute)\s*\(/,
    kotlin: /\b(?:executeQuery|executeUpdate|execute)\s*\(/,
    csharp: /\bnew\s+SqlCommand\s*\(|\bExecute(?:Reader|NonQuery|Scalar)\s*\(/,
  },
  html: {
    javascript: /\binnerHTML\s*=(?!=)|\bdocument\s*\.\s*write\s*\(|\bdangerouslySetInnerHTML\b|\binsertAdjacentHTML\s*\(/,
    typescript: /\binnerHTML\s*=(?!=)|\bdocument\s*\.\s*write\s*\(|\bdangerouslySetInnerHTML\b|\binsertAdjacentHTML\s*\(/,
    jsx: /\bdangerouslySetInnerHTML\b/,
    tsx: /\bdangerouslySetInnerHTML\b/,
    python: /\brender_template_string\s*\(|\bMarkup\s*\(/,
  },
};

/** Assignment extractor: returns the LHS variable name, or undefined. */
const ASSIGNMENT =
  /(?:^|[;({[\s,])(?:(?:const|let|var|val|final|my|our)\s+)?(\$?[A-Za-z_][\w$]*)\s*(?::=|=(?![=>]))/;

/** Identifier token shape (covers `$php_vars` and normal identifiers). */
const TOKEN = /[A-Za-z_$][\w$]*/g;

function tokenizeBounded(text: string, cap: number): string[] {
  // String.prototype.match (never regex .exec — the static-safety guard
  // forbids exec-call shapes in engine modules); the input is already
  // windowed to a bounded slice, and the result is capped again here.
  const all = text.match(TOKEN);
  if (all === null) return [];
  return all.slice(0, cap);
}

function referencesTainted(text: string, tainted: ReadonlySet<string>): boolean {
  if (tainted.size === 0) return false;
  for (const token of tokenizeBounded(text, MAX_TOKENS_PER_SNIPPET)) {
    if (tainted.has(token)) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// The bounded flow pass (single forward scan, no recursion, no fixpoint)
// ---------------------------------------------------------------------------

/**
 * Analyze ONE masked file: single forward pass; a variable is tainted
 * when assigned from a source or from another tainted variable (unless
 * the assignment goes through a listed sanitizer), and a sink call whose
 * argument references a tainted variable (or contains a bare source)
 * emits a flow finding for the corresponding flow rule.
 *
 * Deterministic and linear; every bound above is enforced inline.
 */
export function analyzeFileFlows(
  family: string,
  maskedLines: readonly string[],
  flowRules: readonly FlowRuleRef[],
  originalLines?: readonly string[],
): SastFlowFinding[] {
  if (flowRules.length === 0) return [];
  const sources = SOURCES[family];
  const sanitizers = SANITIZERS[family];
  const sinksByKind: Array<{ ruleId: string; kind: SastFlowKind; sink: RegExp; count: number }> = [];
  for (const ref of flowRules) {
    const sink = SINKS[ref.flow]?.[family];
    if (sink !== undefined) {
      sinksByKind.push({ ruleId: ref.id, kind: ref.flow, sink, count: 0 });
    }
  }
  if (sinksByKind.length === 0) return [];

  const tainted = new Set<string>();
  const findings: SastFlowFinding[] = [];

  for (let i = 0; i < maskedLines.length; i += 1) {
    const masked = maskedLines[i] ?? '';
    if (masked.length === 0) continue;

    // 1. SINKS first: a sink whose argument is tainted (or a bare
    //    source expression) is a flow finding — sanitized arguments are
    //    suppressed (explicit sanitizer allowlist only).
    for (const entry of sinksByKind) {
      if (entry.count >= MAX_FLOW_FINDINGS_PER_RULE_PER_FILE) continue;
      const sinkMatch = masked.match(entry.sink);
      if (sinkMatch === null || sinkMatch.index === undefined) continue;
      const argStart = sinkMatch.index + sinkMatch[0].length;
      const arg = masked.slice(argStart, argStart + MAX_SINK_ARGUMENT_WINDOW);
      let sanitized = false;
      if (sanitizers !== undefined && sanitizers.test(arg)) sanitized = true;
      if (!sanitized && entry.kind === 'sql') {
        // Parameterization placeholders live INSIDE string literals
        // (masked away), so the placeholder idiom is checked on the
        // ORIGINAL text window — masked content can never add a
        // finding, only remove one (honest suppression).
        const original = (originalLines?.[i] ?? masked).slice(
          argStart,
          argStart + MAX_SINK_ARGUMENT_WINDOW,
        );
        if (SQL_PARAMETERIZED.test(original)) sanitized = true;
      }
      if (sanitized) continue;
      const taintedUse =
        referencesTainted(arg, tainted) || (sources !== undefined && sources.test(arg));
      if (!taintedUse) continue;
      findings.push({ ruleId: entry.ruleId, lineIndex: i, column: sinkMatch.index + 1 });
      entry.count += 1;
    }

    // 2. Assignment / propagation (kills included).
    const assign = masked.match(ASSIGNMENT);
    if (assign !== null && assign.index !== undefined && assign[1] !== undefined) {
      const lhs = assign[1] as string;
      const eqOffset = assign.index + assign[0].length;
      const rhs = masked.slice(eqOffset, eqOffset + MAX_SINK_ARGUMENT_WINDOW);
      if (sanitizers !== undefined && sanitizers.test(rhs)) {
        tainted.delete(lhs); // sanitized → clean (explicit allowlist)
      } else if (
        referencesTainted(rhs, tainted) ||
        (sources !== undefined && sources.test(rhs))
      ) {
        if (tainted.size < MAX_FLOW_VARS) tainted.add(lhs);
      } else {
        tainted.delete(lhs); // overwritten with a clean value → kill
      }
      continue;
    }

    // 3. A bare source line taints nothing by itself (no LHS); flows
    //    through bare sources are caught directly at the sink (step 1).
  }
  return findings;
}

/** Collect the flow-enabled rules of ONE family from the rule registry. */
export function flowRulesForFamily(family: string, rules: readonly SastRule[]): FlowRuleRef[] {
  const refs: FlowRuleRef[] = [];
  for (const rule of rules) {
    if (rule.flow !== undefined && (rule.languages === undefined || rule.languages.includes(family))) {
      refs.push({ id: rule.id, flow: rule.flow });
    }
  }
  return refs;
}
