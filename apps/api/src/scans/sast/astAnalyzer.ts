/**
 * BOUNDED AST / DATAFLOW ANALYZER (Pump 16, MAIN-APP ONLY).
 *
 * Additive on top of the existing lexical matcher + bounded semantic pass:
 * this module tokenizes a file, builds a SHALLOW structural tree (statements,
 * call expressions, assignments, function parameter summaries) and runs a
 * one-level, source → variable → sink taint analysis over CODE tokens.
 *
 * WHAT IT ADDS (real precision, not a second line matcher):
 *  - comments and string BODIES are single/dropped tokens, so a commented-out
 *    dangerous call or a credential-shaped literal cannot create a finding;
 *  - dotted/member chains (`req.body.name`, `os.system`, `db.query`) instead
 *    of loose identifier tokens — fewer false positives from unrelated names;
 *  - a narrow constant-query-plus-parameters pattern suppresses SQL findings;
 *    arbitrary sanitizer calls do not erase taint across different contexts;
 *  - template-literal interpolations are visible to taint;
 *  - ONE level of interprocedural propagation via function parameter
 *    summaries, with a single bounded extra iteration (NO fixpoint).
 *
 * HONEST BOUNDS (all asserted in tests): statements, functions, tainted
 * variables, nesting depth, findings per rule per file, total findings and a
 * cooperative deadline. No recursion in the analysis loop, no cross-file
 * resolution, no control-flow sensitivity, no eval of target code.
 *
 * Rules remain DATA: this module never defines a vulnerability rule. It only
 * reports which loaded dataset rule (chosen by category) describes the class
 * of a detected flow. No dataset rule → no AST finding (fail closed).
 */

import type { SastRule } from './rules.js';
import type { AstFlowKind, AstLanguageProfile } from './astProfiles.js';
import {
  astProfileFor,
  isSourceChain,
  sinkKindForChain,
} from './astProfiles.js';
import { chainAt, lexSource, matchingClose, type Token } from './astLexer.js';

export const MAX_AST_STATEMENTS = 2_000;
export const MAX_AST_FUNCTIONS = 64;
export const MAX_TAINTED_VARS = 512;
export const MAX_AST_DEPTH = 32;
export const MAX_AST_FINDINGS_PER_RULE_PER_FILE = 3;
export const MAX_AST_FINDINGS_TOTAL = 200;

export type AstReporterMap = Partial<Record<AstFlowKind, string>>;

export interface AstCandidate {
  readonly ruleId: string;
  /** 0-based line index of the sink in the ORIGINAL file. */
  readonly lineIndex: number;
  /** 1-based column of the sink token. */
  readonly column: number;
  readonly kind: AstFlowKind;
}

export interface AstAnalysisResult {
  readonly candidates: AstCandidate[];
  readonly statements: number;
  readonly tokens: number;
  readonly functions: number;
  readonly taintedVariables: number;
  readonly truncated: boolean;
}

export interface AstAnalyzeOptions {
  readonly family: string;
  readonly content: string;
  readonly reporters: AstReporterMap;
  /** Cooperative deadline/abort check from the engine. */
  readonly shouldStop?: () => boolean;
}

interface Statement {
  readonly tokens: Token[];
  readonly depth: number;
}

const CATEGORY_HINTS: Readonly<Record<AstFlowKind, readonly string[]>> = {
  command: ['command-injection', 'command-execution', 'command'],
  sql: ['sql-injection', 'sql'],
  html: ['xss', 'cross-site-scripting', 'html-injection', 'html'],
  code: ['code-injection', 'code-execution', 'unsafe-deserialization'],
};

const DECLARATION_KEYWORDS = new Set(['const', 'let', 'var', 'val', 'final', 'my', 'our', 'local', 'dim', 'auto', 'def', 'function', 'func', 'fn', 'public', 'private', 'protected', 'static', 'async', 'await', 'return', 'if', 'for', 'while', 'switch', 'catch', 'try', 'else', 'class', 'interface', 'type', 'import', 'from', 'export', 'new', 'delete', 'typeof', 'void', 'yield']);

/**
 * Choose ONE loaded dataset rule per flow class to REPORT a detected flow.
 * Selection is by category + language gating, deterministic by rule id.
 * No matching rule → that class is silently (and honestly) not reported.
 */
export function astReporterRules(rules: readonly SastRule[], family: string): AstReporterMap {
  const out: AstReporterMap = {};
  for (const kind of ['command', 'sql', 'html', 'code'] as const) {
    const hints = CATEGORY_HINTS[kind];
    const candidates = rules
      .filter((rule) => rule.languages === undefined || rule.languages.includes(family))
      // Exact normalized category only: e.g. "nosql" is not SQL injection,
      // and an unrelated category containing "command" is not a match.
      .filter((rule) => hints.includes(rule.category.trim().toLowerCase().replace(/[_.\s]+/g, '-')))
      .map((rule) => rule.id)
      .sort();
    const chosen = candidates[0];
    if (chosen !== undefined) out[kind] = chosen;
  }
  return out;
}

function splitStatements(tokens: readonly Token[], profile: AstLanguageProfile): Statement[] {
  const statements: Statement[] = [];
  let current: Token[] = [];
  let depth = 0;
  const flush = (): void => {
    if (current.length > 0 && statements.length < MAX_AST_STATEMENTS) {
      statements.push({ tokens: current, depth });
      current = [];
    }
  };
  let previous: Token | undefined;
  for (const token of tokens) {
    if (previous !== undefined && token.line > previous.line) {
      const continuesExpression =
        token.kind === 'member' || token.kind === 'op' || token.kind === 'sep' ||
        (token.kind === 'open' && token.value === '(') ||
        (previous.kind === 'op' || previous.kind === 'member' || previous.kind === 'open' ||
         previous.kind === 'sep');
      if (!continuesExpression && (profile.newlineStatements || depth === 0)) flush();
    }
    if (token.kind === 'open' && token.value === '{') {
      flush();
      depth = Math.min(MAX_AST_DEPTH, depth + 1);
      previous = token;
      continue;
    }
    if (token.kind === 'close' && token.value === '}') {
      flush();
      depth = Math.max(0, depth - 1);
      previous = token;
      continue;
    }
    if (token.kind === 'sep' && token.value === ';') {
      flush();
      previous = token;
      continue;
    }
    current.push(token);
    previous = token;
  }
  flush();
  return statements;
}

/** Collect bounded function → parameter-name summaries (one level only). */
function collectFunctions(statements: readonly Statement[]): Map<string, string[]> {
  const functions = new Map<string, string[]>();
  for (const statement of statements) {
    const tokens = statement.tokens;
    for (let i = 0; i < tokens.length; i += 1) {
      const token = tokens[i];
      if (token?.kind !== 'ident' || (token.value !== 'function' && token.value !== 'def' && token.value !== 'func' && token.value !== 'fn')) continue;
      const name = tokens[i + 1];
      const open = tokens[i + 2];
      if (name?.kind !== 'ident' || open?.kind !== 'open' || open.value !== '(') continue;
      const close = matchingClose(tokens, i + 2);
      if (close < 0 || functions.size >= MAX_AST_FUNCTIONS) continue;
      const params: string[] = [];
      for (let p = i + 3; p < close; p += 1) {
        const candidate = tokens[p];
        if (candidate?.kind === 'ident' && !DECLARATION_KEYWORDS.has(candidate.value)) {
          const chain = chainAt(tokens, p);
          if (chain.chain === candidate.value) params.push(candidate.value);
          p = Math.max(p, chain.next - 1);
        }
      }
      functions.set(name.value, params.slice(0, 12));
    }
  }
  return functions;
}

function isAssignmentOperator(token: Token | undefined): boolean {
  if (token === undefined || token.kind !== 'op') return false;
  return token.value === '=' || token.value === ':=' || token.value === '+=' || token.value === '.=';
}

/** Names referenced by a token range (ident chains + template interpolations). */
function references(tokens: readonly Token[], from: number, to: number): string[] {
  const out: string[] = [];
  for (let i = from; i < to && out.length < 256; i += 1) {
    const token = tokens[i];
    if (token === undefined) continue;
    if (token.kind === 'template') {
      for (const name of token.interpolations ?? []) out.push(name);
      continue;
    }
    if (token.kind === 'ident') {
      const chain = chainAt(tokens, i);
      out.push(token.value);
      if (chain.chain !== token.value) out.push(chain.chain);
      i = Math.max(i, chain.next - 1);
    }
  }
  return out;
}

function rangeHasSource(profile: AstLanguageProfile, tokens: readonly Token[], from: number, to: number): boolean {
  for (let i = from; i < to; i += 1) {
    const token = tokens[i];
    if (token === undefined) continue;
    if (token.kind === 'template') {
      // `${req.body.dir}` is recorded as flat identifier names; rebuild the
      // dotted chain so a source inside an interpolation is still visible.
      const parts = token.interpolations ?? [];
      if (parts.length > 0 && isSourceChain(profile, parts.join('.'))) return true;
      if (parts.some((part) => isSourceChain(profile, part))) return true;
      continue;
    }
    if (token.kind !== 'ident') continue;
    const chain = chainAt(tokens, i);
    if (isSourceChain(profile, chain.chain)) return true;
  }
  return false;
}

function rangeIsParameterized(profile: AstLanguageProfile, tokens: readonly Token[], from: number, to: number): boolean {
  // Only a literal first argument followed directly by a separate parameter
  // argument can be treated as a parameterized query. A marker elsewhere,
  // a template literal or concatenation does NOT establish parameterization.
  const query = tokens[from];
  const separator = tokens[from + 1];
  if (query?.kind !== 'string' || separator?.kind !== 'sep' || separator.value !== ',' || from + 2 >= to) return false;
  return profile.parameterizedSql.some((marker) => query.value.includes(marker));
}

interface PassContext {
  profile: AstLanguageProfile;
  statements: readonly Statement[];
  functions: ReadonlyMap<string, string[]>;
  reporters: AstReporterMap;
  tainted: Set<string>;
  functionTaint: Map<string, Set<string>>;
  perRule: Map<string, number>;
  candidates: AstCandidate[];
  seen: Set<string>;
  shouldStop?: () => boolean;
}

/** One bounded forward pass over the shallow statement tree. */
function runPass(context: PassContext, collectTaint: boolean): void {
  const { profile, statements, functions, reporters } = context;
  const scopeStack: Array<Set<string>> = [];

  for (let s = 0; s < statements.length; s += 1) {
    if (s % 64 === 0 && (context.shouldStop?.() ?? false)) return;
    const statement = statements[s];
    if (statement === undefined) continue;
    const tokens = statement.tokens;

    // Scope snapshots on nested blocks (bounded depth).
    if (statement.depth > 0 && scopeStack.length < statement.depth) {
      while (scopeStack.length < statement.depth) scopeStack.push(new Set(context.tainted));
    } else if (statement.depth < scopeStack.length) {
      while (scopeStack.length > statement.depth) {
        const snapshot = scopeStack.pop();
        if (snapshot !== undefined) context.tainted = snapshot;
        else context.tainted = new Set();
      }
    }

    const isTainted = (from: number, to: number): boolean => {
      for (const name of references(tokens, from, to)) {
        if (context.tainted.has(name)) return true;
        const root = name.split('.')[0] ?? name;
        if (context.tainted.has(root)) return true;
      }
      return false;
    };

    // ---- SINKS: iterate calls over the whole statement ----
    for (let i = 0; i < tokens.length; i += 1) {
      const token = tokens[i];
      if (token?.kind !== 'ident') continue;
      const chain = chainAt(tokens, i);
      const calleeOpen = tokens[chain.next];
      if (calleeOpen?.kind !== 'open' || calleeOpen.value !== '(') continue;
      const kind = sinkKindForChain(profile, chain.chain);
      const close = matchingClose(tokens, chain.next);
      const argFrom = chain.next + 1;
      const argTo = close < 0 ? tokens.length : close;
      const argsTainted = isTainted(argFrom, argTo) || rangeHasSource(profile, tokens, argFrom, argTo);

      // One level of interprocedural propagation: a call to a known local
      // function with tainted arguments taints that function's parameters.
      const params = functions.get(token.value);
      if (params !== undefined && argsTainted && collectTaint) {
        const set = context.functionTaint.get(token.value) ?? new Set<string>();
        for (let p = 0; p < params.length; p += 1) {
          const param = params[p];
          if (param !== undefined) set.add(param);
        }
        if (set.size > 0) context.functionTaint.set(token.value, set);
      }

      if (kind === undefined) continue;
      const ruleId = reporters[kind];
      if (ruleId === undefined) continue;
      if ((context.perRule.get(ruleId) ?? 0) >= MAX_AST_FINDINGS_PER_RULE_PER_FILE) continue;
      if (context.candidates.length >= MAX_AST_FINDINGS_TOTAL) continue;
      if (!argsTainted) continue;
      if (kind === 'sql' && rangeIsParameterized(profile, tokens, argFrom, argTo)) continue;
      const key = `${ruleId}\n${token.line}`;
      if (context.seen.has(key)) continue;
      context.seen.add(key);
      context.perRule.set(ruleId, (context.perRule.get(ruleId) ?? 0) + 1);
      context.candidates.push({ ruleId, lineIndex: token.line - 1, column: token.column, kind });
    }

    // ---- ASSIGNMENTS: propagation, kills and assignment-form HTML sinks ----
    let assignIndex = -1;
    let depth = 0;
    for (let i = 0; i < tokens.length; i += 1) {
      const token = tokens[i];
      if (token?.kind === 'open') depth += 1;
      else if (token?.kind === 'close') depth = Math.max(0, depth - 1);
      else if (depth === 0 && isAssignmentOperator(token)) { assignIndex = i; break; }
    }
    if (assignIndex < 0) continue;

    // LHS simple name = the first meaningful identifier before the operator.
    let lhs = '';
    let lhsChain = '';
    for (let i = 0; i < assignIndex; i += 1) {
      const token = tokens[i];
      if (token?.kind !== 'ident' || DECLARATION_KEYWORDS.has(token.value)) continue;
      const chain = chainAt(tokens, i);
      if (chain.next > assignIndex) break;
      lhs = token.value;
      lhsChain = chain.chain;
      break;
    }
    if (lhs === '') continue;
    const rhsFrom = assignIndex + 1;
    const rhsTainted = isTainted(rhsFrom, tokens.length) || rangeHasSource(profile, tokens, rhsFrom, tokens.length);

    // `el.innerHTML = tainted` is an HTML sink without a call.
    const htmlRuleId = reporters.html;
    if (htmlRuleId !== undefined && sinkKindForChain(profile, lhsChain) === 'html' && rhsTainted) {
      const lhsToken = tokens.find((item) => item.kind === 'ident' && item.value === lhs);
      const key = `${htmlRuleId}\n${lhsToken?.line ?? 1}`;
      if (!context.seen.has(key) && (context.perRule.get(htmlRuleId) ?? 0) < MAX_AST_FINDINGS_PER_RULE_PER_FILE) {
        context.seen.add(key);
        context.perRule.set(htmlRuleId, (context.perRule.get(htmlRuleId) ?? 0) + 1);
        context.candidates.push({
          ruleId: htmlRuleId,
          lineIndex: (lhsToken?.line ?? 1) - 1,
          column: lhsToken?.column ?? 1,
          kind: 'html',
        });
      }
    }

    // Encoding or escaping for one context is not automatically safe for
    // another. Keep taint conservatively; findings still need human review.
    if (rhsTainted) {
      if (context.tainted.size < MAX_TAINTED_VARS) context.tainted.add(lhs);
    } else {
      context.tainted.delete(lhs);
    }
  }
}

/** Analyze one file with the bounded AST/dataflow engine. Never throws. */
export function analyzeAstFile(options: AstAnalyzeOptions): AstAnalysisResult {
  const profile = astProfileFor(options.family);
  if (profile === undefined) {
    return { candidates: [], statements: 0, tokens: 0, functions: 0, taintedVariables: 0, truncated: false };
  }
  const lexed = lexSource(options.content, profile);
  const statements = splitStatements(lexed.tokens, profile);
  const functions = collectFunctions(statements);
  const reporters = options.reporters;
  if (Object.keys(reporters).length === 0) {
    return {
      candidates: [], statements: statements.length, tokens: lexed.tokens.length,
      functions: functions.size, taintedVariables: 0, truncated: lexed.truncated,
    };
  }

  const context: PassContext = {
    profile,
    statements,
    functions,
    reporters,
    tainted: new Set<string>(),
    functionTaint: new Map<string, Set<string>>(),
    perRule: new Map<string, number>(),
    candidates: [],
    seen: new Set<string>(),
    ...(options.shouldStop === undefined ? {} : { shouldStop: options.shouldStop }),
  };

  runPass(context, true);

  // ONE bounded extra iteration: seed the parameter names that became tainted
  // at call sites, then re-run the pass to catch sinks INSIDE function bodies.
  // No fixpoint — a single repeat, explicitly documented.
  if (context.functionTaint.size > 0 && !(options.shouldStop?.() ?? false)) {
    const seeded = new Set<string>();
    for (const names of context.functionTaint.values()) for (const name of names) seeded.add(name);
    context.tainted = seeded;
    context.functionTaint = new Map();
    runPass(context, false);
  }

  return {
    candidates: context.candidates.slice(0, MAX_AST_FINDINGS_TOTAL),
    statements: statements.length,
    tokens: lexed.tokens.length,
    functions: functions.size,
    taintedVariables: context.tainted.size,
    truncated: lexed.truncated || statements.length >= MAX_AST_STATEMENTS,
  };
}
