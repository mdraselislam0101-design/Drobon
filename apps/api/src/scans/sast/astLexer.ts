/**
 * BOUNDED TOKENIZER for the shallow AST pass (Pump 16, MAIN-APP ONLY).
 *
 * Pure, synchronous, deterministic text work. Comments are DROPPED (so a
 * commented-out dangerous call can never produce a finding), string bodies
 * become ONE token (so credential-like text inside a literal cannot masquerade
 * as code), and template interpolations are recorded separately so taint can
 * still be seen inside `${...}`.
 *
 * Bounds: MAX_AST_TOKENS per file and a byte cap. A file that exceeds either
 * is analysed only up to the bound and reported as truncated — never guessed.
 * No regex with a global/sticky flag is used; no target code is executed.
 */

import type { AstLanguageProfile } from './astProfiles.js';

export const MAX_AST_TOKENS = 12_000;
export const MAX_AST_BYTES = 262_144;

export type TokenKind =
  | 'ident'
  | 'number'
  | 'string'
  | 'template'
  | 'member'
  | 'op'
  | 'open'
  | 'close'
  | 'sep';

export interface Token {
  readonly kind: TokenKind;
  /** Raw source slice (for strings/templates, includes quotes). */
  readonly value: string;
  readonly start: number;
  readonly end: number;
  /** 1-based line. */
  readonly line: number;
  /** 1-based column. */
  readonly column: number;
  /** Identifier names found inside `${...}` of a template literal. */
  readonly interpolations?: readonly string[];
}

export interface LexResult {
  readonly tokens: Token[];
  readonly truncated: boolean;
}

/** Longest-first so `===`, `=>`, `::`, `->` and `?.` win over their prefixes. */
const OPERATORS = [
  '>>>=', '**=', '&&=', '||=', '??=', '===', '!==', '...', '->', '::', '?.',
  '=>', '==', '!=', '<=', '>=', '&&', '||', '??', '++', '--', '+=', '-=',
  '*=', '/=', '%=', ':=', '.=', '**', '<<', '>>', '=', '+', '-', '*', '/',
  '%', '<', '>', '!', '&', '|', '^', '~', '?', '@',
] as const;

const IDENT_START = /[A-Za-z_$@]/;
const IDENT_PART = /[A-Za-z0-9_$@]/;
const DIGIT = /[0-9]/;

function isWhitespace(char: string): boolean {
  return char === ' ' || char === '\t' || char === '\r' || char === '\n' || char === '\f' || char === '\v';
}

/** Tokenize one bounded source file. Never throws for malformed input. */
export function lexSource(content: string, profile: AstLanguageProfile): LexResult {
  const text = content.slice(0, MAX_AST_BYTES);
  const truncated = Buffer.byteLength(content, 'utf8') > MAX_AST_BYTES;
  const tokens: Token[] = [];
  const memberOps = profile.memberOperators;
  let index = 0;
  let line = 1;
  let lineStart = 0;
  let capped = truncated;

  const push = (kind: TokenKind, start: number, end: number, interpolations?: readonly string[]): void => {
    if (tokens.length >= MAX_AST_TOKENS) { capped = true; return; }
    tokens.push({
      kind,
      value: text.slice(start, end),
      start,
      end,
      line,
      column: start - lineStart + 1,
      ...(interpolations === undefined || interpolations.length === 0 ? {} : { interpolations }),
    });
  };

  const advanceNewlines = (from: number, to: number): void => {
    for (let i = from; i < to; i += 1) {
      if (text[i] === '\n') { line += 1; lineStart = i + 1; }
    }
  };

  const startsWith = (needle: string): boolean =>
    needle.length > 0 && text.startsWith(needle, index);

  while (index < text.length && tokens.length < MAX_AST_TOKENS) {
    const char = text[index] ?? '';
    if (char === '\n') { line += 1; lineStart = index + 1; index += 1; continue; }
    if (isWhitespace(char)) { index += 1; continue; }

    // ---- comments (dropped, but offsets/line numbers are preserved) ----
    let handledComment = false;
    for (const opener of profile.lineComments) {
      if (startsWith(opener)) {
        let end = text.indexOf('\n', index);
        if (end < 0) end = text.length;
        advanceNewlines(index, end);
        index = end;
        handledComment = true;
        break;
      }
    }
    if (handledComment) continue;
    for (const pair of profile.blockComments) {
      if (startsWith(pair.open)) {
        const close = text.indexOf(pair.close, index + pair.open.length);
        const end = close < 0 ? text.length : close + pair.close.length;
        advanceNewlines(index, end);
        index = end;
        handledComment = true;
        break;
      }
    }
    if (handledComment) continue;

    // ---- strings / triple-quoted strings / templates ----
    const triple = (profile.tripleQuotes ?? []).find((quote) => startsWith(quote));
    if (triple !== undefined) {
      const close = text.indexOf(triple, index + triple.length);
      const end = close < 0 ? text.length : close + triple.length;
      push('string', index, end);
      advanceNewlines(index, end);
      index = end;
      continue;
    }
    const quote = profile.quotes.find((candidate) => startsWith(candidate));
    if (quote !== undefined) {
      const start = index;
      index += quote.length;
      const interpolations: string[] = [];
      let closed = false;
      while (index < text.length) {
        const current = text[index] ?? '';
        if (current === '\\') { index += 2; continue; }
        if (startsWith(quote)) { index += quote.length; closed = true; break; }
        if (quote === '`' && current === '$' && text[index + 1] === '{') {
          // Record identifier names inside `${...}` for taint analysis.
          let cursor = index + 2;
          while (cursor < text.length && text[cursor] !== '}') {
            if (IDENT_START.test(text[cursor] ?? '')) {
              const nameStart = cursor;
              cursor += 1;
              while (cursor < text.length && IDENT_PART.test(text[cursor] ?? '')) cursor += 1;
              interpolations.push(text.slice(nameStart, cursor));
            } else {
              cursor += 1;
            }
          }
          index = Math.min(text.length, cursor + 1);
          continue;
        }
        index += 1;
      }
      if (!closed) capped = true;
      const literalEnd = Math.min(index, text.length);
      // Push BEFORE advancing line counters so a multi-line string keeps
      // the line/column of its opening quote.
      push(quote === '`' ? 'template' : 'string', start, literalEnd, interpolations);
      advanceNewlines(start, literalEnd);
      continue;
    }

    // ---- identifiers (incl. $php_vars and @decorators) ----
    if (IDENT_START.test(char)) {
      const start = index;
      index += 1;
      while (index < text.length && IDENT_PART.test(text[index] ?? '')) index += 1;
      push('ident', start, index);
      continue;
    }

    // ---- numbers ----
    if (DIGIT.test(char)) {
      const start = index;
      index += 1;
      while (index < text.length && /[0-9._a-fA-FxXoObB]/.test(text[index] ?? '')) index += 1;
      push('number', start, index);
      continue;
    }

    // ---- member operators ----
    const member = memberOps.find((candidate) => startsWith(candidate));
    if (member !== undefined) {
      const start = index;
      index += member.length;
      push('member', start, index);
      continue;
    }

    // ---- grouping / separators ----
    if (char === '(' || char === '[' || char === '{') {
      push('open', index, index + 1);
      index += 1;
      continue;
    }
    if (char === ')' || char === ']' || char === '}') {
      push('close', index, index + 1);
      index += 1;
      continue;
    }
    if (char === ';' || char === ',' || char === ':') {
      push('sep', index, index + 1);
      index += 1;
      continue;
    }

    // ---- operators ----
    const operator = OPERATORS.find((candidate) => startsWith(candidate));
    if (operator !== undefined) {
      const start = index;
      index += operator.length;
      push('op', start, index);
      continue;
    }

    // Unknown single character: keep position determinism, do not invent code.
    push('op', index, index + 1);
    index += 1;
  }

  // The loop exits on the token cap (not end of input) → report truncation.
  if (index < text.length) capped = true;
  return { tokens, truncated: capped };
}

/**
 * Build the dotted chain starting at an identifier token, following member
 * operators and treating bracket access as `[]`. Returns the chain and the
 * index of the token immediately AFTER the chain.
 */
export function chainAt(tokens: readonly Token[], start: number): { chain: string; next: number } {
  const first = tokens[start];
  if (first === undefined || first.kind !== 'ident') return { chain: '', next: start };
  let chain = first.value;
  let cursor = start + 1;
  while (cursor < tokens.length) {
    const joiner = tokens[cursor];
    const part = tokens[cursor + 1];
    if (joiner?.kind === 'member' && part?.kind === 'ident') {
      chain += `.${part.value}`;
      cursor += 2;
      continue;
    }
    if (joiner?.kind === 'open' && joiner.value === '[') {
      const end = matchingClose(tokens, cursor);
      if (end < 0) break;
      chain += '[]';
      cursor = end + 1;
      continue;
    }
    break;
  }
  return { chain, next: cursor };
}

/** Index of the matching closing token for an `open` at `index`, or -1. */
export function matchingClose(tokens: readonly Token[], index: number): number {
  const opener = tokens[index];
  if (opener === undefined || opener.kind !== 'open') return -1;
  const closing = opener.value === '(' ? ')' : opener.value === '[' ? ']' : '}';
  let depth = 0;
  for (let i = index; i < tokens.length; i += 1) {
    const token = tokens[i];
    if (token?.kind === 'open' && token.value === opener.value) depth += 1;
    else if (token?.kind === 'close' && token.value === closing) {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return -1;
}
