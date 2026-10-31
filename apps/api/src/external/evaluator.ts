/**
 * DAST pack check evaluator — the seven closed check types from
 * Drobon-Dataset `docs/PACKS.md` (v1). Pure functions, no network.
 *
 * Parity contract (GAP-041): this module implements the DATASET's browser
 * semantics, not a keyword search over joined header strings:
 *  - header names and values are normalized (case-folded / OWS-trimmed);
 *  - a header whose every value is blank is ABSENT (BLANK_VALUE_ARRAY);
 *  - a repeated header is evaluated per value, never as one ", "-joined
 *    string, so a pattern cannot match across a value boundary
 *    (ARRAY_JOIN_CROSS_VALUE);
 *  - Set-Cookie uses the browser storage model (COOKIE_MODEL_ABSENT).
 */

import { cookieHasFlag, cookieWillBeStored } from './setCookie.js';

export interface PackDastObservation {
  url: string;
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body?: string;
  contentType?: string;
}

export const DAST_CHECK_TYPES = [
  'http-url',
  'missing-response-header',
  'response-header-missing-directive',
  'cookie-missing-flag',
  'response-header-matches',
  'response-body-matches',
  'response-header-host-differs',
] as const;

export type DastCheckType = (typeof DAST_CHECK_TYPES)[number];

type HeaderMap = Record<string, Array<string | undefined>>;

/** Case-fold header names and trim RFC 7230 optional whitespace per value. */
function normalizeHeaders(headers: unknown): HeaderMap {
  const out: HeaderMap = Object.create(null) as HeaderMap;
  if (typeof headers !== 'object' || headers === null || Array.isArray(headers)) return out;
  for (const [name, value] of Object.entries(headers as Record<string, unknown>)) {
    const list = Array.isArray(value) ? value : [value];
    // Case-variant keys represent repeated HTTP fields, not replacements.
    // Keep values separate: joining them can create cross-value matches.
    const values = out[name.toLowerCase()] ??= [];
    for (const entry of list) values.push(typeof entry === 'string' ? entry.trim() : undefined);
  }
  return out;
}

function headerHasDirective(values: Array<string | undefined>, directive: string): boolean {
  const want = directive.toLowerCase();
  return values.some((value) =>
    typeof value === 'string' && value.split(/[;,]/).some((part) => {
      const name = part.trim().split(/[=\s]/, 1)[0]?.toLowerCase();
      return name === want;
    }),
  );
}

function schemeOf(url: string): string | undefined {
  try { return new URL(url).protocol; } catch { return undefined; }
}

/** Evaluate one closed-vocabulary check. Unknown types never throw and never match. */
export interface PackDastCheckShape {
  type: string;
  header?: unknown;
  directive?: unknown;
  flag?: unknown;
  valuePattern?: unknown;
  requireScheme?: unknown;
}

export function evaluatePackDastCheck(ruleCheck: PackDastCheckShape | null | undefined, obs: PackDastObservation): boolean {
  if (typeof ruleCheck !== 'object' || ruleCheck === null) return false;
  if (!(DAST_CHECK_TYPES as readonly string[]).includes(ruleCheck.type)) return false;
  const headers = normalizeHeaders(obs.headers);

  if (ruleCheck.type === 'http-url') {
    return schemeOf(obs.url) === 'http:';
  }

  if (ruleCheck.type === 'missing-response-header') {
    const name = ruleCheck.header;
    if (typeof name !== 'string') return false;
    const values = headers[name.toLowerCase()];
    return values === undefined || values.every((value) => typeof value !== 'string' || value.trim() === '');
  }

  if (ruleCheck.type === 'response-header-missing-directive') {
    const name = ruleCheck.header;
    const directive = ruleCheck.directive;
    if (typeof name !== 'string' || typeof directive !== 'string') return false;
    const values = headers[name.toLowerCase()];
    return values === undefined || !headerHasDirective(values, directive);
  }

  if (ruleCheck.type === 'cookie-missing-flag') {
    const cookies = headers['set-cookie'];
    if (cookies === undefined) return false;
    return cookies.some((cookie) => cookieWillBeStored(cookie) && !cookieHasFlag(cookie, ruleCheck.flag));
  }

  if (ruleCheck.type === 'response-header-matches') {
    const name = ruleCheck.header;
    const pattern = ruleCheck.valuePattern;
    if (typeof name !== 'string' || typeof pattern !== 'string') return false;
    if (ruleCheck.requireScheme !== undefined && schemeOf(obs.url) !== `${ruleCheck.requireScheme}:`) return false;
    const values = headers[name.toLowerCase()];
    if (values === undefined) return false;
    try {
      const re = new RegExp(pattern, 'i');
      return values.some((value) => typeof value === 'string' && re.test(value));
    } catch { return false; }
  }

  if (ruleCheck.type === 'response-body-matches') {
    const pattern = ruleCheck.valuePattern;
    if (typeof pattern !== 'string' || typeof obs.body !== 'string') return false;
    if (ruleCheck.requireScheme !== undefined && schemeOf(obs.url) !== `${ruleCheck.requireScheme}:`) return false;
    try { return new RegExp(pattern, 'i').test(obs.body); } catch { return false; }
  }

  if (ruleCheck.type === 'response-header-host-differs') {
    const name = ruleCheck.header;
    if (typeof name !== 'string' || obs.status < 300 || obs.status > 399) return false;
    const values = headers[name.toLowerCase()];
    if (values === undefined || typeof values[0] !== 'string') return false;
    try {
      const base = new URL(obs.url);
      const target = new URL(values[0], base);
      if (target.protocol !== 'http:' && target.protocol !== 'https:') return false;
      return target.hostname !== base.hostname;
    } catch { return false; }
  }

  return false;
}
