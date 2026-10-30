/**
 * SCA declaration-document evaluator (Pump 14, MAIN-APP ONLY).
 *
 * Drobon-Dataset ships 1,000 `drobon.pack.sca/v1` rules that classify a
 * DEPENDENCY DECLARATION in a manifest, lockfile or registry-config file.
 * Until now the app only loaded and validated those rules: their declared
 * tests were counted as `skippedTests` and no scan ever evaluated one.
 *
 * This module is the app-side evaluator. It is a closed-vocabulary port of
 * the dataset's `scripts/sca-rule-engine.mjs` semantics — it consumes an
 * ALREADY-PARSED document, never raw text. Parsing a real artifact into a
 * document is the scan layer's job (`scans/sca/declarationScan.ts`).
 *
 * DESIGN RULES (kept deliberately small, like the dataset original):
 *  - six predicates only; anything unknown fails closed (no match);
 *  - explicit bounds on path segments, resolved nodes, keys and names, so a
 *    hostile document cannot turn this into an unbounded walk;
 *  - no network, no filesystem, no execution, no dataset bytes in this file;
 *  - regexes are compiled ONCE per rule at load time, never per document.
 *
 * SCOPE HONESTY: this evaluator classifies declarations. It never decides
 * whether a concrete version is affected by an advisory — that stays the
 * vulnerability-intelligence provider's separate concern.
 */

import type { FindingSeverity } from '@drobon/shared';

export const SCA_CHECK_TYPES = [
  'sca-field-matches',
  'sca-field-not-matches',
  'sca-field-absent',
  'sca-entry-missing-field',
  'sca-key-matches',
  'sca-name-distance',
] as const;
export type ScaCheckType = (typeof SCA_CHECK_TYPES)[number];

/** Parse kinds a declaration rule may name. The scan layer decides which it can parse. */
export const SCA_PARSERS = [
  'json', 'toml', 'yaml', 'requirements', 'xml', 'gradle', 'properties', 'ini', 'lockfile-text',
] as const;
export type ScaParser = (typeof SCA_PARSERS)[number];

/**
 * Parser kinds with a bounded scan-time reader. Pump 18 added the eight
 * non-JSON readers (`scans/sca/declarationReaders.ts`); all nine kinds the
 * dataset declares are now readable. Readers are SUBSET parsers — a rule
 * whose artifact cannot be represented is counted as not evaluated, never
 * silently passed.
 */
export const SCA_READABLE_PARSERS: readonly ScaParser[] = [...SCA_PARSERS];

const SEVERITIES: readonly FindingSeverity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const CWE_PATTERN = /^CWE-[1-9][0-9]{0,5}$/;
const RULE_ID_PATTERN = /^DPK-SCA-[0-9]{4,}$/;
const FIELD_PATTERN = /^[A-Za-z_][A-Za-z0-9_-]{0,63}$/;

/** Hard bounds — a document is untrusted input, even though the store caps it. */
export const SCA_MAX_PATH_SEGMENTS = 12;
export const SCA_MAX_NODES = 512;
export const SCA_MAX_KEYS = 512;
export const SCA_MAX_NAME_LENGTH = 256;

export interface ScaDeclarationCheck {
  type: ScaCheckType;
  path: string;
  valuePattern?: string;
  keyPattern?: string;
  field?: string;
  target?: string;
  maxDistance?: number;
}

export interface ScaDeclarationRule {
  id: string;
  title: string;
  description: string;
  severity: FindingSeverity;
  cwe?: string;
  remediation: string;
  limitation: string;
  ecosystems: string[];
  artifact: string;
  parser: ScaParser;
  check: ScaDeclarationCheck;
}

export interface CompiledScaDeclarationRule {
  rule: ScaDeclarationRule;
  /** Compiled once; present only for the three pattern predicates. */
  pattern?: RegExp;
}

/** Where a predicate fired. Never contains a declared VALUE (values may be secrets). */
export interface ScaMatch {
  path: string;
  key?: string;
}

interface ScaNode {
  path: string;
  value: unknown;
  key: string | number | null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function boundedText(value: unknown): string | undefined {
  if (typeof value === 'string') return value.slice(0, SCA_MAX_NAME_LENGTH);
  if (typeof value === 'boolean' || (typeof value === 'number' && Number.isFinite(value))) return String(value);
  return undefined;
}

function hasOwn(record: Record<string, unknown>, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(record, key);
}

/** Check-field shape per predicate (mirrors the dataset validator's closed fields). */
const CHECK_FIELDS: Record<ScaCheckType, { allowed: readonly string[]; required: readonly string[] }> = {
  'sca-field-matches': { allowed: ['type', 'path', 'valuePattern'], required: ['type', 'path', 'valuePattern'] },
  'sca-field-not-matches': { allowed: ['type', 'path', 'valuePattern'], required: ['type', 'path', 'valuePattern'] },
  'sca-field-absent': { allowed: ['type', 'path'], required: ['type', 'path'] },
  'sca-entry-missing-field': { allowed: ['type', 'path', 'field'], required: ['type', 'path', 'field'] },
  'sca-key-matches': { allowed: ['type', 'path', 'keyPattern'], required: ['type', 'path', 'keyPattern'] },
  'sca-name-distance': { allowed: ['type', 'path', 'target', 'maxDistance'], required: ['type', 'path', 'target', 'maxDistance'] },
};

/** Validate one raw pack rule and compile its regex. Invalid rules are dropped (fail closed). */
export function compileScaDeclarationRule(raw: unknown): CompiledScaDeclarationRule | undefined {
  if (!isRecord(raw)) return undefined;
  const id = raw['id'];
  const title = raw['title'];
  const description = raw['description'];
  const severity = raw['severity'];
  const remediation = raw['remediation'];
  const limitation = raw['limitation'];
  const artifact = raw['artifact'];
  const parser = raw['parser'];
  const ecosystems = raw['ecosystems'];
  const cwe = raw['cwe'];
  if (typeof id !== 'string' || !RULE_ID_PATTERN.test(id)) return undefined;
  if (typeof title !== 'string' || title.length === 0 || title.length > 400) return undefined;
  if (typeof description !== 'string' || description.length === 0 || description.length > 2000) return undefined;
  if (typeof remediation !== 'string' || remediation.length === 0 || remediation.length > 1000) return undefined;
  if (typeof limitation !== 'string' || limitation.length > 2000) return undefined;
  if (typeof severity !== 'string' || !SEVERITIES.includes(severity as FindingSeverity)) return undefined;
  if (typeof artifact !== 'string' || artifact.length === 0 || artifact.length > 120) return undefined;
  if (typeof parser !== 'string' || !(SCA_PARSERS as readonly string[]).includes(parser)) return undefined;
  if (!Array.isArray(ecosystems) || ecosystems.length === 0 || ecosystems.length > 4 ||
      !ecosystems.every((item) => typeof item === 'string' && item.length <= 64)) return undefined;
  if (cwe !== undefined && (typeof cwe !== 'string' || !CWE_PATTERN.test(cwe))) return undefined;

  const rawCheck = raw['check'];
  if (!isRecord(rawCheck)) return undefined;
  const type = rawCheck['type'];
  if (typeof type !== 'string' || !(SCA_CHECK_TYPES as readonly string[]).includes(type)) return undefined;
  const checkType = type as ScaCheckType;
  const shape = CHECK_FIELDS[checkType];
  if (Object.keys(rawCheck).some((key) => !shape.allowed.includes(key))) return undefined;
  if (shape.required.some((key) => !hasOwn(rawCheck, key))) return undefined;
  const path = rawCheck['path'];
  if (typeof path !== 'string' || path.length === 0 || path.length > 200) return undefined;

  const check: ScaDeclarationCheck = { type: checkType, path };
  let compiled: RegExp | undefined;
  const patternSource = rawCheck['valuePattern'] ?? rawCheck['keyPattern'];
  if (patternSource !== undefined) {
    if (typeof patternSource !== 'string' || patternSource.length === 0 || patternSource.length > 500) return undefined;
    try { compiled = new RegExp(patternSource); } catch { return undefined; }
    if (typeof rawCheck['valuePattern'] === 'string') check.valuePattern = rawCheck['valuePattern'];
    if (typeof rawCheck['keyPattern'] === 'string') check.keyPattern = rawCheck['keyPattern'];
  }
  const field = rawCheck['field'];
  if (field !== undefined) {
    if (typeof field !== 'string' || !FIELD_PATTERN.test(field)) return undefined;
    check.field = field;
  }
  const target = rawCheck['target'];
  if (target !== undefined) {
    if (typeof target !== 'string' || target.length < 3 || target.length > 64) return undefined;
    check.target = target;
  }
  const maxDistance = rawCheck['maxDistance'];
  if (maxDistance !== undefined) {
    if (typeof maxDistance !== 'number' || !Number.isInteger(maxDistance) || maxDistance < 1 || maxDistance > 2) return undefined;
    check.maxDistance = maxDistance;
  }

  const rule: ScaDeclarationRule = {
    id, title, description, severity: severity as FindingSeverity, remediation, limitation,
    ecosystems: ecosystems as string[], artifact, parser: parser as ScaParser, check,
    ...(typeof cwe === 'string' ? { cwe } : {}),
  };
  return { rule, ...(compiled === undefined ? {} : { pattern: compiled }) };
}

/** Compile only the valid rules of a loaded pack (never throws). */
export function compileScaDeclarationRules(rawRules: readonly unknown[]): CompiledScaDeclarationRule[] {
  const out: CompiledScaDeclarationRule[] = [];
  for (const raw of rawRules) {
    const compiled = compileScaDeclarationRule(raw);
    if (compiled !== undefined) out.push(compiled);
  }
  return out;
}

/**
 * Resolve a dotted path against a parsed document.
 * Grammar: `a.b`, `a.*`, `a[]`, `a.*[]`; empty path = the document itself.
 * Bounded: at most SCA_MAX_PATH_SEGMENTS segments and SCA_MAX_NODES values.
 */
export function resolveScaPath(document: unknown, path: string): ScaNode[] {
  if (typeof path !== 'string') return [];
  const segments = path === '' ? [''] : path.split('.');
  if (segments.length > SCA_MAX_PATH_SEGMENTS) return [];
  let nodes: ScaNode[] = [{ path: '', value: document, key: null }];
  for (const segment of segments) {
    if (nodes.length === 0) return nodes;
    const arrayWildcard = segment.endsWith('[]');
    const name = arrayWildcard ? segment.slice(0, -2) : segment;
    const next: ScaNode[] = [];
    for (const node of nodes) {
      if (next.length >= SCA_MAX_NODES) break;
      let value = node.value;
      let nodePath = node.path;
      let key = node.key;
      if (name === '*') {
        if (!isRecord(value)) continue;
        for (const [childKey, childValue] of Object.entries(value)) {
          if (next.length >= SCA_MAX_NODES) break;
          const childPath = nodePath === '' ? childKey : `${nodePath}.${childKey}`;
          if (!arrayWildcard) { next.push({ path: childPath, value: childValue, key: childKey }); continue; }
          if (!Array.isArray(childValue)) continue;
          childValue.forEach((item, index) => {
            if (next.length < SCA_MAX_NODES) next.push({ path: `${childPath}[${index}]`, value: item, key: index });
          });
        }
        continue;
      }
      if (name !== '') {
        if (!isRecord(value) || !hasOwn(value, name)) continue;
        value = value[name];
        nodePath = nodePath === '' ? name : `${nodePath}.${name}`;
        key = name;
      }
      if (arrayWildcard) {
        if (!Array.isArray(value)) continue;
        value.forEach((item, index) => {
          if (next.length < SCA_MAX_NODES) next.push({ path: `${nodePath}[${index}]`, value: item, key: index });
        });
        continue;
      }
      next.push({ path: nodePath, value, key });
    }
    nodes = next;
  }
  return nodes;
}

/** Every own key of every object the path reaches. */
export function scaKeysAtPath(document: unknown, path: string): Array<{ path: string; key: string; value: unknown }> {
  const keys: Array<{ path: string; key: string; value: unknown }> = [];
  for (const node of resolveScaPath(document, path)) {
    if (!isRecord(node.value)) continue;
    for (const [key, value] of Object.entries(node.value)) {
      if (keys.length >= SCA_MAX_KEYS) return keys;
      keys.push({ path: node.path, key, value });
    }
  }
  return keys;
}

/** Entry objects reached by `path` (array elements, map values, or the object itself). */
export function scaEntriesAtPath(document: unknown, path: string, field?: string): Array<Record<string, unknown>> {
  const entries: Array<Record<string, unknown>> = [];
  for (const node of resolveScaPath(document, path)) {
    const value = node.value;
    if (Array.isArray(value)) {
      for (const item of value) if (isRecord(item) && entries.length < SCA_MAX_NODES) entries.push(item);
      continue;
    }
    if (!isRecord(value)) continue;
    const children = Object.values(value).filter(isRecord);
    const carriesField = field !== undefined && hasOwn(value, field);
    if (children.length > 0 && !carriesField) {
      for (const child of children) if (entries.length < SCA_MAX_NODES) entries.push(child);
    } else {
      entries.push(value);
    }
  }
  return entries;
}

/** Bounded Levenshtein distance (returns limit+1 as soon as the answer exceeds it). */
export function boundedScaDistance(left: string, right: string, limit: number): number {
  if (left === right) return 0;
  if (Math.abs(left.length - right.length) > limit) return limit + 1;
  const width = Math.min(right.length, SCA_MAX_NAME_LENGTH) + 1;
  const previous = new Array<number>(width);
  const current = new Array<number>(width);
  for (let column = 0; column < width; column += 1) previous[column] = column;
  for (let row = 1; row <= Math.min(left.length, SCA_MAX_NAME_LENGTH); row += 1) {
    current[0] = row;
    let rowMinimum = current[0] ?? row;
    for (let column = 1; column < width; column += 1) {
      const cost = left[row - 1] === right[column - 1] ? 0 : 1;
      current[column] = Math.min(
        (previous[column] ?? 0) + 1,
        (current[column - 1] ?? 0) + 1,
        (previous[column - 1] ?? 0) + cost,
      );
      rowMinimum = Math.min(rowMinimum, current[column] ?? 0);
    }
    if (rowMinimum > limit) return limit + 1;
    for (let column = 0; column < width; column += 1) previous[column] = current[column] ?? 0;
  }
  return previous[width - 1] ?? limit + 1;
}

/**
 * Evaluate one compiled rule against one PARSED document.
 * Returns where it fired, or undefined. Unknown/invalid state never matches.
 */
export function findScaMatch(compiled: CompiledScaDeclarationRule, document: unknown): ScaMatch | undefined {
  const { rule, pattern } = compiled;
  const check = rule.check;
  switch (check.type) {
    case 'sca-field-matches': {
      if (pattern === undefined) return undefined;
      const node = resolveScaPath(document, check.path).find((candidate) => {
        const text = boundedText(candidate.value);
        return text !== undefined && pattern.test(text);
      });
      return node === undefined ? undefined : { path: node.path };
    }
    case 'sca-field-not-matches': {
      if (pattern === undefined) return undefined;
      const nodes = resolveScaPath(document, check.path);
      if (nodes.length === 0) return undefined;
      const hit = nodes.some((node) => {
        const text = boundedText(node.value);
        return text !== undefined && pattern.test(text);
      });
      return hit ? undefined : { path: check.path };
    }
    case 'sca-field-absent':
      return resolveScaPath(document, check.path).length === 0 ? { path: check.path } : undefined;
    case 'sca-entry-missing-field': {
      if (check.field === undefined) return undefined;
      const entries = scaEntriesAtPath(document, check.path, check.field);
      if (entries.length === 0) return undefined;
      const index = entries.findIndex((entry) => !hasOwn(entry, check.field as string));
      return index === -1 ? undefined : { path: `${check.path}[${index}]` };
    }
    case 'sca-key-matches': {
      if (pattern === undefined) return undefined;
      const entry = scaKeysAtPath(document, check.path).find((candidate) => pattern.test(candidate.key));
      return entry === undefined ? undefined : { path: entry.path, key: entry.key };
    }
    case 'sca-name-distance': {
      if (check.target === undefined || check.maxDistance === undefined) return undefined;
      const limit = check.maxDistance;
      const target = check.target;
      const entry = scaKeysAtPath(document, check.path).find((candidate) => {
        if (candidate.key === target || candidate.key.length < 4) return false;
        return boundedScaDistance(candidate.key, target, limit) <= limit;
      });
      return entry === undefined ? undefined : { path: entry.path, key: entry.key };
    }
    default:
      return undefined;
  }
}

/** Boolean form used by load-time declared-test execution. */
export function evaluateScaDeclarationCheck(compiled: CompiledScaDeclarationRule, document: unknown): boolean {
  return findScaMatch(compiled, document) !== undefined;
}
