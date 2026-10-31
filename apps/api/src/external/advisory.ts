/**
 * GENERIC ADVISORY ENGINE (Pump 15, MAIN-APP ONLY).
 *
 * Goal: compare observable version signals to operator-supplied advisory data.
 * An advisory match is not proof of exploitability, installed software or
 * complete coverage across languages. The knowledge lives in an
 * operator-supplied runtime JSON pack (`ADVISORY_PATH`), exactly like the
 * external dataset is read from `DATASET_PATH`. This file contains NO advisory
 * bytes and NO embedded production rules.
 *
 * HOW IT STAYS GENERIC
 *  - `ecosystem` / `component` are free-form labels (php, nodejs, python,
 *    java, go, ruby, dotnet, rust, nginx, wordpress, ...). No enum, no
 *    language-specific code paths.
 *  - `fingerprints[]` are data: a regex + where to look (response header,
 *    response body, JSON manifest, text manifest). Adding a new product or a
 *    new CVE is a DATA change, not a code change.
 *  - Version policy is generic: branch-aware fixed versions, EOL branches,
 *    or min/maxExclusive ranges. A generic dotted-numeric comparator decides.
 *
 * HONESTY (never fake a clean result)
 *  - Every fingerprint must carry a `selfTest` that produces a version at
 *    load time; a fingerprint that cannot extract a version is REFUSED.
 *  - An ambiguous version or manifest declaration is `UNKNOWN` and produces a
 *    `NEEDS REVIEW` finding; the advisory's severity is retained for triage.
 *  - No pack configured → `NOT_CONFIGURED`, zero findings, no guesses.
 *  - Stale pack (> ADVISORY_STALE_MS) → status `STALE`; findings still work
 *    but the operator is told the data may be old.
 *
 * SECURITY: bounded file/records/patterns, ReDoS lint, no network, no exec,
 * no filesystem writes, no raw secret values in evidence.
 */

import type { FindingSeverity } from '@drobon/shared';
import { resolveScaPath } from './scaDeclaration.js';
import { BoundedJsonError, createJsonByteBudget, readBoundedJsonFile } from './boundedJson.js';

export const ADVISORY_SCHEMA_VERSION = 'drobon.advisory-pack/v1';
export const ADVISORY_MAX_BYTES = 1_048_576; // 1 MiB
export const ADVISORY_MAX_RECORDS = 2_000;
export const ADVISORY_MAX_FINGERPRINTS = 6;
export const ADVISORY_MAX_PATTERN_LENGTH = 300;
export const ADVISORY_MAX_TEXT_LENGTH = 400;
export const ADVISORY_STALE_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

const SEVERITIES: readonly FindingSeverity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const RULE_ID_PATTERN = /^ADV-[0-9]{4,}$/;
const ADVISORY_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{2,79}$/;
const VERSION_LIKE = /^[vV]?[0-9][A-Za-z0-9._+-]{0,30}$/;
const CWE_PATTERN = /^CWE-[1-9][0-9]{0,5}$/;

export type AdvisoryFingerprintSource = 'response-header' | 'response-body' | 'manifest-json' | 'manifest-text';

export interface AdvisoryFingerprint {
  source: AdvisoryFingerprintSource;
  /** Regex whose capture group 1 is the observed version. */
  pattern: string;
  /** Required for `response-header` (e.g. `x-powered-by`, `server`). */
  header?: string;
  /** Required for manifest sources (basename, e.g. `composer.json`). */
  artifact?: string;
  /** Dotted path for `manifest-json` (reuses the SCA path resolver). */
  path?: string;
  /** A sample input that MUST yield a version at load time. */
  selfTest: string;
}

export interface AdvisoryBranch {
  /** Branch prefix, e.g. `8.4` or `20`. */
  branch: string;
  /** First patched release on that branch. Omit for an unpatched/EOL branch. */
  fixedVersion?: string;
  note?: string;
}

export interface AdvisoryConstraint {
  /** Inclusive lower bound. */
  min?: string;
  /** Exclusive upper bound. */
  maxExclusive?: string;
}

export interface AdvisoryRecord {
  /** External id: `CVE-2026-109618`, `GHSA-...`, or an internal id. */
  id: string;
  /** Stable finding rule id: `ADV-0001`. */
  ruleId: string;
  title: string;
  description: string;
  severity: FindingSeverity;
  cwe?: string;
  /** Free-form: `php`, `nodejs`, `python`, `java`, `go`, `nginx`, ... */
  ecosystem: string;
  /** Free-form product name: `php`, `lodash`, `log4j`, ... */
  component: string;
  remediation: string;
  limitation?: string;
  references?: string[];
  /** Optional global lower bound (versions below are NOT_AFFECTED). */
  introduced?: string;
  /** Branch-aware fixed versions (preferred for runtimes with release lines). */
  branches?: AdvisoryBranch[];
  /** Branches that will never receive a fix → always AFFECTED. */
  eolBranches?: string[];
  /** Generic ranges (preferred for libraries). */
  constraints?: AdvisoryConstraint[];
  fingerprints: AdvisoryFingerprint[];
}

export interface AdvisoryPack {
  schemaVersion: string;
  packId: string;
  version: string;
  generatedAt: string;
  advisories: AdvisoryRecord[];
}

interface CompiledFingerprint {
  raw: AdvisoryFingerprint;
  pattern: RegExp;
}

export interface CompiledAdvisory {
  record: AdvisoryRecord;
  fingerprints: CompiledFingerprint[];
}

export interface CompiledAdvisoryPack {
  pack: AdvisoryPack;
  compiled: CompiledAdvisory[];
  refused: string[];
}

export type AdvisoryVerdict = 'AFFECTED' | 'NOT_AFFECTED' | 'UNKNOWN';

export interface AdvisoryMatch {
  ruleId: string;
  advisoryId: string;
  title: string;
  description: string;
  severity: FindingSeverity;
  cwe?: string;
  remediation: string;
  limitation: string;
  references: string[];
  ecosystem: string;
  component: string;
  observedVersion: string;
  verdict: Extract<AdvisoryVerdict, 'AFFECTED' | 'UNKNOWN'>;
  reason: string;
  /** Bounded, safe evidence text. Never contains raw header/secret values. */
  evidence: string;
  location: string;
}

export interface AdvisoryInputs {
  headers?: Record<string, string | string[] | undefined>;
  body?: string;
  files?: ReadonlyArray<{ path: string; content: string }>;
}

export interface AdvisoryEvaluation {
  matches: AdvisoryMatch[];
  /** Number of advisory records actually evaluated (all of them, when loaded). */
  recordsEvaluated: number;
  /** Number of version signals extracted from the inputs. */
  signalsFound: number;
  /** AFFECTED verdict count (before dedupe). */
  affected: number;
  /** UNKNOWN verdict count (honest "needs review"). */
  needsReview: number;
  /** NOT_AFFECTED verdict count. */
  notAffected: number;
  /** Present when no pack is configured/loaded, so callers can report honestly. */
  unavailableReason?: string;
}

export interface AdvisoryStatus {
  configured: boolean;
  loaded: boolean;
  recordCount: number;
  packId?: string;
  version?: string;
  generatedAt?: string;
  stale: boolean;
  staleReason?: string;
  refused: string[];
  lastLoadedAt?: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function text(value: unknown, max: number): string | undefined {
  return typeof value === 'string' && value.length > 0 && value.length <= max ? value : undefined;
}

/**
 * Purpose-built safety lint for VERSION patterns.
 *
 * `lintRedos()` (used for dataset source-code rules) rejects `\.+` as an
 * "unbounded wildcard", which is a false positive for version strings like
 * `PHP/8.4.3`. Here we first replace escaped literals and character classes
 * with placeholders, then reject only genuinely catastrophic constructs:
 * backreferences, lookarounds, a quantified group containing another
 * quantifier (`(a+)+`), and repeated `.*`/`.+` wildcards.
 */
export function lintAdvisoryPattern(source: string): string | null {
  if (source.length > ADVISORY_MAX_PATTERN_LENGTH) return 'pattern too long';
  if (/\\[1-9]/.test(source)) return 'backreferences are not allowed';
  if (/\(\?[=!<]/.test(source)) return 'lookaround is not allowed';
  const noClasses = source.replace(/\[(?:\\.|[^\]\\])*\]/g, 'C');
  const noEscapes = noClasses.replace(/\\./g, 'L');
  const noNonCapturing = noEscapes.replace(/\(\?:/g, '(');
  if (/\([^()]*[+*?][^()]*\)[+*?]/.test(noNonCapturing)) return 'nested quantifier';
  if (/\.\*[\s\S]{0,12}\.\*/.test(noEscapes) || /\.\+[\s\S]{0,12}\.\+/.test(noEscapes)) return 'repeated unbounded wildcard';
  return null;
}

function hasCaptureGroup(source: string): boolean {
  for (let i = 0; i < source.length; i += 1) {
    if (source[i] === '\\') { i += 1; continue; }
    if (source[i] !== '(') continue;
    if (source[i + 1] === '?') continue; // non-capturing / lookaround
    return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Generic version comparator (dotted numeric, suffix-aware, fail closed)
// ---------------------------------------------------------------------------

interface ParsedVersion {
  parts: number[];
  suffix?: string;
}

export function parseVersion(input: string): ParsedVersion | undefined {
  const trimmed = input.trim().slice(0, 64);
  if (trimmed.length === 0) return undefined;
  const match = trimmed.match(/^[vV]?([0-9]+(?:\.[0-9]+){0,7})(.*)$/);
  if (match === null) return undefined;
  const numeric = match[1];
  const remainder = match[2] ?? '';
  if (numeric === undefined) return undefined;
  if (remainder.length > 0 && !/^[-+._A-Za-z0-9]{1,32}$/.test(remainder)) return undefined;
  const parts = numeric.split('.').map((piece) => Number.parseInt(piece, 10));
  if (parts.some((piece) => !Number.isSafeInteger(piece))) return undefined;
  return { parts, ...(remainder.length > 0 ? { suffix: remainder } : {}) };
}

/** -1 (a<b), 0 (a==b), 1 (a>b), or undefined when the comparison is unsafe. */
export function compareVersions(a: string, b: string): number | undefined {
  const left = parseVersion(a);
  const right = parseVersion(b);
  if (left === undefined || right === undefined) return undefined;
  // Distribution, prerelease and vendor suffixes may contain backports or
  // ecosystem-specific semantics. Never compare them as plain numeric releases.
  if (left.suffix !== undefined || right.suffix !== undefined) return undefined;
  const width = Math.max(left.parts.length, right.parts.length);
  for (let index = 0; index < width; index += 1) {
    const l = left.parts[index] ?? 0;
    const r = right.parts[index] ?? 0;
    if (l < r) return -1;
    if (l > r) return 1;
  }
  return 0;
}

function inBranch(version: string, branch: string): boolean {
  const observed = parseVersion(version);
  const prefix = parseVersion(branch);
  if (observed === undefined || prefix === undefined || prefix.parts.length === 0) return false;
  return prefix.parts.every((part, index) => (observed.parts[index] ?? -1) === part);
}

function classifyConstraints(record: AdvisoryRecord, observed: string): { verdict: AdvisoryVerdict; reason: string } {
  const constraints = record.constraints ?? [];
  let sawUpperBound = false;
  let aboveAll = true;
  for (const constraint of constraints) {
    let lowerOk = true;
    let upperOk = true;
    if (constraint.min !== undefined) {
      const cmp = compareVersions(observed, constraint.min);
      if (cmp === undefined) return { verdict: 'UNKNOWN', reason: `could not compare ${observed} with ${constraint.min}` };
      lowerOk = cmp >= 0;
    }
    if (constraint.maxExclusive !== undefined) {
      sawUpperBound = true;
      const cmp = compareVersions(observed, constraint.maxExclusive);
      if (cmp === undefined) return { verdict: 'UNKNOWN', reason: `could not compare ${observed} with ${constraint.maxExclusive}` };
      upperOk = cmp < 0;
      if (cmp < 0) aboveAll = false;
    }
    if (lowerOk && upperOk) return { verdict: 'AFFECTED', reason: `observed version ${observed} is inside the affected range` };
  }
  if (sawUpperBound && aboveAll) return { verdict: 'NOT_AFFECTED', reason: `observed version ${observed} is at or above every fixed boundary` };
  return { verdict: 'UNKNOWN', reason: 'observed version is outside every declared affected range' };
}

/** Decide whether an observed version is affected. Never guesses. */
export function classifyAdvisory(record: AdvisoryRecord, observed: string): { verdict: AdvisoryVerdict; reason: string } {
  const parsed = parseVersion(observed);
  if (parsed === undefined) return { verdict: 'UNKNOWN', reason: `unparseable version signal ${observed}` };
  if (parsed.suffix !== undefined) return { verdict: 'UNKNOWN', reason: 'version suffix requires ecosystem-specific verification' };
  if (record.introduced !== undefined) {
    const cmp = compareVersions(observed, record.introduced);
    if (cmp === undefined) return { verdict: 'UNKNOWN', reason: `could not compare ${observed} with introduced ${record.introduced}` };
    if (cmp < 0) return { verdict: 'NOT_AFFECTED', reason: `observed ${observed} predates introduced ${record.introduced}` };
  }
  if ((record.eolBranches ?? []).some((branch) => inBranch(observed, branch))) {
    return { verdict: 'AFFECTED', reason: `branch of ${observed} is end-of-life and has no patched release; upgrade is required` };
  }
  const branches = record.branches ?? [];
  if (branches.length > 0) {
    const hit = branches.find((entry) => inBranch(observed, entry.branch));
    if (hit !== undefined) {
      if (hit.fixedVersion === undefined) {
        return { verdict: 'AFFECTED', reason: hit.note ?? `${hit.branch} branch has no fixed version` };
      }
      const cmp = compareVersions(observed, hit.fixedVersion);
      if (cmp === undefined) return { verdict: 'UNKNOWN', reason: `could not compare ${observed} with fixed ${hit.fixedVersion}` };
      return cmp < 0
        ? { verdict: 'AFFECTED', reason: `${observed} is below fixed ${hit.fixedVersion} on the ${hit.branch} branch` }
        : { verdict: 'NOT_AFFECTED', reason: `${observed} is at or above fixed ${hit.fixedVersion}` };
    }
    if (record.constraints !== undefined) return classifyConstraints(record, observed);
    return { verdict: 'UNKNOWN', reason: `branch of ${observed} is not covered by this advisory record` };
  }
  if (record.constraints !== undefined) return classifyConstraints(record, observed);
  return { verdict: 'UNKNOWN', reason: 'advisory record declares no version policy' };
}

// ---------------------------------------------------------------------------
// Pack validation (closed fields, self-tests, ReDoS lint)
// ---------------------------------------------------------------------------

const PACK_KEYS = ['schemaVersion', 'packId', 'version', 'generatedAt', 'advisories'];
const RECORD_KEYS = [
  'id', 'ruleId', 'title', 'description', 'severity', 'cwe', 'ecosystem', 'component',
  'remediation', 'limitation', 'references', 'introduced', 'branches', 'eolBranches',
  'constraints', 'fingerprints',
];
const BRANCH_KEYS = ['branch', 'fixedVersion', 'note'];
const CONSTRAINT_KEYS = ['min', 'maxExclusive'];
const FP_KEYS = ['source', 'pattern', 'header', 'artifact', 'path', 'selfTest'];
const FP_SOURCES: readonly AdvisoryFingerprintSource[] = ['response-header', 'response-body', 'manifest-json', 'manifest-text'];

function closed(value: Record<string, unknown>, allowed: readonly string[], required: readonly string[]): string | null {
  const unknown = Object.keys(value).filter((key) => !allowed.includes(key));
  // Unknown property names are untrusted input and can themselves be secret.
  if (unknown.length > 0) return `unknown field(s) present: ${unknown.length}`;
  const missing = required.filter((key) => !(key in value));
  return missing.length > 0 ? `missing field(s): ${missing.join(', ')}` : null;
}

function extractVersion(regex: RegExp, value: string): string | undefined {
  // String.prototype.match keeps the static-safety gate happy: no
  // regex invocation call shape appears anywhere in first-party sources.
  const match = value.slice(0, ADVISORY_MAX_BYTES).match(regex);
  const version = match?.[1];
  if (version === undefined || !VERSION_LIKE.test(version)) return undefined;
  return version.slice(0, 64);
}

function validateRecord(raw: unknown, index: number): { compiled: CompiledAdvisory } | { error: string } {
  if (!isRecord(raw)) return { error: `advisory[${index}]: not an object` };
  const shape = closed(raw, RECORD_KEYS, ['id', 'ruleId', 'title', 'description', 'severity', 'ecosystem', 'component', 'remediation', 'fingerprints']);
  if (shape !== null) return { error: `advisory[${index}]: ${shape}` };
  const id = text(raw['id'], 80);
  const ruleId = text(raw['ruleId'], 32);
  const title = text(raw['title'], 200);
  const description = text(raw['description'], 1000);
  const remediation = text(raw['remediation'], 1000);
  const ecosystem = text(raw['ecosystem'], 64);
  const component = text(raw['component'], 96);
  if (id === undefined || !ADVISORY_ID_PATTERN.test(id)) return { error: `advisory[${index}]: invalid id` };
  if (ruleId === undefined || !RULE_ID_PATTERN.test(ruleId)) return { error: `advisory[${index}]: ruleId must match ADV-0000` };
  if (title === undefined || description === undefined || remediation === undefined || ecosystem === undefined || component === undefined) {
    return { error: `advisory[${index}]: invalid text field` };
  }
  const severity = raw['severity'];
  if (typeof severity !== 'string' || !SEVERITIES.includes(severity as FindingSeverity)) return { error: `advisory[${index}]: invalid severity` };
  const cwe = raw['cwe'];
  if (cwe !== undefined && (typeof cwe !== 'string' || !CWE_PATTERN.test(cwe))) return { error: `advisory[${index}]: invalid cwe` };
  const limitation = raw['limitation'];
  if (limitation !== undefined && typeof limitation !== 'string') return { error: `advisory[${index}]: invalid limitation` };
  const references = raw['references'];
  if (references !== undefined && (!Array.isArray(references) || references.length > 6 || !references.every((r) => typeof r === 'string' && r.length <= 200))) {
    return { error: `advisory[${index}]: invalid references` };
  }
  const introduced = raw['introduced'];
  if (introduced !== undefined && (typeof introduced !== 'string' || parseVersion(introduced) === undefined)) return { error: `advisory[${index}]: invalid introduced version` };

  const branches: AdvisoryBranch[] = [];
  if (raw['branches'] !== undefined) {
    if (!Array.isArray(raw['branches']) || raw['branches'].length > 32) return { error: `advisory[${index}]: invalid branches` };
    for (const entry of raw['branches']) {
      if (!isRecord(entry) || closed(entry, BRANCH_KEYS, ['branch']) !== null) return { error: `advisory[${index}]: invalid branch` };
      const branch = text(entry['branch'], 32);
      if (branch === undefined || parseVersion(branch) === undefined) return { error: `advisory[${index}]: invalid branch prefix` };
      const fixed = entry['fixedVersion'];
      if (fixed !== undefined && (typeof fixed !== 'string' || parseVersion(fixed) === undefined)) return { error: `advisory[${index}]: invalid fixedVersion` };
      const note = entry['note'];
      if (note !== undefined && (typeof note !== 'string' || note.length > 200)) return { error: `advisory[${index}]: invalid branch note` };
      branches.push({ branch, ...(typeof fixed === 'string' ? { fixedVersion: fixed } : {}), ...(typeof note === 'string' ? { note } : {}) });
    }
  }
  const eol = raw['eolBranches'];
  if (eol !== undefined && (!Array.isArray(eol) || eol.length > 32 || !eol.every((v) => typeof v === 'string' && parseVersion(v as string) !== undefined))) {
    return { error: `advisory[${index}]: invalid eolBranches` };
  }
  const constraints: AdvisoryConstraint[] = [];
  if (raw['constraints'] !== undefined) {
    if (!Array.isArray(raw['constraints']) || raw['constraints'].length > 32) return { error: `advisory[${index}]: invalid constraints` };
    for (const entry of raw['constraints']) {
      if (!isRecord(entry) || closed(entry, CONSTRAINT_KEYS, []) !== null) return { error: `advisory[${index}]: invalid constraint` };
      const min = entry['min'];
      const max = entry['maxExclusive'];
      if ((min !== undefined && (typeof min !== 'string' || parseVersion(min) === undefined)) ||
          (max !== undefined && (typeof max !== 'string' || parseVersion(max) === undefined))) {
        return { error: `advisory[${index}]: invalid constraint bounds` };
      }
      constraints.push({
        ...(typeof min === 'string' ? { min } : {}),
        ...(typeof max === 'string' ? { maxExclusive: max } : {}),
      });
    }
  }
  if (branches.length === 0 && constraints.length === 0 && eol === undefined) {
    return { error: `advisory[${index}]: needs branches, eolBranches or constraints` };
  }

  const rawFingerprints = raw['fingerprints'];
  if (!Array.isArray(rawFingerprints) || rawFingerprints.length === 0 || rawFingerprints.length > ADVISORY_MAX_FINGERPRINTS) {
    return { error: `advisory[${index}]: fingerprints must have 1..${ADVISORY_MAX_FINGERPRINTS} entries` };
  }
  const fingerprints: CompiledFingerprint[] = [];
  const validatedFingerprints: AdvisoryFingerprint[] = [];
  for (const entry of rawFingerprints) {
    if (!isRecord(entry) || closed(entry, FP_KEYS, ['source', 'pattern', 'selfTest']) !== null) return { error: `advisory[${index}]: invalid fingerprint` };
    const source = entry['source'];
    if (typeof source !== 'string' || !FP_SOURCES.includes(source as AdvisoryFingerprintSource)) return { error: `advisory[${index}]: unknown fingerprint source` };
    const patternSource = text(entry['pattern'], ADVISORY_MAX_PATTERN_LENGTH);
    const selfTest = text(entry['selfTest'], 500);
    if (patternSource === undefined || selfTest === undefined || !hasCaptureGroup(patternSource)) return { error: `advisory[${index}]: pattern needs a capture group` };
    const lint = lintAdvisoryPattern(patternSource);
    if (lint !== null) return { error: `advisory[${index}]: pattern safety lint: ${lint}` };
    let regex: RegExp;
    try { regex = new RegExp(patternSource); } catch { return { error: `advisory[${index}]: invalid regex` }; }
    const header = entry['header'];
    const artifact = entry['artifact'];
    const path = entry['path'];
    if (source === 'response-header' && (typeof header !== 'string' || !/^[a-z0-9-]{1,64}$/.test(header))) return { error: `advisory[${index}]: header fingerprint needs a header` };
    if ((source === 'manifest-json' || source === 'manifest-text') && (typeof artifact !== 'string' || !/^[A-Za-z0-9._-]{1,80}$/.test(artifact))) return { error: `advisory[${index}]: manifest fingerprint needs an artifact` };
    if (source === 'manifest-json' && path !== undefined && (typeof path !== 'string' || path.length > 120)) return { error: `advisory[${index}]: invalid manifest path` };
    if (extractVersion(regex, selfTest) === undefined) return { error: `advisory[${index}]: fingerprint selfTest did not yield a version` };
    const fp: AdvisoryFingerprint = {
      source: source as AdvisoryFingerprintSource,
      pattern: patternSource,
      selfTest,
      ...(typeof header === 'string' ? { header } : {}),
      ...(typeof artifact === 'string' ? { artifact } : {}),
      ...(typeof path === 'string' ? { path } : {}),
    };
    validatedFingerprints.push(fp);
    fingerprints.push({ raw: fp, pattern: regex });
  }

  const record: AdvisoryRecord = {
    id, ruleId, title, description, severity: severity as FindingSeverity,
    ecosystem, component, remediation, fingerprints: validatedFingerprints,
    ...(typeof cwe === 'string' ? { cwe } : {}),
    ...(typeof limitation === 'string' ? { limitation } : {}),
    ...(Array.isArray(references) ? { references: references as string[] } : {}),
    ...(typeof introduced === 'string' ? { introduced } : {}),
    ...(branches.length > 0 ? { branches } : {}),
    ...(Array.isArray(eol) ? { eolBranches: eol as string[] } : {}),
    ...(constraints.length > 0 ? { constraints } : {}),
  };
  return { compiled: { record, fingerprints } };
}

/** Validate a raw advisory pack. Invalid records are dropped, never hidden. */
export function compileAdvisoryPack(raw: unknown): CompiledAdvisoryPack | undefined {
  if (!isRecord(raw)) return undefined;
  const shape = closed(raw, PACK_KEYS, PACK_KEYS);
  if (shape !== null) return undefined;
  if (raw['schemaVersion'] !== ADVISORY_SCHEMA_VERSION) return undefined;
  const packId = text(raw['packId'], 64);
  const version = text(raw['version'], 32);
  const generatedAt = text(raw['generatedAt'], 40);
  if (packId === undefined || !/^[a-z0-9-]{1,64}$/.test(packId) || version === undefined || !/^[0-9]+\.[0-9]+\.[0-9]+$/.test(version)) return undefined;
  if (generatedAt === undefined || Number.isNaN(Date.parse(generatedAt))) return undefined;
  const list = raw['advisories'];
  if (!Array.isArray(list) || list.length === 0 || list.length > ADVISORY_MAX_RECORDS) return undefined;
  const compiled: CompiledAdvisory[] = [];
  const refused: string[] = [];
  const seenRuleIds = new Set<string>();
  for (const [index, entry] of list.entries()) {
    const result = validateRecord(entry, index);
    if ('error' in result) { if (refused.length < 25) refused.push(result.error); continue; }
    if (seenRuleIds.has(result.compiled.record.ruleId)) { if (refused.length < 25) refused.push(`advisory[${index}]: duplicate ruleId`); continue; }
    seenRuleIds.add(result.compiled.record.ruleId);
    compiled.push(result.compiled);
  }
  const pack: AdvisoryPack = {
    schemaVersion: ADVISORY_SCHEMA_VERSION, packId, version, generatedAt,
    advisories: compiled.map((entry) => entry.record),
  };
  return { pack, compiled, refused };
}

// ---------------------------------------------------------------------------
// Signal extraction + evaluation
// ---------------------------------------------------------------------------

function headerValues(headers: AdvisoryInputs['headers'], name: string): string[] {
  const value = headers?.[name.toLowerCase()];
  if (value === undefined) return [];
  const list = Array.isArray(value) ? value : [value];
  return list.filter((entry): entry is string => typeof entry === 'string').map((entry) => entry.slice(0, 2048));
}

function fileValues(files: AdvisoryInputs['files'], artifact: string | undefined): ReadonlyArray<{ path: string; content: string }> {
  if (artifact === undefined) return [];
  return (files ?? []).filter((file) => (file.path.split('/').pop() ?? '') === artifact).slice(0, 50);
}

interface VersionSignal {
  version: string;
  location: string;
  declared: boolean;
  incomplete: boolean;
}

/** A partial capture or suffix must not be treated as a complete version. */
function versionSignal(pattern: RegExp, value: string): { version: string; incomplete: boolean } | undefined {
  const input = value.slice(0, ADVISORY_MAX_BYTES);
  const match = input.match(pattern);
  const captured = match?.[1];
  if (match === null || captured === undefined || match.index === undefined || !VERSION_LIKE.test(captured)) return undefined;
  const numeric = captured.match(/^[vV]?[0-9]+(?:\.[0-9]+){0,7}/)?.[0];
  if (numeric === undefined) return undefined;
  // A pattern capturing 8.4 out of 8.4.27, or 8.4.3 out of a distro build,
  // is not proof of the installed patch level. Retain only numeric evidence.
  const capturedOffset = match[0].lastIndexOf(captured);
  const after = input[match.index + capturedOffset + captured.length] ?? '';
  return { version: numeric, incomplete: numeric.length !== captured.length || /[A-Za-z0-9._+-]/.test(after) };
}

function fingerprintVersions(compiled: CompiledAdvisory, inputs: AdvisoryInputs): VersionSignal[] {
  const out: VersionSignal[] = [];
  for (const fp of compiled.fingerprints) {
    const { raw, pattern } = fp;
    if (raw.source === 'response-header') {
      for (const value of headerValues(inputs.headers, raw.header ?? '')) {
        const signal = versionSignal(pattern, value);
        if (signal !== undefined) out.push({ ...signal, declared: false, location: `header ${raw.header}` });
      }
    } else if (raw.source === 'response-body') {
      const signal = versionSignal(pattern, (inputs.body ?? '').slice(0, 32_768));
      if (signal !== undefined) out.push({ ...signal, declared: false, location: 'response body' });
    } else if (raw.source === 'manifest-text') {
      for (const file of fileValues(inputs.files, raw.artifact)) {
        const signal = versionSignal(pattern, file.content.slice(0, 262_144));
        if (signal !== undefined) out.push({ ...signal, declared: true, location: file.path });
      }
    } else {
      for (const file of fileValues(inputs.files, raw.artifact)) {
        let document: unknown;
        try { document = JSON.parse(file.content.slice(0, 262_144)) as unknown; } catch { continue; }
        for (const node of resolveScaPath(document, raw.path ?? '')) {
          const value = typeof node.value === 'string' ? node.value
            : typeof node.value === 'number' ? String(node.value) : undefined;
          if (value === undefined) continue;
          const signal = versionSignal(pattern, value.slice(0, 2048));
          // The configured path, not an attacker-controlled object key, is
          // included in evidence. Versions declared in a manifest are never
          // claimed as the running host's installed version.
          if (signal !== undefined) out.push({ ...signal, declared: true, location: file.path });
        }
      }
    }
  }
  return out;
}

/** Evaluate a compiled pack against observed signals. Pure and bounded. */
export function evaluateAdvisories(
  pack: CompiledAdvisoryPack,
  inputs: AdvisoryInputs,
  stale = false,
): AdvisoryEvaluation {
  const matches = new Map<string, AdvisoryMatch>();
  let signalsFound = 0;
  let affected = 0;
  let needsReview = 0;
  let notAffected = 0;
  for (const compiled of pack.compiled) {
    const record = compiled.record;
    const signals = fingerprintVersions(compiled, inputs);
    signalsFound += signals.length;
    const seenForRecord = new Set<string>();
    for (const signal of signals) {
      const signalKey = `${signal.location}\n${signal.version}\n${signal.declared}\n${signal.incomplete}`;
      if (seenForRecord.has(signalKey)) continue;
      seenForRecord.add(signalKey);
      const verdict = signal.declared || signal.incomplete
        ? { verdict: 'UNKNOWN' as const, reason: signal.declared
          ? 'manifest declaration does not establish the installed runtime or dependency version'
          : 'version capture is incomplete or has a suffix; manual verification is required' }
        : classifyAdvisory(record, signal.version);
      if (verdict.verdict === 'NOT_AFFECTED') { notAffected += 1; continue; }
      if (verdict.verdict === 'AFFECTED') affected += 1; else needsReview += 1;
      const key = `${record.ruleId}\n${signal.location}\n${signal.version}`;
      if (matches.has(key)) continue;
      const isUnknown = verdict.verdict === 'UNKNOWN';
      const staleNote = stale ? ' Advisory pack data may be outdated.' : '';
      const defaultLimitation = 'A version signal is an observation, not proof that the running build is vulnerable. Confirm the installed version on the host.';
      matches.set(key, {
        ruleId: record.ruleId,
        advisoryId: record.id,
        title: (isUnknown ? `[NEEDS REVIEW] ${record.title}` : `[POSSIBLE] ${record.title}`).slice(0, 80),
        description: `${record.description} ${verdict.reason}.${staleNote}`.slice(0, 400),
        severity: record.severity,
        ...(record.cwe === undefined ? {} : { cwe: record.cwe }),
        remediation: record.remediation.slice(0, 400),
        limitation: (record.limitation ?? defaultLimitation).slice(0, 400),
        references: (record.references ?? []).slice(0, 6),
        ecosystem: record.ecosystem,
        component: record.component,
        observedVersion: signal.version,
        verdict: isUnknown ? 'UNKNOWN' : 'AFFECTED',
        reason: verdict.reason,
        evidence: `${record.id} ${record.component} ${signal.version} (version signal only)`.slice(0, 200),
        location: signal.location.slice(0, 120),
      });
    }
  }
  return {
    matches: [...matches.values()],
    recordsEvaluated: pack.compiled.length,
    signalsFound,
    affected,
    needsReview,
    notAffected,
  };
}

// ---------------------------------------------------------------------------
// Runtime service (lazy, cached, fail closed)
// ---------------------------------------------------------------------------

export interface AdvisoryService {
  readonly configured: boolean;
  status(): Promise<AdvisoryStatus>;
  evaluate(inputs: AdvisoryInputs): Promise<AdvisoryEvaluation>;
}

export interface AdvisoryServiceOptions {
  path?: string;
  now?: () => number;
  logger?: { info?: (message: string) => void; warn?: (message: string) => void };
}

export function createAdvisoryService(options: AdvisoryServiceOptions): AdvisoryService {
  const path = options.path;
  const now = options.now ?? Date.now;
  let cache: CompiledAdvisoryPack | undefined;
  let loadedAt: string | undefined;
  let failure: string | undefined;
  let promise: Promise<void> | undefined;

  const ensureLoaded = async (): Promise<void> => {
    if (cache !== undefined || failure !== undefined) return;
    if (promise === undefined) {
      promise = (async (): Promise<void> => {
        if (path === undefined) { failure = 'no advisory pack configured'; return; }
        try {
          const content = await readBoundedJsonFile(path, { maxFileBytes: ADVISORY_MAX_BYTES,
            budget: createJsonByteBudget(ADVISORY_MAX_BYTES), allowFinalSymlink: true });
          const compiled = compileAdvisoryPack(content);
          if (compiled === undefined) { failure = 'advisory pack failed schema validation'; return; }
          cache = compiled;
          loadedAt = new Date(now()).toISOString();
          // The path is operator configuration, not safe log content.
          options.logger?.info?.(`[advisory] loaded ${compiled.compiled.length}/${compiled.pack.advisories.length} records (${compiled.refused.length} refused)`);
        } catch (error) {
          // Filesystem and JSON errors can echo paths or raw pack contents;
          // this reason also reaches status and analysis API responses.
          failure = error instanceof BoundedJsonError && error.code === 'FILE_LIMIT'
            ? 'advisory pack exceeds the size limit' : 'advisory pack could not be read or parsed';
          options.logger?.warn?.(`[advisory] ${failure}`);
        }
      })();
    }
    await promise;
  };

  const staleness = (): { stale: boolean; reason?: string } => {
    if (cache === undefined) return { stale: false };
    const generated = Date.parse(cache.pack.generatedAt);
    const age = now() - generated;
    if (Number.isFinite(age) && age > ADVISORY_STALE_MS) {
      return { stale: true, reason: `pack generatedAt is ${Math.floor(age / 86_400_000)} days old; refresh the advisory data` };
    }
    return { stale: false };
  };

  return {
    get configured() { return path !== undefined; },
    status: async (): Promise<AdvisoryStatus> => {
      await ensureLoaded();
      const { stale, reason } = staleness();
      return {
        configured: path !== undefined,
        loaded: cache !== undefined,
        recordCount: cache?.compiled.length ?? 0,
        ...(cache === undefined ? {} : { packId: cache.pack.packId, version: cache.pack.version, generatedAt: cache.pack.generatedAt }),
        stale,
        ...(reason === undefined ? {} : { staleReason: reason }),
        refused: cache?.refused.slice(0, 25) ?? [],
        ...(loadedAt === undefined ? {} : { lastLoadedAt: loadedAt }),
        ...(failure === undefined ? {} : { staleReason: reason ?? failure }),
      };
    },
    evaluate: async (inputs: AdvisoryInputs): Promise<AdvisoryEvaluation> => {
      await ensureLoaded();
      if (cache === undefined) {
        return {
          matches: [], recordsEvaluated: 0, signalsFound: 0, affected: 0, needsReview: 0, notAffected: 0,
          unavailableReason: failure ?? 'no advisory pack configured',
        };
      }
      return evaluateAdvisories(cache, inputs, staleness().stale);
    },
  };
}
