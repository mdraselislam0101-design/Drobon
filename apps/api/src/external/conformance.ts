/**
 * Pack loader conformance (Drobon-Dataset `docs/PACKS.md` loader checklist).
 *
 * The app used to accept any file with a string `schemaVersion` + `id`. That let
 * an invalid pack, a slow pattern, a wrong rule, or an unknown check type load
 * silently. This module implements the app-side half of the contract:
 *
 *  1. closed field/schema/check-type validation (fail closed);
 *  2. conservative static ReDoS lint over every pattern;
 *  3. load-time execution of every DECLARED test for sast/secrets/dast/sca;
 *  4. honest accounting, so the status surface can show what was refused.
 *
 * This file contains NO dataset bytes: it is application logic that reads the
 * external checkout at runtime. SCA declaration rules are compiled by the
 * app's own document evaluator (`scaDeclaration.ts`) and all their declared
 * tests are executed here — a rule that disagrees is refused, never skipped.
 */

import { isFindingConfidence } from '@drobon/shared';
import { SAST_LANGUAGE_CATALOG } from '../scans/sast/languages.js';
import { INSPECTED_RESPONSE_HEADERS } from '../scans/dast/observedHeaders.js';
import { unresolvedPackLanguageIds } from './languageAliases.js';
import { convertDastPackToRule, convertSastPackToRule, convertSecretsPackToRule } from './packProvider.js';
import { DAST_CHECK_TYPES, evaluatePackDastCheck, type PackDastCheckShape } from './evaluator.js';
import {
  compileScaDeclarationRule,
  evaluateScaDeclarationCheck,
  type CompiledScaDeclarationRule,
} from './scaDeclaration.js';

export type PackFamily = 'sast' | 'secrets' | 'dast' | 'sca';

export interface PackIssue {
  id: string;
  reason: string;
}

export interface PackReport {
  filesSeen: number;
  /** Directory/entry enumeration failures; their hidden file count is unknown. */
  enumerationFailures: number;
  /** Optional manifest was present but could not be safely read/validated. */
  manifestIssue?: string;
  /** Number of known resource-limit rejections; hidden file count may be unknown. */
  resourceLimitFailures?: number;
  accepted: number;
  declaredTests: number;
  executedTests: number;
  skippedTests: number;
  failedTests: number;
  rejected: PackIssue[];
}

export interface PackValidationOutcome {
  rules: unknown[];
  report: PackReport;
}

interface Spec {
  schema: string;
  id: RegExp;
  allowed: string[];
  required: string[];
}

const BASE = ['schemaVersion', 'id', 'title', 'description', 'severity', 'category', 'remediation', 'limitation'];
const SPECS: Record<PackFamily, Spec> = {
  sast: {
    schema: 'drobon.pack.sast/v1', id: /^DPK-SAST-[0-9]{3,6}$/,
    allowed: [...BASE, 'cwe', 'languages', 'patterns', 'tests', 'patternRefs'],
    required: [...BASE, 'patterns', 'tests', 'patternRefs'],
  },
  secrets: {
    schema: 'drobon.pack.secrets/v1', id: /^DPK-SEC-[0-9]{3,6}$/,
    allowed: [...BASE, 'cwe', 'confidence', 'patterns', 'tests', 'denylist', 'matchOnlyEvidence', 'redact', 'patternRefs'],
    required: [...BASE, 'confidence', 'patterns', 'tests', 'redact', 'patternRefs'],
  },
  dast: {
    schema: 'drobon.pack.dast/v1', id: /^DPK-DAST-[0-9]{3,6}$/,
    allowed: [...BASE, 'cwe', 'check', 'tests', 'patternRefs'],
    required: [...BASE, 'check', 'tests', 'patternRefs'],
  },
  sca: {
    schema: 'drobon.pack.sca/v1', id: /^DPK-SCA-[0-9]{4,6}$/,
    allowed: [...BASE, 'cwe', 'ecosystems', 'artifact', 'parser', 'check', 'tests', 'patternRefs'],
    required: [...BASE, 'ecosystems', 'artifact', 'parser', 'check', 'tests', 'patternRefs'],
  },
};

const SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'INFO'];
/** Bound synchronous declared-test work before executing untrusted pack input. */
export const MAX_DECLARED_TESTS_PER_RULE = 256;
export const MAX_DECLARED_TEST_CHARS = 16_384;

function boundedDeclaredTest(value: unknown): boolean {
  try {
    const text = JSON.stringify(value);
    return typeof text === 'string' && text.length <= MAX_DECLARED_TEST_CHARS;
  } catch { return false; }
}

/** Conservative static ReDoS lint (port of the dataset validator's lint). */
export function lintRedos(source: string): string | null {
  const noClasses = source.replace(/\[(?:\\.|[^\]\\])*\]/g, '');
  const noGroupSyntax = noClasses.replace(/\(\?([=:!])/g, '($1');
  if (/\([^()]*[+*?][^()]*\)[+*?]/.test(noGroupSyntax)) return 'nested quantifier';
  if (/(\.\*|\.\+).{0,12}(\.\*|\.\+)/.test(noClasses)) return 'repeated unbounded wildcard';
  return null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function checkClosed(record: Record<string, unknown>, allowed: string[], required: string[]): string | null {
  for (const field of required) {
    if (!(field in record)) return `missing required field '${field}'`;
  }
  const unknown = Object.keys(record).filter((key) => !allowed.includes(key));
  // Unknown keys are untrusted input; expose their count, never their text.
  if (unknown.length > 0) return `unknown field(s) present: ${unknown.length}`;
  return null;
}

function compilePatterns(raw: unknown): { patterns: RegExp[]; reason: string | null } {
  if (!Array.isArray(raw) || raw.length === 0 || raw.length > 8) return { patterns: [], reason: 'patterns must have 1..8 entries' };
  const patterns: RegExp[] = [];
  for (const entry of raw) {
    if (!isRecord(entry) || typeof entry['source'] !== 'string') return { patterns: [], reason: 'pattern.source must be a string' };
    if (entry['flags'] !== undefined && entry['flags'] !== 'i') return { patterns: [], reason: 'pattern.flags must be "i" or absent' };
    if (entry['source'].length > 500) return { patterns: [], reason: 'pattern.source too long' };
    const lint = lintRedos(entry['source']);
    if (lint !== null) return { patterns: [], reason: `ReDoS lint: ${lint}` };
    try { patterns.push(new RegExp(entry['source'], entry['flags'] === 'i' ? 'i' : '')); }
    catch { return { patterns: [], reason: 'invalid regex' }; }
  }
  return { patterns, reason: null };
}

function validateCheck(family: PackFamily, check: unknown): string | null {
  if (!isRecord(check) || typeof check['type'] !== 'string') return 'check.type must be a string';
  if (family === 'dast') {
    if (!(DAST_CHECK_TYPES as readonly string[]).includes(check['type'] as string)) return 'unknown DAST check type';
    const type = check['type'];
    const needsHeader = type !== 'http-url' && type !== 'cookie-missing-flag' && type !== 'response-body-matches';
    const needsPattern = type === 'response-header-matches' || type === 'response-body-matches';
    const required = ['type', ...(needsHeader ? ['header'] : []), ...(needsPattern ? ['valuePattern'] : []),
      ...(type === 'response-header-missing-directive' ? ['directive'] : []), ...(type === 'cookie-missing-flag' ? ['flag'] : [])];
    const shape = checkClosed(check, [...required, ...(needsPattern ? ['requireScheme'] : [])], required);
    if (shape !== null) return `check: ${shape}`;
    if (needsHeader) {
      if (typeof check['header'] !== 'string' || !INSPECTED_RESPONSE_HEADERS.has(check['header'].toLowerCase())) {
        return 'check.header is not in the inspected response-header surface';
      }
    }
    if (type === 'response-header-missing-directive' && (typeof check['directive'] !== 'string' || check['directive'].trim().length === 0)) return 'check.directive must be a non-empty string';
    if (type === 'cookie-missing-flag' && (typeof check['flag'] !== 'string' || !['secure', 'httponly', 'samesite'].includes(check['flag'].toLowerCase()))) return 'check.flag is not a supported cookie flag';
    if (needsPattern) {
      const pattern = check['valuePattern'];
      if (typeof pattern !== 'string' || pattern.length === 0 || pattern.length > 500) return 'check.valuePattern must be a bounded string';
      const lint = lintRedos(pattern);
      if (lint !== null) return `ReDoS lint: ${lint}`;
      try { new RegExp(pattern, 'i'); } catch { return 'invalid DAST regex'; }
      if (check['requireScheme'] !== undefined && check['requireScheme'] !== 'http' && check['requireScheme'] !== 'https') return 'invalid check.requireScheme';
    }
    return null;
  }
  return null;
}

function lineTests(rule: Record<string, unknown>, patterns: RegExp[], denylist: string[]): { tests: number; failures: string[] } {
  const tests = Array.isArray(rule.tests) ? rule.tests : [];
  let positives = 0;
  let negatives = 0;
  const failures: string[] = [];
  for (const [index, test] of tests.entries()) {
    if (!isRecord(test) || typeof test['line'] !== 'string' || typeof test['match'] !== 'boolean') {
      failures.push(`test ${index}: malformed`);
      continue;
    }
    if (test['match']) positives += 1; else negatives += 1;
    let hit = patterns.some((re) => { re.lastIndex = 0; return re.test(test['line'] as string); });
    if (hit && denylist.length > 0) {
      const lowered = (test['line'] as string).toLowerCase();
      if (denylist.some((deny) => lowered.includes(deny.toLowerCase()))) hit = false;
    }
    if (hit !== test['match']) failures.push(`test ${index}: expected ${test['match']}, got ${hit}`);
  }
  if (positives === 0 || negatives === 0) failures.push('tests need a positive and a negative example');
  return { tests: tests.length, failures };
}

function dastTests(rule: Record<string, unknown>): { tests: number; failures: string[] } {
  const tests = Array.isArray(rule.tests) ? rule.tests : [];
  let positives = 0;
  let negatives = 0;
  const failures: string[] = [];
  for (const [index, test] of tests.entries()) {
    const obs = isRecord(test) ? test['observation'] : undefined;
    const expected = isRecord(test) ? test['match'] : undefined;
    if (!isRecord(obs) || typeof expected !== 'boolean' || typeof obs['url'] !== 'string' || typeof obs['status'] !== 'number') {
      failures.push(`test ${index}: malformed observation`);
      continue;
    }
    if (expected) positives += 1; else negatives += 1;
    const hit = evaluatePackDastCheck(rule.check as PackDastCheckShape | undefined, {
      url: obs['url'] as string,
      status: obs['status'] as number,
      headers: (isRecord(obs['headers']) ? obs['headers'] : {}) as Record<string, string | string[] | undefined>,
      ...(typeof obs['body'] === 'string' ? { body: obs['body'] as string } : {}),
    });
    if (hit !== expected) failures.push(`test ${index}: expected ${expected}, got ${hit}`);
  }
  if (positives === 0 || negatives === 0) failures.push('tests need a positive and a negative example');
  return { tests: tests.length, failures };
}

/**
 * Execute the declared tests of one SCA declaration rule through the app's
 * own evaluator. Tests already carry a PARSED `document`; no parser lives in
 * the dataset, so the app never has to guess a file format at load time.
 */
function scaTests(rule: Record<string, unknown>, compiled: CompiledScaDeclarationRule): { tests: number; failures: string[] } {
  const tests = Array.isArray(rule['tests']) ? rule['tests'] : [];
  const failures: string[] = [];
  let positives = 0;
  let negatives = 0;
  for (const [index, test] of tests.entries()) {
    if (!isRecord(test) || typeof test['match'] !== 'boolean' || !('document' in test)) {
      failures.push(`test ${index}: malformed document test`);
      continue;
    }
    if (test['match']) positives += 1; else negatives += 1;
    let hit = false;
    try {
      hit = evaluateScaDeclarationCheck(compiled, test['document']);
    } catch {
      failures.push(`test ${index}: evaluator threw`);
      continue;
    }
    if (hit !== test['match']) failures.push(`test ${index}: expected ${test['match']}, got ${hit}`);
  }
  if (positives === 0 || negatives === 0) failures.push('tests need a positive and a negative example');
  return { tests: tests.length, failures };
}

/** Validate + load one family. Rejected rules are dropped (fail closed). */
export function validatePackRules(rawRules: readonly unknown[], family: PackFamily): PackValidationOutcome {
  const spec = SPECS[family];
  const report: PackReport = {
    filesSeen: rawRules.length, enumerationFailures: 0, accepted: 0, declaredTests: 0, executedTests: 0,
    skippedTests: 0, failedTests: 0, rejected: [],
  };
  const rules: unknown[] = [];
  const acceptedIds = new Set<string>();
  const catalogIds = new Set(SAST_LANGUAGE_CATALOG.map((entry) => entry.id));
  for (const raw of rawRules) {
    // Only a schema-valid rule ID is safe to disclose; invalid IDs can be
    // arbitrary content. Counts still include every rejected entry.
    const id = isRecord(raw) && typeof raw['id'] === 'string' && spec.id.test(raw['id']) ? raw['id'] : '(invalid or missing id)';
    const reject = (reason: string) => {
      if (report.rejected.length < 25) report.rejected.push({ id, reason: reason.slice(0, 240) });
    };
    if (!isRecord(raw)) { reject('not a JSON object'); continue; }
    const closed = checkClosed(raw, spec.allowed, spec.required);
    if (closed !== null) { reject(closed); continue; }
    if (raw['schemaVersion'] !== spec.schema) { reject('unknown schemaVersion'); continue; }
    if (typeof raw['id'] !== 'string' || !spec.id.test(raw['id'])) { reject('invalid id'); continue; }
    if (acceptedIds.has(raw['id'])) { reject('duplicate rule id'); continue; }
    if (typeof raw['title'] !== 'string' || !SEVERITIES.includes(raw['severity'] as string)) { reject('invalid title/severity'); continue; }
    if (!Array.isArray(raw['tests']) || raw['tests'].length === 0) { reject('missing declared tests'); continue; }
    if (raw['tests'].length > MAX_DECLARED_TESTS_PER_RULE || !raw['tests'].every(boundedDeclaredTest)) {
      // Do not report unexecuted fixtures as passing.
      report.declaredTests += raw['tests'].length;
      report.skippedTests += raw['tests'].length;
      report.resourceLimitFailures = (report.resourceLimitFailures ?? 0) + 1;
      reject('declared test limit exceeded');
      continue;
    }
    if (family === 'sast' && raw['languages'] !== undefined) {
      const languages = raw['languages'];
      if (!Array.isArray(languages) || languages.length === 0 ||
          !languages.every((language): language is string => typeof language === 'string' && language.length > 0)) {
        reject('languages must be a non-empty array of language ids'); continue;
      }
      const unresolved = unresolvedPackLanguageIds(languages, catalogIds);
      if (unresolved.length > 0) { reject(`unresolved language id(s): ${unresolved.length}`); continue; }
    }
    if (family === 'secrets' && !isFindingConfidence(raw['confidence'])) { reject('invalid confidence'); continue; }

    if (family === 'sast' || family === 'secrets') {
      const compiled = compilePatterns(raw['patterns']);
      if (compiled.reason !== null) { reject(compiled.reason); continue; }
      if (family === 'secrets') {
        if (raw['redact'] !== true) { reject('redact must be true'); continue; }
        if (raw['denylist'] !== undefined && (!Array.isArray(raw['denylist']) ||
            !raw['denylist'].every((entry) => typeof entry === 'string' && entry.length > 0))) {
          reject('denylist must contain non-empty strings'); continue;
        }
        if (raw['matchOnlyEvidence'] !== undefined && typeof raw['matchOnlyEvidence'] !== 'boolean') {
          reject('matchOnlyEvidence must be a boolean'); continue;
        }
        const denylist = Array.isArray(raw['denylist']) ? raw['denylist'] as string[] : [];
        if (raw['denylist'] === undefined && raw['matchOnlyEvidence'] !== true) { reject('denylist required'); continue; }
        const result = lineTests(raw, compiled.patterns, denylist);
        report.declaredTests += result.tests; report.executedTests += result.tests; report.failedTests += result.failures.length;
        if (result.failures.length > 0) { reject(`declared tests failed: ${result.failures.slice(0, 2).join('; ')}`); continue; }
      } else {
        const result = lineTests(raw, compiled.patterns, []);
        report.declaredTests += result.tests; report.executedTests += result.tests; report.failedTests += result.failures.length;
        if (result.failures.length > 0) { reject(`declared tests failed: ${result.failures.slice(0, 2).join('; ')}`); continue; }
      }
    } else if (family === 'dast') {
      const checkReason = validateCheck(family, raw['check']);
      if (checkReason !== null) { reject(checkReason); continue; }
      const result = dastTests(raw);
      report.declaredTests += result.tests; report.executedTests += result.tests; report.failedTests += result.failures.length;
      if (result.failures.length > 0) { reject(`declared tests failed: ${result.failures.slice(0, 2).join('; ')}`); continue; }
    } else {
      // SCA: compile the rule through the app's declaration evaluator, then
      // run EVERY declared test. No skipped tests, no silent acceptance.
      const compiled = compileScaDeclarationRule(raw);
      if (compiled === undefined) { reject('invalid SCA declaration rule or check'); continue; }
      // Step 2 of the loader checklist applies to SCA patterns too.
      const scaPattern = compiled.rule.check.valuePattern ?? compiled.rule.check.keyPattern;
      if (scaPattern !== undefined) {
        const lint = lintRedos(scaPattern);
        if (lint !== null) { reject(`ReDoS lint: ${lint}`); continue; }
      }
      const result = scaTests(raw, compiled);
      report.declaredTests += result.tests; report.executedTests += result.tests; report.failedTests += result.failures.length;
      if (result.failures.length > 0) { reject(`declared tests failed: ${result.failures.slice(0, 2).join('; ')}`); continue; }
    }
    // Validation and scan-time conversion must agree. Otherwise a rule could
    // be reported as accepted here but silently disappear during a scan.
    const mapped = family === 'sast' ? convertSastPackToRule(raw)
      : family === 'secrets' ? convertSecretsPackToRule(raw)
        : family === 'dast' ? convertDastPackToRule(raw)
          : true; // SCA was compiled above.
    if (!mapped) { reject('rule cannot be mapped to the scanner'); continue; }
    acceptedIds.add(raw['id']);
    rules.push(raw);
    report.accepted += 1;
  }
  return { rules, report };
}

/** Parse a pack identity. With a family, also require its exact v1 schema.
 * The optional family preserves the legacy identity-only helper contract. */
export function parsePackManifest(raw: unknown, family?: PackFamily): { packId: string; version: string } | undefined {
  if (!isRecord(raw) || typeof raw['packId'] !== 'string' || typeof raw['version'] !== 'string') return undefined;
  if (!/^[a-z0-9-]{1,64}$/.test(raw['packId']) || !/^[0-9]+\.[0-9]+\.[0-9]+$/.test(raw['version'])) return undefined;
  if (family !== undefined && (SPECS[family] === undefined || raw['schemaVersion'] !== SPECS[family].schema)) return undefined;
  return { packId: raw['packId'], version: raw['version'] };
}

export function emptyPackReport(): PackReport {
  return { filesSeen: 0, enumerationFailures: 0, accepted: 0, declaredTests: 0, executedTests: 0, skippedTests: 0, failedTests: 0, rejected: [] };
}
