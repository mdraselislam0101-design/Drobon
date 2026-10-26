/**
 * Pack loader conformance (Drobon-Dataset `docs/PACKS.md` loader checklist).
 *
 * The app used to accept any file with a string `schemaVersion` + `id`. That let
 * an invalid pack, a slow pattern, a wrong rule, or an unknown check type load
 * silently. This module implements the app-side half of the contract:
 *
 *  1. closed field/schema/check-type validation (fail closed);
 *  2. conservative static ReDoS lint over every pattern;
 *  3. load-time execution of every DECLARED test for sast/secrets/dast;
 *  4. honest accounting, so the status surface can show what was refused.
 *
 * This file contains NO dataset bytes: it is application logic that reads the
 * external checkout at runtime. SCA declaration rules are loaded and validated,
 * but their `tests[]` are NOT executed here — the app has no declaration-document
 * evaluator yet. They are counted as `skippedTests`, never as passing.
 */

import { DAST_CHECK_TYPES, evaluatePackDastCheck, type PackDastCheckShape } from './evaluator.js';

export type PackFamily = 'sast' | 'secrets' | 'dast' | 'sca';

export interface PackIssue {
  id: string;
  reason: string;
}

export interface PackReport {
  filesSeen: number;
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
    schema: 'drobon.pack.sast/v1', id: /^DPK-SAST-[0-9]{3,}$/,
    allowed: [...BASE, 'cwe', 'languages', 'patterns', 'tests', 'patternRefs'],
    required: [...BASE, 'patterns', 'tests', 'patternRefs'],
  },
  secrets: {
    schema: 'drobon.pack.secrets/v1', id: /^DPK-SEC-[0-9]{3,}$/,
    allowed: [...BASE, 'cwe', 'confidence', 'patterns', 'tests', 'denylist', 'matchOnlyEvidence', 'redact', 'patternRefs'],
    required: [...BASE, 'confidence', 'patterns', 'tests', 'redact', 'patternRefs'],
  },
  dast: {
    schema: 'drobon.pack.dast/v1', id: /^DPK-DAST-[0-9]{3,}$/,
    allowed: [...BASE, 'cwe', 'check', 'tests', 'patternRefs'],
    required: [...BASE, 'check', 'tests', 'patternRefs'],
  },
  sca: {
    schema: 'drobon.pack.sca/v1', id: /^DPK-SCA-[0-9]{4,}$/,
    allowed: [...BASE, 'cwe', 'ecosystems', 'artifact', 'parser', 'check', 'tests', 'patternRefs'],
    required: [...BASE, 'ecosystems', 'artifact', 'parser', 'check', 'tests', 'patternRefs'],
  },
};

const SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'INFO'];
const SCA_CHECK_TYPES = ['sca-field-matches', 'sca-field-not-matches', 'sca-field-absent', 'sca-entry-missing-field', 'sca-key-matches', 'sca-name-distance'];

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
  if (unknown.length > 0) return `unknown field(s): ${unknown.slice(0, 5).join(', ')}`;
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
    if (!(DAST_CHECK_TYPES as readonly string[]).includes(check['type'] as string)) return `unknown DAST check type '${check['type']}'`;
    const type = check['type'];
    const needsHeader = type !== 'http-url' && type !== 'cookie-missing-flag' && type !== 'response-body-matches';
    if (needsHeader && typeof check['header'] !== 'string') return 'check.header must be a string';
    if (type === 'response-header-missing-directive' && typeof check['directive'] !== 'string') return 'check.directive must be a string';
    if (type === 'cookie-missing-flag' && typeof check['flag'] !== 'string') return 'check.flag must be a string';
    if ((type === 'response-header-matches' || type === 'response-body-matches') && typeof check['valuePattern'] !== 'string') return 'check.valuePattern must be a string';
    return null;
  }
  if (family === 'sca') {
    if (!SCA_CHECK_TYPES.includes(check['type'] as string)) return `unknown SCA check type '${check['type']}'`;
    if (typeof check['path'] !== 'string' && check['type'] !== 'sca-name-distance') return 'check.path must be a string';
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

/** Validate + load one family. Rejected rules are dropped (fail closed). */
export function validatePackRules(rawRules: readonly unknown[], family: PackFamily): PackValidationOutcome {
  const spec = SPECS[family];
  const report: PackReport = {
    filesSeen: rawRules.length, accepted: 0, declaredTests: 0, executedTests: 0,
    skippedTests: 0, failedTests: 0, rejected: [],
  };
  const rules: unknown[] = [];
  for (const raw of rawRules) {
    const id = isRecord(raw) && typeof raw['id'] === 'string' ? raw['id'] : '(no id)';
    const reject = (reason: string) => {
      if (report.rejected.length < 25) report.rejected.push({ id, reason: reason.slice(0, 240) });
    };
    if (!isRecord(raw)) { reject('not a JSON object'); continue; }
    const closed = checkClosed(raw, spec.allowed, spec.required);
    if (closed !== null) { reject(closed); continue; }
    if (raw['schemaVersion'] !== spec.schema) { reject('unknown schemaVersion'); continue; }
    if (typeof raw['id'] !== 'string' || !spec.id.test(raw['id'])) { reject('invalid id'); continue; }
    if (typeof raw['title'] !== 'string' || !SEVERITIES.includes(raw['severity'] as string)) { reject('invalid title/severity'); continue; }
    if (!Array.isArray(raw['tests']) || raw['tests'].length === 0) { reject('missing declared tests'); continue; }

    if (family === 'sast' || family === 'secrets') {
      const compiled = compilePatterns(raw['patterns']);
      if (compiled.reason !== null) { reject(compiled.reason); continue; }
      if (family === 'secrets') {
        if (raw['redact'] !== true) { reject('redact must be true'); continue; }
        const denylist = Array.isArray(raw['denylist']) ? raw['denylist'].filter((x): x is string => typeof x === 'string') : [];
        if (raw['denylist'] === undefined && raw['matchOnlyEvidence'] !== true) { reject('denylist required'); continue; }
        const result = lineTests(raw, compiled.patterns, denylist);
        report.declaredTests += result.tests; report.executedTests += result.tests; report.failedTests += result.failures.length;
        if (result.failures.length > 0) { reject(`declared tests failed: ${result.failures.slice(0, 2).join('; ')}`); continue; }
      } else {
        const result = lineTests(raw, compiled.patterns, []);
        report.declaredTests += result.tests; report.executedTests += result.tests; report.failedTests += result.failures.length;
        if (result.failures.length > 0) { reject(`declared tests failed: ${result.failures.slice(0, 2).join('; ')}`); continue; }
      }
    } else {
      const checkReason = validateCheck(family, raw['check']);
      if (checkReason !== null) { reject(checkReason); continue; }
      if (family === 'dast') {
        const result = dastTests(raw);
        report.declaredTests += result.tests; report.executedTests += result.tests; report.failedTests += result.failures.length;
        if (result.failures.length > 0) { reject(`declared tests failed: ${result.failures.slice(0, 2).join('; ')}`); continue; }
      } else {
        // Honest: no declaration-document evaluator in the app yet.
        report.declaredTests += raw['tests'].length;
        report.skippedTests += raw['tests'].length;
      }
    }
    rules.push(raw);
    report.accepted += 1;
  }
  return { rules, report };
}

/** Read a pack.json manifest; never throws, returns undefined for bad input. */
export function parsePackManifest(raw: unknown): { packId: string; version: string } | undefined {
  if (!isRecord(raw) || typeof raw['packId'] !== 'string' || typeof raw['version'] !== 'string') return undefined;
  if (!/^[a-z0-9-]{1,64}$/.test(raw['packId']) || !/^[0-9]+\.[0-9]+\.[0-9]+$/.test(raw['version'])) return undefined;
  return { packId: raw['packId'], version: raw['version'] };
}

export function emptyPackReport(): PackReport {
  return { filesSeen: 0, accepted: 0, declaredTests: 0, executedTests: 0, skippedTests: 0, failedTests: 0, rejected: [] };
}
