/* eslint-disable @typescript-eslint/no-explicit-any -- external dataset JSON is untrusted and shape-checked before use. */
/**
 * Pack providers — convert Drobon-Dataset pack JSON (data) into engine-ready rules.
 * Each pack rule is validated minimally and compiled to RegExp where needed.
 * Fail-closed: invalid pack files are skipped with a warning, never thrown.
 */

import { FINDING_CWE_PATTERN, FINDING_TEXT_MAX_LENGTH, FINDING_TITLE_MAX_LENGTH, isFindingConfidence, isFindingSeverity } from '@drobon/shared';
import type { SastRule } from '../scans/sast/rules.js';
import type { SecretsRule } from '../scans/secrets/rules.js';
import type { DastRule } from '../scans/dast/packTypes.js';
import { SAST_LANGUAGE_CATALOG } from '../scans/sast/languages.js';
import { resolvePackLanguages } from './languageAliases.js';
import { DAST_CHECK_TYPES } from './evaluator.js';

const APP_CATALOG_IDS: ReadonlySet<string> = new Set(SAST_LANGUAGE_CATALOG.map((family) => family.id));

function compilePattern(source: string, flags?: string): RegExp | undefined {
  try {
    if (flags !== undefined && flags !== 'i') return undefined;
    return new RegExp(source, flags ?? '');
  } catch {
    return undefined;
  }
}

/** Normalize untrusted pack text to the persisted Finding contract. Truncation
 * is visible via an ellipsis; the scan-time digest uses this effective rule. */
function findingText(value: unknown, maxLength: number, fallback: string): string {
  if (typeof value !== 'string') return fallback;
  // eslint-disable-next-line no-control-regex -- untrusted pack text must not persist control characters.
  const safe = value.replace(/[\x00-\x1f\x7f]/g, ' ').trim();
  if (safe.length === 0) return fallback;
  if (safe.length <= maxLength) return safe;
  let prefix = safe.slice(0, maxLength - 1);
  // Do not cut a UTF-16 surrogate pair in half.
  if (/[\uD800-\uDBFF]$/.test(prefix)) prefix = prefix.slice(0, -1);
  return `${prefix}…`;
}

export function convertSastPackToRule(raw: any): SastRule | undefined {
  if (raw?.schemaVersion !== 'drobon.pack.sast/v1') return undefined;
  if (typeof raw.id !== 'string' || !/^DPK-SAST-\d{3,6}$/.test(raw.id)) return undefined;
  if (typeof raw.title !== 'string' || !isFindingSeverity(raw.severity)) return undefined;
  const patterns: RegExp[] = [];
  if (!Array.isArray(raw.patterns)) return undefined;
  for (const p of raw.patterns) {
    if (typeof p?.source !== 'string') return undefined;
    const re = compilePattern(p.source, p.flags);
    if (!re) return undefined;
    if (re.global || re.sticky) return undefined;
    patterns.push(re);
  }
  if (patterns.length === 0) return undefined;

  return {
    id: raw.id,
    title: findingText(raw.title, FINDING_TITLE_MAX_LENGTH, `SAST rule ${raw.id}`),
    description: findingText(raw.description, FINDING_TEXT_MAX_LENGTH, 'Rule description was not provided by the configured SAST pack.'),
    severity: raw.severity,
    cwe: typeof raw.cwe === 'string' && FINDING_CWE_PATTERN.test(raw.cwe) ? raw.cwe : undefined,
    category: typeof raw.category === 'string' ? raw.category : 'pack',
    remediation: findingText(raw.remediation, FINDING_TEXT_MAX_LENGTH, 'Remediation guidance was not provided by the configured SAST pack.'),
    limitation: typeof raw.limitation === 'string' ? raw.limitation : '',
    patterns,
    languages: resolvePackLanguages(raw.languages, APP_CATALOG_IDS),
  } as unknown as SastRule;
}

export function convertSecretsPackToRule(raw: any): SecretsRule | undefined {
  if (raw?.schemaVersion !== 'drobon.pack.secrets/v1') return undefined;
  if (typeof raw.id !== 'string' || !/^DPK-SEC-\d{3,6}$/.test(raw.id)) return undefined;
  const severity = raw.severity ?? 'MEDIUM';
  const confidence = raw.confidence ?? 'MEDIUM';
  if (typeof raw.title !== 'string' || !isFindingSeverity(severity) || !isFindingConfidence(confidence)) return undefined;
  const patterns: RegExp[] = [];
  if (!Array.isArray(raw.patterns)) return undefined;
  for (const p of raw.patterns) {
    if (typeof p.source !== 'string') return undefined;
    const re = compilePattern(p.source, p.flags);
    if (!re) return undefined;
    if (re.global || re.sticky) return undefined;
    patterns.push(re);
  }
  if (patterns.length === 0) return undefined;

  const denylist: string[] = Array.isArray(raw.denylist) ? raw.denylist.filter((x: unknown) => typeof x === 'string') : [];
  const redact = raw.redact === true;
  const matchOnlyEvidence = raw.matchOnlyEvidence === true;

  const rule: any = {
    id: raw.id,
    title: findingText(raw.title, FINDING_TITLE_MAX_LENGTH, `Secrets rule ${raw.id}`),
    description: findingText(raw.description, FINDING_TEXT_MAX_LENGTH, 'Rule description was not provided by the configured Secrets pack.'),
    category: typeof raw.category === 'string' ? raw.category : 'pack-secret',
    severity,
    confidence,
    cwe: typeof raw.cwe === 'string' && FINDING_CWE_PATTERN.test(raw.cwe) ? raw.cwe : undefined,
    remediation: findingText(raw.remediation, FINDING_TEXT_MAX_LENGTH, 'Remediation guidance was not provided by the configured Secrets pack.'),
    limitation: typeof raw.limitation === 'string' ? raw.limitation : '',
    patterns,
    matchOnlyEvidence: matchOnlyEvidence ? true : undefined,
    redact,
    denylist,
  };

  // Attach valueSpan + validate for denylist/redact handling
  if (!matchOnlyEvidence) {
    rule.valueSpan = (match: { text: string }) => ({ start: 0, end: match.text.length });
    if (denylist.length > 0) {
      rule.validate = (matched: string) => !denylist.some(d => matched.toLowerCase().includes(d.toLowerCase()));
    }
  }

  return rule as SecretsRule;
}

// DAST pack — see packTypes for DastRule shape
export function convertDastPackToRule(raw: any): DastRule | undefined {
  if (raw?.schemaVersion !== 'drobon.pack.dast/v1') return undefined;
  if (typeof raw.id !== 'string' || !/^DPK-DAST-\d{3,6}$/.test(raw.id)) return undefined;
  if (typeof raw.title !== 'string' || !isFindingSeverity(raw.severity)) return undefined;
  if (!raw.check || typeof raw.check.type !== 'string') return undefined;
  // Fail closed on an unknown check type: a silent `false` would let a pack
  // claim coverage it cannot deliver (loader checklist step 1).
  if (!DAST_CHECK_TYPES.includes(raw.check.type)) return undefined;
  return {
    id: raw.id,
    title: findingText(raw.title, FINDING_TITLE_MAX_LENGTH, `DAST rule ${raw.id}`),
    description: findingText(raw.description, FINDING_TEXT_MAX_LENGTH, 'Rule description was not provided by the configured DAST pack.'),
    severity: raw.severity,
    cwe: typeof raw.cwe === 'string' && FINDING_CWE_PATTERN.test(raw.cwe) ? raw.cwe : undefined,
    category: typeof raw.category === 'string' ? raw.category : 'dast',
    remediation: findingText(raw.remediation, FINDING_TEXT_MAX_LENGTH, 'Remediation guidance was not provided by the configured DAST pack.'),
    limitation: raw.limitation ?? '',
    check: raw.check,
    tests: raw.tests ?? [],
  } as unknown as DastRule;
}
