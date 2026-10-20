/**
 * Pack providers — convert Drobon-Dataset pack JSON (data) into engine-ready rules.
 * Each pack rule is validated minimally and compiled to RegExp where needed.
 * Fail-closed: invalid pack files are skipped with a warning, never thrown.
 */

import type { SastRule } from '../scans/sast/rules.js';
import type { SecretsRule } from '../scans/secrets/rules.js';
import type { DastRule } from '../scans/dast/packTypes.js';

function compilePattern(source: string, flags?: string): RegExp | undefined {
  try {
    const f = flags === 'i' ? 'i' : flags === undefined ? '' : '';
    if (f !== '' && f !== 'i') return undefined;
    return new RegExp(source, f);
  } catch {
    return undefined;
  }
}

export function convertSastPackToRule(raw: any): SastRule | undefined {
  if (raw?.schemaVersion !== 'drobon.pack.sast/v1') return undefined;
  if (typeof raw.id !== 'string' || !/^DPK-SAST-\d+$/.test(raw.id)) return undefined;
  if (typeof raw.title !== 'string' || typeof raw.severity !== 'string') return undefined;
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

  return {
    id: raw.id,
    title: raw.title,
    description: typeof raw.description === 'string' ? raw.description : '',
    severity: raw.severity,
    cwe: typeof raw.cwe === 'string' ? raw.cwe : undefined,
    category: typeof raw.category === 'string' ? raw.category : 'pack',
    remediation: typeof raw.remediation === 'string' ? raw.remediation : '',
    limitation: typeof raw.limitation === 'string' ? raw.limitation : '',
    patterns,
    languages: Array.isArray(raw.languages) ? raw.languages : undefined,
  } as unknown as SastRule;
}

export function convertSecretsPackToRule(raw: any): SecretsRule | undefined {
  if (raw?.schemaVersion !== 'drobon.pack.secrets/v1') return undefined;
  if (typeof raw.id !== 'string' || !/^DPK-SEC-\d+$/.test(raw.id)) return undefined;
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
    title: raw.title,
    description: typeof raw.description === 'string' ? raw.description : '',
    category: typeof raw.category === 'string' ? raw.category : 'pack-secret',
    severity: raw.severity ?? 'MEDIUM',
    confidence: raw.confidence ?? 'MEDIUM',
    cwe: typeof raw.cwe === 'string' ? raw.cwe : undefined,
    remediation: typeof raw.remediation === 'string' ? raw.remediation : '',
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
  if (typeof raw.id !== 'string' || !/^DPK-DAST-\d+$/.test(raw.id)) return undefined;
  if (!raw.check || typeof raw.check.type !== 'string') return undefined;
  return {
    id: raw.id,
    title: raw.title,
    description: raw.description ?? '',
    severity: raw.severity ?? 'LOW',
    cwe: raw.cwe,
    category: raw.category ?? 'dast',
    remediation: raw.remediation ?? '',
    limitation: raw.limitation ?? '',
    check: raw.check,
    tests: raw.tests ?? [],
  } as unknown as DastRule;
}
