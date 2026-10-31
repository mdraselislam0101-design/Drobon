import type { FindingConfidence, FindingSeverity } from '@drobon/shared';

/**
 * Secrets rule framework — engine only, no embedded rules.
 * All rule data lives in Drobon-Dataset packs/secrets/v1 (DPK-SEC-*).
 */

export interface SecretsRuleMatch {
  column: number;
  text: string;
}

export type SecretsLineMatcher = (line: string) => SecretsRuleMatch | undefined;

export interface SecretsRule {
  readonly id: string;
  readonly title: string;
  readonly description: string;
  readonly category: string;
  readonly severity: FindingSeverity;
  readonly confidence: FindingConfidence;
  readonly cwe?: string;
  readonly remediation: string;
  readonly limitation: string;
  readonly patterns: readonly RegExp[];
  /** The full line is supplied so dataset denylists use loader-equivalent semantics. */
  readonly validate?: (matched: string, line?: string) => boolean;
  readonly valueSpan?: (match: SecretsRuleMatch) => { start: number; end: number } | undefined;
  readonly matchOnlyEvidence?: boolean;
}

export function matchSecretsRuleLine(rule: SecretsRule, line: string): SecretsRuleMatch | undefined {
  for (const pattern of rule.patterns) {
    if (pattern.global || pattern.sticky) {
      throw new Error(`Rule pattern must not use the g/y flags: ${rule.id}`);
    }
    const match = line.match(pattern);
    if (match !== null) {
      const candidate: SecretsRuleMatch = {
        column: (match.index ?? 0) + 1,
        text: match[0],
      };
      if (rule.validate !== undefined && !rule.validate(candidate.text, line)) {
        continue;
      }
      return candidate;
    }
  }
  return undefined;
}

const PLACEHOLDER_MARKERS = [
  'changeme','change-me','change_me','placeholder','example','dummy','sample','your','todo','fixme','xxx','redacted','notaset','not-a-secret','notreal','insert','here','fake','synthetic','demo','test','password','secret','token',
] as const;

function isTemplateValue(value: string): boolean {
  return value.includes('<') || value.includes('>') || value.includes('${') || value.includes('{{');
}
const UUID_SHAPE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const PLAIN_HEX_DIGEST = /^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{56}|[0-9a-f]{64}|[0-9a-f]{96}|[0-9a-f]{128})$/i;
function isPlaceholderValue(value: string): boolean {
  const lower = value.toLowerCase();
  return isTemplateValue(value) || PLACEHOLDER_MARKERS.some((m) => lower.includes(m));
}
export function shannonEntropy(value: string): number {
  if (value.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const char of value) counts.set(char, (counts.get(char) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) { const p = count / value.length; entropy -= p * Math.log2(p); }
  return entropy;
}
export function characterClasses(value: string): number {
  let classes = 0;
  if (/[a-z]/.test(value)) classes += 1;
  if (/[A-Z]/.test(value)) classes += 1;
  if (/[0-9]/.test(value)) classes += 1;
  if (/[^A-Za-z0-9]/.test(value)) classes += 1;
  return classes;
}
export function isStrongSecretValue(value: string): boolean {
  return value.length >= 12 && characterClasses(value) >= 2 && shannonEntropy(value) >= 3.5 && !isPlaceholderValue(value) && !UUID_SHAPE.test(value) && !PLAIN_HEX_DIGEST.test(value);
}
export function assignmentValueOf(matched: string): string {
  const quoted = matched.match(/['"]([^'"]{4,})['"]/);
  if (quoted !== null && quoted[1] !== undefined) return quoted[1];
  const sep = matched.search(/[:=]/);
  if (sep === -1) return '';
  return matched.slice(sep + 1).trim().replace(/^['"]/, '').replace(/['"]$/, '');
}
export function redactLiteral(value: string): string {
  return value.length >= 10 ? '<redacted>' : '*'.repeat(value.length);
}

/**
 * No embedded rules — all secrets rules are loaded from dataset packs/secrets/v1.
 */
export const SECRETS_RULES: readonly SecretsRule[] = [];

export function secretsRuleById(id: string): SecretsRule | undefined {
  return SECRETS_RULES.find((rule) => rule.id === id);
}
