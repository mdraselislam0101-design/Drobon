import type { FindingSeverity } from '@drobon/shared';

/**
 * SAST rule framework — engine only, no embedded rules.
 * All rule data lives in Drobon-Dataset packs/sast/v1 (DPK-SAST-*); this module
 * only defines the rule shape and the line matcher. Paid-tool parity: rules are
 * data, engines are code.
 */

export interface SastRuleMatch {
  column: number;
}

export type SastLineMatcher = (line: string) => SastRuleMatch | undefined;

export interface SastRule {
  readonly id: string;
  readonly title: string;
  readonly description: string;
  readonly severity: FindingSeverity;
  readonly cwe?: string;
  readonly category: string;
  readonly remediation: string;
  readonly limitation: string;
  readonly patterns: readonly RegExp[];
  readonly languages?: readonly string[];
  readonly redactEvidence?: (line: string, match: SastRuleMatch) => string;
  readonly flow?: 'command' | 'sql' | 'html';
}

export function matchRuleLine(rule: SastRule, line: string): SastRuleMatch | undefined {
  for (const pattern of rule.patterns) {
    if (pattern.global || pattern.sticky) {
      throw new Error(`Rule pattern must not use the g/y flags: ${rule.id}`);
    }
    const match = pattern.exec(line);
    if (match !== null) {
      return { column: match.index + 1 };
    }
  }
  return undefined;
}

/**
 * No embedded rules — all SAST rules are loaded from dataset packs/sast/v1.
 * Engine falls back to 0 findings when dataset not configured (honest).
 */
export const SAST_RULES: readonly SastRule[] = [];

export function sastRuleById(id: string): SastRule | undefined {
  return SAST_RULES.find((rule) => rule.id === id);
}
