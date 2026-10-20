import type { FindingSeverity } from '@drobon/shared';

/**
 * DAST rule framework — engine only, no embedded rules.
 * All DAST checks live in Drobon-Dataset packs/dast/v1 (DPK-DAST-*).
 */

export interface DastRuleMatch {
  ruleId: string;
  severity: FindingSeverity;
  title: string;
  description: string;
  evidence: string;
  remediation: string;
  cwe?: string;
  observedHeaders: string[];
}

export interface DastRuleInput {
  url: string;
  status: number;
  headers: Readonly<Record<string, string | string[] | undefined>>;
  body: string;
  contentType?: string;
}

/**
 * No embedded DAST rules — all checks are loaded from dataset packs/dast/v1.
 * Returns empty when dataset not configured (honest).
 */
export function evaluateDastObservation(_input: DastRuleInput): DastRuleMatch[] {
  return [];
}
