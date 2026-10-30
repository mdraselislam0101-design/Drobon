import type { Finding, FindingRemediationGuidance, ScaResult } from '@drobon/shared';
import type { RemediationEntry } from '../external/knowledge.js';

/**
 * Remediation framework — resolver only, no embedded guidance content.
 *
 * Guidance is DATA: with a configured Drobon-Dataset checkout, the 4,007
 * `knowledge/remediation/*.json` entries are resolved by rule id and surfaced
 * as RULE_SPECIFIC guidance. Without a dataset the resolver returns an honest
 * UNAVAILABLE fallback: it never invents rule-specific security advice, never
 * repeats scanner evidence, and never claims a fix was verified.
 */

/** Bounded, safe copy of a dataset entry into the shared API contract. */
function text(value: string, max: number): string {
  let clean = '';
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    clean += code < 32 || code === 127 ? ' ' : character;
  }
  return clean.trim().slice(0, max);
}

function scannerFallback(finding: Finding): { why: string; actions: string[]; verification: string } {
  const shared = [
    'Drobon does not perform or attest remediation, credential rotation, or fix verification for you.',
    'Treat the scanner evidence as untrusted text and review it in source context.',
  ];
  switch (finding.scanner) {
    case 'DAST':
      return {
        why: 'No dataset-backed explanation is loaded for this passive observation. A header or body observation does not by itself prove exploitability.',
        actions: [
          ...shared,
          'Confirm the observation on the configured target and review the server configuration that produced it.',
        ],
        verification: 'Run a new passive DAST scan against the configured target after the server configuration change; compare the observed headers and body.',
      };
    case 'SECRETS':
      return {
        why: 'No dataset-backed explanation is loaded for this rule. A detected credential shape may still be a live secret.',
        actions: [...shared, 'If the value is real, rotate it and move it to a secret manager; never paste it into a report.'],
        verification: 'Rerun the secrets scan on a clean snapshot and confirm the rotated value is gone.',
      };
    case 'SCA':
      return {
        why: 'No dataset-backed explanation is loaded for this declaration rule. A declaration observation classifies a manifest entry; it does not prove an installed version is affected.',
        actions: [...shared, 'Review the declared dependency or registry setting in the manifest, then pin or restrict it deliberately.'],
        verification: 'Rerun the SCA scan after changing the manifest and compare the declaration-rule finding fingerprint.',
      };
    default:
      return {
        why: 'No dataset-backed explanation is loaded for this rule in the current configuration.',
        actions: [...shared, 'Configure DATASET_PATH to load rule-specific guidance from Drobon-Dataset.'],
        verification: 'Rerun the SAST scan after the source change and compare the finding fingerprint.',
      };
  }
}

function unavailable(finding: Finding): FindingRemediationGuidance {
  const fallback = scannerFallback(finding);
  return {
    ruleId: finding.ruleId,
    status: 'UNAVAILABLE',
    whyItMatters: fallback.why,
    actions: fallback.actions,
    verification: fallback.verification,
  };
}

/**
 * Resolve guidance for one finding. `entry` comes from the external dataset
 * service (never from client input). A mismatched or malformed entry is
 * ignored — fail closed to the honest fallback instead of shipping bad data.
 */
export function remediationGuidanceForFinding(finding: Finding, entry?: RemediationEntry): FindingRemediationGuidance {
  if (entry === undefined || entry.ruleId !== finding.ruleId) return unavailable(finding);
  if (typeof entry.whyItMatters !== 'string' || typeof entry.verification !== 'string' || !Array.isArray(entry.actions)) {
    return unavailable(finding);
  }
  const actions = entry.actions.filter((a): a is string => typeof a === 'string').map((a) => text(a, 500)).slice(0, 8);
  if (entry.whyItMatters.trim().length === 0 || entry.verification.trim().length === 0 || actions.length === 0) {
    return unavailable(finding);
  }
  return {
    ruleId: finding.ruleId,
    status: 'RULE_SPECIFIC',
    whyItMatters: text(entry.whyItMatters, 1000),
    actions,
    verification: text(entry.verification, 1000),
    ...(typeof entry.standardId === 'string' && /^CWE-\d+$/.test(entry.standardId) ? { standardId: entry.standardId } : {}),
  };
}

export function scaInventoryGuidance(result: ScaResult): {
  status: 'NOT_ASSESSED' | 'ASSESSED';
  message: string;
  verification: string;
} {
  if (result.summary.assessmentState === 'NOT_ASSESSED') {
    return {
      status: 'NOT_ASSESSED',
      message: 'This result records observed dependency inventory only. Vulnerability intelligence is NOT ASSESSED because no provider dataset is loaded; no package is declared safe or vulnerable.',
      verification: 'Use the inventory to identify the actual dependency and version, then consult an approved provider out of band. Rerun SCA when authorized vulnerability intelligence becomes available.',
    };
  }
  return {
    status: 'ASSESSED',
    message: 'Use only advisories actually returned by the configured provider. Drobon does not infer additional package vulnerability or upgrade claims.',
    verification: 'After an intentional dependency change, rerun SCA and compare the actual provider assessment and SBOM.',
  };
}
