import type { Finding, FindingRemediationGuidance, ScaResult } from '@drobon/shared';

/**
 * Remediation framework — engine only, no embedded guidance.
 * All remediation content lives in Drobon-Dataset knowledge/remediation (1310 entries).
 * Paid-tool parity: guidance is data, code is resolver.
 */

function unavailable(ruleId: string): FindingRemediationGuidance {
  return {
    ruleId,
    status: 'UNAVAILABLE',
    whyItMatters: 'No scanner-specific explanation is available for this rule in the current application version. Load the dataset for full guidance.',
    actions: ['Review the scanner rule documentation and source context; do not infer vulnerability details from an unsupported rule.'],
    verification: 'No rule-specific verification procedure is available. Configure DATASET_PATH to load remediation from Drobon-Dataset.',
  };
}

export function remediationGuidanceForFinding(finding: Finding): FindingRemediationGuidance {
  // Dataset remediation is resolved via external service; without it we are honest.
  // The engine never fabricates guidance — dataset provides it when configured.
  return unavailable(finding.ruleId);
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
