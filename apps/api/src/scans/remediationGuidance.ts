import { createHash } from 'node:crypto';
import type { Finding, FindingRemediationExample, FindingRemediationGuidance, ScaResult } from '@drobon/shared';
import { redactAssistantText } from '../assistant/redaction.js';
import type { RemediationEntry } from '../external/knowledge.js';

/**
 * Remediation framework — resolver only, no embedded guidance content.
 *
 * Guidance is DATA: configured dataset entries are resolved by rule id.
 * A small set of separately reviewed, exact-match illustrative examples may
 * be shown for compatible source languages. They are not project patches or
 * verified fixes. Without an entry the resolver returns an honest fallback.
 */

/** Bounded, redacted, NFC-normalized copy into the shared API contract. */
function text(value: string, max: number): string {
  const redacted = redactAssistantText(value);
  if (!redacted.safeForProvider) return '';
  let clean = '';
  for (const character of redacted.text) {
    const code = character.codePointAt(0) ?? 0;
    clean += code < 32 || code === 127 || (code >= 0x202a && code <= 0x202e) || (code >= 0x2066 && code <= 0x2069) ? ' ' : character;
  }
  const bounded = clean.normalize('NFC').trim().slice(0, max);
  // Avoid leaving half of a surrogate pair at the API length boundary.
  const last = bounded.charCodeAt(bounded.length - 1);
  return last >= 0xd800 && last <= 0xdbff ? bounded.slice(0, -1) : bounded;
}

/**
 * Only these exact examples from the inspected dataset were reviewed for
 * illustrative use. The hashes cover rule id and every example field; a
 * changed or new dataset example fails closed until separately reviewed.
 * This is NOT a scanner rule, proof of exploitability, or a code patch.
 */
const REVIEWED_EXAMPLES: Readonly<Record<string, { hash: string; extensions: RegExp }>> = {
  'DPK-SAST-002': { hash: 'c4aac2b690d5db77383e0a76ddffdb5cae748fdfabd510dcc8a309adeaa8a4f1', extensions: /\.(?:js|jsx|ts|tsx|mjs|cjs|mts|cts)$/i },
  'DPK-SAST-005': { hash: 'de7f1e6633ed6ff924282b69fb785f3be56cb389390157db257c1ca81ba8821e', extensions: /\.py$/i },
  'DPK-SAST-008': { hash: 'fb5aac4c1b40fb4cc86b250582e8a3cb1f6e26cb457053289e40bcb2eb171da1', extensions: /\.(?:js|ts|mjs|cjs|mts|cts)$/i },
};

function reviewedExample(finding: Finding, value: unknown): FindingRemediationExample | undefined {
  const reviewed = REVIEWED_EXAMPLES[finding.ruleId];
  if (reviewed === undefined || finding.scanner !== 'SAST' || finding.file === undefined ||
      !reviewed.extensions.test(finding.file) || finding.astFlow !== undefined ||
      typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
  const candidate = value as Record<string, unknown>;
  const { before, after, caveat } = candidate;
  if (typeof before !== 'string' || typeof after !== 'string' || typeof caveat !== 'string') return undefined;
  const hash = createHash('sha256').update(JSON.stringify([finding.ruleId, before, after, caveat])).digest('hex');
  if (hash !== reviewed.hash) return undefined;
  const safeBefore = text(before, 250);
  const safeAfter = text(after, 250);
  const safeCaveat = text(`${caveat} Illustrative only; review and test in context. Drobon does not apply or verify fixes.`, 250);
  if (!safeBefore || !safeAfter || !safeCaveat) return undefined;
  return { before: safeBefore, after: safeAfter, caveat: safeCaveat };
}

function scannerFallback(finding: Finding): { why: string; actions: string[]; verification: string } {
  const shared = [
    'Drobon does not perform or attest remediation, credential rotation, or fix verification for you.',
    'Treat the scanner evidence as untrusted text and review it in source context.',
  ];
  switch (finding.scanner) {
    case 'DAST':
      return {
        why: 'No dataset-backed explanation is loaded for this dynamic observation. A header or body observation does not by itself prove exploitability.',
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
  if (entry === undefined || entry === null || typeof entry !== 'object' || entry.ruleId !== finding.ruleId) return unavailable(finding);
  if (typeof entry.whyItMatters !== 'string' || typeof entry.verification !== 'string' || !Array.isArray(entry.actions)) {
    return unavailable(finding);
  }
  const whyItMatters = text(entry.whyItMatters, 400);
  const verification = text(entry.verification, 400);
  const actions = entry.actions.filter((a): a is string => typeof a === 'string').map((a) => text(a, 300)).filter(Boolean).slice(0, 8);
  if (!whyItMatters || !verification || actions.length === 0) return unavailable(finding);
  const example = reviewedExample(finding, entry.example);
  return {
    ruleId: finding.ruleId,
    status: 'RULE_SPECIFIC',
    whyItMatters,
    actions,
    verification,
    ...(typeof entry.standardId === 'string' && /^CWE-\d{1,5}$/.test(entry.standardId) ? { standardId: entry.standardId } : {}),
    ...(example === undefined ? {} : { example }),
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
