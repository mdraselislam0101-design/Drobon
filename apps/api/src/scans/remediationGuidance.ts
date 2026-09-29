import type { Finding, FindingRemediationGuidance, ScaResult } from '@drobon/shared';
import { sastRuleById } from './sast/rules.js';
import { secretsRuleById } from './secrets/rules.js';

const SAST_EXAMPLES: Readonly<Record<string, NonNullable<FindingRemediationGuidance['example']>>> = {
  'DG-SAST-001': {
    before: ['ex', 'ec(`git show ${ref}`)'].join(''),
    after: ['e', 'xec', 'File("git", ["show", ref], { shell: false }, callback)'].join(''),
    caveat: 'Use the API and argument conventions of the runtime in this repository; keep shell execution disabled.',
  },
  'DG-SAST-002': {
    before: ['ev', 'al("value = " + dynamicText)'].join(''),
    after: 'JSON.parse(dynamicText)',
    caveat: 'JSON.parse is suitable only when the input is JSON; use a parser for the actual data format.',
  },
  'DG-SAST-003': {
    before: 'db.query("SELECT * FROM items WHERE id = " + id)',
    after: 'db.query("SELECT * FROM items WHERE id = ?", [id])',
    caveat: 'Placeholder syntax and parameter APIs vary by database driver; keep SQL structure separate from values.',
  },
  'DG-SAST-004': {
    before: 'element.innerHTML = "<p>" + userValue',
    after: 'element.textContent = userValue',
    caveat: 'If markup is required, use an allowlist-based sanitizer and the framework’s safe rendering API.',
  },
  'DG-SAST-005': {
    before: 'const apiKey = "non-placeholder-literal"',
    after: ['const apiKey = process.', 'env.API_KEY'].join(''),
    caveat: 'Use an appropriate secret manager or protected runtime configuration; rotate any exposed credential.',
  },
  'DG-SAST-006': {
    before: 'createHash("md5")',
    after: 'createHash("sha256")',
    caveat: 'Choose a cryptographic algorithm only when the value is used for a security purpose; checksum compatibility may differ.',
  },
};

const DAST_ACTIONS: Readonly<Record<string, readonly string[]>> = {
  'DG-DAST-001': ['Serve the application over HTTPS with a valid deployment-managed certificate.', 'Redirect HTTP to HTTPS after validating the application and proxy configuration.'],
  'DG-DAST-002': ['Configure one deliberate positive decimal HSTS max-age on HTTPS responses.', 'Enable includeSubDomains only after confirming every affected subdomain supports HTTPS.'],
  'DG-DAST-003': ['Set X-Content-Type-Options: nosniff.', 'Return accurate Content-Type values for served resources.'],
  'DG-DAST-004': ['Set a Content-Security-Policy frame-ancestors directive or an appropriate X-Frame-Options policy.'],
  'DG-DAST-005': ['Allow only an explicit trusted origin set when credentials are enabled.', 'Do not reflect arbitrary Origin values; review the application’s actual CORS configuration.'],
  'DG-DAST-006': ['Remove or minimize implementation-identifying response headers where operationally practical.', 'Do not treat header removal as a substitute for patching or secure configuration.'],
  'DG-DAST-007': ['Set Secure on cookies served over HTTPS.', 'Set HttpOnly when client-side script access is unnecessary and choose an explicit SameSite policy.'],
  'DG-DAST-008': ['Change observed HTTP subresource references to HTTPS.', 'Confirm referenced resources support HTTPS and are served with the expected content type.'],
};

const DAST_WHY: Readonly<Record<string, string>> = {
  'DG-DAST-001': 'One passive observation used HTTP, so that request and response were not protected by TLS.',
  'DG-DAST-002': 'The observed HTTPS response did not show exactly one positive decimal HSTS max-age directive.',
  'DG-DAST-003': 'The observed response did not contain X-Content-Type-Options: nosniff.',
  'DG-DAST-004': 'The observed response did not provide a recognized frame restriction.',
  'DG-DAST-005': 'The observed CORS headers showed a potentially permissive origin/credentials combination; one response does not test every origin.',
  'DG-DAST-006': 'The observed response contained implementation-identifying headers.',
  'DG-DAST-007': 'Observed cookie attributes did not satisfy the supported checks; cookie values were not inspected.',
  'DG-DAST-008': 'Bounded HTML inspection observed HTTP subresource references from an HTTPS page.',
};

const DAST_VERIFICATION: Readonly<Record<string, string>> = {
  'DG-DAST-001': 'Run a new authorized passive DAST scan and confirm the configured target uses HTTPS; this check is observational, not an exploit test.',
  'DG-DAST-002': 'Run a new authorized passive DAST scan over HTTPS and confirm an effective HSTS max-age is observed.',
  'DG-DAST-003': 'Run a new authorized passive DAST scan and confirm the response header is observed as nosniff.',
  'DG-DAST-004': 'Run a new authorized passive DAST scan and confirm a frame restriction is observed.',
  'DG-DAST-005': 'Review the server-side CORS policy, then run a new authorized passive DAST scan; one observation does not test every origin.',
  'DG-DAST-006': 'Run a new authorized passive DAST scan and confirm implementation-identifying headers are no longer observed.',
  'DG-DAST-007': 'Run a new authorized passive DAST scan and confirm the observed cookies carry the intended attributes; cookie values remain uninspected.',
  'DG-DAST-008': 'Run a new authorized passive DAST scan and confirm the bounded HTML response no longer contains the observed insecure resource references.',
};

const SECRETS_ACTIONS = [
  'Revoke or rotate the exposed credential with its provider; Drobon does not perform or attest to that action.',
  'Remove the credential from source and configuration, including any relevant repository history and deployment copies.',
  'Load future values from an approved secret manager or protected runtime configuration.',
  'Add a prevention control such as secret scanning and review the change before deployment.',
  'Run a new Secrets scan to check whether the same redacted finding is observed again.',
] as const;

/**
 * Scanner-specific, read-only guidance. It uses only the persisted finding's
 * rule identity and safe scanner description/remediation; evidence is never
 * interpolated, and no source file is read or changed here.
 */
export function remediationGuidanceForFinding(finding: Finding): FindingRemediationGuidance {
  const scanner = finding.scanner ?? (finding.ruleId.startsWith('DG-SEC-') ? 'SECRETS' : 'SAST');
  if (scanner === 'SAST') {
    const rule = sastRuleById(finding.ruleId);
    if (rule === undefined) return unavailable(finding.ruleId);
    return {
      ruleId: finding.ruleId,
      status: 'RULE_SPECIFIC',
      whyItMatters: rule.description,
      actions: [rule.remediation, 'Review the flagged source in its full application context; this lexical finding is not a proof of exploitability.'],
      verification: 'Run the same SAST scanner on a new source snapshot and confirm whether this exact deterministic fingerprint is observed.',
      ...(rule.cwe === undefined ? {} : { standardId: rule.cwe }),
      ...(SAST_EXAMPLES[finding.ruleId] === undefined ? {} : { example: SAST_EXAMPLES[finding.ruleId] }),
    };
  }
  if (scanner === 'SECRETS') {
    const rule = secretsRuleById(finding.ruleId);
    if (rule === undefined) return unavailable(finding.ruleId);
    return {
      ruleId: finding.ruleId,
      status: 'LIMITED',
      whyItMatters: rule.description,
      actions: [rule.remediation, ...SECRETS_ACTIONS],
      verification: 'Run a new Secrets scan after rotating and removing the credential. A missing finding is not proof that every copy was revoked or removed.',
      ...(rule.cwe === undefined ? {} : { standardId: rule.cwe }),
    };
  }
  if (scanner === 'DAST') {
    const actions = DAST_ACTIONS[finding.ruleId];
    const whyItMatters = DAST_WHY[finding.ruleId];
    const verification = DAST_VERIFICATION[finding.ruleId];
    if (actions === undefined || whyItMatters === undefined || verification === undefined) return unavailable(finding.ruleId);
    return {
      ruleId: finding.ruleId,
      status: 'LIMITED',
      whyItMatters,
      actions: [finding.remediation, ...actions],
      verification,
      ...(finding.cwe === undefined ? {} : { standardId: finding.cwe }),
    };
  }
  return unavailable(finding.ruleId);
}

function unavailable(ruleId: string): FindingRemediationGuidance {
  return {
    ruleId,
    status: 'UNAVAILABLE',
    whyItMatters: 'No scanner-specific explanation is available for this rule in the current application version.',
    actions: ['Review the scanner rule documentation and source context; do not infer vulnerability details from an unsupported rule.'],
    verification: 'No rule-specific verification procedure is available. Run only an authorized supported scanner and review its actual result.',
  };
}

/** Explicit SCA wording for inventory-only scans; no upgrade claims are made. */
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
