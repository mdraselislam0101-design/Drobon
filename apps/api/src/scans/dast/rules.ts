import type { FindingSeverity } from '@drobon/shared';

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

function header(input: DastRuleInput, name: string): string | undefined {
  const value = input.headers[name.toLowerCase()];
  const selected = Array.isArray(value) ? value.join(', ') : value;
  return typeof selected === 'string' ? selected.trim() : undefined;
}

function hasDirective(value: string | undefined, directive: string): boolean {
  return value !== undefined && value.split(';').some((part) =>
    part.trim().split(/\s+/, 1)[0]?.toLowerCase() === directive,
  );
}

function hasEffectiveHsts(value: string | undefined): boolean {
  if (value === undefined) return false;
  const maxAges = [...value.matchAll(/(?:^|;)\s*max-age\s*=\s*([0-9]+)\s*(?=;|$)/gi)];
  if (maxAges.length !== 1 || maxAges[0]?.[1] === undefined) return false;
  try {
    return BigInt(maxAges[0][1]) > 0n;
  } catch {
    return false;
  }
}

function make(
  ruleId: string,
  severity: FindingSeverity,
  title: string,
  description: string,
  evidence: string,
  remediation: string,
  observedHeaders: string[],
  cwe?: string,
): DastRuleMatch {
  return {
    ruleId,
    severity,
    title,
    description,
    evidence,
    remediation,
    observedHeaders,
    ...(cwe === undefined ? {} : { cwe }),
  };
}

/** Deterministic passive checks over one bounded, actually observed GET response. */
export function evaluateDastObservation(input: DastRuleInput): DastRuleMatch[] {
  const findings: DastRuleMatch[] = [];
  const secure = new URL(input.url).protocol === 'https:';
  const hsts = header(input, 'strict-transport-security');
  const nosniff = header(input, 'x-content-type-options');
  const frameOptions = header(input, 'x-frame-options');
  const csp = header(input, 'content-security-policy');
  const allowOrigin = header(input, 'access-control-allow-origin');
  const allowCredentials = header(input, 'access-control-allow-credentials');
  const server = header(input, 'server');
  const poweredBy = header(input, 'x-powered-by');

  if (!secure) {
    findings.push(
      make(
        'DG-DAST-001',
        'MEDIUM',
        'Target uses unencrypted HTTP',
        'The observed target URL uses HTTP, so this request and its response were not protected by TLS.',
        `Observed ${input.url.slice(0, 160)} returned HTTP ${input.status}.`,
        'Serve the application over HTTPS and redirect HTTP to HTTPS.',
        [],
        'CWE-319',
      ),
    );
  } else if (!hasEffectiveHsts(hsts)) {
    findings.push(
      make(
        'DG-DAST-002',
        'LOW',
        'Strict-Transport-Security is missing or ineffective',
        'The HTTPS response did not provide exactly one positive decimal HSTS max-age directive.',
        'Strict-Transport-Security: missing or ineffective max-age.',
        'Configure a deliberate Strict-Transport-Security max-age after confirming all subdomains support HTTPS.',
        ['Strict-Transport-Security: missing or ineffective max-age.'],
      ),
    );
  }

  if (nosniff?.toLowerCase() !== 'nosniff') {
    findings.push(
      make(
        'DG-DAST-003',
        'LOW',
        'X-Content-Type-Options is not nosniff',
        'The response did not set X-Content-Type-Options to nosniff.',
        `X-Content-Type-Options: ${nosniff === undefined ? 'missing' : 'unexpected value'}.`,
        'Set X-Content-Type-Options: nosniff and serve accurate Content-Type values.',
        [`X-Content-Type-Options: ${nosniff === undefined ? 'missing' : 'unexpected value'}`],
      ),
    );
  }

  if (
    !/^(deny|sameorigin)$/i.test(frameOptions ?? '') &&
    !hasDirective(csp, 'frame-ancestors')
  ) {
    findings.push(
      make(
        'DG-DAST-004',
        'LOW',
        'No frame-embedding restriction was observed',
        'Neither X-Frame-Options nor a Content-Security-Policy frame-ancestors directive was present.',
        'X-Frame-Options: missing; CSP frame-ancestors: missing.',
        'Set an appropriate X-Frame-Options or Content-Security-Policy frame-ancestors directive.',
        ['X-Frame-Options: missing', 'CSP frame-ancestors: missing'],
      ),
    );
  }

  const reflectsProbeOrigin = allowOrigin?.toLowerCase() === 'https://drobon-aegis.invalid';
  const wildcardWithCredentials = allowOrigin === '*' && allowCredentials?.toLowerCase() === 'true';
  if (wildcardWithCredentials || (reflectsProbeOrigin && allowCredentials?.toLowerCase() === 'true')) {
    findings.push(
      make(
        'DG-DAST-005',
        'MEDIUM',
        'CORS allows credentials with a broad or reflected origin',
        'The response combined credentialed CORS with a wildcard or the scanner’s synthetic untrusted origin.',
        `Access-Control-Allow-Origin: ${allowOrigin === '*' ? '*' : 'synthetic probe origin'}; Access-Control-Allow-Credentials: true.`,
        'Allow only an explicit trusted origin set; do not reflect arbitrary Origin values when credentials are enabled.',
        [
          `Access-Control-Allow-Origin: ${allowOrigin === '*' ? '*' : 'synthetic probe origin'}`,
          'Access-Control-Allow-Credentials: true',
        ],
      ),
    );
  }

  if (server !== undefined || poweredBy !== undefined) {
    const exposed: string[] = [];
    if (server !== undefined) exposed.push('Server: present');
    if (poweredBy !== undefined) exposed.push('X-Powered-By: present');
    findings.push(
      make(
        'DG-DAST-006',
        'INFO',
        'Server implementation headers are exposed',
        'The response exposed one or more implementation-identifying headers. Header values are intentionally not retained.',
        exposed.join('; '),
        'Remove or minimize implementation-identifying response headers where operationally practical.',
        exposed,
      ),
    );
  }

  const rawCookies = input.headers['set-cookie'];
  const cookies = typeof rawCookies === 'string' ? [rawCookies] : Array.isArray(rawCookies) ? rawCookies : [];
  if (cookies.length > 0) {
    for (const [index, cookie] of cookies.slice(0, 5).entries()) {
      const parts = cookie.split(';').slice(1).map((part) => part.trim().toLowerCase());
      const missing: string[] = [];
      if (secure && !parts.some((part) => part === 'secure')) missing.push('Secure');
      if (!parts.some((part) => part === 'httponly')) missing.push('HttpOnly');
      if (!parts.some((part) => part.startsWith('samesite='))) missing.push('SameSite');
      if (missing.length > 0) {
        // Cookie names and values are both omitted: either may contain sensitive material.
        const evidence = `Set-Cookie #${index + 1} omits ${missing.join(', ')}.`;
        findings.push(
          make(
            'DG-DAST-007',
            'LOW',
            'Cookie security attributes are incomplete',
            'An observed Set-Cookie header omitted one or more recommended security attributes. Cookie names and values are not retained.',
            evidence,
            'Set Secure on HTTPS cookies, HttpOnly when JavaScript access is unnecessary, and an explicit SameSite policy.',
            [`Set-Cookie #${index + 1}: missing ${missing.join(', ')}`],
          ),
        );
      }
    }
  }

  if (secure && (input.contentType === 'text/html' || input.contentType === 'application/xhtml+xml')) {
    const matches = input.body.match(/<(?:script|iframe|img|source)\b[^>]*\bsrc\s*=\s*['"]http:\/\/|<link\b[^>]*\bhref\s*=\s*['"]http:\/\//gi);
    if (matches !== null && matches.length > 0) {
      findings.push(
        make(
          'DG-DAST-008',
          'MEDIUM',
          'HTTPS document references insecure HTTP resources',
          'The bounded response body contained one or more static HTTP subresource references. The target markup was not executed or stored.',
          `${matches.length} insecure HTTP subresource reference(s) observed in the bounded response body.`,
          'Serve all page subresources over HTTPS and remove insecure resource references.',
          ['Response body: insecure subresource references observed'],
        ),
      );
    }
  }

  return findings;
}
