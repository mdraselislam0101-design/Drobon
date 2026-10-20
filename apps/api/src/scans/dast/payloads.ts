/**
 * Active DAST — safe, non-destructive payload catalog.
 * Every payload is synthetic, bounded, and read-only: it never
 * modifies, deletes, or exfiltrates data. Detection is
 * reflection/error-pattern observation, never exploitation.
 *
 * This module is ENGINE LOGIC only (no dataset) — payload shapes
 * are fixed here; dataset packs may add response checks (packRules)
 * that run on every active probe response.
 */

export type ActivePayloadCategory =
  | 'xss-reflected'
  | 'sqli-error'
  | 'open-redirect'
  | 'path-traversal'
  | 'crlf-injection';

export interface ActivePayload {
  /** Stable id for evidence correlation (not a finding ruleId). */
  readonly id: string;
  readonly category: ActivePayloadCategory;
  /** The literal string injected into a query param (GET only). */
  readonly value: string;
  /** How to detect the payload was reflected/triggered (linear, no g/y, bounded). */
  readonly detector: RegExp;
  /** Human description for evidence (never includes the raw payload verbatim in findings without redaction). */
  readonly description: string;
}

/**
 * Safe catalog — 5 categories × 1 payload each to bound active requests.
 * Total active injection budget = min(discoveredPoints, 10) × 1 payload.
 * Additions must stay bounded and pass the linear-time pattern audit.
 */
export const SAFE_ACTIVE_PAYLOADS: readonly ActivePayload[] = [
  {
    id: 'ACT-XSS-01',
    category: 'xss-reflected',
    // Non-executable marker — reflected verbatim check only, never executed (no browser).
    value: 'drobon-xss-1337\"><svg-drobon>',
    detector: /drobon-xss-1337/,
    description: 'Reflected XSS marker echoed in response body',
  },
  {
    id: 'ACT-SQLI-01',
    category: 'sqli-error',
    // Classic error-based probe — detection via DB error message, not data extraction.
    value: "' OR 'drobon'='drobon",
    detector: /(?:SQL syntax|mysql_fetch|ORA-|PostgreSQL.*ERROR|sqlite.*error|unclosed quotation mark)/i,
    description: 'Database error message triggered by injection probe',
  },
  {
    id: 'ACT-REDIR-01',
    category: 'open-redirect',
    // Safe redirect target — same-host check prevents actual cross-host follow; we only observe Location header.
    value: '//drobon-aegis.invalid/redirect-probe',
    detector: /drobon-aegis\.invalid\/redirect-probe/i,
    description: 'Open-redirect payload reflected in Location header',
  },
  {
    id: 'ACT-TRAV-01',
    category: 'path-traversal',
    // Read-only traversal marker — detection via file marker reflection, never file read.
    value: '..%2F..%2F..%2Fetc%2Fdrobon-probe',
    detector: /drobon-probe|root:.*:0:0:/,
    description: 'Path traversal marker reflected in response',
  },
  {
    id: 'ACT-CRLF-01',
    category: 'crlf-injection',
    // CRLF marker — detection via injected header presence, not actual header injection.
    value: '%0D%0AX-Drobon-Probe: injected',
    detector: /X-Drobon-Probe:\s*injected/i,
    description: 'CRLF injection marker reflected in response headers',
  },
] as const;

/** At most one payload per category per injection point (budget control). */
export function payloadsForBudget(maxPerPoint = 1): readonly ActivePayload[] {
  // Deterministic: first N categories in declared order.
  return SAFE_ACTIVE_PAYLOADS.slice(0, Math.max(1, Math.min(5, maxPerPoint)));
}
