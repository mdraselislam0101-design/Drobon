import type { FindingSeverity } from '@drobon/shared';

export interface DastPackCheck {
  type: 'http-url' | 'missing-response-header' | 'response-header-missing-directive' | 'cookie-missing-flag' | 'response-header-matches' | 'response-body-matches' | 'response-header-host-differs';
  header?: string;
  directive?: string;
  flag?: string;
  valuePattern?: string;
  /** Optional scheme scope for header/body match checks (`http` | `https`). */
  requireScheme?: string;
}

/** Dataset pack.json identity, surfaced in scan metadata (loader checklist #6). */
export interface DastPackMetadata {
  packId: string;
  version: string;
}

export interface DastRule {
  id: string;
  title: string;
  description: string;
  severity: FindingSeverity;
  cwe?: string;
  category: string;
  remediation: string;
  limitation: string;
  check: DastPackCheck;
  tests?: unknown[];
}
