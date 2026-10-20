import type { FindingSeverity } from '@drobon/shared';

export interface DastPackCheck {
  type: 'http-url' | 'missing-response-header' | 'response-header-missing-directive' | 'cookie-missing-flag' | 'response-header-matches' | 'response-body-matches' | 'response-header-host-differs';
  header?: string;
  directive?: string;
  flag?: string;
  valuePattern?: string;
  requireScheme?: string;
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
