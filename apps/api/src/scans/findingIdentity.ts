import { createHash } from 'node:crypto';
import type { ScanType } from '@drobon/shared';

/**
 * Stable finding identity. Evidence MUST already be redacted before this
 * helper is called; the digest stores only a hash of its normalized form.
 * Project context prevents unrelated tenants from sharing IDs, while
 * intentionally omitting the random scan UUID keeps rescans stable.
 */
export function findingFingerprint(options: {
  scanner: ScanType;
  projectId: string;
  ruleId: string;
  location: string;
  line?: number;
  evidence: string;
  context?: readonly string[];
}): string {
  const normalizedEvidence = options.evidence.normalize('NFC').replace(/\r\n?/g, '\n').replace(/[ \t]+$/gm, '');
  const normalizedLocation = options.location.normalize('NFC').replace(/\\/g, '/');
  const evidenceDigest = createHash('sha256').update(normalizedEvidence, 'utf8').digest('hex');
  const tuple = [
    'drobon-finding-v1',
    options.scanner,
    options.projectId,
    options.ruleId,
    normalizedLocation,
    options.line ?? null,
    ...(options.context ?? []).map((item) => item.normalize('NFC')),
    evidenceDigest,
  ];
  return createHash('sha256').update(JSON.stringify(tuple), 'utf8').digest('hex');
}
