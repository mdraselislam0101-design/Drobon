import { describe, expect, test } from 'vitest';
import { findingFingerprint } from '../src/scans/findingIdentity.js';

const base = {
  scanner: 'SAST' as const,
  projectId: 'prj_00000000-0000-4000-8000-000000000041',
  ruleId: 'DG-SAST-001',
  location: 'src\\app.ts',
  line: 12,
  evidence: '  eval("<redacted>");  \r\n',
};

describe('scanner-aware stable finding identity', () => {
  test('normalizes line endings, trailing whitespace, Unicode and path separators', () => {
    const first = findingFingerprint(base);
    const equivalent = findingFingerprint({
      ...base,
      location: 'src/app.ts',
      evidence: '  eval("<redacted>");\n',
    });
    expect(first).toBe(equivalent);
    expect(first).toMatch(/^[a-f0-9]{64}$/);
  });

  test('separates scanner, project, rule, source line and caller context', () => {
    const original = findingFingerprint(base);
    expect(findingFingerprint({ ...base, scanner: 'SECRETS' })).not.toBe(original);
    expect(findingFingerprint({ ...base, projectId: 'prj_00000000-0000-4000-8000-000000000042' })).not.toBe(original);
    expect(findingFingerprint({ ...base, ruleId: 'DG-SAST-002' })).not.toBe(original);
    expect(findingFingerprint({ ...base, line: 13 })).not.toBe(original);
    expect(findingFingerprint({ ...base, context: ['different-safe-context'] })).not.toBe(original);
  });

  test('the identity output does not reveal the source evidence', () => {
    const fingerprint = findingFingerprint({ ...base, evidence: 'SYNTHETIC_SECRET_DO_NOT_PERSIST' });
    expect(fingerprint).not.toContain('SYNTHETIC_SECRET_DO_NOT_PERSIST');
    expect(fingerprint).toMatch(/^[a-f0-9]{64}$/);
  });
});
