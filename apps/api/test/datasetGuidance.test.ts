import { describe, expect, test } from 'vitest';
import type { Finding } from '@drobon/shared';
import { remediationGuidanceForFinding } from '../src/scans/remediationGuidance.js';
import { createGuidanceLookup } from '../src/external/guidance.js';
import type { DatasetService } from '../src/external/service.js';

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: `fnd_${'a'.repeat(24)}`,
    scanId: 'scan_00000000-0000-4000-8000-000000000001',
    ruleId: 'DPK-SAST-001',
    scanner: 'SAST',
    severity: 'MEDIUM',
    title: 'Fixture finding',
    description: 'Fixture',
    evidence: 'untrusted fixture evidence',
    remediation: '',
    fingerprint: 'b'.repeat(64),
    projectId: 'prj_00000000-0000-4000-8000-000000000001',
    file: 'src/app.ts',
    line: 1,
    column: 1,
    ...overrides,
  } as Finding;
}

const entry = {
  ruleId: 'DPK-SAST-001',
  whyItMatters: 'Dynamic evaluation executes a string as code.',
  actions: ['Remove eval and use JSON.parse for data.'],
  verification: 'Rerun the SAST scan after the source change.',
  standardId: 'CWE-95',
};

describe('dataset-backed remediation guidance', () => {
  test('a matching dataset entry becomes RULE_SPECIFIC, bounded and scanner-safe', () => {
    const guidance = remediationGuidanceForFinding(finding(), entry);
    expect(guidance.status).toBe('RULE_SPECIFIC');
    expect(guidance.standardId).toBe('CWE-95');
    expect(guidance.actions[0]).toContain('Remove eval');
    expect(JSON.stringify(guidance)).not.toContain('untrusted fixture evidence');
  });

  test('mismatched, malformed or absent entries fail closed to honest UNAVAILABLE', () => {
    expect(remediationGuidanceForFinding(finding()).status).toBe('UNAVAILABLE');
    expect(remediationGuidanceForFinding(finding(), { ...entry, ruleId: 'DPK-SAST-999' }).status).toBe('UNAVAILABLE');
    expect(remediationGuidanceForFinding(finding(), { ...entry, actions: [] }).status).toBe('UNAVAILABLE');
    const fallback = remediationGuidanceForFinding(finding());
    expect(fallback.actions.join(' ')).toContain('Drobon does not perform or attest');
  });

  test('the DAST fallback names the passive-scan verification without inventing advice', () => {
    const dast = finding({ scanner: 'DAST', ruleId: 'DPK-DAST-002' });
    const guidance = remediationGuidanceForFinding(dast);
    expect(guidance.status).toBe('UNAVAILABLE');
    expect(guidance.verification).toContain('passive DAST scan');
  });

  test('one cached lookup serves every surface from the dataset service', async () => {
    let calls = 0;
    const fake = {
      remediation: async () => { calls += 1; return [entry]; },
    } as unknown as DatasetService;
    const lookup = createGuidanceLookup(fake);
    const first = await lookup('DPK-SAST-001');
    const second = await lookup('DPK-SAST-001');
    const missing = await lookup('DPK-SAST-999');
    expect(first).toEqual(entry);
    expect(second).toEqual(entry);
    expect(missing).toBeUndefined();
    expect(calls).toBe(1);
    expect(remediationGuidanceForFinding(finding(), first).status).toBe('RULE_SPECIFIC');
  });
});
