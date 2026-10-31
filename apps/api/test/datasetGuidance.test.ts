import { describe, expect, test } from 'vitest';
import { isFindingRemediationGuidance, type Finding } from '@drobon/shared';
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

  test('long, decomposed and sensitive guidance fits the shared response contract', () => {
    const guidance = remediationGuidanceForFinding(finding(), {
      ...entry,
      whyItMatters: `${'e\u0301'.repeat(450)}\u202e`,
      actions: ['\u0000   ', 'x'.repeat(500), 'password = "SYNTHETIC_GUIDANCE_SECRET_98765"'], // synthetic test fixture
      verification: 'v'.repeat(1000),
      standardId: 'CWE-123456',
    });
    expect(isFindingRemediationGuidance(guidance)).toBe(true);
    expect(guidance.whyItMatters.length).toBeLessThanOrEqual(400);
    expect(guidance.whyItMatters).toBe(guidance.whyItMatters.normalize('NFC'));
    expect(guidance.actions.every((action) => action.length > 0 && action.length <= 300)).toBe(true);
    expect(guidance.verification.length).toBeLessThanOrEqual(400);
    expect(guidance.standardId).toBeUndefined();
    expect(JSON.stringify(guidance)).not.toContain('SYNTHETIC_GUIDANCE_SECRET_98765');
  });

  test('empty actions after sanitization fail closed', () => {
    expect(remediationGuidanceForFinding(finding(), { ...entry, actions: ['\u0000   '] }).status).toBe('UNAVAILABLE');
  });

  test.each([
    {
      ruleId: 'DPK-SAST-002', file: 'src/app.ts',
      before: 'el.innerHTML = "<p>" + name;', after: 'el.textContent = name;',
      caveat: 'textContent drops all markup; if markup is genuinely required, sanitize before assigning.',
    },
    {
      ruleId: 'DPK-SAST-005', file: 'src/app.py',
      before: 'data = pickle.loads(raw)', after: 'data = json.loads(raw)',
      caveat: 'Validate the decoded JSON against a schema — safe parsing does not mean safe values.',
    },
    {
      ruleId: 'DPK-SAST-008', file: 'src/app.js',
      before: 'db.query("SELECT * FROM t WHERE id = " + id)', after: 'db.query("SELECT * FROM t WHERE id = ?", [id])',
      caveat: "Placeholder syntax varies by driver (?, $1, :id) — match this codebase's driver.",
    },
  ])('only the exact reviewed $ruleId example is shown for its compatible language', ({ ruleId, file, before, after, caveat }) => {
    const matching = finding({ ruleId, file });
    const withExample = { ...entry, ruleId, example: { before, after, caveat } };
    const guidance = remediationGuidanceForFinding(matching, withExample);
    expect(isFindingRemediationGuidance(guidance)).toBe(true);
    expect(guidance.example).toMatchObject({ before, after });
    expect(guidance.example?.caveat).toContain('Drobon does not apply or verify fixes');
    expect(remediationGuidanceForFinding(matching, { ...withExample, example: { before, after: `${after} altered`, caveat } }).example).toBeUndefined();
    expect(remediationGuidanceForFinding(finding({ ruleId, file: 'src/incompatible.txt' }), withExample).example).toBeUndefined();
    expect(remediationGuidanceForFinding(finding({ ruleId, file, scanner: 'SECRETS' }), withExample).example).toBeUndefined();
  });

  test.each(['DPK-SAST-001', 'DPK-SAST-003', 'DPK-SAST-004', 'DPK-SAST-006', 'DPK-SAST-007'])(
    'unreviewed example %s is withheld while the rule guidance remains available',
    (ruleId) => {
      const guidance = remediationGuidanceForFinding(finding({ ruleId }), { ...entry, ruleId, example: { before: 'before', after: 'after', caveat: 'review' } });
      expect(guidance.status).toBe('RULE_SPECIFIC');
      expect(guidance.example).toBeUndefined();
    },
  );

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
