import { describe, expect, test } from 'vitest';
import type { Finding } from '@drobon/shared';
import { planRoleExecution, evidenceGaps, evidenceCoverage, SCANNER_TOOL } from '../src/agent/orchestration.js';
import { AGENT_ROLES } from '../src/agent/roles.js';
import { createAgentExecutor } from '../src/agent/execution.js';
import { buildAgentAssessment } from '../src/agent/assessment.js';
import { digestSource } from '../src/agent/snapshot.js';
import type { ScanRecord } from '../src/scans/store.js';

const OWNER = 'usr_orchestration';
const PROJECT = 'prj_00000000-0000-4000-8000-0000000000aa';
const ASSESSMENT = 'asm_00000000-0000-4000-8000-0000000000a1';

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: `fnd_${'a'.repeat(24)}`, scanId: 'scan_00000000-0000-4000-8000-000000000001',
    ruleId: 'DG-SAST-001', severity: 'HIGH', title: 'Example', description: 'Bounded.',
    evidence: 'const value = input;', remediation: 'Review.', fingerprint: 'b'.repeat(64),
    scanner: 'SAST', file: 'src/app.ts', line: 2, column: 3,
    ...overrides,
  } as Finding;
}

describe('role -> scanner gateway', () => {
  test('each scanner is owned by exactly one role and its granted tool', () => {
    const expected = { SAST: ['SAST', 'RUN_SAST'], SCA: ['SCA', 'RUN_SCA'],
      SECRETS: ['SECRETS', 'RUN_SECRETS'], DAST: ['DAST', 'RUN_DAST'] } as const;
    for (const [scanType, [role, tool]] of Object.entries(expected)) {
      const decision = planRoleExecution(scanType as keyof typeof SCANNER_TOOL);
      expect(decision.allowed).toBe(true);
      if (!decision.allowed) continue;
      expect(decision.plan.role).toBe(role);
      expect(decision.plan.tool).toBe(tool);
      expect(decision.plan.maxSteps).toBe(AGENT_ROLES[role].maxSteps);
      expect(decision.plan.evidenceRequired).toEqual(AGENT_ROLES[role].evidenceRequired);
    }
  });

  test('the gateway refuses an unknown scan type and a revoked grant', () => {
    expect(planRoleExecution('UNKNOWN' as never).allowed).toBe(false);
    const revoked = planRoleExecution('SAST', () => ({ allowed: false, reason: 'grant table revoked' }));
    expect(revoked.allowed).toBe(false);
    if (revoked.allowed) throw new Error('unreachable');
    // The reason names the role, never a path, source line or secret value.
    expect(revoked.reason).toContain('SAST');
    expect(revoked.reason).not.toContain('/');
    // A grant for a different role cannot authorize this scanner.
    const crossed = planRoleExecution('DAST', (role, tool) => role === 'SAST' && tool === 'RUN_DAST'
      ? { allowed: true } : { allowed: false, reason: 'crossed' });
    expect(crossed.allowed).toBe(false);
  });
});

describe('evidence contract', () => {
  test('a complete finding has no gaps and an incomplete one names the missing fields', () => {
    expect(evidenceGaps('SAST', finding())).toEqual([]);
    expect(evidenceGaps('SAST', finding({ evidence: '   ' }))).toEqual(['evidence']);
    expect(evidenceGaps('SECRETS', finding({ scanner: 'SECRETS' }))).toEqual([]);
    const source = finding() as Finding & { file?: string; line?: number };
    delete source.file;
    expect(evidenceGaps('SCA', source)).toEqual(['file']);
    // A DAST observation is not required to carry a source file.
    expect(evidenceGaps('DAST', { ...finding(), scanner: 'DAST', evidence: 'HTTP 200' } as Finding)).toEqual([]);
  });

  test('coverage is bounded and reports gaps without exposing values', () => {
    const covered = evidenceCoverage('SAST', [finding(), finding({ id: `fnd_${'c'.repeat(24)}` })]);
    expect(covered).toEqual({ checked: 2, complete: 2, incomplete: 0, hasGaps: false });
    const gapped = evidenceCoverage('SAST', [finding(), finding({ evidence: '' })]);
    expect(gapped.hasGaps).toBe(true);
    expect(gapped.incomplete).toBe(1);
    expect(evidenceCoverage('SAST', Array.from({ length: 10 }, () => finding()), 4).checked).toBe(4);
  });
});

describe('executor applies the gateway before any scanner work', () => {
  const record = { id: 'scan_00000000-0000-4000-8000-000000000001', ownerId: OWNER,
    projectId: PROJECT, assessmentId: ASSESSMENT, scanType: 'SAST', status: 'QUEUED',
    agent: { version: 1 as const, datasetDigest: 'd'.repeat(64), sourceDigest: 'e'.repeat(64),
      engagementId: 'eng_00000000-0000-4000-8000-000000000001' } } as unknown as ScanRecord;
  const context = { signal: new AbortController().signal } as never;
  const base = { projects: { findById: async () => undefined }, assessments: {},
    scans: {}, sources: {}, targetPolicy: {}, now: () => 0 };

  test('a revoked grant fails the job before authorization, Dataset or engine work', async () => {
    let touched = 0;
    const executor = createAgentExecutor({ ...base, executionEnabled: true, providerId: 'filesystem',
      projects: { findById: async () => { touched += 1; return undefined; } },
      roleGrant: () => ({ allowed: false, reason: 'revoked' }) } as never);
    const outcome = await executor.execute(record, context);
    expect(outcome.kind).toBe('failed');
    if (outcome.kind !== 'failed') throw new Error('unreachable');
    expect(outcome.failureMessage).toContain('AGENT ROLE BLOCKED');
    expect(outcome.failureMessage).toContain('SAST');
    // Nothing downstream ran: no project lookup happened.
    expect(touched).toBe(0);
  });

  test('an authorized grant proceeds past the gateway (and stops at the next real check)', async () => {
    let touched = 0;
    const executor = createAgentExecutor({ ...base, executionEnabled: true, providerId: 'filesystem',
      projects: { findById: async () => { touched += 1; return undefined; } } } as never);
    const outcome = await executor.execute(record, context);
    expect(outcome.kind).toBe('failed');
    if (outcome.kind !== 'failed') throw new Error('unreachable');
    expect(outcome.failureMessage).not.toContain('AGENT ROLE BLOCKED');
    expect(touched).toBeGreaterThan(0);
  });
});

describe('reviews honour the role evidence contract', () => {
  const snapshot = { ownerId: OWNER, projectId: PROJECT, files: [{ path: 'src/app.ts', content: 'const a = 1;\nconst b = 2;\n' }],
    createdAt: '2026-01-01T00:00:00.000Z' };
  const sourceDigest = digestSource(snapshot as never);
  const assessmentInput = (findings: Finding[]) => ({
    project: { id: PROJECT, ownerId: OWNER, name: 'Fixture', description: '', status: 'ACTIVE',
      createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z' },
    assessment: { id: ASSESSMENT, projectId: PROJECT, title: 'Fixture', objectives: ['Review'],
      scope: { inScopeHosts: ['fixture.example.org'], outOfScopeHosts: [] }, status: 'ACTIVE',
      createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z',
      authorizationDeclarations: [], history: [], engagements: [{ id: 'eng_00000000-0000-4000-8000-000000000001',
        clientName: 'Fixture', targetUrl: 'https://fixture.example.org/', inScopeHosts: ['fixture.example.org'],
        scopePaths: ['/'], allowedScanTypes: ['SAST'], validFrom: '2026-01-01T00:00:00.000Z',
        validUntil: '2027-01-01T00:00:00.000Z', statement: 'Synthetic.', declaredBy: OWNER,
        declaredAt: '2026-01-01T00:00:00.000Z', state: 'DECLARED', status: 'ACTIVE' }] },
    snapshot,
    scans: [{ id: 'scan_00000000-0000-4000-8000-000000000001', ownerId: OWNER, projectId: PROJECT,
      assessmentId: ASSESSMENT, scanType: 'SAST', status: 'COMPLETED', createdAt: '2026-01-01T00:00:00.000Z',
      updatedAt: '2026-01-01T00:00:00.000Z',
      agent: { version: 1, datasetDigest: 'd'.repeat(64), sourceDigest,
        engagementId: 'eng_00000000-0000-4000-8000-000000000001' },
      resultSummary: { findingsTotal: findings.length }, findings }],
    executionEnabled: true, agentStorageReady: true, datasetConfigured: true, quotaExhausted: false,
    now: '2026-01-01T00:00:00.000Z',
  }) as never;

  test('a finding without its declared evidence is INCONCLUSIVE, not SUSPECTED', () => {
    const complete = buildAgentAssessment(assessmentInput([finding()]));
    expect(complete.reviews[0]?.verdict).toBe('SUSPECTED');
    const gapped = buildAgentAssessment(assessmentInput([finding({ evidence: '' })]));
    expect(gapped.reviews[0]?.verdict).toBe('INCONCLUSIVE');
    expect(gapped.reviews[0]?.basis).toContain('evidence');
    // No source text or secret value leaks into the basis.
    expect(gapped.reviews[0]?.basis).not.toContain('const value');
  });
});
