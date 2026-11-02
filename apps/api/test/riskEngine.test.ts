import { describe, expect, test } from 'vitest';
import {
  RISK_MAX_CLUSTERS,
  RISK_MAX_EVIDENCE,
  RISK_MAX_FINDINGS,
  isRiskAssessment,
  isRiskAssessmentResponse,
  riskBandForScore,
  type FindingSeverity,
  type RiskAssessment,
  type ScanType,
} from '@drobon/shared';
import { buildRiskAssessment, scoreCluster, type RiskFindingView, type RiskInput, type RiskSourceScan } from '../src/risk/engine.js';

const PROJECT = 'prj_00000000-0000-4000-8000-000000000001';
const NOW = '2026-11-02T09:00:00.000Z';
const COMPLETED = '2026-11-01T10:00:00.000Z';

let counter = 0;
function id(): string {
  counter += 1;
  return `fnd_${counter.toString(16).padStart(24, '0')}`;
}

function sast(patch: Partial<RiskFindingView> = {}): RiskFindingView {
  return { id: id(), scanner: 'SAST', severity: 'HIGH', ruleId: 'DG-SAST-001', file: 'src/app.js', ...patch };
}
function dast(patch: Partial<RiskFindingView> = {}): RiskFindingView {
  return {
    id: id(),
    scanner: 'DAST',
    severity: 'HIGH',
    ruleId: 'DG-DAST-990001',
    endpoint: 'https://fixture.example.test/login',
    observedAt: COMPLETED,
    responseStatus: 200,
    ...patch,
  };
}
function secrets(patch: Partial<RiskFindingView> = {}): RiskFindingView {
  return { id: id(), scanner: 'SECRETS', severity: 'CRITICAL', ruleId: 'DG-SEC-001', file: 'src/app.js', ...patch };
}
function sca(patch: Partial<RiskFindingView> = {}): RiskFindingView {
  return { id: id(), scanner: 'SCA', severity: 'MEDIUM', ruleId: 'DPK-SCA-0001', file: 'package.json', ...patch };
}

function source(scanner: ScanType, findings: RiskFindingView[], patch: Partial<RiskSourceScan> = {}): RiskSourceScan {
  return { scanner, scanId: `scan_0000000${SCAN_ORDER[scanner]}-0000-4000-8000-00000000000${SCAN_ORDER[scanner]}`, completedAt: COMPLETED, findings, omitted: false, ...patch };
}
const SCAN_ORDER: Record<ScanType, number> = { SAST: 1, SCA: 2, SECRETS: 3, DAST: 4 };

function input(sources: RiskSourceScan[], patch: Partial<RiskInput> = {}): RiskInput {
  const present = new Set(sources.map((entry) => entry.scanner));
  return {
    projectId: PROJECT,
    generatedAt: NOW,
    sources,
    missingScanners: (['SAST', 'SCA', 'SECRETS', 'DAST'] as ScanType[]).filter((scanner) => !present.has(scanner)),
    ...patch,
  };
}

function build(sources: RiskSourceScan[]): RiskAssessment {
  const assessment = buildRiskAssessment(input(sources));
  // Every test asserts the contract guard: the engine can never emit a shape
  // the API would have to "fix up" afterwards.
  expect(isRiskAssessment(assessment)).toBe(true);
  expect(isRiskAssessmentResponse({ assessment })).toBe(true);
  return assessment;
}

describe('correlated risk engine — honest states', () => {
  test('no completed scan yields NO_COMPLETED_SCANS, an UNKNOWN band and no safety claim', () => {
    const assessment = build([]);
    expect(assessment.status).toBe('NO_COMPLETED_SCANS');
    expect(assessment.band).toBe('UNKNOWN');
    expect(assessment.score).toBe(0);
    expect(assessment.clusters).toHaveLength(0);
    expect(assessment.findingsAnalysed).toBe(0);
    expect(assessment.sources.map((entry) => entry.scanner)).toEqual(['SAST', 'SCA', 'SECRETS', 'DAST']);
    expect(assessment.sources.every((entry) => entry.scanId === null && entry.findings === 0)).toBe(true);
    expect(assessment.disclosures.join(' ')).toContain('not a statement that the project is safe');
    expect(assessment.truncated).toBe(false);
  });

  test('completed scans with zero findings yield NO_FINDINGS and still disclose the gap', () => {
    const assessment = build([source('SAST', [])]);
    expect(assessment.status).toBe('NO_FINDINGS');
    expect(assessment.band).toBe('UNKNOWN');
    expect(assessment.sources[0]).toEqual({ scanner: 'SAST', scanId: expect.stringMatching(/^scan_/), completedAt: COMPLETED, findings: 0 });
    expect(assessment.disclosures.join(' ')).toContain('An empty result is not proof that the project is secure');
    expect(assessment.disclosures.join(' ')).toContain('SCA, SECRETS, DAST has no completed scan');
  });

  test('findings that never overlap produce zero clusters and never a safe verdict', () => {
    const assessment = build([
      source('SAST', [sast({ file: 'src/a.ts', ruleId: 'DG-SAST-001' })]),
      source('DAST', [dast({ ruleId: 'DG-DAST-990002' })]),
    ]);
    expect(assessment.status).toBe('ASSESSED');
    expect(assessment.clusters).toHaveLength(0);
    expect(assessment.band).toBe('UNKNOWN');
    expect(assessment.correlatedFindings).toBe(0);
    expect(assessment.unclusteredFindings).toBe(2);
    expect(assessment.disclosures.join(' ')).toContain('absence of correlation, not evidence that the project is safe');
  });
});

describe('correlated risk engine — correlation rules', () => {
  test('two DAST findings on one path form an ENDPOINT_CLUSTER that cites both findings', () => {
    const a = dast({ severity: 'HIGH', endpoint: 'https://fixture.example.test/login?step=1', ruleId: 'DG-DAST-990001' });
    const b = dast({ severity: 'MEDIUM', endpoint: 'https://fixture.example.test/login?step=2', ruleId: 'DG-DAST-990002' });
    const assessment = build([source('DAST', [a, b])]);
    const cluster = assessment.clusters.find((entry) => entry.kind === 'ENDPOINT_CLUSTER');
    expect(cluster).toBeDefined();
    expect(cluster?.asset).toBe('https://fixture.example.test/login');
    expect(cluster?.evidence.map((entry) => entry.findingId).sort()).toEqual([a.id, b.id].sort());
    expect(cluster?.scanners).toEqual(['DAST']);
    // 6 + 3 + 0 corroboration
    expect(cluster?.score).toBe(9);
    expect(cluster?.band).toBe(riskBandForScore(9));
    expect(assessment.score).toBe(9);
    expect(cluster?.summary).toContain('not proof of an attack chain');
  });

  test('one response with two defects is a SAME_RESPONSE cluster, distinct from the endpoint cluster', () => {
    const a = dast({ observedAt: '2026-11-01T10:00:00.000Z', responseStatus: 200 });
    const b = dast({ observedAt: '2026-11-01T10:00:00.000Z', responseStatus: 200 });
    const c = dast({ observedAt: '2026-11-01T10:05:00.000Z', responseStatus: 200 });
    const assessment = build([source('DAST', [a, b, c])]);
    const kinds = assessment.clusters.map((entry) => entry.kind).sort();
    expect(kinds).toEqual(['ENDPOINT_CLUSTER', 'SAME_RESPONSE']);
    const sameResponse = assessment.clusters.find((entry) => entry.kind === 'SAME_RESPONSE');
    expect(sameResponse?.asset).toContain('2026-11-01T10:00:00.000Z');
    expect(sameResponse?.evidence.map((entry) => entry.findingId).sort()).toEqual([a.id, b.id].sort());
    // Three DAST findings on one path are one endpoint cluster of three members.
    const endpoint = assessment.clusters.find((entry) => entry.kind === 'ENDPOINT_CLUSTER');
    expect(endpoint?.evidence).toHaveLength(3);
  });

  test('a weakness class present in code and at runtime needs the SAME CWE on both sides', () => {
    const code = sast({ cwe: 'CWE-89', severity: 'HIGH', file: 'src/db.js' });
    const runtime = dast({ cwe: 'CWE-89', severity: 'HIGH', ruleId: 'DG-DAST-990002' });
    const otherCwe = dast({ cwe: 'CWE-79', severity: 'LOW', ruleId: 'DG-DAST-990001' });
    const assessment = build([source('SAST', [code]), source('DAST', [runtime, otherCwe])]);
    const correlated = assessment.clusters.filter((entry) => entry.kind === 'CODE_AND_RUNTIME_CWE');
    expect(correlated).toHaveLength(1);
    expect(correlated[0]?.asset).toBe('CWE-89');
    expect(correlated[0]?.scanners).toEqual(['DAST', 'SAST']);
    expect(correlated[0]?.evidence.map((entry) => entry.findingId).sort()).toEqual([code.id, runtime.id].sort());
    // 6 + 6 + 1 corroborating scanner
    expect(correlated[0]?.score).toBe(13);
    expect(correlated[0]?.band).toBe('HIGH');
    // The unrelated CWE never appears in a correlation claim.
    expect(JSON.stringify(correlated)).not.toContain(otherCwe.id);
  });

  test('a hardcoded secret beside a code weakness in one file is clustered, value never repeated', () => {
    const leak = secrets({ file: 'src/config.js', ruleId: 'DG-SEC-001' });
    const code = sast({ file: 'src/config.js', severity: 'MEDIUM', ruleId: 'DG-SAST-004' });
    const elsewhere = sast({ file: 'src/other.js' });
    const assessment = build([source('SECRETS', [leak]), source('SAST', [code, elsewhere])]);
    const cluster = assessment.clusters.find((entry) => entry.kind === 'SECRET_IN_WEAK_FILE');
    expect(cluster?.asset).toBe('src/config.js');
    expect(cluster?.scanners).toEqual(['SAST', 'SECRETS']);
    expect(cluster?.evidence.map((entry) => entry.findingId).sort()).toEqual([leak.id, code.id].sort());
    expect(isRiskAssessment(assessment)).toBe(true);
  });

  test('one rule recurring on several assets becomes a RECURRING_RULE cluster', () => {
    const a = sast({ file: 'src/a.js', ruleId: 'DG-SAST-007', severity: 'LOW' });
    const b = sast({ file: 'src/b.js', ruleId: 'DG-SAST-007', severity: 'LOW' });
    const c = sast({ file: 'src/c.js', ruleId: 'DG-SAST-007', severity: 'LOW' });
    const once = sast({ file: 'src/d.js', ruleId: 'DG-SAST-009', severity: 'LOW' });
    const assessment = build([source('SAST', [a, b, c, once])]);
    const recurring = assessment.clusters.filter((entry) => entry.kind === 'RECURRING_RULE');
    expect(recurring).toHaveLength(1);
    expect(recurring[0]?.evidence).toHaveLength(3);
    expect(recurring[0]?.summary).toContain('3 different assets');
    expect(JSON.stringify(recurring)).not.toContain(once.id);
  });

  test('a single finding can never form a cluster', () => {
    const assessment = build([source('SECRETS', [secrets({ file: 'src/only.js' })])]);
    expect(assessment.clusters).toHaveLength(0);
    expect(assessment.unclusteredFindings).toBe(1);
  });
});

describe('correlated risk engine — accounting, caps and determinism', () => {
  test('correlated plus unclustered equals the findings that were analysed', () => {
    const correlatedA = dast({ endpoint: 'https://fixture.example.test/a' });
    const correlatedB = dast({ endpoint: 'https://fixture.example.test/a' });
    const lonely = sast({ file: 'src/lonely.js', ruleId: 'DG-SAST-050' });
    const assessment = build([source('DAST', [correlatedA, correlatedB]), source('SAST', [lonely])]);
    expect(assessment.findingsAnalysed).toBe(3);
    expect(assessment.correlatedFindings).toBe(2);
    expect(assessment.unclusteredFindings).toBe(1);
    expect(assessment.sources.reduce((sum, entry) => sum + entry.findings, 0)).toBe(3);
  });

  test('evidence is capped and the score is recomputable from the evidence shown', () => {
    // Twelve distinct assets share the rule: one recurring-pattern cluster.
    const findings = Array.from({ length: 12 }, (_, index) => sast({ file: `src/repeat-${index}.js`, ruleId: 'DG-SAST-011', severity: 'LOW' }));
    const assessment = build([source('SAST', findings)]);
    const cluster = assessment.clusters[0];
    expect(cluster?.evidence).toHaveLength(RISK_MAX_EVIDENCE);
    // The score sums exactly the listed evidence: 8 LOW = 8 → MEDIUM.
    // A reader can recompute it from the response alone.
    expect(cluster?.score).toBe(8);
    expect(cluster?.band).toBe('MEDIUM');
    expect(cluster?.summary).toContain('12 different assets');
  });

  test('the assessment is bounded and says so when it truncates', () => {
    const many = Array.from({ length: RISK_MAX_FINDINGS + 100 }, (_, index) =>
      sast({ file: `src/file-${index}.js`, ruleId: 'DG-SAST-100', severity: 'LOW' }));
    const assessment = build([source('SAST', many)]);
    expect(assessment.findingsAnalysed).toBe(RISK_MAX_FINDINGS);
    expect(assessment.truncated).toBe(true);
    expect(assessment.disclosures.join(' ')).toContain('only the first 400 findings');
    expect(assessment.sources[0]?.findings).toBe(RISK_MAX_FINDINGS);
  });

  test('one noisy scanner cannot starve the others of the global cap', () => {
    const noise = Array.from({ length: RISK_MAX_FINDINGS }, (_, index) =>
      sast({ file: `src/noise-${index}.js`, ruleId: 'DG-SAST-200', severity: 'LOW' }));
    const signal = dast({ severity: 'HIGH', endpoint: 'https://fixture.example.test/only', ruleId: 'DG-DAST-990004' });
    const assessment = build([source('SAST', noise), source('DAST', [signal])]);
    expect(assessment.sources.find((entry) => entry.scanner === 'DAST')?.findings).toBe(1);
    expect(assessment.findingsAnalysed).toBe(RISK_MAX_FINDINGS);
    expect(assessment.truncated).toBe(true);
  });

  test('clusters are capped and the omission is disclosed', () => {
    const findings: RiskFindingView[] = [];
    for (let index = 0; index < RISK_MAX_CLUSTERS + 10; index += 1) {
      findings.push(dast({ endpoint: `https://fixture.example.test/p${index}`, observedAt: `2026-11-01T10:${String(index).padStart(2, '0')}:00.000Z` }));
      findings.push(dast({ endpoint: `https://fixture.example.test/p${index}`, observedAt: `2026-11-01T10:${String(index).padStart(2, '0')}:30.000Z` }));
    }
    const assessment = build([source('DAST', findings)]);
    expect(assessment.clusters).toHaveLength(RISK_MAX_CLUSTERS);
    expect(assessment.truncated).toBe(true);
    expect(assessment.disclosures.join(' ')).toContain('cluster(s) omitted');
  });

  test('identical input is byte-identical output, and input order does not matter', () => {
    const findings = [
      dast({ endpoint: 'https://fixture.example.test/x', severity: 'HIGH' }),
      dast({ endpoint: 'https://fixture.example.test/x', severity: 'LOW' }),
      sast({ file: 'src/a.js', ruleId: 'DG-SAST-003', cwe: 'CWE-89' }),
      dast({ endpoint: 'https://fixture.example.test/y', severity: 'MEDIUM', cwe: 'CWE-89' }),
    ];
    const forward = buildRiskAssessment(input([source('DAST', findings.slice(0, 2).concat(findings[3]!)), source('SAST', [findings[2]!])]));
    const reversed = buildRiskAssessment(input([
      source('SAST', [findings[2]!]),
      source('DAST', [findings[3]!, findings[1]!, findings[0]!]),
    ]));
    expect(JSON.stringify(reversed)).toBe(JSON.stringify(forward));
    expect(JSON.stringify(buildRiskAssessment(input([source('DAST', findings.slice(0, 2)), source('SAST', [findings[2]!])]))))
      .toBe(JSON.stringify(buildRiskAssessment(input([source('DAST', findings.slice(0, 2)), source('SAST', [findings[2]!])]))));
  });

  test('cluster ids are stable, derived from kind and asset only', () => {
    const a = dast({ endpoint: 'https://fixture.example.test/id-test' });
    const b = dast({ endpoint: 'https://fixture.example.test/id-test' });
    const first = build([source('DAST', [a, b])]).clusters[0]?.id;
    const second = build([source('DAST', [a, b])]).clusters[0]?.id;
    expect(first).toMatch(/^risk_[a-f0-9]{24}$/);
    expect(second).toBe(first);
  });
});

describe('correlated risk engine — guard rejects tampering', () => {
  const base = () => build([source('DAST', [
    dast({ endpoint: 'https://fixture.example.test/t', severity: 'HIGH' }),
    dast({ endpoint: 'https://fixture.example.test/t', severity: 'MEDIUM' }),
  ])]);

  test('a supplied band that disagrees with the model is rejected', () => {
    const assessment = base();
    expect(isRiskAssessment({ ...assessment, band: 'LOW' })).toBe(false);
    expect(isRiskAssessment({ ...assessment, score: 99 })).toBe(false);
    expect(isRiskAssessment({ ...assessment, correlatedFindings: 0 })).toBe(false);
  });

  test('a cluster with a single evidence item or an unknown scanner is rejected', () => {
    const assessment = base();
    const cluster = assessment.clusters[0]!;
    expect(isRiskAssessment({ ...assessment, clusters: [{ ...cluster, evidence: [cluster.evidence[0]] }] })).toBe(false);
    expect(isRiskAssessment({
      ...assessment,
      clusters: [{ ...cluster, evidence: [{ ...cluster.evidence[0], scanner: 'SAST' }, { ...cluster.evidence[1], scanner: 'SAST' }] }],
    })).toBe(false);
  });

  test('statuses cannot contradict the evidence they carry', () => {
    const assessment = base();
    expect(isRiskAssessment({ ...assessment, status: 'NO_FINDINGS' })).toBe(false);
    expect(isRiskAssessment({ ...assessment, status: 'NO_COMPLETED_SCANS' })).toBe(false);
    expect(isRiskAssessment({ ...assessment, disclosures: [] })).toBe(false);
    expect(isRiskAssessment({ ...assessment, projections: [] })).toBe(false);
  });
});

describe('published scoring model', () => {
  test('score is the severity-weight sum plus one point per additional scanner', () => {
    const lone: RiskFindingView = { id: 'fnd_000000000000000000000001', scanner: 'SAST', severity: 'MEDIUM', ruleId: 'R', file: 'a.js' };
    const other: RiskFindingView = { id: 'fnd_000000000000000000000002', scanner: 'DAST', severity: 'LOW', ruleId: 'R', endpoint: 'https://x.test/a' };
    expect(scoreCluster([lone])).toBe(3);
    expect(scoreCluster([lone, other])).toBe(5);
    // Duplicates are the same finding, never extra score.
    expect(scoreCluster([lone, { ...lone }])).toBe(3);
  });

  test('bands are derived at the documented thresholds', () => {
    expect(riskBandForScore(0)).toBe('UNKNOWN');
    expect(riskBandForScore(1)).toBe('LOW');
    expect(riskBandForScore(4)).toBe('LOW');
    expect(riskBandForScore(5)).toBe('MEDIUM');
    expect(riskBandForScore(11)).toBe('MEDIUM');
    expect(riskBandForScore(12)).toBe('HIGH');
    expect(riskBandForScore(19)).toBe('HIGH');
    expect(riskBandForScore(20)).toBe('CRITICAL');
  });

  test('severity weights are the published ones', () => {
    const severities: FindingSeverity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
    const expected = [10, 6, 3, 1, 0];
    severities.forEach((severity, index) => {
      const finding: RiskFindingView = { id: 'fnd_000000000000000000000003', scanner: 'SCA', severity, ruleId: 'R', file: 'p.json' };
      expect(scoreCluster([finding])).toBe(expected[index]);
    });
    expect(scoreCluster([sca({ severity: 'CRITICAL' })])).toBeGreaterThanOrEqual(10);
  });
});
