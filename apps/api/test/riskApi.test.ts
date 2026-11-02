import { afterEach, describe, expect, test } from 'vitest';
import {
  isRiskAssessmentResponse, riskBandForScore,
  type DastObservation, type DastResult, type Finding, type RiskAssessment, type ScanResultSummary,
} from '@drobon/shared';
import { configureFixtureDastTarget, readJson, sessionCookieFrom, startTestServer, type TestServer } from './helpers.js';

const FIXTURE_LOGIN_PHRASE = 'risk assessment fixture phrase';
const SERVERS: TestServer[] = [];
afterEach(async () => {
  await Promise.all(SERVERS.splice(0).map((server) => server.stop()));
});

async function start(): Promise<TestServer> {
  const server = await startTestServer();
  SERVERS.push(server);
  return server;
}

async function register(server: TestServer, email: string): Promise<string> {
  const response = await fetch(`${server.baseUrl}/api/v1/auth/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: FIXTURE_LOGIN_PHRASE }),
  });
  expect(response.status).toBe(201);
  const session = sessionCookieFrom(response);
  const me = await fetch(`${server.baseUrl}/api/v1/me`, { headers: { cookie: session } });
  const device = me.headers.getSetCookie().find((value) => value.startsWith('drobon_device='));
  return device === undefined ? session : `${session}; ${device.split(';')[0]}`;
}

async function createProject(server: TestServer, cookie: string, name: string): Promise<string> {
  const response = await fetch(`${server.baseUrl}/api/v1/projects`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify({ name }),
  });
  expect(response.status).toBe(201);
  const body = await readJson(response) as { data: { project: { id: string } } };
  return body.data.project.id;
}

let sequence = 0;
/** A unique, well-formed finding id + fingerprint pair for synthetic fixtures. */
function nextIdentity(): { id: string; fingerprint: string } {
  sequence += 1;
  const hex = sequence.toString(16);
  return { id: `fnd_${hex.padStart(24, '0')}`, fingerprint: hex.padStart(64, '0') };
}

interface SeedOptions {
  truncated?: boolean;
  observedAt?: string;
}

async function seedCompletedScan(
  server: TestServer,
  cookie: string,
  owner: { ownerId: string; projectId: string },
  scanType: 'SAST' | 'DAST' | 'SCA' | 'SECRETS',
  build: (scanId: string) => unknown[],
  options: SeedOptions = {},
): Promise<{ scanId: string; findingIds: string[] }> {
  // A DAST scan needs an owner-registered synthetic target (never a real host).
  if (scanType === 'DAST') await configureFixtureDastTarget(server, cookie, owner.projectId);
  const created = await server.scans.createScanWithQuota({
    ownerId: owner.ownerId,
    projectId: owner.projectId,
    scanType,
    consume: async () => ({ ok: true }),
    ...(scanType === 'DAST'
      ? { targetUrl: DAST_TARGET, dastMode: 'PASSIVE' as const, dastActiveConsent: false }
      : {}),
  });
  if (created.outcome !== 'created') throw new Error(`Synthetic scan was not created (${created.outcome}).`);
  const scanId = created.scan.id;
  const claimed = await server.scans.claimNextQueued();
  if (claimed?.id !== scanId) throw new Error('Synthetic scan was not claimed for completion.');
  const findings = build(scanId) as Finding[];
  // A completed DAST scan must carry its real observation payload; the fixture
  // derives one observation per distinct recorded response.
  const dastPayload = scanType === 'DAST' ? dastResultFor(findings) : undefined;
  const summary: ScanResultSummary = {
    findingsTotal: findings.length,
    ...(options.truncated === true ? { truncated: true } : {}),
  };
  const completed = await server.scans.completeScan(scanId, summary, findings, undefined, dastPayload);
  expect(completed?.status).toBe('COMPLETED');
  const ids = findings.map((finding) => (finding as { id: string }).id);
  return { scanId, findingIds: ids };
}

const DAST_TARGET = 'https://fixture.example.org/';

/** The observation payload a passive scan would really have recorded. */
function dastResultFor(findings: readonly Finding[]): DastResult {
  const observations = new Map<string, DastObservation>();
  for (const finding of findings) {
    if (finding.scanner !== 'DAST') continue;
    observations.set(`${finding.endpoint}|${finding.observedAt}|${finding.responseStatus}`, {
      endpoint: finding.endpoint, method: 'GET', status: finding.responseStatus,
      observedAt: finding.observedAt, responseTimeMs: 3,
      bodyBytes: 128, bodyTruncated: false, contentType: 'text/html', headers: [],
    });
  }
  const list = [...observations.values()].slice(0, 3);
  return {
    targetUrl: DAST_TARGET,
    requestCount: Math.max(1, list.length),
    redirectsFollowed: 0,
    partial: false,
    mode: 'PASSIVE' as const,
    observations: list,
  };
}

function sastFinding(scanId: string, projectId: string, patch: Record<string, unknown> = {}) {
  const { id, fingerprint } = nextIdentity();
  return {
    id,
    scanId, ruleId: 'DG-SAST-001', scanner: 'SAST', severity: 'HIGH',
    title: 'Command execution sink', description: 'Synthetic fixture finding.', evidence: 'exec(...)',
    remediation: 'Avoid shell execution.', fingerprint, file: 'src/app.js', line: 4, column: 1, projectId,
    ...patch,
  };
}

function dastFinding(scanId: string, projectId: string, patch: Record<string, unknown> = {}) {
  const { id, fingerprint } = nextIdentity();
  return {
    id,
    scanId, ruleId: 'DG-DAST-990001', scanner: 'DAST', severity: 'HIGH',
    title: 'Reflected marker observed', description: 'Synthetic fixture finding.', evidence: 'Reflected marker in body',
    remediation: 'Encode output.', fingerprint, projectId,
    targetUrl: DAST_TARGET, endpoint: 'https://fixture.example.org/login',
    method: 'GET', responseStatus: 200, responseTimeMs: 3,
    observedAt: '2026-11-01T10:00:00.000Z', observedHeaders: [],
    ...patch,
  };
}

function secretFinding(scanId: string, projectId: string, patch: Record<string, unknown> = {}) {
  const { id, fingerprint } = nextIdentity();
  return {
    id,
    scanId, ruleId: 'DG-SEC-001', scanner: 'SECRETS', severity: 'CRITICAL',
    title: 'Literal credential in source', description: 'Synthetic fixture finding.', evidence: 'AKIA…redacted',
    remediation: 'Rotate and move to a secret manager.', fingerprint, file: 'src/app.js', line: 9, column: 1, projectId,
    ...patch,
  };
}

async function getAssessment(server: TestServer, cookie: string, projectId: string): Promise<{ status: number; data: RiskAssessment }> {
  const response = await fetch(`${server.baseUrl}/api/v1/projects/${encodeURIComponent(projectId)}/risk`, { headers: { cookie } });
  const body = await readJson(response) as { data: unknown };
  if (response.status === 200) {
    expect(isRiskAssessmentResponse(body.data)).toBe(true);
    return { status: response.status, data: (body.data as { assessment: RiskAssessment }).assessment };
  }
  return { status: response.status, data: undefined as unknown as RiskAssessment };
}

describe('GET /api/v1/projects/:projectId/risk', () => {
  test('requires a session and project ownership, and rejects unexpected query parameters', async () => {
    const server = await start();
    const owner = await register(server, 'risk-owner@example.test');
    const other = await register(server, 'risk-other@example.test');
    const projectId = await createProject(server, owner, 'Risk fixture project');
    const path = `${server.baseUrl}/api/v1/projects/${projectId}/risk`;

    expect((await fetch(path)).status).toBe(401);
    expect((await fetch(path, { headers: { cookie: other } })).status).toBe(403);
    expect((await fetch(`${path}?extra=1`, { headers: { cookie: owner } })).status).toBe(422);
    expect((await fetch(`${path}/extra`, { headers: { cookie: owner } })).status).toBe(404);
  });

  test('a project with no completed scan answers NO_COMPLETED_SCANS instead of a safe verdict', async () => {
    const server = await start();
    const owner = await register(server, 'risk-empty@example.test');
    const projectId = await createProject(server, owner, 'Empty risk project');
    const { status, data } = await getAssessment(server, owner, projectId);
    expect(status).toBe(200);
    expect(data.status).toBe('NO_COMPLETED_SCANS');
    expect(data.band).toBe('UNKNOWN');
    expect(data.findingsAnalysed).toBe(0);
    expect(data.clusters).toEqual([]);
    expect(data.sources.every((source) => source.scanId === null)).toBe(true);
    expect(data.disclosures.join(' ')).toContain('not a statement that the project is safe');
  });

  test('combines the latest SAST, SCA, SECRETS and DAST results into correlated clusters', async () => {
    const server = await start();
    const owner = await register(server, 'risk-combined@example.test');
    const projectId = await createProject(server, owner, 'Combined risk project');
    const me = await readJson(await fetch(`${server.baseUrl}/api/v1/me`, { headers: { cookie: owner } })) as {
      data: { user: { id: string } };
    };
    const scope = { ownerId: me.data.user.id, projectId };

    const sast = await seedCompletedScan(server, owner, scope, 'SAST', (scanId) => [
      sastFinding(scanId, projectId, { cwe: 'CWE-89', file: 'src/db.js', ruleId: 'DG-SAST-002' }),
    ]);
    const dast = await seedCompletedScan(server, owner, scope, 'DAST', (scanId) => [
      // Two DAST findings on one endpoint, one sharing the SAST weakness class.
      dastFinding(scanId, projectId, { cwe: 'CWE-89', ruleId: 'DG-DAST-990002', severity: 'HIGH' }),
      dastFinding(scanId, projectId, { ruleId: 'DG-DAST-990003', severity: 'MEDIUM' }),
    ]);
    const secrets = await seedCompletedScan(server, owner, scope, 'SECRETS', (scanId) => [
      secretFinding(scanId, projectId, { file: 'src/db.js' }),
    ]);
    const sca = await seedCompletedScan(server, owner, scope, 'SCA', (scanId) => [
      sastFinding(scanId, projectId, { scanner: 'SCA', ruleId: 'DPK-SCA-0001', file: 'package.json', severity: 'MEDIUM' }),
    ]);

    const { status, data } = await getAssessment(server, owner, projectId);
    expect(status).toBe(200);
    expect(data.status).toBe('ASSESSED');
    expect(data.findingsAnalysed).toBe(5);
    expect(data.correlatedFindings + data.unclusteredFindings).toBe(5);
    expect(data.sources.map((source) => [source.scanner, source.findings])).toEqual([
      ['SAST', 1], ['SCA', 1], ['SECRETS', 1], ['DAST', 2],
    ]);
    expect(data.sources.map((source) => source.scanId)).toEqual([sast.scanId, sca.scanId, secrets.scanId, dast.scanId]);

    const kinds = data.clusters.map((cluster) => cluster.kind);
    expect(kinds).toContain('ENDPOINT_CLUSTER');
    expect(kinds).toContain('CODE_AND_RUNTIME_CWE');
    expect(kinds).toContain('SECRET_IN_WEAK_FILE');
    // The band and the headline score are derived, never chosen by the caller.
    expect(data.score).toBe(Math.max(...data.clusters.map((cluster) => cluster.score)));
    expect(data.band).toBe(riskBandForScore(data.score));

    // Every cluster cites real finding ids from the scans above and nothing else.
    const known = new Set([...sast.findingIds, ...dast.findingIds, ...secrets.findingIds, ...sca.findingIds]);
    for (const cluster of data.clusters) {
      expect(cluster.evidence.length).toBeGreaterThanOrEqual(2);
      for (const item of cluster.evidence) expect(known.has(item.findingId)).toBe(true);
    }
    const runtime = data.clusters.find((cluster) => cluster.kind === 'CODE_AND_RUNTIME_CWE');
    expect(runtime?.scanners).toEqual(['DAST', 'SAST']);
    expect(runtime?.evidence.map((item) => item.findingId).sort()).toEqual([sast.findingIds[0], dast.findingIds[0]].sort());

    // Read-only: no scan was created by reading the assessment.
    const scans = await server.scans.listByProject(projectId);
    expect(scans).toHaveLength(4);
    expect(scans.every((scan) => scan.status === 'COMPLETED')).toBe(true);
  });

  test('only the LATEST completed scan of each scanner is read', async () => {
    const server = await start();
    const owner = await register(server, 'risk-latest@example.test');
    const projectId = await createProject(server, owner, 'Latest scan project');
    const me = await readJson(await fetch(`${server.baseUrl}/api/v1/me`, { headers: { cookie: owner } })) as {
      data: { user: { id: string } };
    };
    const scope = { ownerId: me.data.user.id, projectId };

    const older = await seedCompletedScan(server, owner, scope, 'DAST', (scanId) => [
      dastFinding(scanId, projectId, { ruleId: 'DG-DAST-990001' }),
      dastFinding(scanId, projectId, { ruleId: 'DG-DAST-990002' }),
    ]);
    const newer = await seedCompletedScan(server, owner, scope, 'DAST', (scanId) => [
      dastFinding(scanId, projectId, { ruleId: 'DG-DAST-990005' }),
    ]);
    expect(older.scanId).not.toBe(newer.scanId);

    const { data } = await getAssessment(server, owner, projectId);
    expect(data.sources.find((source) => source.scanner === 'DAST')?.scanId).toBe(newer.scanId);
    expect(data.sources.find((source) => source.scanner === 'DAST')?.findings).toBe(1);
    // The superseded scan's findings are not part of the assessment.
    expect(JSON.stringify(data)).not.toContain(older.findingIds[0]);
    expect(data.clusters).toEqual([]);
  });

  test('a finding marked FALSE_POSITIVE is excluded from the score, and the disclosure says so', async () => {
    const server = await start();
    const owner = await register(server, 'risk-fp@example.test');
    const projectId = await createProject(server, owner, 'False positive project');
    const me = await readJson(await fetch(`${server.baseUrl}/api/v1/me`, { headers: { cookie: owner } })) as {
      data: { user: { id: string } };
    };
    const scope = { ownerId: me.data.user.id, projectId };

    const dast = await seedCompletedScan(server, owner, scope, 'DAST', (scanId) => [
      dastFinding(scanId, projectId, { ruleId: 'DG-DAST-990001' }),
      dastFinding(scanId, projectId, { ruleId: 'DG-DAST-990002' }),
    ]);
    const before = await getAssessment(server, owner, projectId);
    expect(before.data.clusters.map((cluster) => cluster.kind)).toContain('ENDPOINT_CLUSTER');
    expect(before.data.findingsAnalysed).toBe(2);

    const scan = await server.scans.findByProjectAndId(projectId, dast.scanId);
    const target = scan?.findings?.find((finding) => finding.id === dast.findingIds[0]);
    expect(target).toBeDefined();
    const transition = await server.scans.transitionFindingLifecycle(
      projectId, target!.fingerprint, 'FALSE_POSITIVE', me.data.user.id, '2026-11-02T09:10:00.000Z',
    );
    expect(transition.outcome).toBe('updated');

    const after = await getAssessment(server, owner, projectId);
    expect(after.data.findingsAnalysed).toBe(1);
    expect(after.data.clusters).toEqual([]);
    expect(JSON.stringify(after.data)).not.toContain(dast.findingIds[0]);
    expect(after.data.disclosures.join(' ')).toContain('FALSE_POSITIVE');
  });

  test('the response never carries scanner payloads, evidence text or fingerprints', async () => {
    const server = await start();
    const owner = await register(server, 'risk-redaction@example.test');
    const projectId = await createProject(server, owner, 'Redaction project');
    const me = await readJson(await fetch(`${server.baseUrl}/api/v1/me`, { headers: { cookie: owner } })) as {
      data: { user: { id: string } };
    };
    const scope = { ownerId: me.data.user.id, projectId };
    const marker = 'SENTINEL_EVIDENCE_TEXT_DO_NOT_LEAK';
    const seeded = await seedCompletedScan(server, owner, scope, 'DAST', (scanId) => [
      dastFinding(scanId, projectId, { ruleId: 'DG-DAST-990001', evidence: marker }),
      dastFinding(scanId, projectId, { ruleId: 'DG-DAST-990002', description: marker }),
    ]);
    const response = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/risk`, { headers: { cookie: owner } });
    const text = await response.text();
    expect(response.status).toBe(200);
    expect(text).not.toContain(marker);
    // Provenance is the point: the assessment cites the recorded finding ids,
    // but never the evidence text, description or fingerprint behind them.
    expect(text).toContain(seeded.findingIds[0]);
    const scan = await server.scans.findByProjectAndId(projectId, seeded.scanId);
    for (const finding of scan?.findings ?? []) expect(text).not.toContain(finding.fingerprint);
    expect(text).toContain('risk_');
    expect(text).toContain('SEVERITY_SUM_V1');
    expect(text).toContain('DERIVED_CORRELATION');
  });

  test('a truncated scan is reported as bounded, not as complete coverage', async () => {
    const server = await start();
    const owner = await register(server, 'risk-truncated@example.test');
    const projectId = await createProject(server, owner, 'Truncated project');
    const me = await readJson(await fetch(`${server.baseUrl}/api/v1/me`, { headers: { cookie: owner } })) as {
      data: { user: { id: string } };
    };
    const scope = { ownerId: me.data.user.id, projectId };
    await seedCompletedScan(server, owner, scope, 'SAST', (scanId) => [sastFinding(scanId, projectId)], { truncated: true });
    const { data } = await getAssessment(server, owner, projectId);
    expect(data.truncated).toBe(true);
    expect(data.disclosures.join(' ')).toContain('bounded');
  });
});
