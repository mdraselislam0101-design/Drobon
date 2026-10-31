import { afterEach, describe, expect, test } from 'vitest';
import { isSecurityReport, type Finding, type ScanDetail, type SecurityReport } from '@drobon/shared';
import { createDatasetService } from '../src/external/service.js';
import { getMergedDastRules, getMergedSastRules, getMergedSecretsRules } from '../src/external/packIntegration.js';
import { compileScaDeclarationRule } from '../src/external/scaDeclaration.js';
import { createDastTargetPolicy } from '../src/scans/dast/target.js';
import type { DastTransport } from '../src/scans/dast/http.js';
import { readJson, sessionCookieFrom, startTestServer, type TestServer } from './helpers.js';
import { cases as benchmarkCases, manifestDigest } from '../../../benchmarks/accuracy-v2/fixtures.mjs';
import { labResponse } from '../../../benchmarks/local/target.mjs';

/** Opt-in: operator supplies an already mounted, strictly read-only Dataset.
 * This test never creates/writes Dataset files. Source snapshots and app
 * stores are in memory; DAST DNS and transport are synthetic local mocks. */
const datasetPath = process.env['DROBON_MOUNTED_DATASET_TEST_PATH'];
const servers: TestServer[] = [];
afterEach(async () => { await Promise.all(servers.splice(0).map((server) => server.stop())); });

interface FixtureTest {
  match: boolean;
  line?: string;
  document?: unknown;
  observation?: { status: number; headers: Record<string, string | string[]>; body?: string };
}
interface FixtureRule { id: string; tests: FixtureTest[] }
function rule(raw: unknown[], id: string): FixtureRule {
  const found = raw.find((item) => typeof item === 'object' && item !== null && (item as { id?: unknown }).id === id);
  if (found === undefined) throw new Error(`Mounted Dataset fixture rule missing: ${id}`);
  return found as FixtureRule;
}
function positive(item: FixtureRule): FixtureTest {
  const found = item.tests.find((entry) => entry.match === true);
  if (found === undefined) throw new Error(`Mounted Dataset positive fixture missing: ${item.id}`);
  return found;
}
function frozenSource(id: string): { path: string; content: string } {
  const item = benchmarkCases.find((entry: { id: string }) => entry.id === id);
  if (item === undefined || !('content' in item) || !('path' in item) ||
      typeof item.content !== 'string' || typeof item.path !== 'string') throw new Error('Frozen source fixture missing');
  return { path: item.path, content: item.content };
}

async function register(server: TestServer, email: string): Promise<string> {
  const response = await fetch(`${server.baseUrl}/api/v1/auth/register`, { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: 'mounted dataset synthetic password', userType: 'SECURITY_PROFESSIONAL' }) }); // synthetic test account
  expect(response.status).toBe(201);
  const session = sessionCookieFrom(response);
  const me = await fetch(`${server.baseUrl}/api/v1/me`, { headers: { cookie: session } });
  const device = me.headers.getSetCookie().find((value) => value.startsWith('drobon_device='));
  if (device === undefined) throw new Error('Synthetic device cookie missing');
  return `${session}; ${device.split(';')[0]}`;
}

async function createProject(server: TestServer, cookie: string): Promise<string> {
  const response = await fetch(`${server.baseUrl}/api/v1/projects`, { method: 'POST', headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify({ name: 'Mounted Dataset synthetic fixture' }) });
  expect(response.status).toBe(201);
  return ((await readJson(response)) as { data: { project: { id: string } } }).data.project.id;
}

async function upload(server: TestServer, cookie: string, projectId: string, files: Array<{ path: string; content: string }>): Promise<void> {
  const response = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/sources`, { method: 'PUT',
    headers: { 'content-type': 'application/json', cookie }, body: JSON.stringify({ files }) });
  expect(response.status).toBe(200);
}

async function strictAssessment(server: TestServer, cookie: string, projectId: string): Promise<string> {
  const headers = { 'content-type': 'application/json', cookie };
  const target = 'https://fixture.example.org/api/start';
  expect((await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/dast-target`, { method: 'PUT', headers, body: JSON.stringify({ targetUrl: target }) })).status).toBe(200);
  const created = await fetch(`${server.baseUrl}/api/v1/projects/${projectId}/assessments`, { method: 'POST', headers,
    body: JSON.stringify({ title: 'Mock target scope', objectives: ['Test synthetic response only'], scope: { inScopeHosts: ['fixture.example.org'], outOfScopeHosts: [] } }) });
  expect(created.status).toBe(201);
  const assessmentId = ((await readJson(created)) as { data: { assessment: { id: string } } }).data.assessment.id;
  const base = `${server.baseUrl}/api/v1/projects/${projectId}/assessments/${assessmentId}`;
  expect((await fetch(`${base}/status`, { method: 'POST', headers, body: JSON.stringify({ status: 'ACTIVE' }) })).status).toBe(200);
  expect((await fetch(`${base}/engagements`, { method: 'POST', headers, body: JSON.stringify({
    clientName: 'Synthetic fixture', targetUrl: target, inScopeHosts: ['fixture.example.org'], scopePaths: ['/api'], allowedScanTypes: ['DAST'],
    validFrom: new Date(Date.now() - 60_000).toISOString(), validUntil: new Date(Date.now() + 86_400_000).toISOString(),
    statement: 'Mocked transport, no external target contacted.', confirm: true,
  }) })).status).toBe(200);
  return assessmentId;
}

async function scanAndExport(server: TestServer, cookie: string, projectId: string, scanType: string, expectedRule: string, secretLine: string,
  assessmentId?: string): Promise<{ findings: number; partial: boolean; partialReason?: string; declarationRulesEvaluated?: number; declarationRulesNotEvaluated?: number; astMode?: string; astAttribution?: string; ruleId: string; evidence: boolean }> {
  const headers = { 'content-type': 'application/json', cookie };
  const root = `${server.baseUrl}/api/v1/projects/${projectId}/scans`;
  const created = await fetch(root, { method: 'POST', headers, body: JSON.stringify({ scanType, ...(assessmentId === undefined ? {} : { assessmentId }) }) });
  expect(created.status).toBe(201);
  const scanId = ((await readJson(created)) as { data: { scan: { id: string } } }).data.scan.id;
  await server.scanProcessor.drain();
  const detailResponse = await fetch(`${root}/${scanId}`, { headers });
  expect(detailResponse.status).toBe(200);
  const scan = ((await readJson(detailResponse)) as { data: { scan: ScanDetail } }).data.scan;
  expect(scan.status).toBe('COMPLETED');
  const finding = scan.findings.find((item: Finding) => item.ruleId === expectedRule);
  expect(finding).toBeDefined();
  if (finding === undefined) throw new Error(`Expected mounted Dataset finding missing for ${scanType}`);
  expect(finding.evidence.length).toBeGreaterThan(0);
  const detail = await fetch(`${root}/${scanId}/findings/${finding.id}`, { headers });
  expect(detail.status).toBe(200);
  const findingDetail = (await readJson(detail)) as { data: { finding: Finding } };
  expect(findingDetail.data.finding.ruleId).toBe(expectedRule);
  expect(findingDetail.data.finding.evidence.length).toBeGreaterThan(0);
  expect(JSON.stringify(findingDetail).includes(secretLine)).toBe(false);
  const reportResponse = await fetch(`${root}/${scanId}/report`, { method: 'POST', headers, body: '{}' });
  expect(reportResponse.status).toBe(201);
  const report = ((await readJson(reportResponse)) as { data: { report: SecurityReport } }).data.report;
  expect(isSecurityReport(report)).toBe(true);
  expect(report.findings.some((item) => item.ruleId === expectedRule)).toBe(true);
  expect(JSON.stringify(report).includes(secretLine)).toBe(false);
  const download = await fetch(`${root}/${scanId}/report/download?format=json`, { headers });
  expect(download.status).toBe(200);
  const exported = (await download.json()) as SecurityReport;
  expect(isSecurityReport(exported)).toBe(true);
  expect(exported.contentDigest).toBe(report.contentDigest);
  expect(exported.integrityDigest).toBe(report.integrityDigest);
  expect(exported.findings.some((item) => item.ruleId === expectedRule && item.evidence.length > 0)).toBe(true);
  expect(JSON.stringify(exported).includes(secretLine)).toBe(false);
  return { findings: scan.findings.length, partial: scan.resultSummary?.partial === true,
    ...(scan.resultSummary?.partialReason === undefined ? {} : { partialReason: scan.resultSummary.partialReason }),
    ...(scan.resultSummary?.declarationRulesEvaluated === undefined ? {} : { declarationRulesEvaluated: scan.resultSummary.declarationRulesEvaluated }),
    ...(scan.resultSummary?.declarationRulesNotEvaluated === undefined ? {} : { declarationRulesNotEvaluated: scan.resultSummary.declarationRulesNotEvaluated }),
    ...(finding.astFlow?.mode === undefined ? {} : { astMode: finding.astFlow.mode }),
    ...(finding.astFlow?.attribution === undefined ? {} : { astAttribution: finding.astFlow.attribution }),
    ruleId: expectedRule, evidence: true };
}

async function scanEmptySastAndExport(server: TestServer, cookie: string, projectId: string, secretLine: string): Promise<number> {
  const headers = { 'content-type': 'application/json', cookie };
  const root = `${server.baseUrl}/api/v1/projects/${projectId}/scans`;
  const created = await fetch(root, { method: 'POST', headers, body: JSON.stringify({ scanType: 'SAST' }) });
  expect(created.status).toBe(201);
  const scanId = ((await readJson(created)) as { data: { scan: { id: string } } }).data.scan.id;
  await server.scanProcessor.drain();
  const detail = await fetch(`${root}/${scanId}`, { headers });
  expect(detail.status).toBe(200);
  const scan = ((await readJson(detail)) as { data: { scan: ScanDetail } }).data.scan;
  expect(scan.status).toBe('COMPLETED');
  expect(scan.findings).toHaveLength(0);
  const reportResponse = await fetch(`${root}/${scanId}/report`, { method: 'POST', headers, body: '{}' });
  expect(reportResponse.status).toBe(201);
  const download = await fetch(`${root}/${scanId}/report/download?format=json`, { headers });
  expect(download.status).toBe(200);
  const exported = (await download.json()) as SecurityReport;
  expect(isSecurityReport(exported)).toBe(true);
  expect(exported.findings).toHaveLength(0);
  expect(JSON.stringify(exported).includes(secretLine)).toBe(false);
  return scan.findings.length;
}

describe.skipIf(datasetPath === undefined)('real read-only mounted Dataset through the Main App', () => {
  test('discovers, validates, registers and runs all four scanners through finding/evidence/report export', async () => {
    if (datasetPath === undefined) throw new Error('Mounted path required');
    const dataset = createDatasetService({ providerId: 'filesystem', datasetPath });
    const status = await dataset.status();
    const counts = { SAST: status.sastPacks.count, SECRETS: status.secretsPacks.count, SCA: status.scaPacks.count, DAST: status.dastPacks.count };
    expect(counts).toEqual({ SAST: 1000, SECRETS: 1000, SCA: 1000, DAST: 1007 });
    for (const family of ['sast', 'secrets', 'sca', 'dast'] as const) {
      const report = status.conformance[family];
      expect(report.accepted).toBe(report.filesSeen);
      expect(report.failedTests).toBe(0);
      expect(report.skippedTests).toBe(0);
      expect(report.enumerationFailures).toBe(0);
      expect(report.manifestIssue).toBeUndefined();
    }
    const [sast, secrets, sca, dast] = await Promise.all([dataset.sastPacks(), dataset.secretsPacks(), dataset.scaPacks(), dataset.dastPacks()]);
    expect((await getMergedSastRules(dataset)).length).toBe(1000);
    expect((await getMergedSecretsRules(dataset)).length).toBe(1000);
    expect((await getMergedDastRules(dataset)).length).toBe(1007);
    expect(sca.filter((entry) => compileScaDeclarationRule(entry) !== undefined)).toHaveLength(1000);
    const sastLine = positive(rule(sast, 'DPK-SAST-001')).line;
    const secretLine = positive(rule(secrets, 'DPK-SEC-001')).line;
    const scaDocument = positive(rule(sca, 'DPK-SCA-0001')).document;
    const observation = positive(rule(dast, 'DPK-DAST-002')).observation;
    if (sastLine === undefined || secretLine === undefined || scaDocument === undefined || observation === undefined) throw new Error('Incomplete mounted fixture');
    let requests = 0;
    let currentObservation = { status: observation.status, headers: observation.headers, body: observation.body ?? '' };
    const transport: DastTransport = { probe: async () => { requests += 1; return {
      ...currentObservation, bodyTruncated: false, elapsedMs: 1,
    }; } };
    const server = await startTestServer({ datasetPath, vulnIntelProvider: 'filesystem', datasetService: dataset, dastRequireEngagement: true,
      dastTargetPolicy: createDastTargetPolicy({ resolve: async () => ['93.184.216.34'] }), dastTransport: transport });
    servers.push(server);
    // Independent free accounts stay within the existing quota; no invented payment or paid subscription.
    const sourceCookie = await register(server, 'mounted-source@example.test');
    const targetCookie = await register(server, 'mounted-target@example.test');
    const diagnosticCookie = await register(server, 'mounted-diagnostic@example.test');
    const sourceProject = await createProject(server, sourceCookie);
    const targetProject = await createProject(server, targetCookie);
    const diagnosticProject = await createProject(server, diagnosticCookie);
    await upload(server, sourceCookie, sourceProject, [{ path: 'src/fixture.js', content: `${sastLine}\n${secretLine}\n` }]);
    await upload(server, targetCookie, targetProject, [{ path: 'package.json', content: JSON.stringify(scaDocument) }]);
    const assessmentId = await strictAssessment(server, targetCookie, targetProject);
    const outcomes = {
      SAST: await scanAndExport(server, sourceCookie, sourceProject, 'SAST', 'DPK-SAST-001', secretLine),
      SECRETS: await scanAndExport(server, sourceCookie, sourceProject, 'SECRETS', 'DPK-SEC-001', secretLine),
      SCA: await scanAndExport(server, targetCookie, targetProject, 'SCA', 'DPK-SCA-0001', secretLine),
      DAST: await scanAndExport(server, targetCookie, targetProject, 'DAST', 'DPK-DAST-002', secretLine, assessmentId),
    };
    expect(requests).toBe(1);
    // Revisit the existing frozen SAST-04 exception through the mounted
    // Dataset and HTTP/report pipeline, without changing its label or rules.
    expect(manifestDigest()).toBe('8ae13962b8889b7f92018216868c2b1483556ae08c1dfc12d5e730890d6911e6');
    await upload(server, sourceCookie, sourceProject, [frozenSource('SAST-04')]);
    const sast04 = await scanAndExport(server, sourceCookie, sourceProject, 'SAST', 'DPK-SAST-044', secretLine);
    expect(sast04.astMode).toBe('PROJECT');
    expect(sast04.astAttribution).toBe('CATEGORY_REPORTER');
    // Compare the other frozen exceptions with the real mounted pack, not the
    // test-only rule; each result remains a synthetic, narrowly scoped probe.
    await upload(server, diagnosticCookie, diagnosticProject, [frozenSource('SAST-02')]);
    const sast02Findings = await scanEmptySastAndExport(server, diagnosticCookie, diagnosticProject, secretLine);
    await upload(server, targetCookie, targetProject, [frozenSource('SCA-03')]);
    const sca03 = await scanAndExport(server, targetCookie, targetProject, 'SCA', 'DPK-SCA-0718', secretLine);
    const invalidHeader = labResponse('/lab/header-invalid');
    currentObservation = { status: invalidHeader.status,
      headers: Object.fromEntries(Object.entries(invalidHeader.headers).filter(([, value]) => typeof value === 'string')),
      body: invalidHeader.body };
    const diagnosticAssessment = await strictAssessment(server, diagnosticCookie, diagnosticProject);
    const dast02 = await scanAndExport(server, diagnosticCookie, diagnosticProject, 'DAST', 'DPK-DAST-073', secretLine, diagnosticAssessment);
    expect(requests).toBe(2);
    // eslint-disable-next-line no-console -- sanitized counts and rule IDs only; no fixture values.
    console.log('MOUNTED_DATASET_E2E_COUNTS', JSON.stringify({ loaded: counts, outcomes, sast04, sast02Findings, sca03, dast02, mockDastRequests: requests, externalTargetRequests: 0 }));
  }, 90_000);
});
