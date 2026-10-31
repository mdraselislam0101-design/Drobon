import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, test } from 'vitest';
import { createLogger } from '../src/logger.js';
import { createDatasetService } from '../src/external/service.js';
import { validatePackRules } from '../src/external/conformance.js';
import { ADVISORY_SCHEMA_VERSION, createAdvisoryService } from '../src/external/advisory.js';
import { createFilesystemIntelligenceProvider } from '../src/scans/sca/filesystemProvider.js';
import { sessionCookieFrom, startTestServer, type TestServer } from './helpers.js';

// Unlabeled short synthetic markers exercise values a pattern scrubber cannot recognize.
const MARKER = 'q7z-fixture-loader'; // test-only synthetic fixture
const LOGIN_PHRASE = 'loader privacy fixture login phrase';
const dirs: string[] = [];
const servers: TestServer[] = [];

function temporaryRoot(): string {
  const dir = mkdtempSync(join(tmpdir(), `${MARKER}-`));
  dirs.push(dir);
  return dir;
}
function logCollector() {
  const lines: string[] = [];
  return { lines, logger: createLogger({ level: 'debug', out: (line) => lines.push(line) }) };
}
async function loggedInCookie(server: TestServer): Promise<string> {
  const body = { email: 'privacy-loader@example.test', password: LOGIN_PHRASE };
  const registration = await fetch(`${server.baseUrl}/api/v1/auth/register`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ...body, userType: 'DEVELOPER' }),
  });
  expect(registration.status).toBe(201);
  const login = await fetch(`${server.baseUrl}/api/v1/auth/login`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
  });
  expect(login.status).toBe(200);
  return sessionCookieFrom(login);
}

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.stop()));
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe('configured loader privacy', () => {
  test('Dataset loading logs counts without exposing the configured path', async () => {
    const root = temporaryRoot();
    const { lines, logger } = logCollector();
    const service = createDatasetService({ datasetPath: root, providerId: 'filesystem', logger });
    const status = await service.status();
    expect(status.configured).toBe(true);
    expect(status.datasetPath).toBe(root); // Existing internal operator integration remains available.
    expect(lines.join('\n')).toContain('[dataset] Loaded');
    expect(lines.join('\n')).not.toContain(MARKER);
  });

  test('SCA intelligence logs withhold paths, file names, and JSON parse messages', async () => {
    const root = temporaryRoot();
    const npm = join(root, 'vuln-intel', 'npm');
    mkdirSync(npm, { recursive: true });
    writeFileSync(join(npm, 'valid.json'), JSON.stringify({
      fixture: false, id: 'GHSA-aaaa-bbbb-cccc', ecosystem: 'npm', package: 'fixture-pkg',
      summary: 'Synthetic advisory.', severity: 'HIGH', affected: [{ range: '<2.0.0' }],
    }));
    writeFileSync(join(npm, `${MARKER}-shape.json`), JSON.stringify({ unrelated: true }));
    writeFileSync(join(npm, `${MARKER}-broken.json`), `{"fixture":"${MARKER}", broken}`);
    const { lines, logger } = logCollector();
    const provider = createFilesystemIntelligenceProvider({ datasetPath: root, logger });
    const result = await provider.assess([{ dependencyId: 'dep_fixture', ecosystem: 'npm', name: 'fixture-pkg', version: '1.0.0' }]);
    expect(result.datasetStatus).toBe('DATASET_AVAILABLE');
    expect(result.incomplete).toBe(true);
    expect(result.advisories).toHaveLength(1);
    const joined = lines.join('\n');
    expect(joined).toContain('Skipping invalid record shape');
    expect(joined).toContain('Failed to load');
    expect(joined).toContain('Loaded 1 advisory records');
    expect(joined).not.toContain(MARKER);
  });

  test('advisory success, missing-file and malformed-JSON messages withhold arbitrary values', async () => {
    const root = temporaryRoot();
    const { lines, logger } = logCollector();
    const validPath = join(root, 'valid.json');
    writeFileSync(validPath, JSON.stringify({ schemaVersion: ADVISORY_SCHEMA_VERSION, packId: 'fixture-pack', version: '1.0.0', generatedAt: '2026-10-26T00:00:00.000Z', advisories: [{ [MARKER]: true }] }));
    const valid = createAdvisoryService({ path: validPath, logger });
    const validStatus = await valid.status();
    expect(validStatus.loaded).toBe(true);
    expect(validStatus.refused).toHaveLength(1);
    expect(validStatus.refused[0]).toContain('unknown field');
    expect(JSON.stringify(validStatus)).not.toContain(MARKER);
    const badPath = join(root, 'malformed.json');
    writeFileSync(badPath, `{"fixture":"${MARKER}", broken}`);
    const broken = createAdvisoryService({ path: badPath, logger });
    const missing = createAdvisoryService({ path: join(root, `${MARKER}-missing.json`), logger });
    for (const service of [broken, missing]) {
      const status = await service.status();
      const evaluation = await service.evaluate({});
      expect(status.loaded).toBe(false);
      expect(evaluation.unavailableReason).toContain('could not be read');
      expect(JSON.stringify({ status, evaluation })).not.toContain(MARKER);
    }
    expect(lines.join('\n')).toContain('[advisory] loaded');
    expect(lines.join('\n')).not.toContain(MARKER);
  });

  test('rejected rule diagnostics retain counts and valid IDs without echoing untrusted text', () => {
    const base = {
      schemaVersion: 'drobon.pack.sast/v1', id: 'DPK-SAST-900', title: 'Fixture', description: 'Fixture',
      severity: 'MEDIUM', category: 'fixture', remediation: 'Review', limitation: 'Fixture',
      patternRefs: ['DPK-PAT-9001'], languages: ['javascript'], patterns: [{ source: 'eval' }],
      tests: [{ line: 'eval(x)', match: true }, { line: 'const x = 1', match: false }],
    };
    const sast = validatePackRules([
      { ...base, [MARKER]: true },
      { ...base, id: MARKER },
      { ...base, id: 'DPK-SAST-901', languages: [MARKER] },
    ], 'sast');
    const dastRule: Record<string, unknown> = {
      ...base, schemaVersion: 'drobon.pack.dast/v1', id: 'DPK-DAST-900', check: { type: MARKER },
    };
    delete dastRule['languages'];
    delete dastRule['patterns'];
    const dast = validatePackRules([dastRule], 'dast');
    expect(sast.report).toMatchObject({ filesSeen: 3, accepted: 0 });
    expect(sast.report.rejected).toHaveLength(3);
    expect(sast.report.rejected.map((issue) => issue.id)).toContain('DPK-SAST-900');
    expect(dast.report).toMatchObject({ filesSeen: 1, accepted: 0 });
    expect(dast.report.rejected[0]?.reason).toContain('unknown DAST check type');
    expect(JSON.stringify({ sast: sast.report, dast: dast.report })).not.toContain(MARKER);
  });

  test('authenticated Dataset/advisory status responses omit paths and unsafe diagnostics', async () => {
    const root = temporaryRoot();
    const rules = join(root, 'packs', 'sast', 'v1', 'rules');
    mkdirSync(rules, { recursive: true });
    writeFileSync(join(rules, `${MARKER}.json`), '{broken json');
    const dataset = createDatasetService({ datasetPath: root, providerId: 'filesystem' });
    const advisory = createAdvisoryService({ path: join(root, `${MARKER}-missing.json`) });
    const server = await startTestServer({ datasetService: dataset, advisory, logLevel: 'info' });
    servers.push(server);
    expect((await fetch(`${server.baseUrl}/api/v1/dataset/status`)).status).toBe(401);
    const cookie = await loggedInCookie(server);
    const datasetResponse = await fetch(`${server.baseUrl}/api/v1/dataset/status`, { headers: { cookie } });
    const advisoryResponse = await fetch(`${server.baseUrl}/api/v1/advisory/status`, { headers: { cookie } });
    const analyzeResponse = await fetch(`${server.baseUrl}/api/v1/advisory/analyze`, {
      method: 'POST', headers: { cookie, 'content-type': 'application/json' }, body: '{}',
    });
    expect(datasetResponse.status).toBe(200);
    expect(advisoryResponse.status).toBe(200);
    expect(analyzeResponse.status).toBe(200);
    const datasetBody = await datasetResponse.text();
    const advisoryBody = await advisoryResponse.text();
    const analyzeBody = await analyzeResponse.text();
    const parsed = JSON.parse(datasetBody) as { data: { dataset: { configured: boolean; datasetPath?: string; conformance: { sast: { filesSeen: number; accepted: number } } } } };
    expect(parsed.data.dataset.configured).toBe(true);
    expect(parsed.data.dataset.datasetPath).toBeUndefined();
    expect(parsed.data.dataset.conformance.sast).toMatchObject({ filesSeen: 1, accepted: 0 });
    expect([datasetBody, advisoryBody, analyzeBody, ...server.logs].join('\n')).not.toContain(MARKER);
  });
});
