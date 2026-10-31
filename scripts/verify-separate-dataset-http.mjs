/** Audit harness: uses the real application service, production registry/engines,
 * read-only mounted external Dataset, synthetic source/response fixtures,
 * in-memory stores and a loopback-only DAST transport. Never writes Dataset files.
 * Run: node --import tsx scripts/verify-separate-dataset-http.mjs --path /path/to/read-only/Drobon-Dataset
 * This tests the pinned 4,007-rule catalog; it is not a deployment rehearsal. */
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { createServer } from 'node:http';
import { createNodeDastTransport } from '../apps/api/src/scans/dast/http.ts';
import { createDatasetService } from '../apps/api/src/external/service.ts';
import { startTestServer, sessionCookieFrom } from '../apps/api/test/helpers.ts';
import { pdfText } from '../apps/api/test/pdfTextFixture.ts';
import { createDastTargetPolicy } from '../apps/api/src/scans/dast/target.ts';
import { startServer } from '../apps/api/src/server.ts';
import { createLogger } from '../apps/api/src/logger.ts';
import { WITHHELD_SOURCE_EVIDENCE } from '../apps/api/src/scans/findingIdentity.ts';
const pathArg = process.argv.indexOf('--path');
const inputPath = pathArg >= 0 ? process.argv[pathArg + 1] : process.env['DROBON_MOUNTED_DATASET_TEST_PATH'];
assert.ok(
  inputPath && !inputPath.startsWith('--'),
  'Provide the external read-only Dataset path via --path or DROBON_MOUNTED_DATASET_TEST_PATH',
);
const path = resolve(inputPath);
const missingPath = join(tmpdir(), `drobon-audit-missing-${randomUUID()}`);
assert.equal(existsSync(missingPath), false);
const oracle = createDatasetService({
  providerId: 'filesystem',
  datasetPath: path,
});
const raw = {
  SAST: await oracle.sastPacks(),
  SECRETS: await oracle.secretsPacks(),
  DAST: await oracle.dastPacks(),
  SCA: await oracle.scaPacks(),
};
const select = (kind, id) => {
  const rule = raw[kind].find((r) => r.id === id);
  assert.ok(rule, 'Mounted rule missing');
  return rule;
};
const sourceRule = select('SAST', 'DPK-SAST-001');
const secretRule = select('SECRETS', 'DPK-SEC-001');
const scaRule = select('SCA', 'DPK-SCA-0001');
const lockRule = select('SCA', 'DPK-SCA-0043');
const dastRule = select('DAST', 'DPK-DAST-002');
const fixture = (rule, match) => {
  const result = rule.tests.find((x) => x.match === match);
  assert.ok(result, 'Expected test missing');
  return result;
};
const sastYes = fixture(sourceRule, true).line,
  sastNo = fixture(sourceRule, false).line;
const secretYes = fixture(secretRule, true).line,
  secretNo = fixture(secretRule, false).line;
const syntheticToken = secretYes.match(/AKIA[A-Z0-9]{16}/)?.[0];
assert.ok(syntheticToken, 'Synthetic test token shape unavailable');
const withMarker = (entry) => ({
  ...entry.document,
  __audit_only_value: syntheticToken,
});
const scaYes = JSON.stringify(withMarker(fixture(scaRule, true))),
  scaNo = JSON.stringify(withMarker(fixture(scaRule, false)));
const lockYes = JSON.stringify(withMarker(fixture(lockRule, true))),
  lockNo = JSON.stringify(withMarker(fixture(lockRule, false)));
let observation = fixture(dastRule, true).observation;
let requestCount = 0;
const policy = createDastTargetPolicy({
  resolve: async () => ['93.184.216.34'],
});
let localRequests = 0;
const mock = createServer((req, res) => {
  localRequests++;
  if (req.method !== 'GET' || req.url !== '/api/start') {
    res.writeHead(400);
    res.end();
    return;
  }
  res.writeHead(observation.status, {
    ...observation.headers,
    'set-cookie': [`audit=${syntheticToken}; Secure; HttpOnly; SameSite=Strict`],
  });
  res.end(`Audit body marker ${syntheticToken}`);
});
await new Promise((resolve, reject) => {
  mock.once('error', reject);
  mock.listen(0, '127.0.0.1', resolve);
});
const mockPort = mock.address().port,
  nodeTransport = createNodeDastTransport();
// The authorized synthetic hostname is used by the engine; this test-only transport
// routes all probes to the loopback HTTP fixture, never to that hostname/address.
const transport = {
  probe: async (target, options) => {
    assert.equal(target.url, 'https://fixture.example.org/api/start');
    requestCount++;
    return nodeTransport.probe(
      {
        url: `http://127.0.0.1:${mockPort}/api/start`,
        hostname: '127.0.0.1',
        addresses: ['127.0.0.1'],
      },
      options,
    );
  },
};
const servers = [];
const outputs = [];
const noLeak = (value, label) => assert.ok(!value.includes(syntheticToken), `${label}: synthetic marker disclosed`);
// Markdown escapes the stored evidence; compare the escaped value, not raw HTML.
function markdownText(value) {
  const special = new Set(['\\', '`', '*', '_', '{', '}', '[', ']', '(', ')', '#', '+', '-', '.', '!', '|']);
  let result = '';
  for (const character of value) result += special.has(character) ? `\\${character}` : character;
  return result.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
}
async function response(server, url, options = {}, expected = 200) {
  const r = await fetch(server.baseUrl + url, options);
  assert.equal(r.status, expected, `${options.method ?? 'GET'} ${url.split('?')[0]} unexpected status`);
  return r;
}
async function register(server, index) {
  const r = await response(
    server,
    '/api/v1/auth/register',
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        email: `separate-audit-${index}@example.test`,
        password: 'synthetic test audit password', // Local in-memory account only.
        userType: 'SECURITY_PROFESSIONAL',
      }),
    },
    201,
  );
  const session = sessionCookieFrom(r);
  const me = await response(server, '/api/v1/me', {
    headers: { cookie: session },
  });
  const device = me.headers.getSetCookie().find((v) => v.startsWith('drobon_device='));
  assert.ok(device, 'Device cookie missing');
  return `${session}; ${device.split(';')[0]}`;
}
const headers = (cookie) => ({ 'content-type': 'application/json', cookie });
async function project(server, cookie) {
  const r = await response(
    server,
    '/api/v1/projects',
    {
      method: 'POST',
      headers: headers(cookie),
      body: JSON.stringify({ name: 'Separate dataset audit fixture' }),
    },
    201,
  );
  return (await r.json()).data.project.id;
}
async function upload(server, cookie, projectId, path, content) {
  await response(server, `/api/v1/projects/${projectId}/sources`, {
    method: 'PUT',
    headers: headers(cookie),
    body: JSON.stringify({ files: [{ path, content }] }),
  });
}
async function strictAssessment(server, cookie, projectId) {
  const h = headers(cookie),
    target = 'https://fixture.example.org/api/start';
  await response(server, `/api/v1/projects/${projectId}/dast-target`, {
    method: 'PUT',
    headers: h,
    body: JSON.stringify({ targetUrl: target }),
  });
  const created = await response(
    server,
    `/api/v1/projects/${projectId}/assessments`,
    {
      method: 'POST',
      headers: h,
      body: JSON.stringify({
        title: 'Mock-only audit scope',
        objectives: ['Verify local mocked response only'],
        scope: { inScopeHosts: ['fixture.example.org'], outOfScopeHosts: [] },
      }),
    },
    201,
  );
  const assessmentId = (await created.json()).data.assessment.id,
    base = `/api/v1/projects/${projectId}/assessments/${assessmentId}`;
  await response(server, `${base}/status`, {
    method: 'POST',
    headers: h,
    body: JSON.stringify({ status: 'ACTIVE' }),
  });
  await response(server, `${base}/engagements`, {
    method: 'POST',
    headers: h,
    body: JSON.stringify({
      clientName: 'Local synthetic fixture',
      targetUrl: target,
      inScopeHosts: ['fixture.example.org'],
      scopePaths: ['/api'],
      allowedScanTypes: ['DAST'],
      validFrom: new Date(Date.now() - 60_000).toISOString(),
      validUntil: new Date(Date.now() + 86_400_000).toISOString(),
      statement: 'Local mock transport only; no external target contacted.',
      confirm: true,
    }),
  });
  return assessmentId;
}
async function status(server, cookie) {
  const r = await response(server, '/api/v1/dataset/status', {
    headers: headers(cookie),
  });
  const d = (await r.json()).data.dataset;
  assert.equal('datasetPath' in d, false);
  return d;
}
async function scan(server, cookie, projectId, kind, rule, match, options = {}) {
  const root = `/api/v1/projects/${projectId}/scans`,
    h = headers(cookie);
  const created = await response(
    server,
    root,
    {
      method: 'POST',
      headers: h,
      body: JSON.stringify({
        scanType: kind,
        ...(options.assessmentId ? { assessmentId: options.assessmentId } : {}),
      }),
    },
    201,
  );
  const id = (await created.json()).data.scan.id;
  await server.scanProcessor.drain();
  const sr = await response(server, `${root}/${id}`, { headers: h });
  const data = await sr.json();
  noLeak(JSON.stringify(data), `${kind} scan`);
  const result = data.data.scan;
  assert.equal(result.status, 'COMPLETED', `${kind}: scan did not complete`);
  if (options.requirePartial) assert.equal(result.resultSummary?.partial, true, `${kind}: unavailable rules not marked partial`);
  const f = result.findings.find((x) => x.ruleId === rule.id);
  assert.equal(Boolean(f), match, `${kind}/${rule.id} unexpected hit/no-hit`);
  if (f) {
    assert.equal(f.scanner, kind);
    assert.equal(f.severity, rule.severity);
    assert.equal(f.title, rule.title);
    assert.equal(f.cwe, rule.cwe);
    assert.ok(f.evidence.length > 0);
    if (kind === 'SAST' || kind === 'SECRETS') {
      assert.equal(f.evidence, WITHHELD_SOURCE_EVIDENCE);
      assert.equal(f.file, 'src/audit.js');
      assert.equal(f.line, 1);
      if (kind === 'SECRETS') assert.equal(f.confidence, rule.confidence);
    }
    if (kind === 'SCA') {
      assert.equal(f.evidence, `${rule.id}: declaration matched (values withheld)`);
      assert.equal(f.file, rule.artifact);
    }
    if (kind === 'DAST') {
      assert.equal(f.method, 'GET');
      assert.equal(f.endpoint, 'https://fixture.example.org/api/start');
      assert.equal(f.responseStatus, observation.status);
      assert.ok(f.evidence.includes(`pack check ${rule.check.type} matched.`));
    }
    const fd = await response(server, `${root}/${id}/findings/${f.id}`, {
      headers: h,
    });
    const item = (await fd.json()).data.finding;
    assert.equal(item.ruleId, rule.id);
    assert.equal(item.severity, rule.severity);
    noLeak(JSON.stringify(item), `${kind} finding detail`);
  }
  const rr = await response(server, `${root}/${id}/report`, { method: 'POST', headers: h, body: '{}' }, 201);
  const report = (await rr.json()).data.report;
  noLeak(JSON.stringify(report), `${kind} report`);
  if (options.requireUnassessed) assert.equal(report.dependencyIntelligence.status, 'NOT_ASSESSED');
  const reportFinding = report.findings.find((x) => x.ruleId === rule.id);
  assert.equal(Boolean(reportFinding), match, `${kind}: report does not match scan`);
  if (f) {
    assert.equal(reportFinding.evidence, f.evidence);
    assert.equal(reportFinding.severity, f.severity);
  }
  const textFormats = options.allExports ? ['json', 'markdown', 'sarif'] : ['json'];
  for (const fmt of textFormats) {
    const res = await response(server, `${root}/${id}/report/download?format=${fmt}`, { headers: h });
    const body = await res.text();
    noLeak(body, `${kind} ${fmt}`);
    if (fmt === 'json') {
      const json = JSON.parse(body);
      assert.equal(json.contentDigest, report.contentDigest);
      const exportedFinding = json.findings.find((x) => x.ruleId === rule.id);
      assert.equal(Boolean(exportedFinding), match);
      if (f) {
        assert.equal(exportedFinding.evidence, f.evidence);
        assert.equal(exportedFinding.severity, f.severity);
      }
    }
    if (fmt === 'markdown') {
      assert.ok(f && body.includes(rule.id), `${kind}: markdown lacks rule`);
      assert.ok(body.includes(markdownText(f.evidence)), `${kind}: markdown lacks escaped evidence`);
    }
    if (fmt === 'sarif') {
      const sarif = JSON.parse(body);
      const item = sarif.runs[0].results.find((x) => x.ruleId === rule.id);
      assert.ok(item, `${kind}: SARIF lacks rule`);
      const level = rule.severity === 'CRITICAL' || rule.severity === 'HIGH' ? 'error' : rule.severity === 'MEDIUM' ? 'warning' : 'note';
      assert.equal(item.level, level);
      assert.equal(sarif.runs[0].tool.driver.rules[item.ruleIndex].shortDescription.text, f.title);
      // This SARIF exporter deliberately omits the finding's evidence field.
    }
  }
  if (options.allExports) {
    const pr = await response(server, `${root}/${id}/report/download?format=pdf`, { headers: h });
    assert.equal(pr.headers.get('content-type'), 'application/pdf');
    const pdf = Buffer.from(await pr.arrayBuffer());
    assert.equal(pdf.subarray(0, 5).toString(), '%PDF-');
    const text = pdfText(pdf);
    noLeak(text, `${kind} pdf`);
    assert.ok(text.includes(rule.id), `${kind}: PDF lacks rule`);
    assert.ok(text.includes(`[${rule.severity}]`), `${kind}: PDF lacks severity`);
    assert.ok(f, `${kind}: PDF finding missing`);
    const evidenceText = kind === 'DAST' ? `pack check ${rule.check.type} matched.` : f.evidence;
    assert.ok(text.includes(evidenceText), `${kind}: PDF lacks evidence`);
  }
  const s = result.resultSummary ?? {};
  const entry = {
    case: options.label ?? kind,
    ruleId: rule.id,
    expectedMatch: match,
    matched: Boolean(f),
    totalFindings: result.findings.length,
    partial: s.partial ?? false,
    ...(s.partialReason ? { partialReason: s.partialReason } : {}),
    ...(s.astCoverage?.rules
      ? {
          sastRules: {
            count: s.astCoverage.rules.count,
            source: s.astCoverage.rules.source,
          },
        }
      : {}),
    ...(s.declarationRulesEvaluated !== undefined
      ? {
          declarationRulesEvaluated: s.declarationRulesEvaluated,
          declarationRulesNotEvaluated: s.declarationRulesNotEvaluated,
        }
      : {}),
    exports: options.allExports ? ['json', 'markdown', 'sarif', 'pdf'] : ['json'],
  };
  outputs.push(entry);
  return entry;
}
async function wrapper(config, transport, logLines) {
  const logger = createLogger({
    level: 'info',
    service: 'audit',
    env: 'test',
    out: (l) => logLines.push(l),
  });
  const started = await startServer({
    config,
    logger,
    scanProcessorAutoStart: false,
    dastTargetPolicy: policy,
    dastTransport: transport,
  });
  const server = {
    baseUrl: started.url,
    config,
    scanProcessor: started.app.scanProcessor,
    stop: started.stop,
  };
  servers.push(server);
  return server;
}
try {
  // No datasetService/scanEngines are injected: createApp constructs both production services and the real scanner registry.
  const real = await startTestServer({
    datasetPath: path,
    vulnIntelProvider: 'filesystem',
    dastRequireEngagement: true,
    dastTargetPolicy: policy,
    dastTransport: transport,
    logLevel: 'info',
  });
  servers.push(real);
  const cookies = await Promise.all([1, 2, 3, 4].map((i) => register(real, i))),
    projects = [];
  for (const c of cookies) projects.push(await project(real, c));
  const ds = await status(real, cookies[0]);
  assert.equal(ds.configured, true);
  for (const [k, n] of Object.entries({
    sast: 1000,
    secrets: 1000,
    dast: 1007,
    sca: 1000,
  })) {
    assert.equal(ds[k + 'Packs'].count, n);
    assert.equal(ds.conformance[k].accepted, n);
  }
  await upload(real, cookies[0], projects[0], 'src/audit.js', sastYes + '\n' + secretYes + '\n');
  await scan(real, cookies[0], projects[0], 'SAST', sourceRule, true, {
    label: 'SAST positive',
    allExports: true,
  });
  await upload(real, cookies[0], projects[0], 'src/audit.js', sastNo + '\n' + secretYes + '\n');
  await scan(real, cookies[0], projects[0], 'SAST', sourceRule, false, {
    label: 'SAST negative',
  });
  await upload(real, cookies[0], projects[0], 'src/audit.js', secretYes + '\n');
  await scan(real, cookies[0], projects[0], 'SECRETS', secretRule, true, {
    label: 'Secrets positive',
    allExports: true,
  });
  await upload(real, cookies[1], projects[1], 'src/audit.js', secretNo + '\n');
  await scan(real, cookies[1], projects[1], 'SECRETS', secretRule, false, {
    label: 'Secrets negative',
  });
  await upload(real, cookies[1], projects[1], 'package.json', scaYes);
  await scan(real, cookies[1], projects[1], 'SCA', scaRule, true, {
    label: 'SCA manifest positive',
    allExports: true,
  });
  await upload(real, cookies[1], projects[1], 'package.json', scaNo);
  await scan(real, cookies[1], projects[1], 'SCA', scaRule, false, {
    label: 'SCA manifest negative',
  });
  await upload(real, cookies[2], projects[2], 'package-lock.json', lockYes);
  await scan(real, cookies[2], projects[2], 'SCA', lockRule, true, {
    label: 'SCA lockfile positive',
    allExports: true,
  });
  await upload(real, cookies[2], projects[2], 'package-lock.json', lockNo);
  await scan(real, cookies[2], projects[2], 'SCA', lockRule, false, {
    label: 'SCA lockfile negative',
  });
  const a = await strictAssessment(real, cookies[2], projects[2]);
  observation = fixture(dastRule, true).observation;
  await scan(real, cookies[2], projects[2], 'DAST', dastRule, true, {
    label: 'DAST positive',
    assessmentId: a,
    allExports: true,
  });
  const b = await strictAssessment(real, cookies[3], projects[3]);
  observation = fixture(dastRule, false).observation;
  await scan(real, cookies[3], projects[3], 'DAST', dastRule, false, {
    label: 'DAST negative',
    assessmentId: b,
  });
  assert.equal(requestCount, 2);
  noLeak(real.logs.join('\n'), 'real logs');
  const noLogs = [],
    disabled = await wrapper({ ...real.config, vulnIntelProvider: 'none', datasetPath: undefined }, transport, noLogs);
  const c1 = await register(disabled, 'disabled-a'),
    c2 = await register(disabled, 'disabled-b'),
    p1 = await project(disabled, c1),
    p2 = await project(disabled, c2);
  const off = await status(disabled, c1);
  assert.equal(off.configured, false);
  for (const f of ['sast', 'secrets', 'sca', 'dast']) assert.equal(off[f + 'Packs'].status, 'NOT_CONFIGURED');
  await upload(disabled, c1, p1, 'src/audit.js', sastYes + '\n');
  await scan(disabled, c1, p1, 'SAST', sourceRule, false, {
    label: 'SAST dataset disabled', requirePartial: true,
  });
  await upload(disabled, c1, p1, 'src/audit.js', secretYes + '\n');
  await scan(disabled, c1, p1, 'SECRETS', secretRule, false, {
    label: 'Secrets dataset disabled', requirePartial: true,
  });
  await upload(disabled, c1, p1, 'package.json', scaYes);
  await scan(disabled, c1, p1, 'SCA', scaRule, false, {
    label: 'SCA dataset disabled', requirePartial: true, requireUnassessed: true,
  });
  const ca = await strictAssessment(disabled, c2, p2);
  observation = fixture(dastRule, true).observation;
  await scan(disabled, c2, p2, 'DAST', dastRule, false, {
    label: 'DAST dataset disabled',
    requirePartial: true,
    assessmentId: ca,
  });
  assert.equal(requestCount, 3);
  assert.equal(localRequests, 3);
  assert.ok(noLogs.some((x) => x.includes('STARTUP') && x.includes('no external Drobon-Dataset')));
  noLeak(noLogs.join('\n'), 'disabled logs');
  const missingLogs = [],
    missing = await wrapper(
      {
        ...real.config,
        vulnIntelProvider: 'filesystem',
        datasetPath: missingPath,
      },
      transport,
      missingLogs,
    );
  const cm = await register(missing, 'missing'),
    pm = await project(missing, cm),
    ms = await status(missing, cm);
  assert.equal(ms.configured, true);
  for (const f of ['sast', 'secrets', 'sca', 'dast']) {
    assert.equal(ms[f + 'Packs'].status, 'UNAVAILABLE');
    assert.equal(ms[f + 'Packs'].incomplete, true);
    assert.ok(ms.conformance[f].enumerationFailures > 0);
  }
  await upload(missing, cm, pm, 'src/audit.js', sastYes + '\n');
  const missingScan = await scan(missing, cm, pm, 'SAST', sourceRule, false, {
    label: 'SAST missing dataset', requirePartial: true,
  });
  assert.equal(missingScan.partial, true);
  console.log(
    'SEPARATE_HTTP_E2E',
    JSON.stringify({
      cases: outputs,
      mockDastRequests: requestCount,
      actualLoopbackHttpRequests: localRequests,
      externalTargetRequests: 0,
      appServiceInjected: false,
      appEnginesInjected: false,
      strictDastAuthorization: true,
      syntheticTokenNotDisclosed: true,
      disabledStartupWarning: true,
      missingDatasetUnavailable: true,
      pass: true,
    }),
  );
} finally {
  await Promise.all(servers.map((s) => s.stop()));
  await new Promise((resolve, reject) => mock.close((error) => (error ? reject(error) : resolve())));
}
