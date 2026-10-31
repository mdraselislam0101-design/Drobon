import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, test } from 'vitest';
import type { ScaResult, SecurityReport } from '@drobon/shared';
import { createMemoryProjectStore } from '../src/projects/store.js';
import { createMemorySourceStore } from '../src/scans/sources.js';
import { createJsonFileScanStore } from '../src/scans/store.js';
import { createSecretsEngine } from '../src/scans/secrets/engine.js';
import { createSastEngine } from '../src/scans/sast/engine.js';
import { matchSecretsRuleLine, type SecretsRule } from '../src/scans/secrets/rules.js';
import { WITHHELD_SOURCE_EVIDENCE } from '../src/scans/findingIdentity.js';
import { prepareFindingNote } from '../src/scans/findingWorkflow.js';
import { remediationGuidanceForFinding } from '../src/scans/remediationGuidance.js';
import { buildSecurityReport, canonicalJson, renderSecurityReportMarkdown, renderSecurityReportSarif, safeReportProjection, verifySecurityReportIntegrity } from '../src/reports/build.js';
import { renderPortfolioPdf, renderSecurityReportPdf } from '../src/reports/pdf.js';
import { pdfText } from './pdfTextFixture.js';
import { buildAssistantContext } from '../src/assistant/context.js';
import { AssistantService } from '../src/assistant/service.js';
import { createNoAssistantProvider } from '../src/assistant/provider.js';
import { createLogger } from '../src/logger.js';
import { TEST_SAST_RULES } from './fixtures/testData.js';
import { cleanupTempStoreDir, makeTempStoreDir } from './helpers.js';

// Invented disposable strings only. The first rule matches; the second is
// deliberately suppressed by its full-line denylist, reproducing the defect.
const MAIN = 'AKIA12QW34ER56TY78UI';
const NEIGHBOR = 'v9S3pQ7kN2rT4zA6dF8h';
const SHORT = 'q7z';
const rules: readonly SecretsRule[] = [
  { id: 'DG-SEC-701', title: 'Synthetic token', description: 'Synthetic finding', category: 'test', severity: 'HIGH', confidence: 'HIGH', remediation: 'Review.', limitation: 'Test only.', patterns: [/AKIA[0-9A-Z]{16}/] },
  { id: 'DG-SEC-702', title: 'Synthetic neighbor', description: 'Synthetic finding', category: 'test', severity: 'HIGH', confidence: 'HIGH', remediation: 'Review.', limitation: 'Test only.', patterns: [/api_key\s*=\s*["'][A-Za-z0-9]+["']/], validate: (_match, line) => !(line ?? '').includes('AKIA') },
];
function digest(value: unknown): string { return createHash('sha256').update(canonicalJson(value)).digest('hex'); }
function makeHistoricalReport(report: SecurityReport, rawEvidence: string): SecurityReport {
  const findings = report.findings.map((finding) => ({ ...finding, evidence: rawEvidence }));
  const material = {
    reportVersion: report.reportVersion, schemaVersion: report.schemaVersion, project: report.project, scan: report.scan,
    scannerCoverage: report.scannerCoverage, findingSummary: report.findingSummary, findings,
    ...(report.dast === undefined ? {} : { dast: report.dast }),
    ...(report.findingWorkflows === undefined ? {} : { findingWorkflows: report.findingWorkflows }),
    ...(report.sac === undefined ? {} : { sac: report.sac }),
    dependencyIntelligence: report.dependencyIntelligence, inventory: report.inventory,
  };
  const contentDigest = digest(material);
  const unsigned = { reportId: `rpt_${contentDigest.slice(0, 24)}`, generatedAt: report.generatedAt, ...material, contentDigest };
  return { ...unsigned, integrityDigest: digest(unsigned) };
}

describe('source evidence privacy boundaries', () => {
  test('detection denylist is unchanged, but adjacent/short/unknown values never enter source findings', async () => {
    const project = await createMemoryProjectStore().create({ ownerId: 'usr_fixture', name: 'privacy fixture', description: '' });
    const sources = createMemorySourceStore();
    const line = `const aws = "${MAIN}"; api_key="${NEIGHBOR}";`; // test-only synthetic fixture
    expect(matchSecretsRuleLine(rules[0]!, line)).toBeDefined();
    expect(matchSecretsRuleLine(rules[1]!, line)).toBeUndefined();
    await sources.replace({ ownerId: project.ownerId, projectId: project.id, files: [{ path: 'src/privacy.js', content: `${line}\nexec("command" + user); const dbPass="${SHORT}";` }] });
    const dir = makeTempStoreDir('privacy-findings');
    try {
      const file = join(dir, 'scans.json');
      const scans = createJsonFileScanStore(file);
      for (const [scanType, engine] of [
        ['SECRETS', createSecretsEngine({ sources, rules })],
        ['SAST', createSastEngine({ sources, rules: TEST_SAST_RULES })],
      ] as const) {
        const created = await scans.createScanWithQuota({ ownerId: project.ownerId, projectId: project.id, scanType, consume: async () => ({ ok: true }) });
        expect(created.outcome).toBe('created');
        const running = await scans.claimNextQueued();
        if (running === undefined) throw new Error('missing scan');
        const outcome = await engine.execute(running, { signal: AbortSignal.timeout(10_000) });
        if (outcome.kind !== 'completed' || outcome.findings === undefined) throw new Error('missing synthetic finding');
        expect(outcome.findings.length).toBeGreaterThan(0);
        expect(outcome.findings.every((finding) => finding.evidence === WITHHELD_SOURCE_EVIDENCE || finding.evidence.startsWith('AST '))).toBe(true);
        for (const value of [MAIN, NEIGHBOR, SHORT]) expect(JSON.stringify(outcome.findings)).not.toContain(value);
        expect(await scans.completeScan(running.id, outcome.resultSummary, outcome.findings)).toBeDefined();
      }
      const persisted = readFileSync(file, 'utf8');
      for (const value of [MAIN, NEIGHBOR, SHORT]) expect(persisted).not.toContain(value);
    } finally { cleanupTempStoreDir(dir); }
  });

  test('legacy source evidence is projected for API consumers, Assistant, exports and logs without rewriting historical records', async () => {
    const dir = makeTempStoreDir('privacy-legacy');
    try {
      const file = join(dir, 'scans.json');
      const project = await createMemoryProjectStore().create({ ownerId: 'usr_fixture', name: 'legacy fixture', description: '' });
      let scans = createJsonFileScanStore(file);
      await scans.createScanWithQuota({ ownerId: project.ownerId, projectId: project.id, scanType: 'SAST', consume: async () => ({ ok: true }) });
      const running = await scans.claimNextQueued();
      if (running === undefined) throw new Error('missing scan');
      const sources = createMemorySourceStore();
      await sources.replace({ ownerId: project.ownerId, projectId: project.id, files: [{ path: 'src/old.js', content: 'exec("command" + user);' }] });
      const outcome = await createSastEngine({ sources, rules: TEST_SAST_RULES }).execute(running, { signal: AbortSignal.timeout(10_000) });
      if (outcome.kind !== 'completed' || outcome.findings === undefined) throw new Error('missing finding');
      const scan = await scans.completeScan(running.id, outcome.resultSummary, outcome.findings);
      if (scan === undefined) throw new Error('missing completion');
      const report = buildSecurityReport(project, scan, '2026-10-31T00:00:00.000Z');
      expect((await scans.createReport(report)).outcome).toBe('created');
      const rawEvidence = `exec("run"); dbPass="${SHORT}"; api_key="${NEIGHBOR}"`; // test-only synthetic fixture
      const oldReport = makeHistoricalReport(report, rawEvidence);
      expect(verifySecurityReportIntegrity(oldReport)).toBe(true);
      const document = JSON.parse(readFileSync(file, 'utf8')) as { scans: Array<{ findings: Array<{ evidence: string }> }>; reports: SecurityReport[] };
      document.scans[0]!.findings[0]!.evidence = rawEvidence;
      document.reports[0] = oldReport;
      writeFileSync(file, JSON.stringify(document));
      const legacyBytes = readFileSync(file, 'utf8');
      scans = createJsonFileScanStore(file);
      const restored = await scans.findByProjectAndId(project.id, scan.id);
      const safeReport = await scans.findReportByProjectAndScan(project.id, scan.id);
      if (restored === undefined || safeReport === undefined) throw new Error('legacy data unavailable');
      expect(restored.findings?.[0]?.evidence).toBe(WITHHELD_SOURCE_EVIDENCE);
      expect(verifySecurityReportIntegrity(safeReport)).toBe(true);
      expect(safeReport.reportId).not.toBe(oldReport.reportId);
      expect((await scans.workspaceSummary(project.ownerId, project.id)).reports.recent[0]?.reportId).toBe(safeReport.reportId);
      expect(await scans.createReport(report)).toEqual({ outcome: 'existing', report: safeReport });
      const changedSnapshot = buildSecurityReport({ ...project, name: 'Changed project' }, restored, '2026-10-31T01:00:00.000Z');
      expect(await scans.createReport(changedSnapshot)).toEqual({ outcome: 'legacy-report-protected' });
      expect(readFileSync(file, 'utf8')).toBe(legacyBytes);
      const context = buildAssistantContext({ project, scans: [restored], findings: restored.findings ?? [] });
      const answer = await new AssistantService({ scans, provider: createNoAssistantProvider() }).answer(project, { question: 'Explain this finding and its evidence', scanId: scan.id, findingId: restored.findings![0]!.id });
      const singlePdf = pdfText(await renderSecurityReportPdf(oldReport));
      const portfolioPdf = pdfText(await renderPortfolioPdf({
        project: { id: project.id, name: project.name }, generatedAt: oldReport.generatedAt,
        entries: [
          { scanner: 'SAST', status: 'COMPLETED', report: oldReport },
          { scanner: 'SCA', status: 'NOT_RUN' },
          { scanner: 'SECRETS', status: 'NOT_RUN' },
          { scanner: 'DAST', status: 'NOT_RUN' },
        ],
      }));
      const guidance = safeReport.findings.map((finding) => ({ findingId: finding.id, guidance: remediationGuidanceForFinding(finding) }));
      const legacyGuidedPdf = pdfText(await renderSecurityReportPdf(oldReport, guidance));
      const legacyGuidedPortfolio = pdfText(await renderPortfolioPdf({
        project: { id: project.id, name: project.name }, generatedAt: oldReport.generatedAt, includeGuidance: true,
        entries: [
          { scanner: 'SAST', status: 'COMPLETED', report: oldReport, guidance },
          { scanner: 'SCA', status: 'NOT_RUN' }, { scanner: 'SECRETS', status: 'NOT_RUN' }, { scanner: 'DAST', status: 'NOT_RUN' },
        ],
      }));
      expect(legacyGuidedPdf).toContain('Dataset guidance: UNAVAILABLE');
      expect(legacyGuidedPortfolio).toContain('Dataset guidance: UNAVAILABLE');
      const outputs = [JSON.stringify(restored), JSON.stringify(safeReport), renderSecurityReportMarkdown(safeReport), renderSecurityReportSarif(safeReport),
        renderSecurityReportMarkdown(oldReport), renderSecurityReportSarif(oldReport), singlePdf, portfolioPdf,
        renderSecurityReportMarkdown(oldReport, guidance), renderSecurityReportSarif(oldReport, guidance), legacyGuidedPdf, legacyGuidedPortfolio,
        JSON.stringify(context), JSON.stringify(answer)];
      expect(singlePdf).toContain('source snippet withheld');
      expect(portfolioPdf).toContain('source snippet withheld');
      for (const value of [NEIGHBOR, SHORT]) for (const output of outputs) expect(output).not.toContain(value);
      const logs: string[] = [];
      const logger = createLogger({ out: (line) => logs.push(line) });
      logger.error('scanner error', { evidence: rawEvidence, err: new Error(rawEvidence) });
      expect(logs.join('\n')).not.toContain(NEIGHBOR);
      expect(logs.join('\n')).not.toContain(SHORT);
      for (const input of [`api_key="${SHORT}"`, `dbPass="${SHORT}"`]) { // test-only synthetic fixtures
        const prepared = prepareFindingNote(input);
        expect(prepared.ok && prepared.redacted).toBe(true);
        if (prepared.ok) expect(prepared.text).not.toContain(SHORT);
      }
    } finally { cleanupTempStoreDir(dir); }
  });
});

describe('historical non-source evidence', () => {
  test.each(['SCA', 'DAST'] as const)('%s legacy evidence containing a known credential shape is withheld without changing the historical file', async (scanner) => {
    const dir = makeTempStoreDir('privacy-other-legacy');
    try {
      const file = join(dir, 'scans.json');
      const project = await createMemoryProjectStore().create({ ownerId: 'usr_fixture', name: 'other legacy fixture', description: '' });
      let scans = createJsonFileScanStore(file);
      const target = 'https://fixture.example.test/';
      const created = await scans.createScanWithQuota({ ownerId: project.ownerId, projectId: project.id, scanType: scanner,
        ...(scanner === 'DAST' ? { targetUrl: target } : {}), consume: async () => ({ ok: true }) });
      if (created.outcome !== 'created') throw new Error('scan creation failed');
      const running = await scans.claimNextQueued();
      if (running === undefined) throw new Error('scan claim failed');
      const common = { id: `fnd_${'7'.repeat(24)}`, fingerprint: '7'.repeat(64), scanId: running.id, projectId: project.id,
        severity: 'MEDIUM' as const, title: 'Synthetic observation', description: 'Fixture only.', remediation: 'Review.', evidence: 'Benign observation.' };
      const finding = scanner === 'SCA'
        ? { ...common, scanner: 'SCA' as const, ruleId: 'DPK-SCA-001', file: 'package.json', line: 1, column: 1 }
        : { ...common, scanner: 'DAST' as const, ruleId: 'DPK-DAST-001', targetUrl: target, endpoint: target,
            method: 'GET' as const, responseStatus: 200, responseTimeMs: 1, observedAt: '2026-10-31T00:00:00.000Z', observedHeaders: [] };
      const dast = scanner === 'DAST' ? { targetUrl: target, requestCount: 1, redirectsFollowed: 0, partial: false,
        observations: [{ endpoint: target, method: 'GET' as const, status: 200, observedAt: '2026-10-31T00:00:00.000Z', responseTimeMs: 1, bodyBytes: 0, bodyTruncated: false, headers: [] }] } : undefined;
      const sca: ScaResult | undefined = scanner === 'SCA' ? {
        summary: { assessmentState: 'NOT_ASSESSED', datasetStatus: 'NO_DATA_LOADED', providerId: 'none',
          dependenciesTotal: 0, directDependencies: 0, transitiveDependencies: 0, unclassifiedDependencies: 0,
          advisoriesTotal: 0, manifestsAnalyzed: 0, manifestsPartial: 0, manifestsUnsupported: 0, manifestsInvalid: 0,
          transitiveGraph: 'UNAVAILABLE', truncated: false },
        dependencies: [], manifests: [], advisories: [],
        sbom: { bomFormat: 'CycloneDX', specVersion: '1.5', serialNumber: 'urn:uuid:00000000-0000-4000-8000-000000000000',
          version: 1, metadata: { tools: { components: [{ type: 'application', name: 'synthetic', version: '1' }] } }, components: [], dependencies: [] },
      } : undefined;
      const completed = await scans.completeScan(running.id, { findingsTotal: 1 }, [finding], sca, dast);
      if (completed === undefined) throw new Error('scan completion failed');
      const report = buildSecurityReport(project, completed, '2026-10-31T00:00:00.000Z');
      expect(report.findings[0]?.evidence).toBe('Benign observation.');
      expect((await scans.createReport(report)).outcome).toBe('created');
      const rawEvidence = `api_key="${SHORT}"`; // test-only synthetic credential-shaped fixture
      const oldReport = makeHistoricalReport(report, rawEvidence);
      expect(verifySecurityReportIntegrity(oldReport)).toBe(true);
      const document = JSON.parse(readFileSync(file, 'utf8')) as { scans: Array<{ findings: Array<{ evidence: string }> }>; reports: SecurityReport[] };
      document.scans[0]!.findings[0]!.evidence = rawEvidence;
      document.reports[0] = oldReport;
      writeFileSync(file, JSON.stringify(document));
      const before = readFileSync(file, 'utf8');
      scans = createJsonFileScanStore(file);
      const restored = await scans.findByProjectAndId(project.id, completed.id);
      const projected = await scans.findReportByProjectAndScan(project.id, completed.id);
      if (restored === undefined || projected === undefined) throw new Error('historical fixture unavailable');
      expect(verifySecurityReportIntegrity(projected)).toBe(true);
      expect(projected.findings[0]?.evidence).not.toContain(SHORT);
      expect(projected.reportId).not.toBe(oldReport.reportId);
      expect(safeReportProjection(projected)).toEqual(projected);
      for (const output of [JSON.stringify(restored), JSON.stringify(projected), renderSecurityReportMarkdown(oldReport),
        renderSecurityReportSarif(oldReport), pdfText(await renderSecurityReportPdf(oldReport))]) expect(output).not.toContain(SHORT);
      expect(readFileSync(file, 'utf8')).toBe(before);
    } finally { cleanupTempStoreDir(dir); }
  });
});
