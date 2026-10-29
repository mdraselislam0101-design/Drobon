import { fileURLToPath } from 'node:url';
import * as fontkit from 'fontkit';
import PDFDocument from 'pdfkit';
import { FINDING_SEVERITIES, SCAN_TYPES, type Finding, type FindingSeverity, type ScanStatus, type ScanType, type SecurityReport } from '@drobon/shared';
import { verifySecurityReportIntegrity } from './build.js';

/**
 * Download-only PDF rendering. It consumes the same validated report snapshots
 * as the existing JSON/Markdown/SARIF exporters; it does not scan, connect to
 * a target, change a finding, or certify a project. Output is deliberately
 * bounded and explicitly identifies omitted details. The source JSON report
 * remains the complete, authoritative point-in-time record.
 */
export const PDF_MAX_BYTES = 1024 * 1024;
const SINGLE_FINDING_LIMIT = 60;
const PORTFOLIO_FINDING_LIMIT_PER_SCAN = 25;
const ADVISORY_DETAIL_LIMIT = 20;
const FONT_PATH = fileURLToPath(new URL('../assets/fonts/NotoSansBengali.ttf', import.meta.url));
let cachedFont: fontkit.Font | undefined;
function reportFont(): fontkit.Font {
  if (cachedFont === undefined) {
    const loaded = fontkit.openSync(FONT_PATH);
    if (!('hasGlyphForCodePoint' in loaded)) throw new TypeError('Report font is not a single font.');
    cachedFont = loaded;
  }
  return cachedFont;
}

export interface PortfolioPdfEntry {
  scanner: ScanType;
  /** The most recently REQUESTED scan of this type, not an older success. */
  status: ScanStatus | 'NOT_RUN' | 'ORDER_UNCERTAIN';
  requestedAt?: string;
  report?: SecurityReport;
}

export interface PortfolioPdfInput {
  project: { id: string; name: string };
  generatedAt: string;
  entries: PortfolioPdfEntry[];
}

// Font supports Bengali and Latin, not every Unicode script. Never silently
// lose a character: an unsupported glyph becomes '?', with an explicit note.
function safeText(value: string): string {
  let out = '';
  for (const ch of value.normalize('NFC')) {
    const cp = ch.codePointAt(0) ?? 0;
    if (cp === 10) { out += '\n'; continue; }
    // Remove visual-order overrides and controls rather than letting untrusted
    // titles/evidence change the apparent direction of neighboring text.
    if (cp < 32 || cp === 127 || (cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069)) {
      out += ' ';
    } else {
      out += reportFont().hasGlyphForCodePoint(cp) ? ch : '?';
    }
  }
  return out;
}

function text(doc: PDFKit.PDFDocument, value: string, size = 10): void {
  doc.fontSize(size).fillColor('#172335').text(safeText(value), { lineGap: 2 });
}

function heading(doc: PDFKit.PDFDocument, value: string): void {
  doc.moveDown(0.6).fontSize(13).fillColor('#173a70').text(safeText(value), { lineGap: 2 });
  doc.moveDown(0.2);
}

function location(finding: Finding): string {
  if (finding.scanner === 'DAST') return `${finding.method} ${finding.endpoint} (HTTP ${finding.responseStatus})`;
  return `${finding.file}:${finding.line}:${finding.column}`;
}

/** Prioritise bounded detail without changing the canonical report's order. */
function byPriority<T extends { severity: FindingSeverity }>(items: readonly T[]): T[] {
  return items.map((item, index) => ({ item, index }))
    .sort((a, b) => FINDING_SEVERITIES.indexOf(a.item.severity) - FINDING_SEVERITIES.indexOf(b.item.severity) || a.index - b.index)
    .map(({ item }) => item);
}

function printScan(doc: PDFKit.PDFDocument, report: SecurityReport, limit: number): void {
  if (!verifySecurityReportIntegrity(report)) throw new TypeError('Report integrity check failed.');
  const summary = report.scan.resultSummary;
  heading(doc, `${report.scan.scanType} | ${report.scan.id}`);
  text(doc, `Completed: ${report.scan.completedAt} | Report: ${report.reportId}`);
  text(doc, `Findings: ${report.findingSummary.total} | Critical: ${report.findingSummary.bySeverity.CRITICAL} | High: ${report.findingSummary.bySeverity.HIGH} | Medium: ${report.findingSummary.bySeverity.MEDIUM} | Low: ${report.findingSummary.bySeverity.LOW} | Info: ${report.findingSummary.bySeverity.INFO}`);
  if (summary?.partial === true || summary?.truncated === true || summary?.astSupplement?.status === 'PARTIAL' || report.dast?.partial === true) {
    text(doc, `Coverage: PARTIAL${summary?.partialReason === undefined ? '' : ` — ${summary.partialReason}`}`);
  } else {
    text(doc, 'Coverage: this scan ran within its bounded scope; complete security coverage is not established.');
  }
  if (summary?.filesScanned !== undefined || summary?.filesSkipped !== undefined) {
    text(doc, `Files: ${summary.filesScanned ?? 'unknown'} reached; ${summary.filesSkipped ?? 'unknown'} skipped or not reached.`);
  }
  if (summary?.requestsMade !== undefined) text(doc, `HTTP requests: ${summary.requestsMade}; redirects followed: ${summary.redirectsFollowed ?? 'unknown'}.`);
  if (summary?.astCoverage !== undefined) {
    const rules = summary.astCoverage.rules;
    text(doc, `SAST effective rules: ${rules.count} (${rules.source}); rule-set SHA-256: ${rules.sha256} (not a signature).`, 9);
  }
  if (summary?.declarationRulesEvaluated !== undefined) {
    text(doc, `SCA declaration rules: ${summary.declarationRulesEvaluated} evaluated; ${summary.declarationRulesNotEvaluated ?? 'unknown'} not evaluated (including absent artifacts).`, 9);
  }
  if (summary?.astSupplement !== undefined) text(doc, `AST supplement: ${summary.astSupplement.status}; parsed ${summary.astSupplement.parsed}, incomplete ${summary.astSupplement.incomplete}, skipped ${summary.astSupplement.skipped}.`, 9);
  if (report.scan.targetUrl !== undefined) text(doc, `Configured target: ${report.scan.targetUrl}`);
  if (report.scan.scanType !== 'SCA') text(doc, 'Dependency intelligence: NOT_ASSESSED; SCA was not run in this individual scan.');
  if (report.scan.scanType === 'SCA') {
    text(doc, `Dependency intelligence: ${report.dependencyIntelligence.status}; provider: ${report.dependencyIntelligence.providerId ?? 'unknown'}; dataset: ${report.dependencyIntelligence.datasetStatus ?? 'unknown'}.`);
    if (report.inventory.status === 'INCLUDED') {
      const sca = report.inventory.sca;
      text(doc, `Inventory: ${sca.summary.dependenciesTotal} dependency records; advisory matches: ${sca.advisories.length}. An inventory or no match is not a safety verdict.`);
      text(doc, 'A declaration or matched advisory is not proof that the same version is installed or exploitable; verify the environment and advisory.', 9);
      for (const advisory of byPriority(sca.advisories).slice(0, ADVISORY_DETAIL_LIMIT)) {
        text(doc, `Advisory ${advisory.id} [${advisory.severity}]: ${advisory.name}${advisory.version === undefined ? '' : ` ${advisory.version}`} — ${advisory.summary}`);
        if (advisory.url !== undefined) text(doc, `Reference: ${advisory.url}`);
      }
      if (sca.advisories.length > ADVISORY_DETAIL_LIMIT) text(doc, `${sca.advisories.length - ADVISORY_DETAIL_LIMIT} advisory details omitted from this PDF; consult the complete scan report.`);
    }
  }
  if (report.findings.length === 0) text(doc, 'No findings were recorded by this scan; this does not establish that the target is safe.');
  else text(doc, 'Finding details are prioritised by recorded severity; review and validate each result.', 9);
  for (const [index, finding] of byPriority(report.findings).slice(0, limit).entries()) {
    doc.moveDown(0.45);
    text(doc, `${index + 1}. [${finding.severity}] ${finding.title} (${finding.ruleId})`, 10);
    text(doc, `Location: ${location(finding)}${finding.cwe === undefined ? '' : ` | ${finding.cwe}`}${finding.confidence === undefined ? '' : ` | Detection confidence: ${finding.confidence}`}`, 9);
    text(doc, `Description: ${finding.description}`, 9);
    text(doc, `Evidence: ${finding.evidence}`, 9);
    if (finding.scanner === 'SAST' && finding.astFlow !== undefined) {
      const flow = finding.astFlow;
      text(doc, `AST: ${flow.mode} ${flow.category}; attribution: ${flow.attribution}. A flow candidate is not proof of exploitability.`, 9);
      if (flow.source !== undefined) text(doc, `Possible source: ${flow.source.file}:${flow.source.line}:${flow.source.column}`, 9);
      for (const step of flow.via ?? []) text(doc, `Possible flow step: ${step.file}:${step.line}:${step.column}`, 9);
    }
    text(doc, `Remediation: ${finding.remediation}`, 9);
    const workflow = report.findingWorkflows?.find((item) => item.findingId === finding.id);
    if (workflow !== undefined) {
      text(doc, `Workflow: ${workflow.state}; verification: ${workflow.verificationState}; last verification scan: ${workflow.lastVerificationScanId} (${workflow.lastVerificationAt}).`, 9);
      text(doc, 'Partial or truncated scans do not verify absence. The recorded verification may predate the latest scan; check its coverage, especially for older records. No state proves a fix.', 9);
    }
  }
  if (report.findings.length > limit) {
    text(doc, `${report.findings.length - limit} finding details omitted from this bounded PDF; download the complete JSON or Markdown scan report.`);
  }
  text(doc, `Content SHA-256: ${report.contentDigest}. This digest is not a digital signature.`, 8);
}

function printLimitations(doc: PDFKit.PDFDocument): void {
  heading(doc, 'Important limitations');
  text(doc, 'Results are bounded observations, not a guarantee of safety or a compliance certification. Review findings and false positives in context.');
  text(doc, 'A zero-finding, partial, failed or not-assessed result does not establish that a project is secure. Tests do not independently verify third-party permission.');
  text(doc, 'PDF text supports Bengali and Latin. Characters not supported by the bundled font are shown as ?. See the original JSON report for exact text.');
}

/** PDFKit's embedded-font ToUnicode map emits an empty hex string for some
 * shaped Bengali glyphs with no independent code point. Such an entry breaks
 * text extraction for the entire font in common PDF readers. Preserve visual
 * shaping and map only those glyphs to a zero-width character instead. The
 * source JSON is still authoritative for exact text/copy-paste. This guarded
 * compatibility step is covered by a compressed-CMap regression test. */
function repairEmptyUnicodeMappings(doc: PDFKit.PDFDocument): void {
  const internal = doc as unknown as { _font?: { unicode?: unknown } };
  const mappings = internal._font?.unicode;
  if (!Array.isArray(mappings)) throw new TypeError('PDF font Unicode map is unavailable.');
  for (const mapping of mappings) {
    if (!Array.isArray(mapping) || mapping.some((value: unknown) => typeof value !== 'number' || !Number.isInteger(value) || value < 0 || value > 0x10ffff)) {
      throw new TypeError('Invalid PDF font Unicode map.');
    }
    if (mapping.length === 0) mapping.push(0x200b);
  }
}

function render(draw: (doc: PDFKit.PDFDocument) => void): Promise<Buffer> {
  return new Promise<Buffer>((resolve, reject) => {
    const doc = new PDFDocument({
      size: 'A4', margin: 48, compress: true,
      info: { Title: 'Drobon security assessment', Author: 'Drobon', Subject: 'Bounded scan observations; not a certification' },
    });
    const chunks: Buffer[] = [];
    let total = 0;
    let settled = false;
    doc.on('data', (chunk: Buffer) => {
      if (settled) return;
      total += chunk.length;
      if (total > PDF_MAX_BYTES) {
        settled = true;
        doc.destroy();
        reject(new RangeError('PDF export exceeds the size limit.'));
      } else chunks.push(chunk);
    });
    doc.once('error', (error: Error) => { if (!settled) { settled = true; reject(error); } });
    doc.once('end', () => { if (!settled) { settled = true; resolve(Buffer.concat(chunks, total)); } });
    try {
      doc.font(FONT_PATH);
      draw(doc);
      repairEmptyUnicodeMappings(doc);
      doc.end();
    } catch (error) {
      if (!settled) { settled = true; doc.destroy(); reject(error instanceof Error ? error : new Error('PDF rendering failed.')); }
    }
  });
}

export function renderSecurityReportPdf(report: SecurityReport): Promise<Buffer> {
  return render((doc) => {
    text(doc, 'DROBON | SECURITY SCAN REPORT', 19);
    text(doc, `Project: ${report.project.name} (${report.project.id})`);
    text(doc, `Generated: ${report.generatedAt} | Scope: one completed ${report.scan.scanType} scan`);
    printScan(doc, report, SINGLE_FINDING_LIMIT);
    printLimitations(doc);
  });
}

/** Portfolio uses latest attempted scan per scanner; failed/new scans never
 * masquerade as an older successful assessment. It is generated on demand. */
export function renderPortfolioPdf(input: PortfolioPdfInput): Promise<Buffer> {
  if (input.entries.length !== SCAN_TYPES.length || input.entries.some((entry, index) => entry.scanner !== SCAN_TYPES[index] ||
      (entry.status === 'COMPLETED') !== (entry.report !== undefined) ||
      (entry.report !== undefined && (entry.report.project.id !== input.project.id || entry.report.scan.scanType !== entry.scanner)))) {
    return Promise.reject(new TypeError('Invalid portfolio report scope.'));
  }
  return render((doc) => {
    text(doc, 'DROBON | PROJECT SECURITY SUMMARY', 19);
    text(doc, `Project: ${input.project.name} (${input.project.id})`);
    text(doc, `Generated: ${input.generatedAt} | Latest requested scan per scanner`);
    text(doc, 'Each scanner may have used a different source snapshot or target time. Findings are not deduplicated across scanners. ORDER_UNCERTAIN means multiple requests have the same latest timestamp; no scan is selected for that scanner.');
    heading(doc, 'Coverage overview');
    for (const entry of input.entries) {
      const when = entry.requestedAt === undefined ? '' : ` | requested ${entry.requestedAt}`;
      const detail = entry.report === undefined ? '' : ` | ${entry.report.findingSummary.total} findings`;
      text(doc, `${entry.scanner}: ${entry.status}${when}${detail}`);
    }
    for (const entry of input.entries) {
      if (entry.report !== undefined) printScan(doc, entry.report, PORTFOLIO_FINDING_LIMIT_PER_SCAN);
    }
    printLimitations(doc);
  });
}
