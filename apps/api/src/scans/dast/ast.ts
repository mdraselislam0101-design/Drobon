import { isFindingSeverity, isSafeDastUrl, type AstSupplementSummary, type Finding, type FindingSeverity } from '@drobon/shared';
import type { ScanRecord } from '../store.js';
import { findingFingerprint } from '../findingIdentity.js';
import { astProfileFor } from '../sast/astProfiles.js';
import { parserVersions } from '../sast/astCoverage.js';
import { StructuredAstSession } from '../sast/structuredAstSession.js';

export interface DastAstObservation {
  endpoint: string;
  content: string;
  contentType?: string;
  bodyTruncated: boolean;
  responseStatus: number;
  responseTimeMs: number;
  observedAt: string;
}
export interface DastAstRule { id: string; severity: FindingSeverity; category?: string }
type Flow = { type: 'flow'; script: number; line: number; column: number; category: 'html' | 'code' };

/** Choose a category reporter, not a claim that its original check matched. */
function reporterFor(rules: readonly DastAstRule[]): DastAstRule | undefined {
  return rules.filter((rule) => typeof rule.id === 'string' && /^(?:DG|DPK)-DAST-[0-9]{3,6}$/.test(rule.id) &&
    isFindingSeverity(rule.severity) && typeof rule.category === 'string' && rule.category.trim().toLowerCase() === 'content-injection')
    .sort((a, b) => a.id.localeCompare(b.id))[0];
}
function count(value: unknown, max: number): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0 && value <= max;
}
function isFlow(value: unknown): value is Flow {
  if (typeof value !== 'object' || value === null) return false;
  const item = value as Record<string, unknown>;
  return Object.keys(item).length === 5 && item['type'] === 'flow' && count(item['script'], 8) && item['script'] > 0 &&
    count(item['line'], 32_768) && item['line'] > 0 && count(item['column'], 32_768) && item['column'] > 0 &&
    (item['category'] === 'html' || item['category'] === 'code');
}

/**
 * Analyze only the already-authorized baseline HTTP body. The caller supplies
 * bounded observations: no script fetch, browser, JS execution or extra probes.
 * Findings contain only ordinal/line metadata and a generic attribution note.
 */
export async function analyzeDastResponseAst(input: {
  record: ScanRecord;
  observation?: DastAstObservation;
  rules: readonly DastAstRule[];
  signal: AbortSignal;
  remainingMs: number;
  availableFindings: number;
}): Promise<{ summary: AstSupplementSummary; findings: Finding[] }> {
  const reporter = reporterFor(input.rules);
  const base = {
    mode: 'DAST_RESPONSE_SCRIPTS' as const,
    parserVersion: parserVersions().typescript,
    ...(reporter === undefined ? {} : { reporterRuleId: reporter.id }),
  };
  const none = (): { summary: AstSupplementSummary; findings: Finding[] } => ({
    summary: { ...base, status: 'NOT_APPLICABLE', parsed: 0, incomplete: 0, skipped: 0, signals: 0 }, findings: [],
  });
  const partial = (): { summary: AstSupplementSummary; findings: Finding[] } => ({
    summary: { ...base, status: 'PARTIAL', parsed: 0, incomplete: 1, skipped: 0, signals: 0 }, findings: [],
  });
  const observed = input.observation;
  if (observed === undefined) return none();
  if (!isSafeDastUrl(observed.endpoint) || !isSafeDastUrl(input.record.dastTargetUrl)) return partial();
  const profile = astProfileFor('javascript');
  if (profile === undefined || input.signal.aborted || input.remainingMs <= 0) return partial();
  const session = new StructuredAstSession();
  let result;
  try {
    result = await session.analyzeSupplement({ kind: 'DAST', content: observed.content,
      ...(observed.contentType === undefined ? {} : { contentType: observed.contentType }), profile }, input.signal, input.remainingMs);
  } finally { await session.close(); }
  if (result.status !== 'OK' || result.records.length === 0) return partial();
  const first = result.records[0];
  if (typeof first !== 'object' || first === null) return partial();
  const meta = first as Record<string, unknown>;
  if (Object.keys(meta).length !== 4 || meta['type'] !== 'summary' || !count(meta['parsed'], 8) ||
      !count(meta['incomplete'], 8) || meta['parsed'] + meta['incomplete'] > 8 || !count(meta['skipped'], 200) ||
      !result.records.slice(1).every(isFlow)) return partial();
  const flows = result.records.slice(1) as Flow[];
  const findings: Finding[] = [];
  if (reporter !== undefined) for (const flow of flows) {
    if (findings.length >= Math.max(0, input.availableFindings)) break;
    const evidence = `AST ${flow.category} flow candidate in observed script ${flow.script}, line ${flow.line}, column ${flow.column}; manual review required.`;
    const fingerprint = findingFingerprint({ scanner: 'DAST', projectId: input.record.projectId, ruleId: reporter.id,
      location: observed.endpoint, evidence, context: [input.record.dastTargetUrl, 'GET', String(observed.responseStatus)] });
    findings.push({
      id: `fnd_${fingerprint.slice(0, 24)}`, scanId: input.record.id, ruleId: reporter.id,
      scanner: 'DAST', projectId: input.record.projectId, severity: reporter.severity,
      title: `Possible ${flow.category} flow in observed script (AST heuristic)`,
      description: 'A bounded syntax-tree heuristic observed a possible browser-input flow to an HTML or code sink. The category reporter check may not match this script. Runtime execution and exploitability are not established.',
      remediation: 'Review the source and sink, validate untrusted input, and use context-appropriate output encoding or safer APIs. Verify manually.',
      evidence, fingerprint, targetUrl: input.record.dastTargetUrl, endpoint: observed.endpoint, method: 'GET',
      responseStatus: observed.responseStatus, responseTimeMs: Math.min(15_000, observed.responseTimeMs), observedAt: observed.observedAt,
      ...(observed.contentType === undefined ? {} : { contentType: observed.contentType }), observedHeaders: [],
      astContext: { kind: 'DAST_RESPONSE_FLOW', category: flow.category, attribution: 'CATEGORY_REPORTER', script: flow.script, line: flow.line, column: flow.column },
    });
  }
  const skipped = Math.min(200, meta['skipped'] + (observed.bodyTruncated ? 1 : 0) + (reporter !== undefined && findings.length < flows.length ? 1 : 0));
  const hasInputs = meta['parsed'] + meta['incomplete'] + skipped > 0;
  const status: AstSupplementSummary['status'] = !hasInputs ? 'NOT_APPLICABLE'
    : meta['incomplete'] > 0 || skipped > 0 || (meta['parsed'] > 0 && reporter === undefined) ? 'PARTIAL' : 'RAN';
  return { summary: { ...base, status, parsed: meta['parsed'], incomplete: meta['incomplete'], skipped, signals: findings.length }, findings };
}
