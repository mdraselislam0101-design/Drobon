/**
 * Advisory finding builders (Pump 15, MAIN-APP ONLY).
 *
 * Turns a generic advisory verdict into the SAME closed Finding contract the
 * other engines use, so advisory results automatically flow into the findings
 * list, workflow, assistant, reports and UI — no separate surface to maintain.
 *
 * Evidence discipline: only the advisory id, component, observed VERSION and
 * location are copied. No raw header/body/manifest values (they may contain
 * tokens) ever reach a finding.
 */

import {
  FINDING_EVIDENCE_MAX_LENGTH,
  FINDING_TEXT_MAX_LENGTH,
  FINDING_TITLE_MAX_LENGTH,
  type Finding,
  type FindingSeverity,
  type ScanType,
} from '@drobon/shared';
import { findingFingerprint } from './findingIdentity.js';
import type { ScanRecord } from './store.js';
import type { AdvisoryMatch } from '../external/advisory.js';

function safeText(value: string, maxLength: number): string {
  let out = '';
  for (const char of value) {
    const code = char.codePointAt(0) ?? 0;
    out += code < 0x20 || code === 0x7f ? ' ' : char;
    if (out.length >= maxLength) break;
  }
  return out.length > 0 ? out : 'unavailable';
}

export function advisorySeverityCounts(matches: readonly AdvisoryMatch[]): Record<FindingSeverity, number> {
  const out: Record<FindingSeverity, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const match of matches) out[match.severity] += 1;
  return out;
}

interface AdvisoryFindingBase {
  id: string;
  scanId: string;
  ruleId: string;
  severity: FindingSeverity;
  title: string;
  description: string;
  cwe?: string;
  evidence: string;
  remediation: string;
  fingerprint: string;
}

function baseFields(
  match: AdvisoryMatch,
  record: ScanRecord,
  scanner: ScanType,
  location: string,
  line: number | undefined,
): AdvisoryFindingBase {
  const evidence = safeText(match.evidence, FINDING_EVIDENCE_MAX_LENGTH);
  const fingerprint = findingFingerprint({
    scanner,
    projectId: record.projectId,
    ruleId: match.ruleId,
    location,
    ...(line === undefined ? {} : { line }),
    evidence,
    context: [match.ecosystem, match.component, match.observedVersion],
  });
  return {
    id: `fnd_${fingerprint.slice(0, 24)}`,
    scanId: record.id,
    ruleId: match.ruleId,
    severity: match.severity,
    title: safeText(match.title, FINDING_TITLE_MAX_LENGTH),
    description: safeText(match.description, FINDING_TEXT_MAX_LENGTH),
    ...(match.cwe === undefined ? {} : { cwe: match.cwe }),
    evidence,
    remediation: safeText(
      `${match.remediation} Limitation: ${match.limitation}${match.references.length > 0 ? ` References: ${match.references.join(', ')}` : ''}`,
      FINDING_TEXT_MAX_LENGTH,
    ),
    fingerprint,
  };
}

export interface DastAdvisoryContext {
  record: ScanRecord;
  targetUrl: string;
  endpoint: string;
  responseStatus: number;
  responseTimeMs: number;
  observedAt: string;
}

/** Advisory match observed on a LIVE third-party target → DAST finding. */
export function advisoryDastFinding(match: AdvisoryMatch, ctx: DastAdvisoryContext): Finding {
  const base = baseFields(match, ctx.record, 'DAST', ctx.endpoint, undefined);
  return {
    ...base,
    scanner: 'DAST',
    projectId: ctx.record.projectId,
    targetUrl: ctx.targetUrl,
    endpoint: ctx.endpoint,
    method: 'GET',
    responseStatus: ctx.responseStatus,
    responseTimeMs: Math.min(15_000, Math.max(0, Math.trunc(ctx.responseTimeMs))),
    observedAt: ctx.observedAt,
    observedHeaders: [safeText(`${match.location}: ${match.component} ${match.observedVersion}`, 120)],
  };
}

export interface SourceAdvisoryContext {
  record: ScanRecord;
  file: string;
  line: number;
  column: number;
}

/** Advisory match observed in an uploaded manifest → SCA source finding. */
export function advisorySourceFinding(match: AdvisoryMatch, ctx: SourceAdvisoryContext): Finding {
  const base = baseFields(match, ctx.record, 'SCA', ctx.file, ctx.line);
  return {
    ...base,
    scanner: 'SCA',
    projectId: ctx.record.projectId,
    file: ctx.file,
    line: ctx.line,
    column: ctx.column,
  };
}
