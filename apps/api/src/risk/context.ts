/**
 * Adapts the owner-scoped scan store into bounded correlation input.
 *
 * Selection rule (documented, deterministic): the LATEST COMPLETED scan of
 * each scanner type — `completedAt` DESC, ties broken by scan id ASC (a
 * different answer for identical data would make the assessment unstable).
 * Findings whose workflow state is FALSE_POSITIVE are excluded, exactly as
 * the report's disclosures claim.
 */
import {
  SCAN_TYPES,
  findingScanner,
  type Finding,
  type ScanType,
  type RiskAssessmentResponse,
} from '@drobon/shared';
import type { ScanRecord, ScanStore } from '../scans/store.js';
import { buildRiskAssessment, type RiskFindingView, type RiskSourceScan } from './engine.js';

export interface RiskContextDeps {
  scans: ScanStore;
}

/** Bounded read of one finding: only fields correlation may use. */
function toView(finding: Finding): RiskFindingView | undefined {
  const scanner = findingScanner(finding);
  if (scanner === undefined) return undefined;
  const base: RiskFindingView = {
    id: finding.id,
    scanner,
    severity: finding.severity,
    ruleId: finding.ruleId,
    ...(finding.cwe === undefined ? {} : { cwe: finding.cwe }),
  };
  if (finding.scanner === 'DAST') {
    return { ...base, endpoint: finding.endpoint, observedAt: finding.observedAt, responseStatus: finding.responseStatus };
  }
  return { ...base, file: finding.file };
}

/** Latest completed scan per scanner; `completedAt` DESC then id ASC. */
export function selectLatestCompleted(records: readonly ScanRecord[]): Map<ScanType, ScanRecord> {
  const latest = new Map<ScanType, ScanRecord>();
  for (const record of records) {
    if (record.status !== 'COMPLETED') continue;
    const current = latest.get(record.scanType);
    if (current === undefined) {
      latest.set(record.scanType, record);
      continue;
    }
    const a = record.completedAt ?? record.createdAt;
    const b = current.completedAt ?? current.createdAt;
    if (a > b || (a === b && record.id < current.id)) latest.set(record.scanType, record);
  }
  return latest;
}

export async function gatherRiskAssessment(
  deps: RiskContextDeps,
  projectId: string,
  ownerId: string,
  nowIso: string,
): Promise<RiskAssessmentResponse> {
  const allScans = await deps.scans.listByProject(projectId);
  // Ownership is checked by the route; re-filter at the store boundary so a row
  // from another account can never reach the assessment.
  const owned = allScans.filter((scan) => scan.projectId === projectId && scan.ownerId === ownerId);
  const latest = selectLatestCompleted(owned);
  const selected = [...latest.values()];
  const selectedFindings = selected.flatMap((scan) => scan.findings ?? []);
  const workflows = await deps.scans.getFindingWorkflowsForFindings(projectId, selectedFindings);
  const falsePositives = new Set(
    workflows.filter((workflow) => workflow.state === 'FALSE_POSITIVE').map((workflow) => workflow.fingerprint),
  );

  const sources: RiskSourceScan[] = [];
  for (const scanner of SCAN_TYPES) {
    const scan = latest.get(scanner);
    if (scan === undefined) continue;
    const findings: RiskFindingView[] = [];
    for (const finding of scan.findings ?? []) {
      // A recorded false positive is never scored — the disclosure says so.
      if (falsePositives.has(finding.fingerprint)) continue;
      const view = toView(finding);
      if (view === undefined) continue;
      findings.push(view);
    }
    sources.push({
      scanner,
      scanId: scan.id,
      completedAt: scan.completedAt ?? scan.createdAt,
      findings,
      omitted: scan.resultSummary?.truncated === true,
    });
  }

  const missingScanners = SCAN_TYPES.filter((scanner) => !latest.has(scanner));
  return {
    assessment: buildRiskAssessment({ projectId, generatedAt: nowIso, sources, missingScanners }),
  };
}
