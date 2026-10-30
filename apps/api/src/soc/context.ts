/** Adapts existing owner-scoped stores into bounded SOC triage input. */
import { SOC_MAX_SCANS, type FindingLifecycleState, type ScanType, type SocSourceStatus } from '@drobon/shared';
import type { ScanRecord, ScanStore } from '../scans/store.js';
import type { DatasetService } from '../external/service.js';
import type { AdvisoryService } from '../external/advisory.js';
import type { SocInput, SocScanView } from './engine.js';

export interface SocContextDeps {
  scans: ScanStore;
  dataset: DatasetService;
  advisory: AdvisoryService;
}

export async function gatherSocInput(
  deps: SocContextDeps,
  projectId: string,
  ownerId: string,
  nowIso: string,
): Promise<SocInput> {
  const [allScans, datasetStatus, advisoryStatus] = await Promise.all([
    deps.scans.listByProject(projectId),
    deps.dataset.status(),
    deps.advisory.status(),
  ]);
  // The route has already checked project ownership; filter once more at the
  // store boundary so no accidentally inconsistent row reaches this view.
  const owned = allScans.filter((scan) => scan.projectId === projectId && scan.ownerId === ownerId);
  const selected = owned.slice(0, SOC_MAX_SCANS);
  const latest = new Map<ScanType, ScanRecord>();
  for (const scan of selected) {
    if (scan.status !== 'COMPLETED') continue;
    const previous = latest.get(scan.scanType);
    if (previous === undefined || (scan.completedAt ?? scan.createdAt) > (previous.completedAt ?? previous.createdAt)) {
      latest.set(scan.scanType, scan);
    }
  }
  const latestIds = new Set([...latest.values()].map((scan) => scan.id));
  const latestFindings = [...latest.values()].flatMap((scan) => scan.findings ?? []);
  const workflows = await deps.scans.getFindingWorkflowsForFindings(projectId, latestFindings);
  const workflowStates = new Map<string, FindingLifecycleState>(workflows.map((workflow) => [workflow.fingerprint, workflow.state]));

  const scans: SocScanView[] = selected.map((scan) => ({
    id: scan.id,
    scanType: scan.scanType,
    status: scan.status,
    createdAt: scan.createdAt,
    ...(scan.completedAt === undefined ? {} : { completedAt: scan.completedAt }),
    partial: scan.resultSummary?.partial === true || scan.dast?.partial === true || scan.resultSummary?.astSupplement?.status === 'PARTIAL',
    truncated: scan.resultSummary?.truncated === true,
    ...(latestIds.has(scan.id) && scan.scanType === 'SCA' && scan.sca !== undefined ? { sca: {
      assessmentState: scan.sca.summary.assessmentState,
      advisories: scan.sca.advisories.map((item) => ({ id: item.id, dependencyId: item.dependencyId, name: item.name, severity: item.severity })),
    } } : {}),
    findings: latestIds.has(scan.id) ? (scan.findings ?? []).map((finding) => {
      const state = workflowStates.get(finding.fingerprint);
      return {
        id: finding.id,
        ruleId: finding.ruleId,
        severity: finding.severity,
        ...(state === undefined ? {} : { workflowState: state }),
      };
    }) : [],
  }));
  const dataset: SocSourceStatus = !datasetStatus.configured ? 'NOT_CONFIGURED'
    : [datasetStatus.sastPacks, datasetStatus.scaPacks, datasetStatus.secretsPacks, datasetStatus.dastPacks]
      .every((category) => category.status === 'AVAILABLE') ? 'AVAILABLE' : 'UNAVAILABLE';
  const advisory: SocSourceStatus = !advisoryStatus.configured ? 'NOT_CONFIGURED'
    : !advisoryStatus.loaded || advisoryStatus.recordCount === 0 ? 'UNAVAILABLE'
      : advisoryStatus.stale ? 'STALE' : 'AVAILABLE';
  return {
    projectId,
    generatedAt: nowIso,
    scans,
    scansOmitted: Math.max(0, owned.length - selected.length),
    dataset,
    advisory,
  };
}
