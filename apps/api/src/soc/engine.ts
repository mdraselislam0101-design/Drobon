/**
 * SOC-style project triage derived exclusively from saved scan records.
 *
 * This is a read-only snapshot, not a SIEM, intrusion detector, alert
 * delivery system or incident response platform. Alerts describe scan
 * history and configuration gaps; they do not claim an attack happened.
 */
import { createHash } from 'node:crypto';
import {
  SCAN_TYPES,
  SOC_MAX_ALERTS,
  SOC_MAX_SCANS,
  SOC_RECENT_SCAN_DAYS,
  type FindingLifecycleState,
  type FindingSeverity,
  type ScanStatus,
  type ScanType,
  type SocAlert,
  type SocPosture,
  type SocSourceStatus,
  type SocWatchRuleId,
} from '@drobon/shared';

export interface SocScanView {
  id: string;
  scanType: ScanType;
  status: ScanStatus;
  createdAt: string;
  completedAt?: string;
  partial: boolean;
  truncated: boolean;
  /** Findings are populated only for the latest completed scan of each type. */
  findings: ReadonlyArray<{ id: string; ruleId: string; severity: FindingSeverity; workflowState?: FindingLifecycleState }>;
  /** Saved SCA intelligence, not inferred from normal finding counts. */
  sca?: { assessmentState: 'ASSESSED' | 'NOT_ASSESSED'; advisories: ReadonlyArray<{ id: string; dependencyId: string; name: string; severity: FindingSeverity }> };
}

export interface SocInput {
  projectId: string;
  generatedAt: string;
  scans: readonly SocScanView[];
  scansOmitted: number;
  dataset: SocSourceStatus;
  advisory: SocSourceStatus;
}

interface DraftAlert {
  ruleId: SocWatchRuleId;
  severity: FindingSeverity;
  title: string;
  detail: string;
  observedAt: string;
  scanId?: string;
  findingId?: string;
  /** Internal discriminator for separate advisory/dependency matches. */
  identity?: string;
}

function alertId(projectId: string, draft: DraftAlert): string {
  const digest = createHash('sha256')
    .update(JSON.stringify([projectId, draft.ruleId, draft.scanId ?? null, draft.findingId ?? null, ...(draft.identity === undefined ? [] : [draft.identity])]), 'utf8')
    .digest('hex').slice(0, 24);
  return `soca_${digest}`;
}

/** Deterministic for a given input, including its injected generatedAt time. */
export function buildSocPosture(input: SocInput): SocPosture {
  const scans = input.scans.slice(0, SOC_MAX_SCANS);
  const omitted = input.scansOmitted + Math.max(0, input.scans.length - scans.length);
  const drafts: DraftAlert[] = [];
  const lastCompleted = new Map<ScanType, SocScanView>();

  for (const scan of scans) {
    if (scan.status === 'COMPLETED') {
      const prior = lastCompleted.get(scan.scanType);
      if (prior === undefined || (scan.completedAt ?? scan.createdAt) > (prior.completedAt ?? prior.createdAt)) {
        lastCompleted.set(scan.scanType, scan);
      }
      if (scan.partial || scan.truncated) {
        drafts.push({
          ruleId: 'SCAN_PARTIAL', severity: 'MEDIUM', title: 'Incomplete scan result',
          detail: `${scan.scanType} or its AST supplement reported partial or truncated coverage; additional findings may exist.`,
          observedAt: scan.completedAt ?? scan.createdAt, scanId: scan.id,
        });
      }
    } else if (scan.status === 'FAILED' || scan.status === 'TIMED_OUT') {
      drafts.push({
        ruleId: 'SCAN_FAILED', severity: 'MEDIUM', title: 'A scan did not complete',
        detail: `${scan.scanType} ended ${scan.status}; its target was not fully assessed.`,
        observedAt: scan.completedAt ?? scan.createdAt, scanId: scan.id,
      });
    }
  }

  const safeLabel = (value: string, fallback: string): string => Array.from(value, (char) => {
    const code = char.codePointAt(0) ?? 0;
    return code < 32 || code === 127 || (code >= 0x202a && code <= 0x202e) || (code >= 0x2066 && code <= 0x2069) ? ' ' : char;
  }).join('').replace(/\s+/g, ' ').trim().slice(0, 80) || fallback;
  for (const scan of lastCompleted.values()) {
    if (scan.scanType === 'SCA') {
      if (scan.sca === undefined || scan.sca.assessmentState === 'NOT_ASSESSED') {
        drafts.push({
          ruleId: 'SCA_NOT_ASSESSED', severity: 'MEDIUM', title: 'Dependency intelligence not assessed',
          detail: 'The latest completed SCA scan has no assessed advisory result. This does not mean dependencies are safe.',
          observedAt: scan.completedAt ?? scan.createdAt, scanId: scan.id,
        });
      }
      for (const advisory of scan.sca?.advisories ?? []) {
        if (advisory.severity !== 'CRITICAL' && advisory.severity !== 'HIGH') continue;
        drafts.push({
          ruleId: 'HIGH_SEVERITY_ADVISORY', severity: advisory.severity, title: 'High-severity dependency advisory matched',
          detail: `Latest completed SCA scan matched ${safeLabel(advisory.id, 'an advisory')} for ${safeLabel(advisory.name, 'a dependency')}; review the saved SCA detail.`,
          observedAt: scan.completedAt ?? scan.createdAt, scanId: scan.id, identity: `${advisory.id}\u0000${advisory.dependencyId}`,
        });
      }
    }
    for (const finding of scan.findings) {
      if (finding.severity !== 'CRITICAL' && finding.severity !== 'HIGH') continue;
      const workflow = finding.workflowState === undefined ? 'not recorded' : finding.workflowState;
      drafts.push({
        ruleId: 'HIGH_SEVERITY_FINDING', severity: finding.severity, title: 'High-severity finding recorded',
        detail: `${scan.scanType} rule ${finding.ruleId}; user-managed workflow: ${workflow}. Review the finding and verify any fix.`,
        observedAt: scan.completedAt ?? scan.createdAt, scanId: scan.id, findingId: finding.id,
      });
    }
  }

  const nowMs = Date.parse(input.generatedAt);
  const maxAge = SOC_RECENT_SCAN_DAYS * 24 * 60 * 60 * 1000;
  const missing = SCAN_TYPES.filter((scanner) => {
    const last = lastCompleted.get(scanner);
    if (last === undefined) return true;
    const age = nowMs - Date.parse(last.completedAt ?? last.createdAt);
    return !Number.isFinite(age) || age < 0 || age > maxAge;
  });
  if (missing.length > 0) {
    drafts.push({
      ruleId: 'MISSING_RECENT_SCANS', severity: 'MEDIUM', title: 'Recent scan coverage not recorded',
      detail: `No recent completed scan among the ${scans.length} reviewed for: ${missing.join(', ')}.`, observedAt: input.generatedAt,
    });
  }
  if (input.dataset !== 'AVAILABLE') {
    drafts.push({
      ruleId: 'DATASET_UNAVAILABLE', severity: 'LOW', title: 'Rule source unavailable',
      detail: `Current dataset status is ${input.dataset}; this is not a statement about historical scans.`, observedAt: input.generatedAt,
    });
  }
  if (input.advisory === 'STALE') {
    drafts.push({
      ruleId: 'ADVISORY_STALE', severity: 'LOW', title: 'Advisory data is stale',
      detail: 'The currently configured advisory data is outside its freshness window.', observedAt: input.generatedAt,
    });
  } else if (input.advisory !== 'AVAILABLE') {
    drafts.push({
      ruleId: 'ADVISORY_UNAVAILABLE', severity: 'LOW', title: 'Advisory data unavailable',
      detail: `Current advisory status is ${input.advisory}; known-vulnerability coverage may be limited.`, observedAt: input.generatedAt,
    });
  }

  const rank = (severity: FindingSeverity): number => ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].indexOf(severity);
  drafts.sort((a, b) => rank(a.severity) - rank(b.severity) || b.observedAt.localeCompare(a.observedAt) || a.ruleId.localeCompare(b.ruleId));
  const alerts: SocAlert[] = drafts.slice(0, SOC_MAX_ALERTS).map((draft) => {
    const { identity: _identity, ...publicDraft } = draft;
    return { id: alertId(input.projectId, draft), ...publicDraft };
  });
  return {
    schemaVersion: '1.0', projectId: input.projectId, generatedAt: input.generatedAt,
    scansReviewed: scans.length,
    scansOmitted: omitted,
    scannerCoverage: SCAN_TYPES.map((scanner) => ({
      scanner,
      lastCompletedAt: lastCompleted.get(scanner)?.completedAt ?? null,
    })),
    sources: { dataset: input.dataset, advisory: input.advisory },
    alerts,
    limitations: [
      'Derived on request from saved scan records only; no external security logs or live intrusion monitoring.',
      'Alerts are observations or coverage gaps, not confirmed attacks, incidents or compliance findings.',
      'The most recent 100 scans are reviewed; alerts are not independently acknowledged or persisted.',
      'A completed scan or absence of alerts does not prove that a target is secure.',
    ],
    truncated: omitted > 0 || drafts.length > SOC_MAX_ALERTS,
  };
}
