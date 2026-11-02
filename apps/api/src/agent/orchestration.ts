/**
 * Role -> processor wiring for the deterministic Agent coordinator.
 *
 * The seven logical roles live in `roles.ts`; the four scanner engines live in
 * `scans/`. This module is the only place that joins them:
 *
 *  - `planRoleExecution()` decides *which role owns a scanner job and whether
 *    that role is granted the matching tool*. The decision is fail closed and
 *    runs before the engine is reached, so a coordinator bug or a narrowed
 *    grant table can never silently execute a scanner on behalf of a role that
 *    does not hold the grant.
 *  - `evidenceGaps()` checks a produced finding against the role's declared
 *    evidence fields. It never returns source text, secret values or rule
 *    prose, only field names, and it never upgrades a verdict.
 *
 * Neither function talks to the network, the filesystem or a model.
 */
import type { Finding, ScanType } from '@drobon/shared';
import { AGENT_ROLES, authoriseAgentTool, roleForScanType,
  type AgentRoleId, type AgentTool, type ToolDecision } from './roles.js';

/** Scanner job types the coordinator may dispatch (no other scan type exists). */
export type ScannableType = 'SAST' | 'SCA' | 'SECRETS' | 'DAST';

/** The single tool that authorises running one scanner through its engine. */
export const SCANNER_TOOL: Readonly<Record<ScannableType, AgentTool>> = Object.freeze({
  SAST: 'RUN_SAST',
  SCA: 'RUN_SCA',
  SECRETS: 'RUN_SECRETS',
  DAST: 'RUN_DAST',
});

function isScannable(value: ScanType): value is ScannableType {
  return value === 'SAST' || value === 'SCA' || value === 'SECRETS' || value === 'DAST';
}

export interface RoleExecutionPlan {
  role: AgentRoleId;
  tool: AgentTool;
  /** Bound on model/tool turns for one job of this role. */
  maxSteps: number;
  evidenceRequired: readonly string[];
}

export type RoleExecutionDecision =
  | { allowed: true; plan: RoleExecutionPlan }
  | { allowed: false; reason: string };

/**
 * Grant lookup. Injectable only so a test can prove the gateway refuses a
 * revoked grant; production always uses the static table in `roles.ts`.
 */
export type ToolGrant = (role: AgentRoleId, tool: AgentTool) => ToolDecision;

/**
 * Resolve the owning role and its tool grant for one scanner job. Unknown scan
 * types, unknown roles and missing grants are all refused with a bounded
 * reason that names the role but never any project content.
 */
export function planRoleExecution(
  scanType: ScanType,
  grant: ToolGrant = authoriseAgentTool,
): RoleExecutionDecision {
  if (!isScannable(scanType)) return { allowed: false, reason: 'No agent role owns this scan type.' };
  const role = roleForScanType(scanType);
  const tool = SCANNER_TOOL[scanType];
  const decision = grant(role, tool);
  if (!decision.allowed) {
    return { allowed: false, reason: `The ${role} role is not authorized to run ${scanType}.` };
  }
  const definition = AGENT_ROLES[role];
  return { allowed: true, plan: { role, tool, maxSteps: definition.maxSteps, evidenceRequired: definition.evidenceRequired } };
}

/**
 * Fields a stored finding must actually carry before the coordinator may treat
 * it as evidence-backed. Names only; a missing field is reported, never filled.
 */
export function evidenceGaps(scanType: ScannableType, finding: Finding): string[] {
  const gaps: string[] = [];
  if (finding.ruleId.trim().length === 0) gaps.push('ruleId');
  if (finding.fingerprint.trim().length === 0) gaps.push('fingerprint');
  if (finding.evidence.trim().length === 0) gaps.push('evidence');
  if (scanType !== 'DAST') {
    const source = finding as Finding & { file?: unknown; line?: unknown };
    if (typeof source.file !== 'string' || source.file.length === 0) gaps.push('file');
    if (typeof source.line !== 'number' || !Number.isInteger(source.line) || source.line < 1) gaps.push('line');
  }
  return gaps;
}

/**
 * Bounded, non-identifying summary of an evidence check for one job. The count
 * is capped so a large scan cannot turn into an unbounded status document.
 */
export interface EvidenceCoverage {
  checked: number;
  complete: number;
  incomplete: number;
  /** True when at least one finding could not be tied to its declared evidence. */
  hasGaps: boolean;
}

export function evidenceCoverage(scanType: ScannableType, findings: readonly Finding[], limit = 500): EvidenceCoverage {
  const bounded = findings.slice(0, Math.max(0, limit));
  let incomplete = 0;
  for (const finding of bounded) {
    if (evidenceGaps(scanType, finding).length > 0) incomplete += 1;
  }
  return {
    checked: bounded.length,
    complete: bounded.length - incomplete,
    incomplete,
    hasGaps: incomplete > 0,
  };
}
