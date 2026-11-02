/**
 * Seven logical Agent roles. These are ROLE DEFINITIONS, not seven models and
 * not seven processes: one local model (when one is approved and available) may
 * serve every role through separate instructions, contexts and tool grants.
 *
 * Every role declares the exact internal tools it may ask for and the evidence
 * a result must carry. A role that is not granted a tool cannot reach it, so
 * the orchestrator cannot silently widen its own scope: the Master role owns
 * planning only and has no scanner or network tool at all.
 */

export const AGENT_ROLE_IDS = ['MASTER', 'RECON', 'SAST', 'DAST', 'SCA', 'SECRETS', 'VALIDATION'] as const;
export type AgentRoleId = (typeof AGENT_ROLE_IDS)[number];

export const AGENT_TOOLS = [
  'PLAN_ASSESSMENT',
  'INVENTORY_SOURCE',
  'RUN_SAST',
  'RUN_SCA',
  'RUN_SECRETS',
  'RUN_DAST',
  'READ_FINDINGS',
  'VALIDATE_EVIDENCE',
  'DRAFT_REPORT',
  'PROPOSE_REMEDIATION',
  'RETEST_SCAN',
] as const;
export type AgentTool = (typeof AGENT_TOOLS)[number];

/** Tools that can send bytes to a target; only the DAST role may hold them. */
export const NETWORK_TOOLS: readonly AgentTool[] = ['RUN_DAST'];

export interface AgentRoleDefinition {
  id: AgentRoleId;
  title: string;
  responsibility: string;
  tools: readonly AgentTool[];
  /** Fields a role's result must contain before it may be shown as a finding. */
  evidenceRequired: readonly string[];
  /** Bound on model/tool turns for one job of this role. */
  maxSteps: number;
}

export const AGENT_ROLES: Readonly<Record<AgentRoleId, AgentRoleDefinition>> = Object.freeze({
  MASTER: {
    id: 'MASTER',
    title: 'Master Agent',
    responsibility: 'Turn an assessment objective into a bounded plan and track task state and failures.',
    tools: ['PLAN_ASSESSMENT', 'READ_FINDINGS', 'DRAFT_REPORT'],
    evidenceRequired: ['objective', 'assessmentId', 'plannedTools'],
    maxSteps: 8,
  },
  RECON: {
    id: 'RECON',
    title: 'Recon Agent',
    responsibility: 'Describe the already-uploaded attack surface; never discover hosts or expand scope.',
    tools: ['INVENTORY_SOURCE', 'READ_FINDINGS'],
    evidenceRequired: ['sourceDigest', 'inventoryCounts'],
    maxSteps: 4,
  },
  SAST: {
    id: 'SAST',
    title: 'SAST Agent',
    responsibility: 'Run the existing SAST engine on the bound source snapshot and cite rule locations.',
    tools: ['RUN_SAST', 'READ_FINDINGS', 'PROPOSE_REMEDIATION'],
    evidenceRequired: ['ruleId', 'filePath', 'line'],
    maxSteps: 4,
  },
  DAST: {
    id: 'DAST',
    title: 'DAST Agent',
    responsibility: 'Run the existing passive DAST engine against the authorized target only.',
    tools: ['RUN_DAST', 'READ_FINDINGS', 'PROPOSE_REMEDIATION'],
    evidenceRequired: ['requestUrl', 'observation', 'ruleId'],
    maxSteps: 4,
  },
  SCA: {
    id: 'SCA',
    title: 'SCA Agent',
    responsibility: 'Run the existing SCA engine and report dependency evidence without inventing matches.',
    tools: ['RUN_SCA', 'READ_FINDINGS', 'PROPOSE_REMEDIATION'],
    evidenceRequired: ['packageName', 'evidenceSource'],
    maxSteps: 4,
  },
  SECRETS: {
    id: 'SECRETS',
    title: 'Secrets Agent',
    responsibility: 'Run the existing Secrets engine and report redacted locations only.',
    tools: ['RUN_SECRETS', 'READ_FINDINGS', 'PROPOSE_REMEDIATION'],
    evidenceRequired: ['ruleId', 'filePath', 'redaction'],
    maxSteps: 4,
  },
  VALIDATION: {
    id: 'VALIDATION',
    title: 'Validation Agent',
    responsibility: 'Cross-check findings against stored evidence, label uncertainty honestly and never scan.',
    tools: ['READ_FINDINGS', 'VALIDATE_EVIDENCE', 'PROPOSE_REMEDIATION', 'RETEST_SCAN'],
    evidenceRequired: ['findingId', 'evidenceIds', 'confidence', 'missingEvidence'],
    maxSteps: 6,
  },
});

/** The specialist role that owns one scanner; the Master role owns planning. */
export function roleForScanType(scanType: 'SAST' | 'SCA' | 'SECRETS' | 'DAST'): AgentRoleId {
  switch (scanType) {
    case 'SAST': return 'SAST';
    case 'SCA': return 'SCA';
    case 'SECRETS': return 'SECRETS';
    case 'DAST': return 'DAST';
  }
}

export type ToolDecision = { allowed: true } | { allowed: false; reason: string };

/** Fail-closed tool grant: unknown tool, unknown role or no grant is refused. */
export function authoriseAgentTool(role: AgentRoleId, tool: AgentTool): ToolDecision {
  const definition = AGENT_ROLES[role];
  if (definition === undefined) return { allowed: false, reason: 'Unknown agent role.' };
  if (!(AGENT_TOOLS as readonly string[]).includes(tool)) return { allowed: false, reason: 'Unknown agent tool.' };
  if (!definition.tools.includes(tool)) return { allowed: false, reason: `Role ${role} is not granted ${tool}.` };
  return { allowed: true };
}

/** Roles that may open a socket to the authorized target (DAST only, today). */
export function rolesWithNetworkAccess(): AgentRoleId[] {
  return AGENT_ROLE_IDS.filter((role) => AGENT_ROLES[role].tools.some((tool) => NETWORK_TOOLS.includes(tool)));
}

/** Audit record for one tool request; contains no source text or secret value. */
export interface AgentToolAudit {
  role: AgentRoleId;
  tool: AgentTool;
  allowed: boolean;
  reason?: string;
}

export function auditAgentTool(role: AgentRoleId, tool: AgentTool): AgentToolAudit {
  const decision = authoriseAgentTool(role, tool);
  return decision.allowed
    ? { role, tool, allowed: true }
    : { role, tool, allowed: false, reason: decision.reason };
}
