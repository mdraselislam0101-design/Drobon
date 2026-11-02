import {
  AGENT_ROLES, AGENT_ROLE_IDS, rolesWithNetworkAccess, type AgentRoleId,
} from './roles.js';
import type { LocalModelAvailability } from './localModel.js';
import type { StorageBoundaryIssue, StorageBoundaryCode } from '../lib/storageBoundary.js';

/**
 * Read-only description of what the Agent can ACTUALLY do right now. It is
 * built from the same typed sources the runtime uses, so the UI cannot drift
 * from the implementation, and it never upgrades a capability to "ready" on
 * the strength of a configuration flag alone.
 */
export interface AgentRoleCapability {
  id: AgentRoleId;
  title: string;
  responsibility: string;
  tools: readonly string[];
  evidenceRequired: readonly string[];
  maxSteps: number;
  /** True when the role's tools are wired to the existing runtime surfaces. */
  integrated: boolean;
  note: string;
}

export interface AgentCapabilities {
  generatedAt: string;
  roles: AgentRoleCapability[];
  networkRoles: AgentRoleId[];
  model: { state: LocalModelAvailability['state']; provider: 'NONE' | 'LOCAL_LOOPBACK'; note: string };
  storage: { code: StorageBoundaryCode; issues: StorageBoundaryIssue[]; note: string };
  execution: { enabled: boolean; note: string };
  limitations: string[];
}

export interface AgentCapabilitiesInput {
  now: string;
  executionEnabled: boolean;
  storageCode: StorageBoundaryCode;
  storageIssues: readonly StorageBoundaryIssue[];
  model: LocalModelAvailability;
}

/**
 * Which roles are genuinely wired today. Planning, the four scanners and the
 * deterministic review are runtime surfaces; the model-backed reasoning paths
 * are not, so they stay false even when a model is configured.
 */
const INTEGRATION: Readonly<Record<AgentRoleId, { integrated: boolean; note: string }>> = Object.freeze({
  MASTER: { integrated: true, note: 'Deterministic plan and task tracking only; no free-form objective interpretation.' },
  RECON: { integrated: true, note: 'Bounded inventory of the uploaded snapshot; no live host discovery.' },
  SAST: { integrated: true, note: 'Runs the existing SAST engine through the durable scan processor.' },
  DAST: { integrated: true, note: 'Passive DAST only, inside the recorded engagement scope.' },
  SCA: { integrated: true, note: 'Runs the existing SCA engine; no vulnerability data is generated here.' },
  SECRETS: { integrated: true, note: 'Runs the existing Secrets engine; values are never returned.' },
  VALIDATION: { integrated: true, note: 'Evidence cross-checks and uncertainty labels; no exploit reproduction.' },
});

export function buildAgentCapabilities(input: AgentCapabilitiesInput): AgentCapabilities {
  const roles: AgentRoleCapability[] = AGENT_ROLE_IDS.map((id) => {
    const role = AGENT_ROLES[id];
    const integration = INTEGRATION[id];
    return {
      id,
      title: role.title,
      responsibility: role.responsibility,
      tools: [...role.tools],
      evidenceRequired: [...role.evidenceRequired],
      maxSteps: role.maxSteps,
      integrated: integration.integrated,
      note: integration.note,
    };
  });
  const modelReady = input.model.state === 'READY';
  return {
    generatedAt: input.now,
    roles,
    networkRoles: rolesWithNetworkAccess(),
    model: {
      state: input.model.state,
      provider: modelReady ? 'LOCAL_LOOPBACK' : 'NONE',
      note: modelReady
        ? 'A loopback-only local endpoint is configured. Model output is contract-validated but is not used to change finding verdicts.'
        : 'No local model is configured. All reasoning shown in this app is deterministic rule evaluation, not AI inference.',
    },
    storage: {
      code: input.storageCode,
      issues: [...input.storageIssues],
      note: input.storageCode === 'STORAGE_READY'
        ? 'Agent store paths passed the startup boundary attestation. This is not proof that a same-identity writer is excluded.'
        : 'Agent execution is refused while the storage boundary is not attested.',
    },
    execution: {
      enabled: input.executionEnabled,
      note: input.executionEnabled
        ? 'New agent jobs may be created; authorization, Dataset freshness and the storage boundary are rechecked per job.'
        : 'Agent execution is disabled (default, or production where it is not permitted).',
    },
    limitations: [
      'Seven logical roles, not seven models or seven deployed processes.',
      'No paid or remote AI provider is used, and none can be configured: the endpoint must be loopback.',
      'Model assistance, when configured, is advisory and cannot upgrade a finding verdict.',
      'Independent exploit validation, false-positive proof and vendor parity are not claimed.',
    ],
  };
}
