import { createHash, randomUUID } from 'node:crypto';
import {
  FINDING_HISTORY_EVENTS_MAX,
  FINDING_LIFECYCLE_STATES,
  FINDING_NOTE_MAX_LENGTH,
  FINDING_NOTES_MAX_COUNT,
  type Finding,
  type FindingLifecycleAction,
  type FindingLifecycleEvent,
  type FindingLifecycleState,
  type FindingRemediationNote,
  type FindingWorkflow,
} from '@drobon/shared';
import { matchRuleLine, sastRuleById } from './sast/rules.js';
import { matchSecretsRuleLine, SECRETS_RULES } from './secrets/rules.js';

export interface FindingWorkflowRecord extends FindingWorkflow {
  history: FindingLifecycleEvent[];
}

export interface WorkflowScanContext {
  id: string;
  projectId: string;
  scanType: Finding['scanner'] | 'SCA';
  completedAt: string;
}

export type PreparedFindingNote =
  | { ok: true; text: string; redacted: boolean }
  | { ok: false; reason: 'EMPTY' | 'TOO_LONG' | 'CONTROL_CHARACTER' | 'HTML_NOT_ALLOWED' };

const TRANSITIONS: Readonly<Record<FindingLifecycleState, readonly FindingLifecycleState[]>> = {
  OPEN: ['ACKNOWLEDGED', 'IN_PROGRESS', 'RESOLVED'],
  ACKNOWLEDGED: ['IN_PROGRESS', 'RESOLVED'],
  IN_PROGRESS: ['ACKNOWLEDGED', 'RESOLVED'],
  RESOLVED: [],
  REOPENED: ['ACKNOWLEDGED', 'IN_PROGRESS', 'RESOLVED'],
};

function uuidFromSeed(seed: string): string {
  const hash = createHash('sha256').update(seed, 'utf8').digest('hex').slice(0, 32);
  return `${hash.slice(0, 8)}-${hash.slice(8, 12)}-${hash.slice(12, 16)}-${hash.slice(16, 20)}-${hash.slice(20)}`;
}

export function findingWorkflowKey(projectId: string, fingerprint: string): string {
  return `${projectId}:${fingerprint}`;
}

function makeEvent(
  findingId: string,
  previousState: FindingLifecycleState | null,
  newState: FindingLifecycleState,
  actorId: string,
  actorType: 'USER' | 'SYSTEM',
  action: FindingLifecycleAction,
  at: string,
  noteId?: string,
  deterministicSeed?: string,
): FindingLifecycleEvent {
  const uuid = deterministicSeed === undefined ? randomUUID() : uuidFromSeed(deterministicSeed);
  return {
    id: `fev_${uuid}`,
    findingId,
    previousState,
    newState,
    actorId,
    actorType,
    action,
    at,
    ...(noteId === undefined ? {} : { noteId }),
  };
}

export function createInitialFindingWorkflow(finding: Finding, scan: WorkflowScanContext): FindingWorkflowRecord {
  const at = scan.completedAt;
  const seed = `${scan.projectId}:${finding.fingerprint}:${finding.id}`;
  const initial: FindingLifecycleEvent = makeEvent(
    finding.id, null, 'OPEN', 'system:scanner', 'SYSTEM', 'FINDING_OBSERVED', at, undefined,
    `${scan.id}:${finding.fingerprint}:initial`,
  );
  return {
    id: `fwf_${uuidFromSeed(seed)}`,
    projectId: scan.projectId,
    findingId: finding.id,
    fingerprint: finding.fingerprint,
    scanner: finding.scanner ?? (finding.ruleId.startsWith('DG-SEC-') ? 'SECRETS' : 'SAST'),
    ruleId: finding.ruleId,
    state: 'OPEN',
    firstObservedScanId: scan.id,
    firstObservedAt: at,
    lastObservedScanId: scan.id,
    lastObservedAt: at,
    lastVerificationScanId: scan.id,
    lastVerificationAt: at,
    verificationState: 'OBSERVED',
    notes: [],
    historyTotal: 1,
    updatedAt: at,
    history: [initial],
  };
}

function appendEvent(
  workflow: FindingWorkflowRecord,
  scan: WorkflowScanContext,
  action: FindingLifecycleAction,
  previousState: FindingLifecycleState,
  newState: FindingLifecycleState,
): FindingLifecycleRecordUpdate {
  if (workflow.history.length >= FINDING_HISTORY_EVENTS_MAX) return { workflow, appended: false };
  const event = makeEvent(
    workflow.findingId,
    previousState,
    newState,
    'system:scanner',
    'SYSTEM',
    action,
    scan.completedAt,
    undefined,
    `${scan.id}:${workflow.fingerprint}:${action}:${workflow.history.length}`,
  );
  const history = [...workflow.history, event];
  return {
    appended: true,
    workflow: { ...workflow, history, historyTotal: history.length, updatedAt: scan.completedAt },
  };
}

interface FindingLifecycleRecordUpdate {
  workflow: FindingWorkflowRecord;
  appended: boolean;
}

/** Apply an actual completed scanner result to a persisted fingerprint workflow. */
export function observeFindingInScan(
  workflow: FindingWorkflowRecord,
  finding: Finding,
  scan: WorkflowScanContext,
): FindingWorkflowRecord {
  const stateBefore = workflow.state;
  const stateAfter: FindingLifecycleState = stateBefore === 'RESOLVED' ? 'REOPENED' : stateBefore;
  const verificationChanged = workflow.verificationState !== 'OBSERVED';
  let updated: FindingWorkflowRecord = {
    ...workflow,
    state: stateAfter,
    lastObservedScanId: scan.id,
    lastObservedAt: scan.completedAt,
    lastVerificationScanId: scan.id,
    lastVerificationAt: scan.completedAt,
    verificationState: 'OBSERVED',
    updatedAt: scan.completedAt,
  };
  if (stateAfter !== stateBefore) {
    const added = appendEvent(updated, scan, 'FINDING_REOBSERVED', stateBefore, stateAfter);
    // User transitions reserve capacity for this safety-critical automatic reopen.
    if (!added.appended) {
      // User transitions reserve the final audit slot so a resolved finding
      // can never be silently left resolved after an actual reobservation.
      throw new Error('Resolved finding cannot be reopened without an audit-history slot.');
    }
    updated = added.workflow;
  } else if (verificationChanged && workflow.history.length < FINDING_HISTORY_EVENTS_MAX - 1) {
    updated = appendEvent(updated, scan, 'FINDING_REOBSERVED', stateBefore, stateAfter).workflow;
  }
  // Scanner-authored fields are immutable; only workflow metadata changes.
  void finding;
  return updated;
}

/** A completed same-scanner scan did not contain the fingerprint. */
export function markFindingNotObserved(
  workflow: FindingWorkflowRecord,
  scan: WorkflowScanContext,
): FindingWorkflowRecord {
  if (workflow.verificationState === 'NOT_OBSERVED_IN_LATEST_SCAN' && workflow.lastVerificationScanId === scan.id) return workflow;
  let updated: FindingWorkflowRecord = {
    ...workflow,
    lastVerificationScanId: scan.id,
    lastVerificationAt: scan.completedAt,
    verificationState: 'NOT_OBSERVED_IN_LATEST_SCAN',
    updatedAt: scan.completedAt,
  };
  // Keep one audit slot available for automatic reopening of a user-resolved item.
  if (workflow.verificationState === 'OBSERVED' && workflow.history.length < FINDING_HISTORY_EVENTS_MAX - 1) {
    updated = appendEvent(updated, scan, 'NOT_OBSERVED', workflow.state, workflow.state).workflow;
  }
  return updated;
}

export function canTransitionFinding(current: FindingLifecycleState, next: FindingLifecycleState): boolean {
  return (FINDING_LIFECYCLE_STATES as readonly string[]).includes(next) && TRANSITIONS[current].includes(next);
}

export function appendUserStateEvent(
  workflow: FindingWorkflowRecord,
  next: FindingLifecycleState,
  actorId: string,
  at: string,
): FindingWorkflowRecord | undefined {
  if (!canTransitionFinding(workflow.state, next) || workflow.history.length >= FINDING_HISTORY_EVENTS_MAX - 1) return undefined;
  const event = makeEvent(workflow.findingId, workflow.state, next, actorId, 'USER', 'STATE_CHANGED', at);
  const history = [...workflow.history, event];
  return { ...workflow, state: next, history, historyTotal: history.length, updatedAt: at };
}

export function appendUserNote(
  workflow: FindingWorkflowRecord,
  prepared: Extract<PreparedFindingNote, { ok: true }>,
  actorId: string,
  at: string,
): FindingWorkflowRecord | undefined {
  if (workflow.notes.length >= FINDING_NOTES_MAX_COUNT || workflow.history.length >= FINDING_HISTORY_EVENTS_MAX - 1) return undefined;
  const noteId = `fnt_${randomUUID()}`;
  const note: FindingRemediationNote = { id: noteId, text: prepared.text, actorId, createdAt: at, redacted: prepared.redacted };
  const event = makeEvent(workflow.findingId, workflow.state, workflow.state, actorId, 'USER', 'NOTE_ADDED', at, noteId);
  const history = [...workflow.history, event];
  return { ...workflow, notes: [...workflow.notes, note], history, historyTotal: history.length, updatedAt: at };
}

/**
 * Strict plain-text normalization. Credential-shaped lines and private-key
 * blocks are replaced before they can enter the durable workflow store.
 */
export function prepareFindingNote(value: unknown): PreparedFindingNote {
  if (typeof value !== 'string') return { ok: false, reason: 'EMPTY' };
  const normalized = value.normalize('NFC').replace(/\r\n?/g, '\n').replace(/\t/g, ' ').trim();
  if (normalized.length === 0) return { ok: false, reason: 'EMPTY' };
  if (normalized.length > FINDING_NOTE_MAX_LENGTH) return { ok: false, reason: 'TOO_LONG' };
  for (let index = 0; index < normalized.length; index += 1) {
    const code = normalized.charCodeAt(index);
    if ((code < 0x20 && code !== 0x09 && code !== 0x0a) || code === 0x7f) return { ok: false, reason: 'CONTROL_CHARACTER' };
  }
  if (/<\/?[a-z][^>]*>/i.test(normalized)) return { ok: false, reason: 'HTML_NOT_ALLOWED' };
  if (/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/i.test(normalized)) {
    return { ok: true, text: '[private key material omitted]', redacted: true };
  }
  const sastCredentialRule = sastRuleById('DG-SAST-005');
  let redacted = false;
  const lines = normalized.split('\n').map((line) => {
    const hasSecretRuleMatch = SECRETS_RULES.some((rule) =>
      rule.matchOnlyEvidence !== true && matchSecretsRuleLine(rule, line) !== undefined,
    );
    const sastMatch = sastCredentialRule !== undefined && matchRuleLine(sastCredentialRule, line) !== undefined;
    const opaqueLongValue = /\b[A-Za-z0-9+/_=-]{32,}\b/.test(line);
    if (hasSecretRuleMatch || sastMatch || opaqueLongValue) {
      redacted = true;
      return '[credential-shaped content omitted]';
    }
    return line;
  });
  const text = lines.join('\n').trim();
  if (text.length === 0) return { ok: false, reason: 'EMPTY' };
  return { ok: true, text, redacted };
}
