import { ASSESSMENT_ID_PATTERN } from './assessmentIds.js';
import { FINDING_ID_PATTERN, FINDING_RULE_ID_PATTERN, SCAN_ID_PATTERN, isFindingSeverity, isScanType, type FindingSeverity, type ScanType } from './scans.js';

/** Deterministic bounded coordinator; no language model is implied. */
export const AGENT_TASK_STATES = ['READY', 'BLOCKED', 'QUEUED', 'RUNNING', 'CANCELLING', 'CANCELLED', 'COMPLETED', 'PARTIAL', 'FAILED'] as const;
export type AgentTaskState = (typeof AGENT_TASK_STATES)[number];
export const AGENT_VERDICTS = ['CONFIRMED', 'LIKELY', 'SUSPECTED', 'INCONCLUSIVE', 'FALSE_POSITIVE', 'NOT_VERIFIED', 'BLOCKED'] as const;
export type AgentVerdict = (typeof AGENT_VERDICTS)[number];

export interface AgentTask {
  scanner: ScanType;
  state: AgentTaskState;
  reason: string;
  scanId?: string;
  findingsTotal?: number;
  /** Content snapshot, not a trusted signature or Dataset commit identity. */
  datasetDigest?: string;
}
export interface AgentFindingReview {
  scanId: string;
  findingId: string;
  ruleId: string;
  scanner: ScanType;
  severity: FindingSeverity;
  verdict: AgentVerdict;
  /** Why this narrow structural verdict was assigned; not an exploit claim. */
  basis: string;
  priority: number;
}
export interface AgentAttackPath {
  status: 'THEORETICAL';
  confidence: 'LOW';
  entryPoint: 'NOT_ESTABLISHED';
  findingIds: string[];
  explanation: string;
  prerequisites: string;
  impact: string;
  remediation: string;
}
export interface AgentAssessment {
  assessmentId: string;
  generatedAt: string;
  mode: 'DETERMINISTIC';
  model: 'NONE';
  state: 'NOT_STARTED' | 'ACTIVE' | 'PARTIAL' | 'COMPLETE' | 'BLOCKED';
  inventory: {
    sourceFiles: number;
    targetConfigured: boolean;
    manifestFiles: number;
    routeCandidates: number;
    routeAnalysis: 'COMPLETE' | 'PARTIAL' | 'NOT_APPLICABLE';
  };
  tasks: AgentTask[];
  reviews: AgentFindingReview[];
  reviewsOmitted: number;
  paths: AgentAttackPath[];
  limitations: string[];
}
export interface AgentAssessmentResponse { agent: AgentAssessment }
export interface AgentCancellationResponse { scanId: string; state: 'CANCELLING' | 'CANCELLED' }
export interface AgentExecutionResponse {
  agent: AgentAssessment;
  actions: Array<{ scanner: ScanType; result: 'CREATED' | 'EXISTING' | 'BLOCKED' | 'INCONCLUSIVE'; reason: string }>;
}

function object(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
function keys(value: Record<string, unknown>, required: string[], optional: string[] = []): boolean {
  return required.every((key) => Object.hasOwn(value, key)) && Object.keys(value).every((key) => required.includes(key) || optional.includes(key));
}
function text(value: unknown, max = 300): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= max && !/[\u0000-\u001f\u007f]/.test(value); // eslint-disable-line no-control-regex
}
function count(value: unknown): value is number { return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0; }
function scanId(value: unknown): value is string { return typeof value === 'string' && SCAN_ID_PATTERN.test(value); }
function findingId(value: unknown): value is string { return typeof value === 'string' && FINDING_ID_PATTERN.test(value); }

export function isAgentAssessment(value: unknown): value is AgentAssessment {
  if (!object(value) || !keys(value, ['assessmentId', 'generatedAt', 'mode', 'model', 'state', 'inventory', 'tasks', 'reviews', 'reviewsOmitted', 'paths', 'limitations']) ||
      typeof value['assessmentId'] !== 'string' || !ASSESSMENT_ID_PATTERN.test(value['assessmentId']) ||
      typeof value['generatedAt'] !== 'string' || !Number.isFinite(Date.parse(value['generatedAt'])) ||
      value['mode'] !== 'DETERMINISTIC' || value['model'] !== 'NONE' ||
      !['NOT_STARTED', 'ACTIVE', 'PARTIAL', 'COMPLETE', 'BLOCKED'].includes(String(value['state'])) ||
      !object(value['inventory']) || !keys(value['inventory'], ['sourceFiles', 'targetConfigured', 'manifestFiles', 'routeCandidates', 'routeAnalysis']) ||
      !count(value['inventory']['sourceFiles']) || value['inventory']['sourceFiles'] > 200 || typeof value['inventory']['targetConfigured'] !== 'boolean' ||
      !count(value['inventory']['manifestFiles']) || value['inventory']['manifestFiles'] > 200 ||
      !count(value['inventory']['routeCandidates']) || value['inventory']['routeCandidates'] > 10000 ||
      !['COMPLETE', 'PARTIAL', 'NOT_APPLICABLE'].includes(String(value['inventory']['routeAnalysis'])) ||
      !Array.isArray(value['tasks']) || value['tasks'].length !== 4 ||
      !Array.isArray(value['reviews']) || value['reviews'].length > 100 || !count(value['reviewsOmitted']) ||
      !Array.isArray(value['paths']) || value['paths'].length > 20 || !Array.isArray(value['limitations']) ||
      value['limitations'].length > 12 || !value['limitations'].every((item) => text(item))) return false;
  const seen = new Set<ScanType>();
  for (const task of value['tasks']) {
    if (!object(task) || !keys(task, ['scanner', 'state', 'reason'], ['scanId', 'findingsTotal', 'datasetDigest']) ||
        !isScanType(task['scanner']) || seen.has(task['scanner']) ||
        !(AGENT_TASK_STATES as readonly unknown[]).includes(task['state']) || !text(task['reason']) ||
        (task['scanId'] !== undefined && !scanId(task['scanId'])) ||
        (task['datasetDigest'] !== undefined && (typeof task['datasetDigest'] !== 'string' || !/^[a-f0-9]{64}$/.test(task['datasetDigest']))) ||
        (task['findingsTotal'] !== undefined && (!count(task['findingsTotal']) || task['findingsTotal'] > 200))) return false;
    seen.add(task['scanner']);
  }
  for (const review of value['reviews']) {
    if (!object(review) || !keys(review, ['scanId', 'findingId', 'ruleId', 'scanner', 'severity', 'verdict', 'basis', 'priority']) ||
        !scanId(review['scanId']) || !findingId(review['findingId']) || typeof review['ruleId'] !== 'string' || !FINDING_RULE_ID_PATTERN.test(review['ruleId']) || !isScanType(review['scanner']) || !isFindingSeverity(review['severity']) ||
        !(AGENT_VERDICTS as readonly unknown[]).includes(review['verdict']) || !text(review['basis']) ||
        !count(review['priority']) || review['priority'] > 100) return false;
  }
  for (const path of value['paths']) {
    if (!object(path) || !keys(path, ['status', 'confidence', 'entryPoint', 'findingIds', 'explanation', 'prerequisites', 'impact', 'remediation']) ||
        path['status'] !== 'THEORETICAL' || path['confidence'] !== 'LOW' || path['entryPoint'] !== 'NOT_ESTABLISHED' ||
        !Array.isArray(path['findingIds']) || path['findingIds'].length !== 2 || !path['findingIds'].every(findingId) ||
        !text(path['explanation']) || !text(path['prerequisites']) || !text(path['impact']) || !text(path['remediation'])) return false;
  }
  return true;
}
export function isAgentAssessmentResponse(value: unknown): value is AgentAssessmentResponse {
  return object(value) && keys(value, ['agent']) && isAgentAssessment(value['agent']);
}
export function isAgentCancellationResponse(value: unknown): value is AgentCancellationResponse {
  return object(value) && keys(value, ['scanId', 'state']) && scanId(value['scanId']) &&
    (value['state'] === 'CANCELLING' || value['state'] === 'CANCELLED');
}
export function isAgentExecutionResponse(value: unknown): value is AgentExecutionResponse {
  return object(value) && keys(value, ['agent', 'actions']) && isAgentAssessment(value['agent']) &&
    Array.isArray(value['actions']) && value['actions'].length <= 4 && value['actions'].every((action) =>
      object(action) && keys(action, ['scanner', 'result', 'reason']) && isScanType(action['scanner']) &&
      ['CREATED', 'EXISTING', 'BLOCKED', 'INCONCLUSIVE'].includes(String(action['result'])) && text(action['reason']));
}
