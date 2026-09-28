import { PROJECT_ID_PATTERN } from './projects.js';
import { type FindingLifecycleState } from './findings.js';
import { FINDING_ID_PATTERN, SCAN_ID_PATTERN } from './scans.js';

export const ASSISTANT_QUESTION_MAX_LENGTH = 1_200;
export const ASSISTANT_CONTEXT_MAX_ITEMS = 40;
export const ASSISTANT_CONTEXT_ITEM_MAX_LENGTH = 1_800;
export const ASSISTANT_CONTEXT_MAX_LENGTH = 12_000;
export const ASSISTANT_RESPONSE_MAX_LENGTH = 4_000;
export const ASSISTANT_EVIDENCE_REFS_MAX = 30;
export const ASSISTANT_LIST_MAX = 10;

export const ASSISTANT_STATES = ['SUPPORTED', 'PARTIALLY_SUPPORTED', 'NOT_ASSESSED', 'UNAVAILABLE'] as const;
export type AssistantState = (typeof ASSISTANT_STATES)[number];

export const ASSISTANT_MODES = ['DETERMINISTIC', 'PROVIDER'] as const;
export type AssistantMode = (typeof ASSISTANT_MODES)[number];

export const ASSISTANT_PROVIDER_STATES = ['NONE', 'UNAVAILABLE', 'AVAILABLE'] as const;
export type AssistantProviderState = (typeof ASSISTANT_PROVIDER_STATES)[number];

export const ASSISTANT_SOURCE_TYPES = [
  'PROJECT', 'SCAN', 'FINDING', 'REMEDIATION', 'LIFECYCLE', 'REPORT', 'SBOM', 'DAST_OBSERVATION',
] as const;
export type AssistantSourceType = (typeof ASSISTANT_SOURCE_TYPES)[number];

export const ASSISTANT_SENSITIVITIES = ['PUBLIC_METADATA', 'SECURITY_METADATA', 'REDACTED_SECURITY_EVIDENCE'] as const;
export type AssistantSensitivity = (typeof ASSISTANT_SENSITIVITIES)[number];

export interface AssistantQuestionRequest {
  question: string;
  /** One project-owned scan. Omit to use the latest completed scan(s) as applicable. */
  scanId?: string;
  /** Required with scanId; the ID is resolved only inside that authorized scan. */
  findingId?: string;
  /** Used only by the deterministic scan-comparison question. */
  compareScanId?: string;
}

export interface AssistantContextItem {
  sourceType: AssistantSourceType;
  sourceId: string;
  projectId: string;
  scanId?: string;
  content: string;
  sensitivity: AssistantSensitivity;
  createdAt?: string;
}

export interface AssistantEvidenceReference {
  sourceType: AssistantSourceType;
  sourceId: string;
  projectId: string;
  scanId?: string;
}

export interface AssistantContextSummary {
  itemCount: number;
  characterCount: number;
  redactedItems: number;
  truncated: boolean;
}

export interface AssistantResponse {
  state: AssistantState;
  mode: AssistantMode;
  providerState: AssistantProviderState;
  answer: string;
  facts: string[];
  interpretations: string[];
  recommendations: string[];
  limitations: string[];
  evidence: AssistantEvidenceReference[];
  context: AssistantContextSummary;
}

export interface AssistantStatusResponse {
  providerState: AssistantProviderState;
  providerId: string | null;
  deterministicQuestionsAvailable: true;
  conversationPersistence: 'NOT_IMPLEMENTED';
  toolsEnabled: false;
}

function exactKeys(record: Record<string, unknown>, allowed: readonly string[], required: readonly string[]): boolean {
  const keys = Object.keys(record);
  return keys.every((key) => allowed.includes(key)) && required.every((key) => Object.prototype.hasOwnProperty.call(record, key));
}

function boundedText(value: unknown, max: number, allowEmpty = false): value is string {
  if (typeof value !== 'string' || value.length > max || (!allowEmpty && value.length === 0)) return false;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if ((code < 0x20 && code !== 0x09 && code !== 0x0a) || code === 0x7f) return false;
  }
  return true;
}

export function isAssistantQuestionRequest(value: unknown): value is AssistantQuestionRequest {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  if (!exactKeys(record, ['question', 'scanId', 'findingId', 'compareScanId'], ['question']) ||
      !boundedText(record['question'], ASSISTANT_QUESTION_MAX_LENGTH) || record['question'].trim().length === 0) return false;
  if (record['scanId'] !== undefined && (typeof record['scanId'] !== 'string' || !SCAN_ID_PATTERN.test(record['scanId']))) return false;
  if (record['findingId'] !== undefined && (typeof record['findingId'] !== 'string' || !FINDING_ID_PATTERN.test(record['findingId']))) return false;
  if (record['compareScanId'] !== undefined && (typeof record['compareScanId'] !== 'string' || !SCAN_ID_PATTERN.test(record['compareScanId']))) return false;
  if (record['findingId'] !== undefined && record['scanId'] === undefined) return false;
  return true;
}

function isAssistantEvidenceReference(value: unknown): value is AssistantEvidenceReference {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  return exactKeys(record, ['sourceType', 'sourceId', 'projectId', 'scanId'], ['sourceType', 'sourceId', 'projectId']) &&
    typeof record['sourceType'] === 'string' && (ASSISTANT_SOURCE_TYPES as readonly string[]).includes(record['sourceType']) &&
    boundedText(record['sourceId'], 120) && typeof record['projectId'] === 'string' && PROJECT_ID_PATTERN.test(record['projectId']) &&
    (record['scanId'] === undefined || (typeof record['scanId'] === 'string' && SCAN_ID_PATTERN.test(record['scanId'])));
}

function boundedList(value: unknown): value is string[] {
  return Array.isArray(value) && value.length <= ASSISTANT_LIST_MAX && value.every((item) => boundedText(item, 500));
}

export function isAssistantResponse(value: unknown): value is AssistantResponse {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  if (!exactKeys(record, ['state', 'mode', 'providerState', 'answer', 'facts', 'interpretations', 'recommendations', 'limitations', 'evidence', 'context'],
      ['state', 'mode', 'providerState', 'answer', 'facts', 'interpretations', 'recommendations', 'limitations', 'evidence', 'context']) ||
      typeof record['state'] !== 'string' || !(ASSISTANT_STATES as readonly string[]).includes(record['state']) ||
      typeof record['mode'] !== 'string' || !(ASSISTANT_MODES as readonly string[]).includes(record['mode']) ||
      typeof record['providerState'] !== 'string' || !(ASSISTANT_PROVIDER_STATES as readonly string[]).includes(record['providerState']) ||
      !boundedText(record['answer'], ASSISTANT_RESPONSE_MAX_LENGTH) ||
      !boundedList(record['facts']) || !boundedList(record['interpretations']) ||
      !boundedList(record['recommendations']) || !boundedList(record['limitations']) ||
      !Array.isArray(record['evidence']) || record['evidence'].length > ASSISTANT_EVIDENCE_REFS_MAX ||
      !record['evidence'].every(isAssistantEvidenceReference)) return false;
  const context = record['context'];
  if (typeof context !== 'object' || context === null || Array.isArray(context)) return false;
  const summary = context as Record<string, unknown>;
  return exactKeys(summary, ['itemCount', 'characterCount', 'redactedItems', 'truncated'], ['itemCount', 'characterCount', 'redactedItems', 'truncated']) &&
    typeof summary['itemCount'] === 'number' && Number.isInteger(summary['itemCount']) && summary['itemCount'] >= 0 && summary['itemCount'] <= ASSISTANT_CONTEXT_MAX_ITEMS &&
    typeof summary['characterCount'] === 'number' && Number.isInteger(summary['characterCount']) && summary['characterCount'] >= 0 && summary['characterCount'] <= ASSISTANT_CONTEXT_MAX_LENGTH &&
    typeof summary['redactedItems'] === 'number' && Number.isInteger(summary['redactedItems']) && summary['redactedItems'] >= 0 && summary['redactedItems'] <= ASSISTANT_CONTEXT_MAX_ITEMS &&
    typeof summary['truncated'] === 'boolean';
}

export function isAssistantStatusResponse(value: unknown): value is AssistantStatusResponse {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  return exactKeys(record, ['providerState', 'providerId', 'deterministicQuestionsAvailable', 'conversationPersistence', 'toolsEnabled'],
    ['providerState', 'providerId', 'deterministicQuestionsAvailable', 'conversationPersistence', 'toolsEnabled']) &&
    typeof record['providerState'] === 'string' && (ASSISTANT_PROVIDER_STATES as readonly string[]).includes(record['providerState']) &&
    (record['providerId'] === null || boundedText(record['providerId'], 64)) &&
    (record['providerState'] === 'AVAILABLE' ? typeof record['providerId'] === 'string' : true) &&
    record['deterministicQuestionsAvailable'] === true && record['conversationPersistence'] === 'NOT_IMPLEMENTED' && record['toolsEnabled'] === false;
}

/** Lifecycle state is referenced here to keep assistant context contracts explicit. */
export type AssistantLifecycleState = FindingLifecycleState;
