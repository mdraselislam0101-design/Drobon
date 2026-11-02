import { AGENT_ROLES, type AgentRoleId } from './roles.js';

/**
 * Local-model boundary for the Agent roles.
 *
 * This module is an INTEGRATION CONTRACT plus a fail-closed client — it is not
 * a model. No runtime or weights ship with the app, so the default state is
 * `NONE` and every completion returns UNAVAILABLE. Nothing here can reach a
 * paid or remote provider: the endpoint must be a literal loopback HTTP URL,
 * there is no fallback, and an invalid or oversized answer is rejected rather
 * than repaired.
 *
 * The model may only cite evidence ids that the caller already supplied, so a
 * hallucinated finding cannot enter a report as evidence. Reasoning QUALITY is
 * therefore unverified until an approved model and an independent benchmark
 * exist; this module does not claim otherwise.
 */

export const LOCAL_MODEL_MAX_RESPONSE_BYTES = 64 * 1024;
export const LOCAL_MODEL_DEFAULT_TIMEOUT_MS = 15_000;

export interface LocalModelConfig {
  /** Must be loopback http(s); anything else is refused at construction. */
  endpoint: string;
  model: string;
  timeoutMs?: number;
  maxResponseBytes?: number;
}

export type LocalModelAvailability =
  | { state: 'NONE' | 'UNAVAILABLE'; endpoint: null }
  | { state: 'READY'; endpoint: 'loopback' };

export interface LocalModelEvidenceRef {
  /** Opaque evidence identifier from this app; never source or secret text. */
  id: string;
  kind: string;
  summary: string;
}

export interface LocalModelRequest {
  role: AgentRoleId;
  /** Fixed policy text chosen by the app, never by the model or the user. */
  securityPolicy: string;
  task: string;
  untrustedEvidence: readonly LocalModelEvidenceRef[];
}

export interface LocalModelAnswer {
  role: AgentRoleId;
  conclusion: string;
  confidence: 'LOW' | 'MEDIUM' | 'HIGH';
  evidenceIds: string[];
  missingEvidence: string[];
  recommendation: string;
}

export type LocalModelResult =
  | { state: 'UNAVAILABLE'; reason: string }
  | { state: 'ANSWER'; answer: LocalModelAnswer };

const ANSWER_KEYS = ['confidence', 'conclusion', 'evidenceIds', 'missingEvidence', 'recommendation', 'role'] as const;
const CONFIDENCES = ['LOW', 'MEDIUM', 'HIGH'] as const;
const EVIDENCE_ID = /^[A-Za-z0-9:_.-]{1,120}$/;
const MAX_TEXT = 2_000;
const MAX_ITEMS = 32;

/** Loopback only: 127.0.0.0/8, ::1 and the literal `localhost` hostname. */
export function isLoopbackEndpoint(endpoint: string): boolean {
  let url: URL;
  try { url = new URL(endpoint); } catch { return false; }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return false;
  if (url.username !== '' || url.password !== '') return false;
  const hostname = url.hostname.toLowerCase();
  if (hostname === 'localhost' || hostname === '[::1]' || hostname === '::1') return true;
  const octets = hostname.split('.');
  return octets.length === 4 && octets[0] === '127' && octets.every((part) => /^\d{1,3}$/.test(part));
}

function validText(value: unknown, max = MAX_TEXT): value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > max) return false;
  // Reject ASCII control characters without a control-character regex.
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    if (code < 0x20 || code === 0x7f) return false;
  }
  return true;
}

function parseAnswer(role: AgentRoleId, body: unknown, allowed: ReadonlySet<string>): LocalModelAnswer | undefined {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) return undefined;
  const record = body as Record<string, unknown>;
  // Closed shape: an extra field means the model ignored the contract.
  if (Object.keys(record).length !== ANSWER_KEYS.length) return undefined;
  if (!ANSWER_KEYS.every((key) => Object.prototype.hasOwnProperty.call(record, key))) return undefined;
  if (record['role'] !== role) return undefined;
  if (!validText(record['conclusion']) || !validText(record['recommendation'])) return undefined;
  if (!(CONFIDENCES as readonly unknown[]).includes(record['confidence'])) return undefined;
  const evidenceIds = record['evidenceIds'];
  const missingEvidence = record['missingEvidence'];
  if (!Array.isArray(evidenceIds) || evidenceIds.length > MAX_ITEMS || !evidenceIds.every((id) => typeof id === 'string' && EVIDENCE_ID.test(id))) {
    return undefined;
  }
  if (!Array.isArray(missingEvidence) || missingEvidence.length > MAX_ITEMS || !missingEvidence.every((item) => validText(item, 300))) {
    return undefined;
  }
  // A citation the caller never supplied is fabricated evidence: refuse it.
  if (!evidenceIds.every((id) => allowed.has(id))) return undefined;
  return {
    role,
    conclusion: record['conclusion'],
    confidence: record['confidence'] as LocalModelAnswer['confidence'],
    evidenceIds: evidenceIds as string[],
    missingEvidence: missingEvidence as string[],
    recommendation: record['recommendation'],
  };
}

export interface LocalModelFetch {
  (input: string, init: { method: string; headers: Record<string, string>; body: string; signal: AbortSignal }): Promise<{
    ok: boolean;
    status: number;
    text(): Promise<string>;
  }>;
}

export interface LocalModelDependencies {
  config?: LocalModelConfig | undefined;
  fetchImpl?: LocalModelFetch | undefined;
}

export interface LocalModelProvider {
  availability(): LocalModelAvailability;
  /** Never fabricates: every non-answer path returns UNAVAILABLE with a code. */
  complete(request: LocalModelRequest): Promise<LocalModelResult>;
}

/**
 * @throws when a configured endpoint is not loopback — refuse to start rather
 * than risk sending source, secrets or assessment data to a remote service.
 */
export function createLocalModelProvider(dependencies: LocalModelDependencies = {}): LocalModelProvider {
  const config = dependencies.config;
  if (config === undefined) {
    return {
      availability: () => ({ state: 'NONE', endpoint: null }),
      complete: async () => ({ state: 'UNAVAILABLE', reason: 'no-local-model-configured' }),
    };
  }
  if (!isLoopbackEndpoint(config.endpoint)) {
    throw new Error('Local model endpoint must be a loopback http(s) URL; remote providers are not permitted.');
  }
  if (config.model.trim().length === 0 || config.model.length > 200) {
    throw new Error('Local model name must be a short non-empty identifier.');
  }
  const timeoutMs = config.timeoutMs ?? LOCAL_MODEL_DEFAULT_TIMEOUT_MS;
  const maxBytes = config.maxResponseBytes ?? LOCAL_MODEL_MAX_RESPONSE_BYTES;
  const endpoint = config.endpoint;
  const model = config.model;

  return {
    availability: () => ({ state: 'READY', endpoint: 'loopback' }),
    complete: async (request) => {
      const role = AGENT_ROLES[request.role];
      if (role === undefined) return { state: 'UNAVAILABLE', reason: 'unknown-role' };
      const ids = new Set(request.untrustedEvidence.map((item) => item.id));
      const payload = {
        model,
        // Evidence is data, never instructions: it is delivered in its own field.
        system: `${request.securityPolicy}\nRole: ${role.title}. ${role.responsibility} ` +
          'Return exactly one JSON object with keys confidence, conclusion, evidenceIds, missingEvidence, recommendation, role. ' +
          'Cite only supplied evidence ids. Never invent a tool result or a finding.',
        task: request.task,
        untrustedEvidence: request.untrustedEvidence.map(({ id, kind, summary }) => ({ id, kind, summary })),
      };
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      const fetchImpl = dependencies.fetchImpl ?? (globalThis.fetch as unknown as LocalModelFetch | undefined);
      if (fetchImpl === undefined) return { state: 'UNAVAILABLE', reason: 'no-fetch-available' };
      try {
        const response = await fetchImpl(endpoint, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify(payload),
          signal: controller.signal,
        });
        if (!response.ok) return { state: 'UNAVAILABLE', reason: `http-${response.status}` };
        const text = await response.text();
        if (text.length > maxBytes) return { state: 'UNAVAILABLE', reason: 'response-too-large' };
        let parsed: unknown;
        try { parsed = JSON.parse(text) as unknown; } catch { return { state: 'UNAVAILABLE', reason: 'invalid-json' }; }
        const answer = parseAnswer(request.role, parsed, ids);
        return answer === undefined ? { state: 'UNAVAILABLE', reason: 'contract-violation' } : { state: 'ANSWER', answer };
      } catch (error) {
        const aborted = controller.signal.aborted || (error as { name?: string }).name === 'AbortError';
        return { state: 'UNAVAILABLE', reason: aborted ? 'timeout' : 'transport-error' };
      } finally {
        clearTimeout(timer);
      }
    },
  };
}
