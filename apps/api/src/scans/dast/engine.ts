import {
  MAX_FINDINGS_PER_SCAN,
  type Finding,
  type FindingSeverity,
  type ScanFailureCode,
  type ScanResultSummary,
} from '@drobon/shared';
import { INSPECTED_RESPONSE_HEADERS } from './observedHeaders.js';
import type { EngineOutcome, ScanEngine, ScanEngineContext } from '../engines.js';
import type { ScanRecord } from '../store.js';
import { DastHttpError, createNodeDastTransport, type DastProbeResponse, type DastTransport } from './http.js';
import { evaluateDastObservation, type DastRuleMatch } from './rules.js';
import type { DatasetService } from '../../external/service.js';
import { createDastTargetPolicy, DastTargetError, type DastTargetPolicy, type ResolvedDastTarget } from './target.js';
import { findingFingerprint } from '../findingIdentity.js';
import { createActiveDastEngine } from './activeEngine.js';

export const DAST_MAX_REQUESTS = 3;
export const DAST_MAX_REDIRECTS = 2;
export const DAST_MAX_RESPONSE_BYTES = 32_768;
export const DAST_REQUEST_TIMEOUT_MS = 5_000;
export const DAST_SCAN_DEADLINE_MS = 15_000;

export interface DastEngineOptions {
  targetPolicy?: DastTargetPolicy;
  transport?: DastTransport;
  now?: () => number;
  requestTimeoutMs?: number;
  scanDeadlineMs?: number;
  maxRequests?: number;
  maxRedirects?: number;
  maxResponseBytes?: number;
  /** Optional dataset DAST pack rules (evaluated alongside built-in rules). */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- legacy untyped boundary; new modules use unknown.
  packRules?: readonly { id: string; title: string; description: string; severity: import('@drobon/shared').FindingSeverity; cwe?: string; remediation: string; check: any }[];
  dataset?: DatasetService;
}

function statusCounts(findings: readonly Finding[]): Record<FindingSeverity, number> {
  return {
    CRITICAL: findings.filter((finding) => finding.severity === 'CRITICAL').length,
    HIGH: findings.filter((finding) => finding.severity === 'HIGH').length,
    MEDIUM: findings.filter((finding) => finding.severity === 'MEDIUM').length,
    LOW: findings.filter((finding) => finding.severity === 'LOW').length,
    INFO: findings.filter((finding) => finding.severity === 'INFO').length,
  };
}

function responseHeader(response: DastProbeResponse, name: string): string | undefined {
  const value = response.headers[name.toLowerCase()];
  if (Array.isArray(value)) return value[0];
  return typeof value === 'string' ? value : undefined;
}



function boundedResponseHeaders(headers: DastProbeResponse['headers']): DastProbeResponse['headers'] {
  const bounded: DastProbeResponse['headers'] = {};
  for (const name of INSPECTED_RESPONSE_HEADERS) {
    const value = headers[name];
    if (typeof value === 'string') bounded[name] = value.slice(0, 2048);
    else if (Array.isArray(value)) bounded[name] = value.slice(0, 5).map((entry) => entry.slice(0, 2048));
  }
  return bounded;
}

function boundProbeResponse(response: DastProbeResponse, maxBytes: number): DastProbeResponse | undefined {
  if (
    !Number.isInteger(response.status) || response.status < 100 || response.status > 599 ||
    typeof response.body !== 'string' || !Number.isFinite(response.elapsedMs) || response.elapsedMs < 0 ||
    typeof response.bodyTruncated !== 'boolean' || typeof response.headers !== 'object' || response.headers === null
  ) return undefined;
  const bytes = Buffer.from(response.body, 'utf8');
  const clipped = bytes.length > maxBytes;
  const body = clipped ? bytes.subarray(0, maxBytes).toString('utf8') : response.body;
  return {
    status: response.status,
    headers: boundedResponseHeaders(response.headers),
    body,
    bodyTruncated: response.bodyTruncated || clipped,
    elapsedMs: Math.min(15_000, Math.trunc(response.elapsedMs)),
  };
}

function safeContentType(response: DastProbeResponse): string | undefined {
  const value = responseHeader(response, 'content-type');
  if (value === undefined) return undefined;
  const mediaType = value.split(';', 1)[0]?.trim().toLowerCase();
  return mediaType !== undefined && /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/.test(mediaType)
    ? mediaType.slice(0, 120)
    : undefined;
}

function safeHeaderSummaries(response: DastProbeResponse): string[] {
  const headers: string[] = [];
  const value = (name: string): string | undefined => responseHeader(response, name)?.trim();
  const contentType = safeContentType(response);
  if (contentType !== undefined) headers.push(`Content-Type: ${contentType}`);
  for (const [name, label, expected] of [
    ['strict-transport-security', 'Strict-Transport-Security', undefined],
    ['x-content-type-options', 'X-Content-Type-Options', 'nosniff'],
    ['x-frame-options', 'X-Frame-Options', undefined],
    ['content-security-policy', 'Content-Security-Policy', undefined],
    ['access-control-allow-origin', 'Access-Control-Allow-Origin', undefined],
    ['access-control-allow-credentials', 'Access-Control-Allow-Credentials', undefined],
  ] as const) {
    const observed = value(name);
    if (observed === undefined) continue;
    if (name === 'access-control-allow-origin') {
      headers.push(`${label}: ${observed === '*' ? '*' : observed.toLowerCase() === 'https://drobon-aegis.invalid' ? 'synthetic probe origin' : 'other origin'}`);
    } else if (name === 'access-control-allow-credentials') {
      headers.push(`${label}: ${observed.toLowerCase() === 'true' ? 'true' : 'not true'}`);
    } else if (name === 'x-frame-options') {
      headers.push(`${label}: ${/^(deny|sameorigin)$/i.test(observed) ? observed.toLowerCase() : 'other value'}`);
    } else if (name === 'x-content-type-options') {
      headers.push(`${label}: ${observed.toLowerCase() === expected ? 'nosniff' : 'other value'}`);
    } else if (name === 'strict-transport-security') {
      headers.push(`${label}: present`);
    } else {
      headers.push(`${label}: present`);
    }
  }
  if (value('server') !== undefined) headers.push('Server: present');
  if (value('x-powered-by') !== undefined) headers.push('X-Powered-By: present');
  const cookies = response.headers['set-cookie'];
  if (Array.isArray(cookies) && cookies.length > 0) headers.push(`Set-Cookie: ${Math.min(cookies.length, 5)} header(s), values redacted`);
  return headers.slice(0, 12);
}

function buildFinding(
  record: ScanRecord,
  targetUrl: string,
  endpoint: string,
  response: DastProbeResponse,
  rule: DastRuleMatch,
  observedAt: string,
): Finding {
  const contentType = safeContentType(response);
  const fingerprint = findingFingerprint({
    scanner: 'DAST', projectId: record.projectId, ruleId: rule.ruleId,
    location: endpoint, evidence: rule.evidence,
    context: [targetUrl, 'GET', String(response.status)],
  });
  return {
    id: `fnd_${fingerprint.slice(0, 24)}`,
    scanId: record.id,
    ruleId: rule.ruleId,
    scanner: 'DAST',
    severity: rule.severity,
    title: rule.title,
    description: rule.description,
    ...(rule.cwe === undefined ? {} : { cwe: rule.cwe }),
    evidence: rule.evidence.slice(0, 200),
    remediation: rule.remediation,
    fingerprint,
    projectId: record.projectId,
    targetUrl,
    endpoint,
    method: 'GET',
    responseStatus: response.status,
    responseTimeMs: response.elapsedMs,
    ...(contentType === undefined ? {} : { contentType }),
    observedAt,
    observedHeaders: rule.observedHeaders.slice(0, 12),
  };
}

function failed(code: ScanFailureCode, message: string): EngineOutcome {
  return { kind: 'failed', failureCode: code, failureMessage: message };
}

function timedOut(code: 'DAST_REQUEST_TIMEOUT' | 'DAST_SCAN_TIMEOUT', message: string): EngineOutcome {
  return { kind: 'timed-out', failureCode: code, failureMessage: message };
}

function isRedirect(status: number): boolean {
  return status === 301 || status === 302 || status === 303 || status === 307 || status === 308;
}

/**
 * One explicit target, a bounded chain of same-host redirects, passive
 * response checks only. It never authenticates, crawls, executes content,
 * or sends a second class of probe.
 */
export function createDastEngine(options: DastEngineOptions = {}): ScanEngine {
  // If active mode requested, delegate to the safe active engine (bounded crawl+injection).
  // Keeps one scanType (DAST) with mode flag — passive is default, active requires consent.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- legacy untyped boundary; new modules use unknown.
  const activeDelegate = createActiveDastEngine(options as any);

  const policy = options.targetPolicy ?? createDastTargetPolicy();
  const transport = options.transport ?? createNodeDastTransport();
  const now = options.now ?? Date.now;
  const maxRequests = Math.min(DAST_MAX_REQUESTS, options.maxRequests ?? DAST_MAX_REQUESTS);
  const maxRedirects = Math.min(DAST_MAX_REDIRECTS, options.maxRedirects ?? DAST_MAX_REDIRECTS);
  const maxResponseBytes = Math.min(DAST_MAX_RESPONSE_BYTES, options.maxResponseBytes ?? DAST_MAX_RESPONSE_BYTES);
  const requestTimeoutMs = Math.min(DAST_REQUEST_TIMEOUT_MS, options.requestTimeoutMs ?? DAST_REQUEST_TIMEOUT_MS);
  const scanDeadlineMs = Math.min(DAST_SCAN_DEADLINE_MS, options.scanDeadlineMs ?? DAST_SCAN_DEADLINE_MS);

  return {
    scanType: 'DAST',
    execute: async (record: ScanRecord, context: ScanEngineContext): Promise<EngineOutcome> => {
      const anyRec = record as unknown as Record<string, unknown>;
      if (anyRec['dastMode'] === 'ACTIVE_SAFE') {
        return activeDelegate.execute(record, context);
      }
      const configuredUrl = record.dastTargetUrl;
      if (context.signal.aborted) return timedOut('DAST_SCAN_TIMEOUT', 'The DAST scan was interrupted before it started.');
      if (configuredUrl === undefined) {
        return failed('DAST_TARGET_NOT_FOUND', 'Configure a safe DAST target before requesting a scan.');
      }
      const startedAt = now();
      const deadline = startedAt + scanDeadlineMs;
      let current: ResolvedDastTarget;
      try {
        current = await policy.resolveNormalized(configuredUrl);
      } catch (error) {
        if (error instanceof DastTargetError) {
          return failed(error.code, 'The configured DAST target is unavailable or not permitted.');
        }
        return failed('DAST_DNS_FAILED', 'The configured DAST target could not be resolved safely.');
      }
      const originalHostname = current.hostname;
      const visited = new Set<string>();
      const observations: Array<{
        endpoint: string;
        method: 'GET';
        status: number;
        observedAt: string;
        responseTimeMs: number;
        bodyBytes: number;
        bodyTruncated: boolean;
        contentType?: string;
        headers: string[];
      }> = [];
      const findings: Finding[] = [];
      let redirectsFollowed = 0;
      let partialReason: string | undefined;

      while (observations.length < maxRequests) {
        if (context.signal.aborted || now() >= deadline) {
          return timedOut('DAST_SCAN_TIMEOUT', 'The DAST scan exceeded its execution deadline.');
        }
        if (visited.has(current.url)) {
          partialReason = 'A redirect loop was detected; the repeated URL was not requested again.';
          break;
        }
        visited.add(current.url);
        // Re-resolve immediately before each request. All answers must be
        // public and the socket is then pinned to the first vetted address.
        try {
          current = await policy.resolveNormalized(current.url);
        } catch (error) {
          if (observations.length === 0) {
            const code: ScanFailureCode = error instanceof DastTargetError ? error.code : 'DAST_DNS_FAILED';
            return failed(code, 'The DAST target did not pass the network safety check.');
          }
          partialReason = 'A redirect destination did not pass target safety checks and was not followed.';
          break;
        }
        const remainingMs = deadline - now();
        if (remainingMs <= 0) return timedOut('DAST_SCAN_TIMEOUT', 'The DAST scan exceeded its execution deadline.');
        let response: DastProbeResponse;
        try {
          response = await transport.probe(current, {
            timeoutMs: Math.max(1, Math.min(requestTimeoutMs, remainingMs)),
            maxResponseBytes,
            signal: context.signal,
          });
        } catch (error) {
          if (error instanceof DastHttpError && error.kind === 'timeout') {
            return timedOut('DAST_REQUEST_TIMEOUT', 'The DAST HTTP request timed out.');
          }
          if (context.signal.aborted || (error instanceof DastHttpError && error.kind === 'aborted')) {
            return timedOut('DAST_SCAN_TIMEOUT', 'The DAST scan was interrupted before it completed.');
          }
          return failed('DAST_REQUEST_FAILED', 'The DAST target did not return a usable HTTP response.');
        }
        if (context.signal.aborted || now() >= deadline) {
          return timedOut('DAST_SCAN_TIMEOUT', 'The DAST scan exceeded its execution deadline.');
        }
        const boundedResponse = boundProbeResponse(response, maxResponseBytes);
        if (boundedResponse === undefined) {
          return failed('DAST_REQUEST_FAILED', 'The DAST target did not return a usable HTTP response.');
        }
        response = boundedResponse;
        const observedAt = new Date(now()).toISOString();
        const contentType = safeContentType(response);
        const endpoint = current.url;
        const headerSummary = safeHeaderSummaries(response);
        observations.push({
          endpoint,
          method: 'GET',
          status: response.status,
          observedAt,
          responseTimeMs: response.elapsedMs,
          bodyBytes: Buffer.byteLength(response.body, 'utf8'),
          bodyTruncated: response.bodyTruncated,
          ...(contentType === undefined ? {} : { contentType }),
          headers: headerSummary,
        });
        const ruleMatches = evaluateDastObservation({
          url: endpoint,
          status: response.status,
          headers: response.headers,
          body: response.body,
          ...(contentType === undefined ? {} : { contentType }),
        });
        for (const rule of ruleMatches) {
          findings.push(buildFinding(record, configuredUrl, endpoint, response, rule, observedAt));
        }
        // Dataset DAST packs (honest extension — same finding model, same caps)
        // eslint-disable-next-line @typescript-eslint/no-explicit-any -- legacy untyped boundary; new modules use unknown.
        let allPackRules: typeof options.packRules = options.packRules as any;
        if (options.dataset?.configured) {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any -- legacy untyped boundary; new modules use unknown.
          try { const { getMergedDastRules } = await import('../../external/packIntegration.js'); const ds = await getMergedDastRules(options.dataset as any); if (ds.length > 0) allPackRules = ds as any; } catch { /* fail closed: optional path */ }
        }
        if (allPackRules && allPackRules.length > 0) {
          const { evaluatePackDastCheck } = await import('../../external/evaluator.js');
          for (const packRule of allPackRules) {
            let matched = false;
            // eslint-disable-next-line @typescript-eslint/no-explicit-any -- legacy untyped boundary; new modules use unknown.
            try { matched = evaluatePackDastCheck(packRule.check, { url: endpoint, status: response.status, headers: response.headers, body: response.body, contentType } as any); } catch { /* fail closed: optional path */ }
            if (matched) {
              // eslint-disable-next-line @typescript-eslint/no-explicit-any -- legacy untyped boundary; new modules use unknown.
              const packMatch = { ruleId: packRule.id, severity: packRule.severity, title: packRule.title, description: packRule.description, evidence: `Observed ${endpoint.slice(0,120)} → pack check ${packRule.check.type} matched.`, remediation: packRule.remediation, cwe: packRule.cwe, observedHeaders: [] } as any;
              findings.push(buildFinding(record, configuredUrl, endpoint, response, packMatch, observedAt));
              if (findings.length > MAX_FINDINGS_PER_SCAN) break;
            }
          }
        }
        if (response.bodyTruncated) {
          partialReason = 'The response body reached the configured inspection limit and was truncated.';
        }
        const location = responseHeader(response, 'location');
        if (!isRedirect(response.status) || location === undefined) break;
        if (redirectsFollowed >= maxRedirects || observations.length >= maxRequests) {
          partialReason = 'The redirect/request limit was reached; no additional request was made.';
          break;
        }
        try {
          const next = await policy.resolveRedirect(current, location, originalHostname);
          if (visited.has(next.url)) {
            partialReason = 'A redirect loop was detected; the repeated URL was not requested again.';
            break;
          }
          current = next;
        } catch {
          partialReason = 'A redirect was not followed because it failed the same-host, HTTPS, or address safety policy.';
          break;
        }
        redirectsFollowed += 1;
      }

      const truncated = findings.length > MAX_FINDINGS_PER_SCAN;
      const boundedFindings = findings.slice(0, MAX_FINDINGS_PER_SCAN);
      const partial = partialReason !== undefined;
      const result: ScanResultSummary = {
        findingsTotal: boundedFindings.length,
        findingsBySeverity: statusCounts(boundedFindings),
        requestsMade: observations.length,
        redirectsFollowed,
        ...(truncated ? { truncated: true } : {}),
        ...(partialReason === undefined ? {} : { partial: true, partialReason: partialReason.slice(0, 200) }),
      };
      return {
        kind: 'completed',
        resultSummary: result,
        findings: boundedFindings,
        dast: {
          targetUrl: configuredUrl,
          requestCount: observations.length,
          redirectsFollowed,
          partial,
          ...(partialReason === undefined ? {} : { partialReason: partialReason.slice(0, 200) }),
          observations,
        },
      };
    },
  };
}
