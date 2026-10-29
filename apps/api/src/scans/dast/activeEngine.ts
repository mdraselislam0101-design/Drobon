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
import { extractCrawlCandidates, injectionPointsFromUrls, buildInjectedUrl } from './crawler.js';
import { payloadsForBudget, type ActivePayload } from './payloads.js';
import { isDastRequestAuthorized, type DastRequestAuthorizer } from './authorization.js';
import { analyzeDastResponseAst, type DastAstObservation, type DastAstRule } from './ast.js';

/**
 * Active DAST engine — safe, bounded, opt-in complement to passive DAST.
 *
 * Scope (paid-tool parity):
 * - crawls at most 10 same-host links from the baseline response (static HTML only, no JS)
 * - injects at most 1 safe payload per discovered point (GET only, max 10 injections)
 * - total requests ≤ 20 (passive is 3), redirects ≤ 2, deadline 30s, throttle 200ms between probes
 * - only synthetic payloads from payloads.ts (no user-supplied payloads, no POST/PUT/DELETE)
 * - every URL re-validated by DastTargetPolicy before use (public address, same-host, HTTPS downgrade blocked)
 * - findings are observations, never proof of exploitability; absence is not proof of safety
 *
 * Consent: the scan record must carry dastActiveConsent=true (set via the scan creation route
 * when the user explicitly confirms they have permission to test the target). Without it
 * the engine fails closed with DAST_ACTIVE_CONSENT_REQUIRED.
 */

export const ACTIVE_DAST_MAX_REQUESTS = 20;
export const ACTIVE_DAST_MAX_CRAWL_LINKS = 10;
export const ACTIVE_DAST_MAX_INJECTIONS = 10;
export const ACTIVE_DAST_MAX_REDIRECTS = 2;
export const ACTIVE_DAST_MAX_RESPONSE_BYTES = 32_768;
export const ACTIVE_DAST_REQUEST_TIMEOUT_MS = 5_000;
export const ACTIVE_DAST_SCAN_DEADLINE_MS = 30_000;
export const ACTIVE_DAST_THROTTLE_MS = 200;

export interface ActiveDastEngineOptions {
  targetPolicy?: DastTargetPolicy;
  transport?: DastTransport;
  now?: () => number;
  requestTimeoutMs?: number;
  scanDeadlineMs?: number;
  maxRequests?: number;
  maxRedirects?: number;
  maxResponseBytes?: number;
  throttleMs?: number;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- legacy untyped boundary; new modules use unknown.
  packRules?: readonly { id: string; title: string; description: string; severity: FindingSeverity; category?: string; cwe?: string; remediation: string; check: any }[];
  dataset?: DatasetService;
  /** Revalidate assessment-linked authorization before each request. */
  authorize?: DastRequestAuthorizer;
}

function statusCounts(findings: readonly Finding[]): Record<FindingSeverity, number> {
  return {
    CRITICAL: findings.filter((f) => f.severity === 'CRITICAL').length,
    HIGH: findings.filter((f) => f.severity === 'HIGH').length,
    MEDIUM: findings.filter((f) => f.severity === 'MEDIUM').length,
    LOW: findings.filter((f) => f.severity === 'LOW').length,
    INFO: findings.filter((f) => f.severity === 'INFO').length,
  };
}

function responseHeader(response: DastProbeResponse, name: string): string | undefined {
  const v = response.headers[name.toLowerCase()];
  if (Array.isArray(v)) return v[0];
  return typeof v === 'string' ? v : undefined;
}



function boundedHeaders(headers: DastProbeResponse['headers']): DastProbeResponse['headers'] {
  const b: DastProbeResponse['headers'] = {};
  for (const n of INSPECTED_RESPONSE_HEADERS) {
    const v = headers[n];
    if (typeof v === 'string') b[n] = v.slice(0, 2048);
    else if (Array.isArray(v)) b[n] = v.slice(0, 5).map((e) => e.slice(0, 2048));
  }
  return b;
}

function boundProbeResponse(resp: DastProbeResponse, maxBytes: number): DastProbeResponse | undefined {
  if (!Number.isInteger(resp.status) || resp.status < 100 || resp.status > 599 ||
      typeof resp.body !== 'string' || !Number.isFinite(resp.elapsedMs) || resp.elapsedMs < 0 ||
      typeof resp.bodyTruncated !== 'boolean' || typeof resp.headers !== 'object' || resp.headers === null) return undefined;
  const bytes = Buffer.from(resp.body, 'utf8');
  const clipped = bytes.length > maxBytes;
  let body = clipped ? bytes.subarray(0, maxBytes).toString('utf8') : resp.body;
  while (body.length > 0 && Buffer.byteLength(body, 'utf8') > Math.max(0, maxBytes)) body = body.slice(0, -1);
  // Findings and their observation must use the same contract-bounded time.
  return { status: resp.status, headers: boundedHeaders(resp.headers), body, bodyTruncated: resp.bodyTruncated || clipped, elapsedMs: Math.min(15_000, Math.trunc(resp.elapsedMs)) };
}

function safeContentType(resp: DastProbeResponse): string | undefined {
  const v = responseHeader(resp, 'content-type');
  if (v === undefined) return undefined;
  const mt = v.split(';', 1)[0]?.trim().toLowerCase();
  return mt !== undefined && /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/.test(mt) ? mt.slice(0, 120) : undefined;
}

function safeHeaderSummaries(resp: DastProbeResponse): string[] {
  const hdrs: string[] = [];
  const val = (n: string): string | undefined => responseHeader(resp, n)?.trim();
  const ct = safeContentType(resp);
  if (ct !== undefined) hdrs.push(`Content-Type: ${ct}`);
  for (const [n, label, expected] of [
    ['strict-transport-security', 'Strict-Transport-Security', undefined],
    ['x-content-type-options', 'X-Content-Type-Options', 'nosniff'],
    ['x-frame-options', 'X-Frame-Options', undefined],
    ['content-security-policy', 'Content-Security-Policy', undefined],
    ['access-control-allow-origin', 'Access-Control-Allow-Origin', undefined],
    ['access-control-allow-credentials', 'Access-Control-Allow-Credentials', undefined],
  ] as const) {
    const ob = val(n);
    if (ob === undefined) continue;
    if (n === 'access-control-allow-origin') hdrs.push(`${label}: ${ob === '*' ? '*' : ob.toLowerCase() === 'https://drobon-aegis.invalid' ? 'synthetic probe origin' : 'other origin'}`);
    else if (n === 'access-control-allow-credentials') hdrs.push(`${label}: ${ob.toLowerCase() === 'true' ? 'true' : 'not true'}`);
    else if (n === 'x-frame-options') hdrs.push(`${label}: ${/^(deny|sameorigin)$/i.test(ob) ? ob.toLowerCase() : 'other value'}`);
    else if (n === 'x-content-type-options') hdrs.push(`${label}: ${ob.toLowerCase() === expected ? 'nosniff' : 'other value'}`);
    else hdrs.push(`${label}: present`);
  }
  if (val('server') !== undefined) hdrs.push('Server: present');
  if (val('x-powered-by') !== undefined) hdrs.push('X-Powered-By: present');
  const cookies = resp.headers['set-cookie'];
  if (Array.isArray(cookies) && cookies.length > 0) hdrs.push(`Set-Cookie: ${Math.min(cookies.length, 5)} header(s), values redacted`);
  return hdrs.slice(0, 12);
}

function buildFinding(record: ScanRecord, targetUrl: string, endpoint: string, response: DastProbeResponse, rule: DastRuleMatch, observedAt: string): Finding {
  const ct = safeContentType(response);
  const fp = findingFingerprint({ scanner: 'DAST', projectId: record.projectId, ruleId: rule.ruleId, location: endpoint, evidence: rule.evidence, context: [targetUrl, 'GET', String(response.status)] });
  return { id: `fnd_${fp.slice(0,24)}`, scanId: record.id, ruleId: rule.ruleId, scanner: 'DAST', severity: rule.severity, title: rule.title, description: rule.description, ...(rule.cwe === undefined ? {} : { cwe: rule.cwe }), evidence: rule.evidence.slice(0,200), remediation: rule.remediation, fingerprint: fp, projectId: record.projectId, targetUrl, endpoint, method: 'GET', responseStatus: response.status, responseTimeMs: response.elapsedMs, ...(ct === undefined ? {} : { contentType: ct }), observedAt, observedHeaders: rule.observedHeaders.slice(0,12) };
}

function failed(code: ScanFailureCode, msg: string): EngineOutcome { return { kind: 'failed', failureCode: code, failureMessage: msg }; }
function timedOut(code: 'DAST_REQUEST_TIMEOUT' | 'DAST_SCAN_TIMEOUT', msg: string): EngineOutcome { return { kind: 'timed-out', failureCode: code, failureMessage: msg }; }
function isRedirect(s: number): boolean { return s===301||s===302||s===303||s===307||s===308; }

function activeReflectionFinding(_record: ScanRecord, _targetUrl: string, endpoint: string, response: DastProbeResponse, payload: ActivePayload, _observedAt: string): DastRuleMatch | undefined {
  // Check body or relevant header depending on category.
  let reflected = false;
  if (payload.category === 'open-redirect' || payload.category === 'crlf-injection') {
    const loc = responseHeader(response, 'location') ?? '';
    const allHeaders = JSON.stringify(response.headers);
    reflected = payload.detector.test(loc) || payload.detector.test(allHeaders);
  } else {
    reflected = payload.detector.test(response.body);
  }
  if (!reflected) return undefined;
  const severity: FindingSeverity = payload.category === 'xss-reflected' ? 'MEDIUM' : payload.category === 'sqli-error' ? 'HIGH' : 'LOW';
  // Active markers are built-in probe observations, not dataset rule IDs.
  // Numeric DG identifiers satisfy the persisted Finding contract.
  const ruleIdByCategory: Record<ActivePayload['category'], string> = {
    'xss-reflected': 'DG-DAST-990001', 'sqli-error': 'DG-DAST-990002',
    'open-redirect': 'DG-DAST-990003', 'path-traversal': 'DG-DAST-990004',
    'crlf-injection': 'DG-DAST-990005',
  };
  return {
    ruleId: ruleIdByCategory[payload.category],
    severity,
    title: `Active probe: ${payload.description}`,
    description: `A bounded active probe produced a matching response observation from ${endpoint.slice(0,80)}. This is not confirmed exploitability — verify manually.`,
    evidence: `Payload ${payload.id} (${payload.category}) matched a response at ${endpoint.slice(0,100)} — verify manually.`,
    remediation: 'Validate and encode user input before reflection; apply output encoding and parameterized queries.',
    ...(payload.category === 'xss-reflected' ? { cwe: 'CWE-79' } : payload.category === 'sqli-error' ? { cwe: 'CWE-89' } : payload.category === 'open-redirect' ? { cwe: 'CWE-601' } : {}),
    observedHeaders: [],
  };
}

export function createActiveDastEngine(options: ActiveDastEngineOptions = {}): ScanEngine {
  const policy = options.targetPolicy ?? createDastTargetPolicy();
  const transport = options.transport ?? createNodeDastTransport();
  const now = options.now ?? Date.now;
  const maxRequests = Math.min(ACTIVE_DAST_MAX_REQUESTS, options.maxRequests ?? ACTIVE_DAST_MAX_REQUESTS);
  const maxRedirects = Math.min(ACTIVE_DAST_MAX_REDIRECTS, options.maxRedirects ?? ACTIVE_DAST_MAX_REDIRECTS);
  const maxResponseBytes = Math.min(ACTIVE_DAST_MAX_RESPONSE_BYTES, options.maxResponseBytes ?? ACTIVE_DAST_MAX_RESPONSE_BYTES);
  const requestTimeoutMs = Math.min(ACTIVE_DAST_REQUEST_TIMEOUT_MS, options.requestTimeoutMs ?? ACTIVE_DAST_REQUEST_TIMEOUT_MS);
  const scanDeadlineMs = Math.min(ACTIVE_DAST_SCAN_DEADLINE_MS, options.scanDeadlineMs ?? ACTIVE_DAST_SCAN_DEADLINE_MS);
  const throttleMs = Math.max(0, Math.min(1000, options.throttleMs ?? ACTIVE_DAST_THROTTLE_MS));

  return {
    scanType: 'DAST' as const, // Active shares DAST scanType; mode is in record.dastMode (passive is default, active requires consent)
    execute: async (record: ScanRecord, context: ScanEngineContext): Promise<EngineOutcome> => {
      const configuredUrl = record.dastTargetUrl;
      if (context.signal.aborted) return timedOut('DAST_SCAN_TIMEOUT', 'The active DAST scan was interrupted before it started.');
      if (configuredUrl === undefined) return failed('DAST_TARGET_NOT_FOUND', 'Configure a safe DAST target before requesting a scan.');
      // Consent gate: active requires explicit opt-in stored on the record.
      const recAny = record as unknown as Record<string, unknown>;
      const activeMode = recAny['dastMode'] === 'ACTIVE' || recAny['dastMode'] === 'ACTIVE_SAFE';
      if (activeMode && recAny['dastActiveConsent'] !== true) {
        return failed('DAST_TARGET_BLOCKED', 'Active DAST requires explicit permission confirmation for the target.');
      }
      // If not active mode, delegate to passive behavior (keep single engine backward compatible).
      // But we are the active engine — if passive requested, we still run passive baseline safely.
      const isActive = activeMode;

      const startedAt = now();
      const deadline = startedAt + scanDeadlineMs;
      let current: ResolvedDastTarget;
      try { current = await policy.resolveNormalized(configuredUrl); } catch (error) {
        if (error instanceof DastTargetError) return failed(error.code, 'The configured DAST target is unavailable or not permitted.');
        return failed('DAST_DNS_FAILED', 'The configured DAST target could not be resolved safely.');
      }
      const originalHostname = current.hostname;
      const visited = new Set<string>();
      const observations: Array<{ endpoint: string; method: 'GET'; status: number; observedAt: string; responseTimeMs: number; bodyBytes: number; bodyTruncated: boolean; contentType?: string; headers: string[]; }> = [];
      const findings: Finding[] = [];
      let redirectsFollowed = 0;
      let partialReason: string | undefined;
      let baselineBody = '';
      let authorizationRefused = false;
      let astObservation: DastAstObservation | undefined;
      let probingBaseline = true;
      // The same response rules apply to every bounded probe in this scan.
      let allPackRules = options.packRules ?? [];
      if (options.dataset?.configured) {
        try {
          const { getMergedDastRules } = await import('../../external/packIntegration.js');
          const loaded = await getMergedDastRules(options.dataset);
          if (loaded.length > 0) allPackRules = loaded;
        } catch { /* optional pack unavailable; coverage is marked below */ }
      }
      const astRules: readonly DastAstRule[] = allPackRules;
      const markMissingRules = (): void => {
        if (allPackRules.length === 0) {
          partialReason = `${partialReason === undefined ? '' : `${partialReason} `}No DAST response rules were available.`.slice(0, 200);
        }
      };
      const applyAst = async () => {
        const ast = await analyzeDastResponseAst({ record, ...(astObservation === undefined ? {} : { observation: astObservation }),
          rules: astRules, signal: context.signal, remainingMs: deadline - now(), availableFindings: MAX_FINDINGS_PER_SCAN - findings.length });
        findings.push(...ast.findings);
        if (ast.summary.status === 'PARTIAL' && partialReason === undefined) partialReason = 'Response script AST analysis was incomplete; see AST coverage.';
        return ast.summary;
      };

      // Helper to probe one URL (with re-resolve, throttle, bounded response, passive+active checks)
      const probeOne = async (url: string, payload?: ActivePayload): Promise<{ response: DastProbeResponse; bounded: DastProbeResponse; endpoint: string } | undefined> => {
        if (context.signal.aborted || now() >= deadline) return undefined;
        if (!(await isDastRequestAuthorized(record, url, options.authorize))) {
          authorizationRefused = true;
          partialReason = 'A request was skipped because the linked assessment scope or authorization no longer permits it.';
          return undefined;
        }
        if (visited.has(url)) { partialReason = 'A redirect loop was detected; the repeated URL was not requested again.'; return undefined; }
        visited.add(url);
        let resolved: ResolvedDastTarget;
        try { resolved = await policy.resolveNormalized(url); } catch {
          if (observations.length === 0) return undefined;
          partialReason = url.includes('?')
            ? 'Query-bearing crawl URLs are not supported by the current target safety policy and were not requested.'
            : 'A crawl or probe destination did not pass target safety checks and was not requested.';
          return undefined;
        }
        // Throttle between requests (except first).
        if (observations.length > 0 && throttleMs > 0) {
          const wait = Math.min(throttleMs, Math.max(0, deadline - now()));
          if (wait > 0) await new Promise<void>((r) => setTimeout(r, wait));
          if (context.signal.aborted || now() >= deadline) return undefined;
        }
        const remainingMs = deadline - now();
        if (remainingMs <= 0) return undefined;
        // Recheck after DNS and throttling, immediately before transport.
        if (!(await isDastRequestAuthorized(record, url, options.authorize))) {
          authorizationRefused = true;
          partialReason = 'A request was skipped because the linked assessment scope or authorization no longer permits it.';
          return undefined;
        }
        let resp: DastProbeResponse;
        try {
          resp = await transport.probe(resolved, { timeoutMs: Math.max(1, Math.min(requestTimeoutMs, remainingMs)), maxResponseBytes, signal: context.signal });
        } catch (error) {
          if (error instanceof DastHttpError && error.kind === 'timeout') throw new Error('timeout');
          if (context.signal.aborted || (error instanceof DastHttpError && error.kind === 'aborted')) throw new Error('aborted');
          if (observations.length > 0) partialReason ??= 'A permitted active request failed; its response was not assessed.';
          return undefined;
        }
        const bounded = boundProbeResponse(resp, maxResponseBytes);
        if (bounded === undefined) {
          if (observations.length > 0) partialReason ??= 'An active response was unusable and was not assessed.';
          return undefined;
        }
        resp = bounded;
        const observedAt = new Date(now()).toISOString();
        const ct = safeContentType(resp);
        const endpoint = resolved.url;
        const headerSummary = safeHeaderSummaries(resp);
        if (probingBaseline && astObservation === undefined && !isRedirect(resp.status)) {
          astObservation = { endpoint, content: resp.body, ...(ct === undefined ? {} : { contentType: ct }),
            bodyTruncated: resp.bodyTruncated, responseStatus: resp.status, responseTimeMs: resp.elapsedMs, observedAt };
        }
        observations.push({ endpoint, method: 'GET', status: resp.status, observedAt, responseTimeMs: resp.elapsedMs, bodyBytes: Buffer.byteLength(resp.body, 'utf8'), bodyTruncated: resp.bodyTruncated, ...(ct === undefined ? {} : { contentType: ct }), headers: headerSummary });
        // Passive checks on every response (same as passive engine)
        const passiveMatches = evaluateDastObservation({ url: endpoint, status: resp.status, headers: resp.headers, body: resp.body, ...(ct === undefined ? {} : { contentType: ct }) });
        for (const rule of passiveMatches) findings.push(buildFinding(record, configuredUrl, endpoint, resp, rule, observedAt));
        // Active reflection check if this was an injection
        if (payload !== undefined) {
          const activeMatch = activeReflectionFinding(record, configuredUrl, endpoint, resp, payload, observedAt);
          if (activeMatch) findings.push(buildFinding(record, configuredUrl, endpoint, resp, activeMatch, observedAt));
        }
        // Dataset packs
        if (allPackRules.length > 0) {
          const { evaluatePackDastCheck } = await import('../../external/evaluator.js');
          for (const packRule of allPackRules) {
            let matched=false;
            // eslint-disable-next-line @typescript-eslint/no-explicit-any -- legacy untyped boundary; new modules use unknown.
            try { matched = evaluatePackDastCheck(packRule.check, { url: endpoint, status: resp.status, headers: resp.headers, body: resp.body, contentType: ct } as any); } catch { /* fail closed: optional path */ }
            if (matched) {
              // eslint-disable-next-line @typescript-eslint/no-explicit-any -- legacy untyped boundary; new modules use unknown.
              const pm = { ruleId: packRule.id, severity: packRule.severity, title: packRule.title, description: packRule.description, evidence: `Observed ${endpoint.slice(0,120)} → pack check ${packRule.check.type} matched.`, remediation: packRule.remediation, cwe: packRule.cwe, observedHeaders: [] } as any;
              findings.push(buildFinding(record, configuredUrl, endpoint, resp, pm, observedAt));
              if (findings.length > MAX_FINDINGS_PER_SCAN) break;
            }
          }
        }
        if (resp.bodyTruncated) partialReason = 'The response body reached the configured inspection limit and was truncated.';
        return { response: resp, bounded: resp, endpoint };
      };

      // Phase 1: Baseline passive probe (1 request, may follow redirects up to 2)
      let baselineResult: Awaited<ReturnType<typeof probeOne>> | undefined;
      while (observations.length < (isActive ? 1 : maxRequests)) {
        const urlToProbe = current.url;
        try {
          const res = await probeOne(urlToProbe);
          if (!res) break;
          baselineResult = res;
          baselineBody = res.bounded.body;
        } catch (e) {
          if ((e as Error).message === 'timeout') return timedOut('DAST_REQUEST_TIMEOUT', 'The DAST HTTP request timed out.');
          if ((e as Error).message === 'aborted') return timedOut('DAST_SCAN_TIMEOUT', 'The DAST scan was interrupted before it completed.');
          return failed('DAST_REQUEST_FAILED', 'The DAST target did not return a usable HTTP response.');
        }
        const loc = responseHeader(baselineResult!.bounded, 'location');
        if (!isRedirect(baselineResult!.bounded.status) || loc === undefined) break;
        // Active mode has a one-request baseline budget. Do not claim a
        // redirect was followed when the loop will not actually request it.
        if (isActive || redirectsFollowed >= maxRedirects || observations.length >= maxRequests) { partialReason = 'The redirect/request limit was reached; no additional request was made.'; break; }
        try {
          const next = await policy.resolveRedirect(current, loc, originalHostname);
          if (visited.has(next.url)) { partialReason = 'A redirect loop was detected; the repeated URL was not requested again.'; break; }
          current = next;
        } catch { partialReason = 'A redirect was not followed because it failed the same-host, HTTPS, or address safety policy.'; break; }
        redirectsFollowed += 1;
      }

      probingBaseline = false;
      if (observations.length === 0) {
        return authorizationRefused
          ? failed('DAST_TARGET_BLOCKED', 'The linked assessment does not authorize this DAST request.')
          : failed('DAST_REQUEST_FAILED', 'The DAST target did not return a usable HTTP response.');
      }
      if (!isActive) {
        // Passive mode: done after baseline (matches existing engine behavior but we already handled it)
        const astSupplement = await applyAst();
        if (context.signal.aborted || now() >= deadline) return timedOut('DAST_SCAN_TIMEOUT', 'The DAST scan exceeded its execution deadline.');
        markMissingRules();
        const truncated = findings.length > MAX_FINDINGS_PER_SCAN;
        if (truncated) partialReason = `${partialReason === undefined ? '' : `${partialReason} `}Finding details reached the configured cap.`.slice(0, 200);
        const bounded = findings.slice(0, MAX_FINDINGS_PER_SCAN);
        const partial = partialReason !== undefined;
        const result: ScanResultSummary = { astSupplement, findingsTotal: bounded.length, findingsBySeverity: statusCounts(bounded), requestsMade: observations.length, redirectsFollowed, ...(truncated?{truncated:true}:{}), ...(partial?{partial:true, partialReason: partialReason!.slice(0,200)}:{}) };
        return { kind: 'completed', resultSummary: result, findings: bounded, dast: { targetUrl: configuredUrl, requestCount: observations.length, redirectsFollowed, partial, ...(partialReason===undefined?{}:{partialReason: partialReason.slice(0,200)}), observations } };
      }

      // Phase 2: Active crawl (only if active and we have budget left)
      if (now() >= deadline || context.signal.aborted) return timedOut('DAST_SCAN_TIMEOUT', 'The active DAST scan exceeded its execution deadline.');
      const crawlLinks = extractCrawlCandidates(baselineBody, configuredUrl, ACTIVE_DAST_MAX_CRAWL_LINKS);
      // Dedupe against already visited; keep only unvisited
      const newLinks = crawlLinks.filter((u) => !visited.has(u)).slice(0, ACTIVE_DAST_MAX_CRAWL_LINKS);

      // Phase 2a: Probe crawled URLs (passive checks on each, throttled)
      for (const link of newLinks) {
        if (observations.length >= maxRequests) { partialReason = 'The active DAST request limit was reached; remaining crawl targets were not probed.'; break; }
        if (now() >= deadline || context.signal.aborted) break;
        try { await probeOne(link); } catch (e) {
          if ((e as Error).message === 'timeout') return timedOut('DAST_REQUEST_TIMEOUT', 'The DAST HTTP request timed out.');
          if ((e as Error).message === 'aborted') return timedOut('DAST_SCAN_TIMEOUT', 'The DAST scan was interrupted before it completed.');
        }
      }

      // Phase 3: Active injection (safe payloads on query/path points)
      const allUrls = [configuredUrl, ...newLinks];
      const points = injectionPointsFromUrls(allUrls).slice(0, ACTIVE_DAST_MAX_INJECTIONS);
      const payloads = payloadsForBudget(1); // 1 payload per point to bound requests
      for (const point of points) {
        if (observations.length >= maxRequests) { partialReason = 'The active DAST request limit was reached; remaining injection probes were skipped.'; break; }
        if (now() >= deadline || context.signal.aborted) break;
        for (const payload of payloads.slice(0,1)) {
          if (observations.length >= maxRequests) break;
          const injected = buildInjectedUrl(point, payload.value);
          if (!injected) continue;
          // Validate injected URL still passes policy before probing. In particular,
          // query-bearing URLs are forbidden by the existing target policy; do
          // not silently imply they were inspected or weaken the SSRF boundary.
          try { await policy.resolveNormalized(injected); } catch {
            partialReason ??= point.param === '__path__'
              ? 'Some active probe URLs did not pass target safety checks and were not requested.'
              : 'Query-parameter probes are not supported by the current target safety policy and were not requested.';
            continue;
          }
          try { await probeOne(injected, payload); } catch (e) {
            if ((e as Error).message === 'timeout') return timedOut('DAST_REQUEST_TIMEOUT', 'The DAST HTTP request timed out.');
            if ((e as Error).message === 'aborted') return timedOut('DAST_SCAN_TIMEOUT', 'The DAST scan was interrupted before it completed.');
          }
          break; // 1 payload per point
        }
      }

      const astSupplement = await applyAst();
      if (context.signal.aborted || now() >= deadline) return timedOut('DAST_SCAN_TIMEOUT', 'The active DAST scan exceeded its execution deadline.');
      markMissingRules();
      const truncated = findings.length > MAX_FINDINGS_PER_SCAN;
      if (truncated) partialReason = `${partialReason === undefined ? '' : `${partialReason} `}Finding details reached the configured cap.`.slice(0, 200);
      const boundedFindings = findings.slice(0, MAX_FINDINGS_PER_SCAN);
      const partial = partialReason !== undefined;
      const result: ScanResultSummary = { astSupplement, findingsTotal: boundedFindings.length, findingsBySeverity: statusCounts(boundedFindings), requestsMade: observations.length, redirectsFollowed, ...(truncated?{truncated:true}:{}), ...(partial?{partial:true, partialReason: partialReason!.slice(0,200)}:{}) };
      return { kind: 'completed', resultSummary: result, findings: boundedFindings, dast: { targetUrl: configuredUrl, mode: 'ACTIVE_SAFE', requestCount: observations.length, redirectsFollowed, partial, ...(partialReason===undefined?{}:{partialReason: partialReason.slice(0,200)}), observations } };
    },
  };
}
