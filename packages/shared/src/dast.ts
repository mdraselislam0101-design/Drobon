import { isRecord } from './guards.js';

/** One real, bounded HTTP response observed by the passive DAST probe. */
export interface DastObservation {
  endpoint: string;
  method: 'GET';
  status: number;
  observedAt: string;
  responseTimeMs: number;
  bodyBytes: number;
  bodyTruncated: boolean;
  /** Content-Type media type only; parameters and arbitrary header values are omitted. */
  contentType?: string;
  /** Small allowlisted summaries only. Set-Cookie values are never included. */
  headers: string[];
}

/** Completed one-target DAST foundation result; no crawl or browser data. */
export interface DastResult {
  targetUrl: string;
  requestCount: number;
  redirectsFollowed: number;
  partial: boolean;
  partialReason?: string;
  observations: DastObservation[];
}

function isTimestamp(value: unknown): value is string {
  return typeof value === 'string' && !Number.isNaN(Date.parse(value));
}

function isBoundedText(value: unknown, maxLength: number): value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > maxLength) return false;
  // eslint-disable-next-line no-control-regex -- result contracts forbid control characters.
  return !/[\u0000-\u001f\u007f]/.test(value);
}

/** Syntax-level guard for public result URLs; server target policy also checks DNS/IPs. */
export function isSafeDastUrl(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > 2048) return false;
  try {
    const url = new URL(value);
    return (
      (url.protocol === 'http:' || url.protocol === 'https:') &&
      url.username.length === 0 &&
      url.password.length === 0 &&
      url.search.length === 0 &&
      url.hash.length === 0 &&
      url.port.length === 0 &&
      url.toString() === value
    );
  } catch {
    return false;
  }
}

export function isDastObservation(value: unknown): value is DastObservation {
  if (!isRecord(value)) return false;
  const allowed = ['endpoint', 'method', 'status', 'observedAt', 'responseTimeMs', 'bodyBytes', 'bodyTruncated', 'contentType', 'headers'];
  if (Object.keys(value).some((key) => !allowed.includes(key))) return false;
  if (
    !isSafeDastUrl(value['endpoint']) ||
    value['method'] !== 'GET' ||
    typeof value['status'] !== 'number' ||
    !Number.isInteger(value['status']) ||
    value['status'] < 100 ||
    value['status'] > 599 ||
    !isTimestamp(value['observedAt']) ||
    typeof value['responseTimeMs'] !== 'number' ||
    !Number.isInteger(value['responseTimeMs']) ||
    value['responseTimeMs'] < 0 ||
    typeof value['bodyBytes'] !== 'number' ||
    !Number.isInteger(value['bodyBytes']) ||
    value['bodyBytes'] < 0 ||
    value['bodyBytes'] > 32_768 ||
    typeof value['bodyTruncated'] !== 'boolean' ||
    !Array.isArray(value['headers']) ||
    value['headers'].length > 12 ||
    !value['headers'].every((header) => isBoundedText(header, 120))
  ) {
    return false;
  }
  if (value['contentType'] !== undefined && !isBoundedText(value['contentType'], 120)) return false;
  return true;
}

export function isDastResult(value: unknown): value is DastResult {
  if (!isRecord(value)) return false;
  const allowed = ['targetUrl', 'requestCount', 'redirectsFollowed', 'partial', 'partialReason', 'observations'];
  if (Object.keys(value).some((key) => !allowed.includes(key))) return false;
  if (
    !isSafeDastUrl(value['targetUrl']) ||
    typeof value['requestCount'] !== 'number' ||
    !Number.isInteger(value['requestCount']) ||
    value['requestCount'] < 1 ||
    value['requestCount'] > 3 ||
    typeof value['redirectsFollowed'] !== 'number' ||
    !Number.isInteger(value['redirectsFollowed']) ||
    value['redirectsFollowed'] < 0 ||
    value['redirectsFollowed'] > 2 ||
    typeof value['partial'] !== 'boolean' ||
    !Array.isArray(value['observations']) ||
    value['observations'].length !== value['requestCount'] ||
    value['observations'].length > 3 ||
    !value['observations'].every((observation) => isDastObservation(observation))
  ) {
    return false;
  }
  if (value['partialReason'] !== undefined) {
    if (value['partial'] !== true || !isBoundedText(value['partialReason'], 200)) return false;
  }
  if (value['partial'] === true && value['partialReason'] === undefined) return false;
  if (value['observations'].some((observation) => observation.bodyTruncated) && value['partial'] !== true) return false;
  const target = new URL(value['targetUrl']);
  if (!value['observations'].every((observation) => {
    if (typeof observation !== 'object' || observation === null) return false;
    const endpoint = new URL((observation as DastObservation).endpoint);
    return endpoint.hostname === target.hostname &&
      (target.protocol !== 'https:' || endpoint.protocol === 'https:');
  })) return false;
  if (value['redirectsFollowed'] > value['requestCount'] - 1) return false;
  return true;
}
