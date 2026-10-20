/**
 * Active DAST — bounded link/form crawler (no browser, no JS execution).
 * Extracts same-host URLs from static HTML only; every candidate is
 * re-validated by the DastTargetPolicy before any request.
 */

const HREF_ATTRS = /(?:href|src|action)\s*=\s*(?:"([^"]{1,2048})"|'([^']{1,2048})'|([^\s"'`>]{1,2048}))/gi;
const MAX_CRAWL_CANDIDATES = 20;
const MAX_CRAWL_LINKS = 10;

/** Extract candidate URLs from static HTML (no JS execution, regex only, bounded). */
export function extractCrawlCandidates(html: string, baseUrl: string, maxLinks = MAX_CRAWL_LINKS): string[] {
  if (typeof html !== 'string' || html.length === 0 || html.length > 32_768) return [];
  let base: URL;
  try {
    base = new URL(baseUrl);
  } catch {
    return [];
  }
  const baseHost = base.hostname.toLowerCase();
  const baseProto = base.protocol;
  const candidates: string[] = [];
  const seen = new Set<string>();

  // Bound scanning: at most 200 attribute matches to avoid pathological HTML.
  let matchCount = 0;
  for (const match of html.matchAll(HREF_ATTRS)) {
    if (matchCount++ >= MAX_CRAWL_CANDIDATES * 2) break;
    const raw = match[1] ?? match[2] ?? match[3];
    if (raw === undefined || raw.length === 0) continue;
    const trimmed = raw.trim();
    // Reject dangerous schemes, data URIs, javascript:, mailto:, tel:, etc.
    if (/^(?:javascript|data|mailto|tel|ftp|ws|wss):/i.test(trimmed)) continue;
    if (trimmed.startsWith('#') || trimmed.startsWith('mailto:')) continue;
    let resolved: URL;
    try {
      resolved = new URL(trimmed, base);
    } catch {
      continue;
    }
    // Same-host + same-or-upgrade scheme only (http→https allowed, https→http blocked elsewhere).
    if (resolved.hostname.toLowerCase() !== baseHost) continue;
    if (resolved.protocol !== 'http:' && resolved.protocol !== 'https:') continue;
    if (baseProto === 'https:' && resolved.protocol !== 'https:') continue;
    // Strip credentials, fragment, and enforce caps.
    if (resolved.username.length > 0 || resolved.password.length > 0) continue;
    resolved.hash = '';
    // Keep query for injection-point discovery but bound it.
    if (resolved.search.length > 512) continue;
    const canonical = resolved.toString();
    if (canonical.length > 2048 || canonical.length < 10) continue;
    if (seen.has(canonical)) continue;
    seen.add(canonical);
    candidates.push(canonical);
    if (candidates.length >= maxLinks) break;
  }

  return candidates;
}

/** Find injection points (query params + path) in a URL list. Each URL is at most one point. */
export interface InjectionPoint {
  /** Canonical URL before injection (bound, same-host, validated). */
  url: string;
  /** Query param name to inject into (or `__path__` for path injection). */
  param: string;
}

export function injectionPointsFromUrls(urls: readonly string[]): InjectionPoint[] {
  const points: InjectionPoint[] = [];
  const seenBase = new Set<string>();
  for (const raw of urls) {
    let parsed: URL;
    try {
      parsed = new URL(raw);
    } catch {
      continue;
    }
    const baseKey = `${parsed.hostname}${parsed.pathname}`;
    if (seenBase.has(baseKey)) continue;
    seenBase.add(baseKey);
    // Prefer query params as injection surface (safe GET).
    if (parsed.searchParams.size > 0) {
      for (const name of parsed.searchParams.keys()) {
        if (name.length === 0 || name.length > 64) continue;
        if (!/^[A-Za-z0-9._-]+$/.test(name)) continue;
        points.push({ url: raw, param: name });
        break; // At most one param per URL to bound requests.
      }
    } else {
      // Path-based URL — treat path tail as injection point (bounded).
      if (parsed.pathname.length > 1 && parsed.pathname.length <= 200) {
        points.push({ url: raw, param: '__path__' });
      }
    }
    if (points.length >= MAX_CRAWL_LINKS) break;
  }
  return points;
}

/** Build the injected URL for a point + payload (GET only, bounded, no credentials). */
export function buildInjectedUrl(point: InjectionPoint, payloadValue: string): string | undefined {
  if (payloadValue.length === 0 || payloadValue.length > 128) return undefined;
  let parsed: URL;
  try {
    parsed = new URL(point.url);
  } catch {
    return undefined;
  }
  if (point.param === '__path__') {
    // Path injection: append payload as encoded segment (bounded, no traversal bypass).
    const encoded = encodeURIComponent(payloadValue).slice(0, 128);
    // Never produce // or allow ../ to escape — encode handles it.
    parsed.pathname = `${parsed.pathname.replace(/\/$/, '')}/${encoded}`.slice(0, 1024);
  } else {
    parsed.searchParams.set(point.param, payloadValue.slice(0, 128));
  }
  // Enforce global URL cap.
  const next = parsed.toString();
  if (next.length > 2048 || next.length < 10) return undefined;
  return next;
}
