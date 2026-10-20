/**
 * DAST pack check evaluator — implements the 7 check types from PACKS.md.
 * Pure functions, no network, deterministic.
 */

export interface PackDastObservation {
  url: string;
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body?: string;
  contentType?: string;
}

function header(obs: PackDastObservation, name: string): string | undefined {
  const v = obs.headers[name.toLowerCase()];
  const sel = Array.isArray(v) ? v.join(', ') : v;
  return typeof sel === 'string' ? sel.trim() : undefined;
}

export function evaluatePackDastCheck(ruleCheck: any, obs: PackDastObservation): boolean {
  const t = ruleCheck.type;
  if (t === 'http-url') {
    try { return new URL(obs.url).protocol === 'http:'; } catch { return false; }
  }
  if (t === 'missing-response-header') {
    const h = ruleCheck.header;
    if (typeof h !== 'string') return false;
    const v = header(obs, h);
    return v === undefined || v.trim() === '';
  }
  if (t === 'response-header-missing-directive') {
    const h = ruleCheck.header as string;
    const d = ruleCheck.directive as string;
    if (typeof h !== 'string' || typeof d !== 'string') return false;
    const v = header(obs, h);
    if (v === undefined) return true;
    const parts = v.split(/[;,]/).map(s => s.trim());
    return !parts.some(p => p.split(/[=\s]/)[0]?.toLowerCase() === d.toLowerCase());
  }
  if (t === 'cookie-missing-flag') {
    const flag = ruleCheck.flag as string;
    const raw = obs.headers['set-cookie'];
    const cookies = typeof raw === 'string' ? [raw] : Array.isArray(raw) ? raw : [];
    if (cookies.length === 0) return false;
    for (const c of cookies.slice(0,5)) {
      const parts = c.split(';').slice(1).map(p=>p.trim().toLowerCase());
      const has = flag === 'Secure' ? parts.some(p=>p==='secure') : flag === 'HttpOnly' ? parts.some(p=>p==='httponly') : parts.some(p=>p.startsWith('samesite='));
      if (!has) return true;
    }
    return false;
  }
  if (t === 'response-header-matches') {
    const h = ruleCheck.header as string;
    const pat = ruleCheck.valuePattern as string;
    if (typeof h !== 'string' || typeof pat !== 'string') return false;
    const v = header(obs, h);
    if (v === undefined) return false;
    try { const re = new RegExp(pat, 'i'); return re.test(v); } catch { return false; }
  }
  if (t === 'response-body-matches') {
    const pat = ruleCheck.valuePattern as string;
    if (typeof pat !== 'string' || !obs.body) return false;
    if (ruleCheck.requireScheme) {
      try { if (new URL(obs.url).protocol.slice(0,-1) !== ruleCheck.requireScheme) return false; } catch { return false; }
    }
    try { const re = new RegExp(pat, 'i'); return re.test(obs.body); } catch { return false; }
  }
  if (t === 'response-header-host-differs') {
    const h = ruleCheck.header as string;
    if (typeof h !== 'string') return false;
    if (obs.status < 300 || obs.status > 399) return false;
    const v = header(obs, h);
    if (!v) return false;
    try {
      const base = new URL(obs.url);
      const target = new URL(v, base);
      if (target.protocol !== 'http:' && target.protocol !== 'https:') return false;
      return target.hostname.toLowerCase() !== base.hostname.toLowerCase();
    } catch { return false; }
  }
  return false;
}
