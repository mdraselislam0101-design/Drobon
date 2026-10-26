/**
 * Browser-accurate Set-Cookie model (app-side port of Drobon-Dataset's
 * `scripts/lib/set-cookie.mjs` semantics, RFC 6265 §5.2/§5.3).
 *
 * Application logic only — no dataset bytes are copied here. A keyword search
 * over the raw header mis-reads `Secure=0` (the flag IS on) and a discarded
 * header such as `no-equals-sign` (no cookie is stored). Those two shapes
 * were the entire DAST parity gap (GAP-041).
 */

const KNOWN_SAMESITE = new Set(['strict', 'lax', 'none']);
function hasControlCharacter(text: string): boolean {
  for (const character of text) {
    const code = character.codePointAt(0) ?? 0;
    if (code <= 8 || (code >= 10 && code <= 31) || code === 127) return true;
  }
  return false;
}

interface ParsedCookie {
  ok: boolean;
  secure: boolean;
  httpOnly: boolean;
  sameSiteDeclared: boolean;
  sameSiteValue: string | null;
}

/** Split on ';' outside double-quoted spans. */
function splitAttributes(text: string): string[] {
  const parts: string[] = [];
  let current = '';
  let quoted = false;
  for (const character of text) {
    if (character === '"') quoted = !quoted;
    if (character === ';' && !quoted) {
      parts.push(current);
      current = '';
      continue;
    }
    current += character;
  }
  parts.push(current);
  return parts;
}

function parseSetCookie(raw: unknown): ParsedCookie {
  const empty: ParsedCookie = { ok: false, secure: false, httpOnly: false, sameSiteDeclared: false, sameSiteValue: null };
  if (typeof raw !== 'string' || raw.length === 0 || hasControlCharacter(raw)) return empty;
  const segments = splitAttributes(raw);
  const pair = (segments[0] ?? '').trim();
  const equals = pair.indexOf('=');
  if (equals <= 0 || pair.slice(0, equals).trim().length === 0) return empty;

  const attributes: Array<{ name: string; value: string }> = [];
  for (const segment of segments.slice(1)) {
    const text = segment.trim();
    if (text.length === 0) continue;
    const index = text.indexOf('=');
    const name = (index === -1 ? text : text.slice(0, index)).trim().toLowerCase();
    if (name.length === 0) continue;
    attributes.push({ name, value: index === -1 ? '' : text.slice(index + 1).trim() });
  }
  // RFC 6265 §5.3: last duplicate attribute wins.
  const last = (name: string) => {
    for (let i = attributes.length - 1; i >= 0; i -= 1) {
      if (attributes[i]?.name === name) return attributes[i];
    }
    return undefined;
  };
  const sameSite = last('samesite');
  const declared = sameSite !== undefined && KNOWN_SAMESITE.has(sameSite.value.toLowerCase());
  return {
    ok: true,
    secure: last('secure') !== undefined,
    httpOnly: last('httponly') !== undefined,
    sameSiteDeclared: declared,
    sameSiteValue: sameSite?.value.toLowerCase() ?? null,
  };
}

/** A `SameSite=None` cookie without `Secure` is refused by shipping browsers. */
export function cookieWillBeStored(raw: unknown): boolean {
  const parsed = parseSetCookie(raw);
  if (!parsed.ok) return false;
  return !(parsed.sameSiteDeclared && parsed.sameSiteValue === 'none' && !parsed.secure);
}

export function cookieHasFlag(raw: unknown, flag: unknown): boolean {
  const parsed = parseSetCookie(raw);
  if (!parsed.ok || typeof flag !== 'string') return false;
  switch (flag.toLowerCase()) {
    case 'secure': return parsed.secure;
    case 'httponly': return parsed.httpOnly;
    case 'samesite': return parsed.sameSiteDeclared;
    default: return false;
  }
}
