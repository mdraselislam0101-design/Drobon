import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { hasAmbiguousDastReference } from './reference.js';

export type DastTargetErrorCode = 'DAST_TARGET_INVALID' | 'DAST_TARGET_BLOCKED' | 'DAST_DNS_FAILED';

export class DastTargetError extends Error {
  constructor(readonly code: DastTargetErrorCode) {
    super(code);
    this.name = 'DastTargetError';
  }
}

export interface ResolvedDastTarget {
  /** Canonical URL without credentials, query, or fragment. */
  url: string;
  /** Canonical host without IPv6 brackets. */
  hostname: string;
  /** Every currently resolved address, verified public before use. */
  addresses: string[];
}

export type DastAddressResolver = (hostname: string) => Promise<readonly string[]>;

const MAX_TARGET_URL_LENGTH = 2048;
const RESERVED_HOST_SUFFIXES = [
  '.localhost',
  '.local',
  '.internal',
  '.test',
  '.invalid',
  '.example',
  '.home.arpa',
  '.onion',
] as const;

const IPV4_BLOCKED_CIDRS = [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.88.99.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
] as const;

const IPV6_BLOCKED_CIDRS = [
  ['::', 128],
  ['::1', 128],
  ['::ffff:0:0', 96],
  ['64:ff9b::', 96],
  ['64:ff9b:1::', 48],
  ['100::', 64],
  ['2001::', 23],
  ['2001:db8::', 32],
  ['2002::', 16],
  ['3fff::', 20],
  ['fc00::', 7],
  ['fe80::', 10],
  ['fec0::', 10],
  ['ff00::', 8],
] as const;

function ipv4Value(address: string): bigint | undefined {
  if (isIP(address) !== 4) return undefined;
  return address.split('.').reduce((value, part) => (value << 8n) | BigInt(Number(part)), 0n);
}

function ipv6Value(address: string): bigint | undefined {
  if (isIP(address) !== 6 || address.includes('%')) return undefined;
  let input = address.toLowerCase();
  const embedded = input.match(/(?:^|:)(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (embedded?.[1] !== undefined) {
    const v4 = ipv4Value(embedded[1]);
    if (v4 === undefined) return undefined;
    const high = Number((v4 >> 16n) & 0xffffn).toString(16);
    const low = Number(v4 & 0xffffn).toString(16);
    input = input.replace(embedded[1], `${high}:${low}`);
  }
  const halves = input.split('::');
  if (halves.length > 2) return undefined;
  const left = halves[0] === '' ? [] : (halves[0] ?? '').split(':');
  const right = halves.length === 1 || halves[1] === '' ? [] : (halves[1] ?? '').split(':');
  const zeros = halves.length === 1 ? 0 : 8 - left.length - right.length;
  if ((halves.length === 1 && left.length !== 8) || zeros < 0 || (halves.length === 2 && zeros < 1)) {
    return undefined;
  }
  const words = [...left, ...Array.from({ length: zeros }, () => '0'), ...right];
  if (words.length !== 8 || words.some((part) => !/^[0-9a-f]{1,4}$/.test(part))) {
    return undefined;
  }
  return words.reduce((value, part) => (value << 16n) | BigInt(`0x${part}`), 0n);
}

function parseCidr(network: string, family: 4 | 6): bigint | undefined {
  return family === 4 ? ipv4Value(network) : ipv6Value(network);
}

function inCidr(address: bigint, network: string, bits: number, family: 4 | 6): boolean {
  const base = parseCidr(network, family);
  if (base === undefined) return true; // A malformed policy entry must fail closed.
  const width = family === 4 ? 32n : 128n;
  const mask = ((1n << width) - 1n) ^ ((1n << (width - BigInt(bits))) - 1n);
  return (address & mask) === (base & mask);
}

/** True only for globally routable unicast addresses (conservative ranges). */
export function isPublicDastAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) {
    const value = ipv4Value(address);
    return value !== undefined && !IPV4_BLOCKED_CIDRS.some(([network, bits]) =>
      inCidr(value, network, bits, 4),
    );
  }
  if (family === 6) {
    const value = ipv6Value(address);
    if (value === undefined) return false;
    // IPv4-mapped IPv6 must receive the exact same IPv4 policy.
    if (inCidr(value, '::ffff:0:0', 96, 6)) {
      const mapped = value & 0xffffffffn;
      const v4 = [24n, 16n, 8n, 0n].map((shift) => Number((mapped >> shift) & 0xffn)).join('.');
      return isPublicDastAddress(v4);
    }
    // Global unicast allocations are in 2000::/3; all other ranges are denied.
    if (!inCidr(value, '2000::', 3, 6)) return false;
    return !IPV6_BLOCKED_CIDRS.some(([network, bits]) => inCidr(value, network, bits, 6));
  }
  return false;
}

function rejectTraversalPath(raw: string): void {
  const match = raw.match(/^https?:\/\/[^/?#]*(\/[^?#]*)?/i);
  const path = match?.[1] ?? '/';
  // %25 can hide another layer of encoded dots or separators. Reject it
  // before DNS, including for legacy unlinked scans without an engagement.
  if (/%(?:2e|2f|5c|25)/i.test(path)) throw new DastTargetError('DAST_TARGET_INVALID');
  for (const segment of path.split('/')) {
    let decoded = segment;
    for (let attempt = 0; attempt < 2; attempt += 1) {
      try {
        decoded = decodeURIComponent(decoded);
      } catch {
        throw new DastTargetError('DAST_TARGET_INVALID');
      }
      if (decoded === '.' || decoded === '..' || decoded.includes('\\')) {
        throw new DastTargetError('DAST_TARGET_INVALID');
      }
    }
  }
}

/** Parse and canonicalize syntax before DNS or network activity. */
export function normalizeDastTarget(raw: unknown): { url: string; hostname: string } {
  if (
    typeof raw !== 'string' ||
    raw.length === 0 ||
    raw.length > MAX_TARGET_URL_LENGTH ||
    raw !== raw.trim() ||
    // eslint-disable-next-line no-control-regex -- reject control characters in untrusted URLs.
    /[\u0000-\u0020\u007f\\]/.test(raw) ||
    /[?#]/.test(raw)
  ) {
    throw new DastTargetError('DAST_TARGET_INVALID');
  }
  // Check raw input before WHATWG URL normalization; matrix-parameter
  // dot segments may otherwise cross an engagement prefix on some servers.
  if (hasAmbiguousDastReference(raw)) throw new DastTargetError('DAST_TARGET_INVALID');
  rejectTraversalPath(raw);
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new DastTargetError('DAST_TARGET_INVALID');
  }
  if (
    (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') ||
    parsed.username.length > 0 ||
    parsed.password.length > 0 ||
    parsed.search.length > 0 ||
    parsed.hash.length > 0 ||
    parsed.port.length > 0
  ) {
    throw new DastTargetError('DAST_TARGET_INVALID');
  }
  const hostname = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  if (
    hostname.length === 0 ||
    hostname.length > 253 ||
    hostname === 'metadata' ||
    hostname === 'metadata.google.internal' ||
    RESERVED_HOST_SUFFIXES.some((suffix) => hostname.endsWith(suffix)) ||
    (isIP(hostname) === 0 && (!hostname.includes('.') || hostname.split('.').some((label) => label.length === 0)))
  ) {
    throw new DastTargetError('DAST_TARGET_BLOCKED');
  }
  parsed.hostname = isIP(hostname) === 6 ? `[${hostname}]` : hostname;
  parsed.port = '';
  parsed.hash = '';
  parsed.search = '';
  const url = parsed.toString();
  return { url, hostname };
}

const systemResolver: DastAddressResolver = async (hostname) => {
  if (isIP(hostname) !== 0) return [hostname];
  try {
    const records = await lookup(hostname, { all: true, verbatim: true });
    return records.map((record) => record.address);
  } catch {
    throw new DastTargetError('DAST_DNS_FAILED');
  }
};

export interface DastTargetPolicy {
  prepare(raw: unknown): Promise<ResolvedDastTarget>;
  resolveNormalized(url: string): Promise<ResolvedDastTarget>;
  resolveRedirect(current: ResolvedDastTarget, location: string, originalHostname: string): Promise<ResolvedDastTarget>;
}

export function createDastTargetPolicy(options: { resolve?: DastAddressResolver; resolveTimeoutMs?: number } = {}): DastTargetPolicy {
  const resolve = options.resolve ?? systemResolver;
  const resolveTimeoutMs = Math.max(100, Math.min(10_000, options.resolveTimeoutMs ?? 3_000));

  const resolveNormalized = async (url: string): Promise<ResolvedDastTarget> => {
    const parsed = normalizeDastTarget(url);
    let addresses: readonly string[];
    try {
      if (isIP(parsed.hostname) !== 0) {
        // A literal address is its own DNS answer and cannot be overridden
        // by an injected resolver (including in controlled test setups).
        addresses = [parsed.hostname];
      } else {
        let timeout: ReturnType<typeof setTimeout> | undefined;
        try {
          addresses = await Promise.race([
          resolve(parsed.hostname),
          new Promise<never>((_resolve, reject) => {
            timeout = setTimeout(() => reject(new DastTargetError('DAST_DNS_FAILED')), resolveTimeoutMs);
          }),
          ]);
        } finally {
          if (timeout !== undefined) clearTimeout(timeout);
        }
      }
    } catch (error) {
      if (error instanceof DastTargetError) throw error;
      throw new DastTargetError('DAST_DNS_FAILED');
    }
    if (addresses.length === 0 || addresses.length > 16 || addresses.some((address) => !isPublicDastAddress(address))) {
      throw new DastTargetError('DAST_TARGET_BLOCKED');
    }
    return { ...parsed, addresses: [...new Set(addresses)].sort() };
  };

  return {
    prepare: async (raw) => {
      const normalized = normalizeDastTarget(raw);
      return resolveNormalized(normalized.url);
    },
    resolveNormalized,
    resolveRedirect: async (current, location, originalHostname) => {
      // eslint-disable-next-line no-control-regex -- reject control characters in untrusted redirects.
      if (location.length === 0 || location.length > MAX_TARGET_URL_LENGTH || /[\u0000-\u001f\u007f\\]/.test(location) ||
          hasAmbiguousDastReference(location)) {
        throw new DastTargetError('DAST_TARGET_INVALID');
      }
      let redirectUrl: URL;
      try {
        redirectUrl = new URL(location, current.url);
      } catch {
        throw new DastTargetError('DAST_TARGET_INVALID');
      }
      // Reject cross-host and HTTPS downgrade redirects on syntax alone,
      // before DNS can contact a resolver for an out-of-scope hostname.
      const normalized = normalizeDastTarget(redirectUrl.toString());
      const currentProtocol = new URL(current.url).protocol;
      const nextProtocol = new URL(normalized.url).protocol;
      if (normalized.hostname !== originalHostname || (currentProtocol === 'https:' && nextProtocol !== 'https:')) {
        throw new DastTargetError('DAST_TARGET_BLOCKED');
      }
      return resolveNormalized(normalized.url);
    },
  };
}
