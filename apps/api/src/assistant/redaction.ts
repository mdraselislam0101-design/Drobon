export interface RedactedAssistantText {
  text: string;
  redacted: boolean;
  safeForProvider: boolean;
}

const PRIVATE_KEY_BLOCK = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/gi;
const AUTH_HEADER = /\b(authorization|proxy-authorization)\s*:\s*(?:bearer|basic)\s+[^\s,;]+/gi;
const COOKIE_HEADER = /\b(set-cookie|cookie)\s*:\s*[^\r\n]*/gi;
const SECRET_ASSIGNMENT = /\b(password|passwd|pwd|secret|client[_-]?secret|api[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token|token|credential|private[_-]?key)\b\s*[:=]\s*(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;]+)?/gi;
const JWT = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g;
const KNOWN_TOKEN = /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{16,}|AKIA[0-9A-Z]{16})\b/g;
const LONG_OPAQUE = /\b[A-Za-z0-9+/_=-]{40,}\b/g;
const URL_CREDENTIALS = /\b(https?:\/\/)[^\s/@:]+:[^\s/@]+@/gi;

/**
 * Defense-in-depth for assistant context and future provider adapters.
 * Scanner evidence is already redacted at source; this second pass also
 * covers tokens, cookies, credential assignments, PEM blocks and opaque
 * high-entropy-looking values in every evidence category.
 */
export function redactAssistantText(input: string): RedactedAssistantText {
  // eslint-disable-next-line no-control-regex -- strip controls from untrusted evidence before response or provider use.
  let text = input.normalize('NFC').replace(/\r\n?/g, '\n').replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, ' ');
  let redacted = false;
  const apply = (pattern: RegExp, replacement: string): void => {
    pattern.lastIndex = 0;
    if (pattern.test(text)) {
      redacted = true;
      pattern.lastIndex = 0;
      text = text.replace(pattern, replacement);
    }
  };
  apply(PRIVATE_KEY_BLOCK, '[private key omitted]');
  apply(AUTH_HEADER, '$1: [credential omitted]');
  apply(COOKIE_HEADER, '$1: [cookie values omitted]');
  apply(SECRET_ASSIGNMENT, '$1=[credential omitted]');
  apply(JWT, '[token omitted]');
  apply(KNOWN_TOKEN, '[token omitted]');
  apply(URL_CREDENTIALS, '$1[credentials omitted]@');
  apply(LONG_OPAQUE, '[opaque value omitted]');

  // A malformed/private-key prefix or a residual credential header fails
  // closed rather than being eligible for any future provider boundary.
  const unresolved = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|\b(?:authorization|proxy-authorization|set-cookie|cookie)\s*:\s*[^\r\n]*\S/i.test(text);
  if (unresolved) return { text: '[sensitive evidence omitted]', redacted: true, safeForProvider: false };
  return { text, redacted, safeForProvider: true };
}
