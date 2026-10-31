import { redactAssistantText } from './assistant/redaction.js';
import type { EnvironmentName, LogLevel } from '@drobon/shared';

const LEVEL_ORDER: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
};

export const REDACTED = '[REDACTED]';
const CIRCULAR = '[CIRCULAR]';
const TRUNCATED = '[TRUNCATED]';
const MAX_DEPTH = 20;

/**
 * Key fragments (compared case-insensitively, punctuation ignored) whose
 * values are always redacted. Over-redaction is intentional: a redacted
 * harmless field costs nothing, a leaked secret costs everything.
 */
const SENSITIVE_KEY_PARTS = [
  'password',
  'passwd',
  'secret',
  'token',
  'authorization',
  'cookie',
  'apikey',
  'privatekey',
  'credential',
  'sessionid',
  'sessionkey',
  'evidence',
  'sourcecontent',
  'rawline',
] as const;

/** Keys whose string values may embed `user:pass@` credentials in URLs. */
const URL_KEYS = new Set(['url', 'uri', 'endpoint', 'dsn', 'connectionstring']);

const BEARER_LIKE = /^(?:bearer|basic)\s+\S+$/i;
const EMBEDDED_CREDENTIALS = /:\/\/[^/]*:[^/@]*@/;

function normalizeKey(key: string): string {
  return key.toLowerCase().replace(/[^a-z0-9]/g, '');
}

function isSensitiveKey(key: string): boolean {
  const normalized = normalizeKey(key);
  return SENSITIVE_KEY_PARTS.some((part) => normalized.includes(part));
}

function redactScalar(value: string, key: string | undefined): string {
  // These are server-generated, non-secret identifiers needed for audit correlation.
  // Do not exempt arbitrary text or values merely because they end in "id".
  if (key !== undefined && /^(scanid|projectid)$/.test(normalizeKey(key)) &&
      /^(?:scan|prj)_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) return value;
  if (BEARER_LIKE.test(value)) {
    return REDACTED;
  }
  if (
    key !== undefined &&
    URL_KEYS.has(normalizeKey(key)) &&
    EMBEDDED_CREDENTIALS.test(value)
  ) {
    return REDACTED;
  }
  const safe = redactAssistantText(value);
  return safe.safeForProvider ? safe.text : REDACTED;
}

/**
 * Deep-copy a value, redacting anything sensitive. Handles cycles and
 * pathological depth. Error messages and stacks are withheld in every
 * environment; only a closed set of exception names is retained.
 */
export function redactValue(value: unknown, seen?: Set<object>, depth?: number): unknown {
  const visited = seen ?? new Set<object>();
  const level = depth ?? 0;
  if (level > MAX_DEPTH) {
    return TRUNCATED;
  }
  if (typeof value === 'string') {
    return redactScalar(value, undefined);
  }
  if (typeof value !== 'object' || value === null) {
    return value;
  }
  if (value instanceof Error) {
    return { name: safeErrorName(value), message: REDACTED };
  }
  if (visited.has(value)) {
    return CIRCULAR;
  }
  visited.add(value);
  if (Array.isArray(value)) {
    return value.map((entry) => redactValue(entry, visited, level + 1));
  }
  const out: Record<string, unknown> = {};
  for (const [key, entry] of Object.entries(value)) {
    if (isSensitiveKey(key)) {
      out[key] = REDACTED;
      continue;
    }
    if (typeof entry === 'string') {
      out[key] = redactScalar(entry, key);
      continue;
    }
    out[key] = redactValue(entry, visited, level + 1);
  }
  return out;
}

const SAFE_ERROR_NAMES = new Set(['Error', 'TypeError', 'RangeError', 'SyntaxError', 'ReferenceError', 'URIError', 'EvalError', 'AggregateError']);

function safeErrorName(error: Error): string {
  // Error.name, message and stack are all writable and may contain arbitrary
  // source text, even a very short secret that no pattern can recognize.
  return SAFE_ERROR_NAMES.has(error.name) ? error.name : 'Error';
}

function serializeError(error: unknown): unknown {
  if (error instanceof Error) {
    // Do not emit messages or stacks in any environment. Pattern-based
    // scrubbing cannot prove an arbitrary exception payload is secret-free.
    return { name: safeErrorName(error), message: REDACTED };
  }
  // Thrown strings and non-Error values are just as untrusted.
  return REDACTED;
}

export type LogFields = Record<string, unknown>;

export interface Logger {
  readonly level: LogLevel;
  debug(message: string, fields?: LogFields): void;
  info(message: string, fields?: LogFields): void;
  warn(message: string, fields?: LogFields): void;
  error(message: string, fields?: LogFields): void;
  /** Derive a logger with extra bindings (e.g. `{ requestId }`). */
  child(bindings: LogFields): Logger;
}

export interface LoggerOptions {
  level?: LogLevel;
  service?: string;
  env?: EnvironmentName;
  /** ISO timestamp source (injectable for tests). */
  now?: () => string;
  /** Line sink (injectable for tests). Defaults to stdout/stderr. */
  out?: (line: string, level: LogLevel) => void;
}

function defaultOut(line: string, level: LogLevel): void {
  if (level === 'error' || level === 'warn') {
    process.stderr.write(`${line}\n`);
  } else {
    process.stdout.write(`${line}\n`);
  }
}

export function createLogger(options: LoggerOptions = {}): Logger {
  const level = options.level ?? 'info';
  const service = options.service ?? 'drobon-aegis-api';
  const now = options.now ?? ((): string => new Date().toISOString());
  const out = options.out ?? defaultOut;

  const emit = (entryLevel: LogLevel, message: string, fields: LogFields): void => {
    if (LEVEL_ORDER[entryLevel] < LEVEL_ORDER[level]) {
      return;
    }
    const redacted = redactValue(fields) as Record<string, unknown>;
    const line = JSON.stringify({
      time: now(),
      level: entryLevel,
      service,
      msg: redactScalar(message, undefined),
      ...redacted,
    });
    out(line, entryLevel);
  };

  const withErr = (fields: LogFields | undefined): LogFields => {
    if (fields === undefined || !('err' in fields)) {
      return fields ?? {};
    }
    const { err, ...rest } = fields;
    return { ...rest, err: serializeError(err) };
  };

  const make = (bindings: LogFields): Logger => ({
    level,
    debug: (message, fields): void => emit('debug', message, { ...bindings, ...withErr(fields) }),
    info: (message, fields): void => emit('info', message, { ...bindings, ...withErr(fields) }),
    warn: (message, fields): void => emit('warn', message, { ...bindings, ...withErr(fields) }),
    error: (message, fields): void =>
      emit('error', message, { ...bindings, ...withErr(fields) }),
    child: (extra): Logger => make({ ...bindings, ...extra }),
  });

  return make({});
}
