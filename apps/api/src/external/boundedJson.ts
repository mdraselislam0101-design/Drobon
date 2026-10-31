/** Bounded local JSON input shared by Dataset, SCA intelligence and advisory readers.
 * Error messages intentionally contain no paths, filenames or input values. */
import { constants } from 'node:fs';
import { lstat, open } from 'node:fs/promises';

export const DEFAULT_JSON_PARSE_LIMITS = { maxDepth: 64, maxTokens: 100_000 } as const;
export interface JsonParseLimits { maxDepth: number; maxTokens: number }
export type BoundedJsonErrorCode = 'FILE_LIMIT' | 'TOTAL_LIMIT' | 'DEPTH_LIMIT' | 'TOKEN_LIMIT' |
  'DUPLICATE_KEY' | 'INVALID_JSON' | 'UNSAFE_FILE' | 'CHANGED_FILE';

export class BoundedJsonError extends Error {
  constructor(readonly code: BoundedJsonErrorCode) {
    super(`Local JSON input rejected: ${code}`);
    this.name = 'BoundedJsonError';
  }
}

export function isResourceLimitError(error: unknown): boolean {
  return error instanceof BoundedJsonError &&
    (error.code === 'FILE_LIMIT' || error.code === 'TOTAL_LIMIT' || error.code === 'DEPTH_LIMIT' || error.code === 'TOKEN_LIMIT');
}

type Frame = { kind: 'object'; keys: Set<string>; expectingKey: boolean } | { kind: 'array' };

/**
 * A linear lexical preflight enforces nesting/tokens and detects duplicate
 * object keys (including equivalent escaped keys). JSON.parse still performs
 * the full grammar validation. Brackets inside strings are not nesting.
 */
export function parseBoundedJson(text: string, limits: JsonParseLimits = DEFAULT_JSON_PARSE_LIMITS): unknown {
  if (!Number.isSafeInteger(limits.maxDepth) || limits.maxDepth < 1 || !Number.isSafeInteger(limits.maxTokens) || limits.maxTokens < 1) {
    throw new TypeError('Invalid JSON input limits');
  }
  const stack: Frame[] = [];
  let tokens = 0;
  const count = (): void => { if (++tokens > limits.maxTokens) throw new BoundedJsonError('TOKEN_LIMIT'); };
  for (let i = 0; i < text.length;) {
    const char = text[i];
    if (char === ' ' || char === '\n' || char === '\r' || char === '\t') { i += 1; continue; }
    if (char === '"') {
      const start = i;
      i += 1;
      let closed = false;
      while (i < text.length) {
        if (text[i] === '\\') { i += 2; continue; }
        if (text[i] === '"') { i += 1; closed = true; break; }
        i += 1;
      }
      if (!closed) throw new BoundedJsonError('INVALID_JSON');
      count();
      const frame = stack[stack.length - 1];
      if (frame?.kind === 'object' && frame.expectingKey) {
        let key: unknown;
        try { key = JSON.parse(text.slice(start, i)) as unknown; }
        catch { throw new BoundedJsonError('INVALID_JSON'); }
        if (typeof key !== 'string') throw new BoundedJsonError('INVALID_JSON');
        if (frame.keys.has(key)) throw new BoundedJsonError('DUPLICATE_KEY');
        frame.keys.add(key);
        frame.expectingKey = false;
      }
      continue;
    }
    if (char === '{' || char === '[') {
      count();
      stack.push(char === '{' ? { kind: 'object', keys: new Set<string>(), expectingKey: true } : { kind: 'array' });
      if (stack.length > limits.maxDepth) throw new BoundedJsonError('DEPTH_LIMIT');
      i += 1;
      continue;
    }
    if (char === '}' || char === ']') {
      const frame = stack.pop();
      if (frame === undefined || (char === '}' ? frame.kind !== 'object' : frame.kind !== 'array')) throw new BoundedJsonError('INVALID_JSON');
      i += 1;
      continue;
    }
    if (char === ',') {
      const frame = stack[stack.length - 1];
      if (frame?.kind === 'object') frame.expectingKey = true;
      i += 1;
      continue;
    }
    if (char === ':') { i += 1; continue; }
    count();
    // Consume a primitive token; the native parser checks its exact syntax.
    const start = i;
    while (i < text.length && !/[\s,\]}:{["]/.test(text[i] ?? '')) i += 1;
    if (i === start) throw new BoundedJsonError('INVALID_JSON');
  }
  if (stack.length !== 0) throw new BoundedJsonError('INVALID_JSON');
  try { return JSON.parse(text) as unknown; }
  catch { throw new BoundedJsonError('INVALID_JSON'); }
}

/** One byte budget can be shared across every file read in a loader pass. */
export interface JsonByteBudget { readonly maxBytes: number; readBytes: number; reservedBytes: number }
export function createJsonByteBudget(maxBytes: number): JsonByteBudget {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) throw new TypeError('Invalid JSON byte budget');
  return { maxBytes, readBytes: 0, reservedBytes: 0 };
}

export interface BoundedJsonFileOptions {
  maxFileBytes: number;
  budget: JsonByteBudget;
  parseLimits?: JsonParseLimits;
  /** Only for a directly configured advisory file; Dataset entries never use it. */
  allowFinalSymlink?: boolean;
}

/** Read at most the remaining budget from a regular file before parsing it. */
export async function readBoundedJsonFile(path: string, options: BoundedJsonFileOptions): Promise<unknown> {
  if (!options.allowFinalSymlink && (await lstat(path)).isSymbolicLink()) throw new BoundedJsonError('UNSAFE_FILE');
  const flags = constants.O_RDONLY | (constants.O_NONBLOCK ?? 0) | (options.allowFinalSymlink ? 0 : (constants.O_NOFOLLOW ?? 0));
  const handle = await open(path, flags);
  let reserved = 0;
  let actual = 0;
  try {
    const info = await handle.stat();
    if (!info.isFile() || !Number.isSafeInteger(info.size) || info.size < 0) throw new BoundedJsonError('UNSAFE_FILE');
    if (info.size > options.maxFileBytes) throw new BoundedJsonError('FILE_LIMIT');
    const remaining = options.budget.maxBytes - options.budget.readBytes - options.budget.reservedBytes;
    if (info.size > remaining) throw new BoundedJsonError('TOTAL_LIMIT');
    // Reserve before any await, so even concurrent users of the same budget
    // cannot collectively read past the cap. The extra byte detects growth.
    reserved = Math.min(info.size + 1, remaining);
    options.budget.reservedBytes += reserved;
    const bytes = Buffer.alloc(reserved);
    while (actual < bytes.length) {
      const result = await handle.read(bytes, actual, bytes.length - actual, null);
      if (result.bytesRead === 0) break;
      actual += result.bytesRead;
    }
    if (actual !== info.size || (await handle.stat()).size !== info.size) throw new BoundedJsonError('CHANGED_FILE');
    return parseBoundedJson(bytes.subarray(0, actual).toString('utf8'), options.parseLimits ?? DEFAULT_JSON_PARSE_LIMITS);
  } finally {
    options.budget.reservedBytes -= reserved;
    options.budget.readBytes += actual;
    await handle.close();
  }
}
