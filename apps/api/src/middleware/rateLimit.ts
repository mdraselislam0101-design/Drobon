import { rateLimited } from '../errors.js';
import type { Middleware } from '../http.js';

export interface RateLimitOptions {
  maxRequests: number;
  windowMs: number;
  /** Clock source (injectable for tests). */
  now?: () => number;
  /** Bucket key (defaults to the direct peer IP). */
  key?: (ip: string) => string;
}

interface Bucket {
  count: number;
  resetAtMs: number;
}

const SWEEP_THRESHOLD = 10_000;

/**
 * In-memory fixed-window rate limiter (per client key). Emits RateLimit
 * headers on every response and answers over-limit requests with 429 +
 * `Retry-After`.
 *
 * This is explicitly single-process and non-durable: it protects one API
 * instance against abuse and accidents. A distributed limiter (backed by
 * shared state) is future work and is NOT claimed here.
 */
export function createRateLimiter(options: RateLimitOptions): {
  middleware: Middleware;
  reset: () => void;
} {
  const now = options.now ?? Date.now;
  const keyOf = options.key ?? ((ip: string): string => ip);
  const buckets = new Map<string, Bucket>();

  const sweep = (nowMs: number): void => {
    if (buckets.size < SWEEP_THRESHOLD) {
      return;
    }
    for (const [key, bucket] of buckets) {
      if (bucket.resetAtMs <= nowMs) {
        buckets.delete(key);
      }
    }
  };

  const middleware: Middleware = async (_req, res, ctx, next): Promise<void> => {
    const nowMs = now();
    const bucketKey = keyOf(ctx.ip);
    sweep(nowMs);
    let bucket = buckets.get(bucketKey);
    if (bucket === undefined || bucket.resetAtMs <= nowMs) {
      bucket = { count: 0, resetAtMs: nowMs + options.windowMs };
      buckets.set(bucketKey, bucket);
    }
    bucket.count += 1;
    const remaining = Math.max(0, options.maxRequests - bucket.count);
    const resetSec = Math.max(0, Math.ceil((bucket.resetAtMs - nowMs) / 1000));
    res.setHeader('ratelimit-limit', String(options.maxRequests));
    res.setHeader('ratelimit-remaining', String(remaining));
    res.setHeader('ratelimit-reset', String(resetSec));
    if (bucket.count > options.maxRequests) {
      throw rateLimited(Math.max(1, resetSec));
    }
    await next();
  };

  return {
    middleware,
    reset: (): void => {
      buckets.clear();
    },
  };
}
