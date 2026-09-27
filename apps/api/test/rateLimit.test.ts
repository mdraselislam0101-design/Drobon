import { describe, expect, test } from 'vitest';
import { createRateLimiter } from '../src/middleware/rateLimit.js';
import { readJson, startTestServer } from './helpers.js';

describe('rate limiting', () => {
  test('allows N requests then answers 429 with Retry-After + RateLimit headers', async () => {
    const server = await startTestServer({
      rateLimitMaxRequests: 3,
      rateLimitWindowMs: 60_000,
    });
    try {
      for (let i = 0; i < 3; i += 1) {
        const res = await fetch(`${server.baseUrl}/livez`);
        expect(res.status).toBe(200);
        expect(res.headers.get('ratelimit-limit')).toBe('3');
        expect(res.headers.get('ratelimit-remaining')).toBe(String(2 - i));
      }
      const limited = await fetch(`${server.baseUrl}/livez`);
      expect(limited.status).toBe(429);
      expect(limited.headers.get('ratelimit-remaining')).toBe('0');
      expect(Number(limited.headers.get('retry-after'))).toBeGreaterThan(0);
      const body = (await readJson(limited)) as { error: { code: string } };
      expect(body.error.code).toBe('RATE_LIMITED');
    } finally {
      await server.stop();
    }
  });

  test('the window resets and the limiter can be reset explicitly', async () => {
    let nowMs = 1_000_000;
    const limiter = createRateLimiter({
      maxRequests: 1,
      windowMs: 1000,
      now: () => nowMs,
    });
    const headers = new Map<string, string>();
    const res = {
      setHeader: (name: string, value: string): void => {
        headers.set(name, value);
      },
    };
    const ctx = { ip: '203.0.113.7' };
    const next = async (): Promise<void> => {};
    await limiter.middleware(
      {} as never,
      res as never,
      ctx as never,
      next,
    );
    await expect(
      limiter.middleware({} as never, res as never, ctx as never, next),
    ).rejects.toMatchObject({ code: 'RATE_LIMITED' });
    nowMs += 1001;
    await limiter.middleware({} as never, res as never, ctx as never, next);
    limiter.reset();
    await limiter.middleware({} as never, res as never, ctx as never, next);
  });

  test('buckets are isolated per key', async () => {
    const limiter = createRateLimiter({ maxRequests: 1, windowMs: 60_000 });
    const noopRes = { setHeader: (): void => {} };
    const next = async (): Promise<void> => {};
    await limiter.middleware({} as never, noopRes as never, { ip: '10.0.0.1' } as never, next);
    await limiter.middleware({} as never, noopRes as never, { ip: '10.0.0.2' } as never, next);
    await expect(
      limiter.middleware({} as never, noopRes as never, { ip: '10.0.0.1' } as never, next),
    ).rejects.toMatchObject({ code: 'RATE_LIMITED' });
  });
});
