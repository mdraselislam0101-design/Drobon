import type { IncomingHttpHeaders, IncomingMessage, RequestOptions } from 'node:http';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import type { LookupFunction } from 'node:net';
import { isIP } from 'node:net';
import type { ResolvedDastTarget } from './target.js';

export interface DastProbeResponse {
  status: number;
  headers: IncomingHttpHeaders;
  body: string;
  bodyTruncated: boolean;
  elapsedMs: number;
}

export interface DastProbeOptions {
  timeoutMs: number;
  maxResponseBytes: number;
  signal: AbortSignal;
}

/** The only production network-execution seam used by DAST. */
export interface DastTransport {
  probe(target: ResolvedDastTarget, options: DastProbeOptions): Promise<DastProbeResponse>;
}

export class DastHttpError extends Error {
  constructor(readonly kind: 'timeout' | 'network' | 'aborted') {
    super(kind);
    this.name = 'DastHttpError';
  }
}

/**
 * One bounded GET. The caller must resolve and vet every address first;
 * the custom lookup pins this connection to a vetted IP so the socket
 * cannot perform a second, rebinding DNS lookup. Redirects are never
 * followed by this transport.
 */
export function createNodeDastTransport(): DastTransport {
  return {
    probe: (target, options) =>
      new Promise<DastProbeResponse>((resolve, reject) => {
        if (options.signal.aborted) {
          reject(new DastHttpError('aborted'));
          return;
        }
        const address = target.addresses[0];
        if (address === undefined) {
          reject(new DastHttpError('network'));
          return;
        }
        const url = new URL(target.url);
        const family = isIP(address);
        if (family !== 4 && family !== 6) {
          reject(new DastHttpError('network'));
          return;
        }
        const pinnedLookup = ((
          _hostname: string,
          lookupOptions: unknown,
          callback?: (error: NodeJS.ErrnoException | null, address: string | Array<{ address: string; family: number }>, family?: number) => void,
        ): void => {
          const done = typeof lookupOptions === 'function' ? lookupOptions as typeof callback : callback;
          if (typeof done !== 'function') return;
          const all = typeof lookupOptions === 'object' && lookupOptions !== null && 'all' in lookupOptions &&
            (lookupOptions as { all?: unknown }).all === true;
          if (all) done(null, [{ address, family }]);
          else done(null, address, family);
        }) as LookupFunction;
        const requestOptions: RequestOptions = {
          method: 'GET',
          agent: false,
          maxHeaderSize: 8192,
          lookup: pinnedLookup,
          headers: {
            accept: 'text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.1',
            'accept-encoding': 'identity',
            'cache-control': 'no-cache',
            origin: 'https://drobon-aegis.invalid',
            'user-agent': 'Drobon-Aegis-DAST/1.0',
            connection: 'close',
          },
        };
        const startedAt = Date.now();
        const request = (url.protocol === 'https:' ? httpsRequest : httpRequest)(
          url,
          requestOptions,
          (response: IncomingMessage) => {
            const chunks: Buffer[] = [];
            let received = 0;
            let truncated = false;
            const finish = (): void => {
              if (settled) return;
              settled = true;
              cleanup();
              const status = response.statusCode;
              if (status === undefined || status < 100 || status > 599) {
                reject(new DastHttpError('network'));
                return;
              }
              resolve({
                status,
                headers: response.headers,
                body: Buffer.concat(chunks, received).toString('utf8'),
                bodyTruncated: truncated,
                elapsedMs: Math.max(0, Date.now() - startedAt),
              });
            };
            response.on('data', (chunk: Buffer | string) => {
              const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
              const remaining = Math.max(0, options.maxResponseBytes - received);
              if (bytes.length > remaining) {
                if (remaining > 0) {
                  chunks.push(bytes.subarray(0, remaining));
                  received += remaining;
                }
                truncated = true;
                // Stop reading immediately; no decompression or unbounded buffering.
                response.pause();
                request.destroy();
                finish();
                return;
              }
              if (bytes.length > 0) {
                chunks.push(bytes);
                received += bytes.length;
              }
            });
            response.once('end', finish);
            response.once('aborted', () => {
              truncated = true;
              finish();
            });
            response.once('error', () => {
              if (!settled) rejectOnce(new DastHttpError('network'));
            });
            function rejectOnce(error: Error): void {
              if (settled) return;
              settled = true;
              cleanup();
              reject(error);
            }
          },
        );

        let settled = false;
        const cleanup = (): void => {
          clearTimeout(timer);
          options.signal.removeEventListener('abort', onAbort);
        };
        const onAbort = (): void => {
          request.destroy(new DastHttpError('aborted'));
        };
        const timer = setTimeout(() => {
          request.destroy(new DastHttpError('timeout'));
        }, options.timeoutMs);
        timer.unref?.();
        options.signal.addEventListener('abort', onAbort, { once: true });
        request.once('error', (error: Error) => {
          if (settled) return;
          settled = true;
          cleanup();
          if (error instanceof DastHttpError) reject(error);
          else reject(new DastHttpError('network'));
        });
        request.end();
      }),
  };
}
