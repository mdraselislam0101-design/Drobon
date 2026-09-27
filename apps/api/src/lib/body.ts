import type { IncomingMessage } from 'node:http';
import { invalidJsonBody, payloadTooLarge, unsupportedMediaType } from '../errors.js';

function isJsonContentType(header: string | undefined): boolean {
  if (header === undefined) {
    return false;
  }
  const mediaType = header.split(';')[0]?.trim().toLowerCase();
  return mediaType === 'application/json';
}

/**
 * Read and parse a JSON request body with strict guards:
 * - `Content-Type` must be `application/json` (415 otherwise),
 * - payloads past `maxBytes` are rejected (413),
 * - empty or malformed payloads are rejected (400).
 *
 * Oversized bodies are drained (not socket-destroyed) so the connection
 * stays alive long enough to deliver the 413 response. Drain time is
 * backstopped by the server's `requestTimeout`.
 */
export async function readJsonBody(
  req: IncomingMessage,
  options: { maxBytes: number },
): Promise<unknown> {
  const contentType = req.headers['content-type'];
  if (!isJsonContentType(contentType)) {
    throw unsupportedMediaType();
  }
  const chunks: Buffer[] = [];
  let total = 0;
  let overflow = false;
  await new Promise<void>((resolve, reject) => {
    const cleanup = (): void => {
      req.off('data', onData);
    };
    const onData = (chunk: unknown): void => {
      if (overflow) {
        return; // Keep draining; stop storing.
      }
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
      total += buffer.length;
      if (total > options.maxBytes) {
        overflow = true;
        chunks.length = 0;
        return;
      }
      chunks.push(buffer);
    };
    const onEnd = (): void => {
      cleanup();
      resolve();
    };
    const onError = (error: unknown): void => {
      cleanup();
      reject(error instanceof Error ? error : new Error(String(error)));
    };
    req.on('data', onData);
    req.once('end', onEnd);
    req.once('close', onEnd);
    req.once('error', onError);
  });
  if (overflow) {
    throw payloadTooLarge(options.maxBytes);
  }
  const text = Buffer.concat(chunks).toString('utf8');
  if (text.trim().length === 0) {
    throw invalidJsonBody('Request body must not be empty.');
  }
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw invalidJsonBody();
  }
}
