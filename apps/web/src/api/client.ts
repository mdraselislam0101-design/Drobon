import {
  parseApiResponse,
  type ApiErrorDetail,
  type EchoResponse,
  type HealthResponse,
  type StatusResponse,
} from '@drobon/shared';

export type ClientErrorKind = 'timeout' | 'aborted' | 'network' | 'http' | 'invalid-response';

/**
 * Typed API failure. `message` is always safe to show users (it comes from
 * the server's error contract or from our own fixed strings — never from
 * raw transport internals).
 */
export class ApiClientError extends Error {
  readonly kind: ClientErrorKind;
  readonly status?: number;
  readonly code?: string;
  readonly requestId?: string;

  constructor(options: {
    kind: ClientErrorKind;
    message: string;
    status?: number;
    code?: string;
    requestId?: string;
  }) {
    super(options.message);
    this.name = 'ApiClientError';
    this.kind = options.kind;
    if (options.status !== undefined) {
      this.status = options.status;
    }
    if (options.code !== undefined) {
      this.code = options.code;
    }
    if (options.requestId !== undefined) {
      this.requestId = options.requestId;
    }
  }
}

export interface ApiClientOptions {
  baseUrl: string;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
  generateId?: () => string;
}

export interface RequestOptions {
  signal?: AbortSignal;
}

function defaultGenerateId(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  return `web-${Date.now().toString(36)}-${Math.floor(Math.random() * 1e9).toString(36)}`;
}

export interface ApiClient {
  getStatus(signal?: AbortSignal): Promise<StatusResponse>;
  getLivez(signal?: AbortSignal): Promise<HealthResponse>;
  postEcho(message: string, signal?: AbortSignal): Promise<EchoResponse>;
}

/**
 * The single boundary between the React app and the HTTP API. Every request:
 * - carries a client-generated `x-request-id` (correlation),
 * - races against a timeout (default 10s) plus optional caller signal,
 * - validates the response envelope against the shared contracts.
 */
export function createApiClient(options: ApiClientOptions): ApiClient {
  const baseUrl = options.baseUrl;
  const timeoutMs = options.timeoutMs ?? 10_000;
  const fetchImpl = options.fetchImpl ?? globalThis.fetch.bind(globalThis);
  const generateId = options.generateId ?? defaultGenerateId;

  const request = async <T>(path: string, init: RequestInit, requestId: string): Promise<T> => {
    const externalSignal = init.signal ?? null;
    const controller = new AbortController();
    let timedOut = false;
    const onExternalAbort = (): void => {
      controller.abort();
    };
    if (externalSignal !== null) {
      if (externalSignal.aborted) {
        throw new ApiClientError({
          kind: 'aborted',
          message: 'The request was cancelled.',
          requestId,
        });
      }
      externalSignal.addEventListener('abort', onExternalAbort, { once: true });
    }
    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, timeoutMs);
    let response: Response;
    try {
      response = await fetchImpl(`${baseUrl}${path}`, {
        ...init,
        signal: controller.signal,
        headers: {
          accept: 'application/json',
          'x-request-id': requestId,
          ...(init.headers ?? {}),
        },
      });
    } catch {
      if (timedOut) {
        throw new ApiClientError({
          kind: 'timeout',
          message: 'The request timed out. Please try again.',
          requestId,
        });
      }
      if (externalSignal?.aborted === true) {
        throw new ApiClientError({
          kind: 'aborted',
          message: 'The request was cancelled.',
          requestId,
        });
      }
      throw new ApiClientError({
        kind: 'network',
        message: 'Could not reach the server. Check your connection and try again.',
        requestId,
      });
    } finally {
      clearTimeout(timer);
      externalSignal?.removeEventListener('abort', onExternalAbort);
    }

    let payload: unknown;
    try {
      payload = (await response.json()) as unknown;
    } catch {
      throw new ApiClientError({
        kind: 'invalid-response',
        message: 'The server returned an unreadable response.',
        status: response.status,
        requestId,
      });
    }
    const parsed = parseApiResponse<T>(payload);
    if (parsed === undefined) {
      throw new ApiClientError({
        kind: 'invalid-response',
        message: 'The server returned an unexpected response shape.',
        status: response.status,
        requestId,
      });
    }
    if (!parsed.ok) {
      const detail: ApiErrorDetail = parsed.error;
      throw new ApiClientError({
        kind: 'http',
        message: detail.message,
        status: response.status,
        code: detail.code,
        requestId: parsed.meta.requestId,
      });
    }
    return parsed.data;
  };

  return {
    getStatus: (signal?: AbortSignal): Promise<StatusResponse> =>
      request<StatusResponse>(
        '/api/v1/status',
        signal === undefined ? {} : { signal },
        generateId(),
      ),
    getLivez: (signal?: AbortSignal): Promise<HealthResponse> =>
      request<HealthResponse>('/livez', signal === undefined ? {} : { signal }, generateId()),
    postEcho: (message: string, signal?: AbortSignal): Promise<EchoResponse> =>
      request<EchoResponse>(
        '/api/v1/echo',
        {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ message }),
          ...(signal === undefined ? {} : { signal }),
        },
        generateId(),
      ),
  };
}
