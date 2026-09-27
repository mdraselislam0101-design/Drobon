import {
  isAuthResponse,
  isCapabilityResponse,
  isCurrentUserResponse,
  isLogoutResponse,
  isProjectResponse,
  isProjectsResponse,
  isSubscriptionResponse,
  isUsageResponse,
  parseApiResponse,
  type ApiErrorDetail,
  type AuthResponse,
  type AuthzCapability,
  type CapabilityResponse,
  type EchoResponse,
  type HealthResponse,
  type CurrentUserResponse,
  type LogoutResponse,
  type ProjectResponse,
  type ProjectsResponse,
  type StatusResponse,
  type SubscriptionResponse,
  type UsageResponse,
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
  /** Server-provided issue details (e.g. 422 field errors), if any. */
  readonly details?: unknown;

  constructor(options: {
    kind: ClientErrorKind;
    message: string;
    status?: number;
    code?: string;
    requestId?: string;
    details?: unknown;
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
    if (options.details !== undefined) {
      this.details = options.details;
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
  /** Create an account; the API sets the session cookie on success. */
  postRegister(email: string, password: string, signal?: AbortSignal): Promise<AuthResponse>;
  /** Authenticate; the API sets the session cookie on success. */
  postLogin(email: string, password: string, signal?: AbortSignal): Promise<AuthResponse>;
  /** Revoke the session. Idempotent (always resolves on HTTP success). */
  postLogout(signal?: AbortSignal): Promise<LogoutResponse>;
  /** Current authenticated user — rejects with 401 when anonymous. */
  getMe(signal?: AbortSignal): Promise<CurrentUserResponse>;
  /**
   * Ask the API whether the capability is granted (Pump 3). 403 is an
   * expected outcome the caller may render — the API decides, never the
   * client's view of its own role.
   */
  getCapability(
    level: AuthzCapability,
    signal?: AbortSignal,
  ): Promise<CapabilityResponse>;
  /**
   * Read a user record by id (ownership foundation). Self-read for every
   * account; ADMIN+ for others; uniform 403 otherwise.
   */
  getUserById(id: string, signal?: AbortSignal): Promise<CurrentUserResponse>;
  /**
   * The authenticated account's OWN subscription + the entitlements the
   * server derives from it (Pump 4). Read-only; rejects with 401 when
   * anonymous. The response is validated against the shared guard — the
   * client renders the server's verdict and never recomputes it.
   */
  getSubscription(signal?: AbortSignal): Promise<SubscriptionResponse>;
  /**
   * The authenticated account's OWN usage view (Pump 5): plan, current
   * UTC period, used/limit/remaining and the quota status. Read-only and
   * display-only; rejects with 401 when anonymous. The response is
   * validated against the shared guard — the server computes the quota,
   * the client only renders it.
   */
  getUsage(signal?: AbortSignal): Promise<UsageResponse>;
  /**
   * The authenticated caller's OWN projects (Pump 6), ordered
   * `updatedAt` DESC then `id` ASC by the server. Rejects with 401 when
   * anonymous. Validated by the shared guard.
   */
  getProjects(signal?: AbortSignal): Promise<ProjectsResponse>;
  /**
   * One of the caller's OWN projects. A missing/foreign/malformed id
   * rejects with 403 (the API's uniform no-oracle denial).
   */
  getProject(projectId: string, signal?: AbortSignal): Promise<ProjectResponse>;
  /**
   * Create a project. The server assigns id, ownership, status (ACTIVE)
   * and timestamps — only name/description travel in the body.
   */
  createProject(
    input: { name: string; description?: string },
    signal?: AbortSignal,
  ): Promise<ProjectResponse>;
  /**
   * Update a project's name/description (owner only). Status changes go
   * through the explicit archive/unarchive operations.
   */
  updateProject(
    projectId: string,
    input: { name?: string; description?: string },
    signal?: AbortSignal,
  ): Promise<ProjectResponse>;
  /** Archive a project (explicit lifecycle operation, owner only, idempotent). */
  archiveProject(projectId: string, signal?: AbortSignal): Promise<ProjectResponse>;
  /** Unarchive a project (explicit lifecycle operation, owner only, idempotent). */
  unarchiveProject(projectId: string, signal?: AbortSignal): Promise<ProjectResponse>;
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
        // Cookie auth (Pump 2): the session lives in an httpOnly cookie.
        // `include` makes split-host deployments work; same-origin
        // behavior is identical.
        credentials: 'include',
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
        ...(detail.details === undefined ? {} : { details: detail.details }),
      });
    }
    return parsed.data;
  };

  /**
   * Auth endpoints validate their payloads against the shared guards — a
   * response that smuggles extra fields or mangles the user shape fails as
   * `invalid-response` instead of reaching application state.
   */
  const authRequest = async <T>(
    path: string,
    init: RequestInit,
    guard: (value: unknown) => value is T,
  ): Promise<T> => {
    const data = await request<unknown>(path, init, generateId());
    if (!guard(data)) {
      throw new ApiClientError({
        kind: 'invalid-response',
        message: 'The server returned an unexpected response shape.',
        requestId: generateId(),
      });
    }
    return data;
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
    postRegister: (email: string, password: string, signal?: AbortSignal): Promise<AuthResponse> =>
      authRequest<AuthResponse>(
        '/api/v1/auth/register',
        {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ email, password }),
          ...(signal === undefined ? {} : { signal }),
        },
        isAuthResponse,
      ),
    postLogin: (email: string, password: string, signal?: AbortSignal): Promise<AuthResponse> =>
      authRequest<AuthResponse>(
        '/api/v1/auth/login',
        {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ email, password }),
          ...(signal === undefined ? {} : { signal }),
        },
        isAuthResponse,
      ),
    postLogout: (signal?: AbortSignal): Promise<LogoutResponse> =>
      authRequest<LogoutResponse>(
        '/api/v1/auth/logout',
        {
          method: 'POST',
          ...(signal === undefined ? {} : { signal }),
        },
        isLogoutResponse,
      ),
    getMe: (signal?: AbortSignal): Promise<CurrentUserResponse> =>
      authRequest<CurrentUserResponse>(
        '/api/v1/me',
        signal === undefined ? {} : { signal },
        isCurrentUserResponse,
      ),
    getCapability: (
      level: AuthzCapability,
      signal?: AbortSignal,
    ): Promise<CapabilityResponse> =>
      authRequest<CapabilityResponse>(
        `/api/v1/authz/capabilities/${level}`,
        signal === undefined ? {} : { signal },
        isCapabilityResponse,
      ),
    getUserById: (id: string, signal?: AbortSignal): Promise<CurrentUserResponse> =>
      authRequest<CurrentUserResponse>(
        `/api/v1/users?id=${encodeURIComponent(id)}`,
        signal === undefined ? {} : { signal },
        isCurrentUserResponse,
      ),
    getSubscription: (signal?: AbortSignal): Promise<SubscriptionResponse> =>
      authRequest<SubscriptionResponse>(
        '/api/v1/subscription',
        signal === undefined ? {} : { signal },
        isSubscriptionResponse,
      ),
    getUsage: (signal?: AbortSignal): Promise<UsageResponse> =>
      authRequest<UsageResponse>(
        '/api/v1/usage',
        signal === undefined ? {} : { signal },
        isUsageResponse,
      ),
    getProjects: (signal?: AbortSignal): Promise<ProjectsResponse> =>
      authRequest<ProjectsResponse>(
        '/api/v1/projects',
        signal === undefined ? {} : { signal },
        isProjectsResponse,
      ),
    getProject: (projectId: string, signal?: AbortSignal): Promise<ProjectResponse> =>
      authRequest<ProjectResponse>(
        `/api/v1/projects/${encodeURIComponent(projectId)}`,
        signal === undefined ? {} : { signal },
        isProjectResponse,
      ),
    createProject: (
      input: { name: string; description?: string },
      signal?: AbortSignal,
    ): Promise<ProjectResponse> =>
      authRequest<ProjectResponse>(
        '/api/v1/projects',
        {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify(input),
          ...(signal === undefined ? {} : { signal }),
        },
        isProjectResponse,
      ),
    updateProject: (
      projectId: string,
      input: { name?: string; description?: string },
      signal?: AbortSignal,
    ): Promise<ProjectResponse> =>
      authRequest<ProjectResponse>(
        `/api/v1/projects/${encodeURIComponent(projectId)}`,
        {
          method: 'PATCH',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify(input),
          ...(signal === undefined ? {} : { signal }),
        },
        isProjectResponse,
      ),
    archiveProject: (projectId: string, signal?: AbortSignal): Promise<ProjectResponse> =>
      authRequest<ProjectResponse>(
        `/api/v1/projects/${encodeURIComponent(projectId)}/archive`,
        { method: 'POST', ...(signal === undefined ? {} : { signal }) },
        isProjectResponse,
      ),
    unarchiveProject: (projectId: string, signal?: AbortSignal): Promise<ProjectResponse> =>
      authRequest<ProjectResponse>(
        `/api/v1/projects/${encodeURIComponent(projectId)}/unarchive`,
        { method: 'POST', ...(signal === undefined ? {} : { signal }) },
        isProjectResponse,
      ),
  };
}
