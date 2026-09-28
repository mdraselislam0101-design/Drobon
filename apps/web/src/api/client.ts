import {
  isAssistantResponse,
  isAssistantStatusResponse,
  isAuthResponse,
  isCapabilityResponse,
  isCurrentUserResponse,
  isLogoutResponse,
  isProjectResponse,
  isProjectsResponse,
  isScanDetailResponse,
  isFindingsPageResponse,
  isFindingDetailResponse,
  isFindingHistoryResponse,
  isFindingWorkflowResponse,
  isSecurityReportResponse,
  isScanResponse,
  isScansResponse,
  isSourceSnapshotResponse,
  isSubscriptionResponse,
  isUsageResponse,
  isPaymentConfigResponse,
  isPaymentHistoryResponse,
  isPaymentDetailResponse,
  isAdminPaymentsResponse,
  isAdminDashboardResponse,
  isAdminAccountsResponse,
  isAdminScansResponse,
  isAdminFindingsResponse,
  isAdminAuditResponse,
  isPaymentAuditResponse,
  isWorkspaceSecurityOverviewResponse,
  parseApiResponse,
  type ApiErrorDetail,
  type AssistantQuestionRequest,
  type AssistantResponse,
  type AssistantStatusResponse,
  type AuthResponse,
  type AuthzCapability,
  type CapabilityResponse,
  type EchoResponse,
  type HealthResponse,
  type CurrentUserResponse,
  type LogoutResponse,
  type ProjectResponse,
  type ProjectsResponse,
  type ScanDetailResponse,
  type ScanResponse,
  type FindingsPageResponse,
  type FindingDetailResponse,
  type FindingHistoryResponse,
  type FindingLifecycleState,
  type FindingWorkflowResponse,
  type FindingSeverity,
  type SecurityReportResponse,
  type ScansResponse,
  type ScanType,
  type SourceFileInput,
  type SourceSnapshotResponse,
  type StatusResponse,
  type SubscriptionResponse,
  type UsageResponse,
  type PaymentConfigResponse,
  type PaymentHistoryResponse,
  type PaymentDetailResponse,
  type AdminPaymentsResponse,
  type AdminDashboardResponse,
  type AdminAccountsResponse,
  type AdminScansResponse,
  type AdminFindingsResponse,
  type AdminAuditResponse,
  type AccountRole,
  type UserType,
  type Plan,
  type ScanStatus,
  type PaymentAuditAction,
  type PaymentAuditResponse,
  type WorkspaceSecurityOverviewResponse,
  type PaymentMethod,
  type PaymentStatus,
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

export interface ReportDownload {
  blob: Blob;
  filename: string;
  contentType: string;
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
  postRegister(email: string, password: string, userTypeOrSignal?: UserType | AbortSignal, signal?: AbortSignal): Promise<AuthResponse>;
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
  getPaymentConfig(signal?: AbortSignal): Promise<PaymentConfigResponse>;
  getPaymentHistory(page?: number, pageSize?: number, signal?: AbortSignal): Promise<PaymentHistoryResponse>;
  createPayment(input: { plan: 'PRO'; amountMinorUnits: number; currency: 'BDT'; paymentMethod: PaymentMethod; reference: string }, signal?: AbortSignal): Promise<PaymentDetailResponse>;
  getPayment(paymentId: string, signal?: AbortSignal): Promise<PaymentDetailResponse>;
  cancelPayment(paymentId: string, signal?: AbortSignal): Promise<PaymentDetailResponse>;
  getAdminDashboard(signal?: AbortSignal): Promise<AdminDashboardResponse>;
  getAdminAccounts(query?: { page?: number; pageSize?: number; role?: AccountRole; userType?: UserType | 'NONE'; plan?: Plan; search?: string }, signal?: AbortSignal): Promise<AdminAccountsResponse>;
  getAdminScans(query?: { page?: number; pageSize?: number; status?: ScanStatus; type?: ScanType; accountId?: string; projectId?: string; from?: string; to?: string }, signal?: AbortSignal): Promise<AdminScansResponse>;
  getAdminFindings(query?: { page?: number; pageSize?: number; severity?: FindingSeverity; scanner?: ScanType; state?: FindingLifecycleState; projectId?: string; from?: string; to?: string }, signal?: AbortSignal): Promise<AdminFindingsResponse>;
  getAdminAudit(query?: { page?: number; pageSize?: number; action?: PaymentAuditAction; accountId?: string; paymentId?: string; from?: string; to?: string }, signal?: AbortSignal): Promise<AdminAuditResponse>;
  getAdminPayments(page?: number, pageSize?: number, status?: PaymentStatus, signal?: AbortSignal): Promise<AdminPaymentsResponse>;
  startPaymentReview(paymentId: string, signal?: AbortSignal): Promise<PaymentDetailResponse>;
  approvePayment(paymentId: string, signal?: AbortSignal): Promise<PaymentDetailResponse>;
  rejectPayment(paymentId: string, reason: string, signal?: AbortSignal): Promise<PaymentDetailResponse>;
  getPaymentAudit(paymentId: string, signal?: AbortSignal): Promise<PaymentAuditResponse>;
  /**
   * The authenticated account's OWN usage view (Pump 5): plan, current
   * UTC period, used/limit/remaining and the quota status. Read-only and
   * display-only; rejects with 401 when anonymous. The response is
   * validated against the shared guard — the server computes the quota,
   * the client only renders it.
   */
  getUsage(signal?: AbortSignal): Promise<UsageResponse>;
  /** Bounded, authenticated overview of the caller's own project security activity. */
  getSecurityOverview(signal?: AbortSignal): Promise<WorkspaceSecurityOverviewResponse>;
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
  /** Configure/clear the explicit project-associated passive DAST target. */
  setDastTarget(projectId: string, targetUrl: string, signal?: AbortSignal): Promise<ProjectResponse>;
  clearDastTarget(projectId: string, signal?: AbortSignal): Promise<ProjectResponse>;
  /** Archive a project (explicit lifecycle operation, owner only, idempotent). */
  archiveProject(projectId: string, signal?: AbortSignal): Promise<ProjectResponse>;
  /** Unarchive a project (explicit lifecycle operation, owner only, idempotent). */
  unarchiveProject(projectId: string, signal?: AbortSignal): Promise<ProjectResponse>;
  /**
   * One project's scans (Pump 7), in the server's documented order.
   * A missing/foreign/malformed project id fails with the server's
   * uniform 403 — the honest error.
   */
  getScans(projectId: string, signal?: AbortSignal): Promise<ScansResponse>;
  /**
   * Request a scan (Pump 7). The client supplies ONLY the scan type and
   * an idempotency key — ownership, quota, ids, status and timestamps
   * are all server-authoritative. The key makes network retries safe:
   * a retry returns the ORIGINAL scan instead of charging twice.
   */
  createScan(
    projectId: string,
    scanType: ScanType,
    idempotencyKey: string,
    signal?: AbortSignal,
  ): Promise<ScanResponse>;
  /**
   * One scan's detail (Pump 8): the scan AND its real findings (bounded,
   * server-ordered) — the only read surface for findings.
   */
  getScan(
    projectId: string,
    scanId: string,
    signal?: AbortSignal,
  ): Promise<ScanDetailResponse>;
  /** Server-filtered, bounded finding page for one owned completed scan. */
  getFindings(
    projectId: string,
    scanId: string,
    filters?: { severity?: FindingSeverity; scanner?: ScanType; page?: number; pageSize?: number },
    signal?: AbortSignal,
  ): Promise<FindingsPageResponse>;
  /** Authorized detail for one finding nested under its project and scan. */
  getFinding(projectId: string, scanId: string, findingId: string, signal?: AbortSignal): Promise<FindingDetailResponse>;
  /** Server-enforced finding workflow transition; source evidence is never sent. */
  setFindingLifecycle(projectId: string, scanId: string, findingId: string, state: FindingLifecycleState, signal?: AbortSignal): Promise<FindingWorkflowResponse>;
  /** Add normalized, credential-redacted plain-text remediation notes. */
  addFindingNote(projectId: string, scanId: string, findingId: string, note: string, signal?: AbortSignal): Promise<FindingWorkflowResponse>;
  /** Bounded, newest-first lifecycle event history. */
  getFindingHistory(projectId: string, scanId: string, findingId: string, page?: number, pageSize?: number, signal?: AbortSignal): Promise<FindingHistoryResponse>;
  /** Create or return the persisted deterministic report for a completed scan. */
  createReport(projectId: string, scanId: string, signal?: AbortSignal): Promise<SecurityReportResponse>;
  /** Retrieve an existing persisted report without regenerating it. */
  getReport(projectId: string, scanId: string, signal?: AbortSignal): Promise<SecurityReportResponse>;
  /** Authenticated, bounded JSON or Markdown export. */
  downloadReport(projectId: string, scanId: string, format: 'json' | 'markdown', signal?: AbortSignal): Promise<ReportDownload>;
  /** Provider availability; currently reports the honest no-provider state. */
  getAssistantStatus(signal?: AbortSignal): Promise<AssistantStatusResponse>;
  /** Read-only deterministic question over one server-authorized project. */
  askAssistant(projectId: string, input: AssistantQuestionRequest, signal?: AbortSignal): Promise<AssistantResponse>;
  /**
   * The project's source-snapshot metadata (Pump 8) — the SAST scan
   * target. Content never travels back; 404 means no snapshot yet.
   */
  getSources(projectId: string, signal?: AbortSignal): Promise<SourceSnapshotResponse>;
  /**
   * Replace (or clear) the project's source snapshot — the deterministic
   * SAST input. Paths and content are validated by the server's single
   * path policy; the client sends exactly { files: [{ path, content }] }.
   */
  uploadSources(
    projectId: string,
    files: SourceFileInput[],
    signal?: AbortSignal,
  ): Promise<SourceSnapshotResponse>;
}

/**
 * The single boundary between the React app and the HTTP API. Every request:
 * - carries a client-generated `x-request-id` (correlation),
 * - races against a timeout (default 10s) plus optional caller signal,
 * - validates the response envelope against the shared contracts.
 */
function adminQuery(values: Record<string, string | number | undefined>): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(values)) {
    if (value !== undefined) params.set(key, String(value));
  }
  const serialized = params.toString();
  return serialized === '' ? '' : `?${serialized}`;
}

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

  const requestReportDownload = async (
    path: string,
    format: 'json' | 'markdown',
    signal?: AbortSignal,
  ): Promise<ReportDownload> => {
    const requestId = generateId();
    const controller = new AbortController();
    let timedOut = false;
    const onExternalAbort = (): void => controller.abort();
    if (signal !== undefined) {
      if (signal.aborted) throw new ApiClientError({ kind: 'aborted', message: 'The request was cancelled.', requestId });
      signal.addEventListener('abort', onExternalAbort, { once: true });
    }
    const timer = setTimeout(() => { timedOut = true; controller.abort(); }, timeoutMs);
    try {
      const response = await fetchImpl(`${baseUrl}${path}`, {
        credentials: 'include',
        signal: controller.signal,
        headers: { accept: format === 'json' ? 'application/json' : 'text/markdown', 'x-request-id': requestId },
      });
      if (!response.ok) {
        const payload = await response.json().catch(() => undefined) as unknown;
        const parsed = parseApiResponse<unknown>(payload);
        if (parsed !== undefined && !parsed.ok) {
          throw new ApiClientError({ kind: 'http', message: parsed.error.message, status: response.status, code: parsed.error.code, requestId: parsed.meta.requestId });
        }
        throw new ApiClientError({ kind: 'invalid-response', message: 'The server returned an unreadable report response.', status: response.status, requestId });
      }
      const contentType = response.headers.get('content-type') ?? '';
      const contentDisposition = response.headers.get('content-disposition') ?? '';
      const filenameMatch = /^attachment; filename="(drobon-rpt_[0-9a-f]{24}\.(?:json|md))"$/.exec(contentDisposition);
      const expectedType = format === 'json' ? /^application\/json(?:;\s*charset=utf-8)?$/i : /^text\/markdown(?:;\s*charset=utf-8)?$/i;
      const expectedSuffix = format === 'json' ? '.json' : '.md';
      const declaredLength = response.headers.get('content-length');
      if (!expectedType.test(contentType) || filenameMatch === null || !filenameMatch[1]?.endsWith(expectedSuffix) ||
          (declaredLength !== null && (!/^\d+$/.test(declaredLength) || Number(declaredLength) > 1024 * 1024))) {
        throw new ApiClientError({ kind: 'invalid-response', message: 'The server returned an unexpected report download.', status: response.status, requestId });
      }
      const chunks: ArrayBuffer[] = [];
      let totalBytes = 0;
      const reader = response.body?.getReader();
      if (reader !== undefined) {
        try {
          while (true) {
            const part = await reader.read();
            if (part.done) break;
            totalBytes += part.value.byteLength;
            if (totalBytes > 1024 * 1024) {
              await reader.cancel();
              throw new ApiClientError({ kind: 'invalid-response', message: 'The report download exceeds the allowed size.', status: response.status, requestId });
            }
            const copy = new Uint8Array(part.value.byteLength);
            copy.set(part.value);
            chunks.push(copy.buffer);
          }
        } finally {
          reader.releaseLock();
        }
      }
      if (totalBytes === 0) throw new ApiClientError({ kind: 'invalid-response', message: 'The report download was empty.', status: response.status, requestId });
      const blob = new Blob(chunks, { type: contentType });
      return { blob, filename: filenameMatch[1], contentType };
    } catch (error) {
      if (error instanceof ApiClientError) throw error;
      if (timedOut) throw new ApiClientError({ kind: 'timeout', message: 'The request timed out. Please try again.', requestId });
      if (signal?.aborted === true) throw new ApiClientError({ kind: 'aborted', message: 'The request was cancelled.', requestId });
      throw new ApiClientError({ kind: 'network', message: 'Could not reach the server. Check your connection and try again.', requestId });
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener('abort', onExternalAbort);
    }
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
    postRegister: (email: string, password: string, userTypeOrSignal?: UserType | AbortSignal, suppliedSignal?: AbortSignal): Promise<AuthResponse> => {
      const userType = typeof userTypeOrSignal === 'string' ? userTypeOrSignal : undefined;
      const signal = typeof userTypeOrSignal === 'string' ? suppliedSignal : userTypeOrSignal;
      return authRequest<AuthResponse>(
        '/api/v1/auth/register',
        {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ email, password, ...(userType === undefined ? {} : { userType }) }),
          ...(signal === undefined ? {} : { signal }),
        },
        isAuthResponse,
      );
    },
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
    getPaymentConfig: (signal?: AbortSignal): Promise<PaymentConfigResponse> =>
      authRequest<PaymentConfigResponse>('/api/v1/payments/config', signal === undefined ? {} : { signal }, isPaymentConfigResponse),
    getPaymentHistory: (page = 1, pageSize = 20, signal?: AbortSignal): Promise<PaymentHistoryResponse> =>
      authRequest<PaymentHistoryResponse>(`/api/v1/payments?page=${page}&pageSize=${pageSize}`, signal === undefined ? {} : { signal }, isPaymentHistoryResponse),
    createPayment: (input, signal?: AbortSignal): Promise<PaymentDetailResponse> =>
      authRequest<PaymentDetailResponse>('/api/v1/payments', {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'idempotency-key': generateId() },
        body: JSON.stringify(input),
        ...(signal === undefined ? {} : { signal }),
      }, isPaymentDetailResponse),
    getPayment: (paymentId, signal?: AbortSignal): Promise<PaymentDetailResponse> =>
      authRequest<PaymentDetailResponse>(`/api/v1/payments/${encodeURIComponent(paymentId)}`, signal === undefined ? {} : { signal }, isPaymentDetailResponse),
    cancelPayment: (paymentId, signal?: AbortSignal): Promise<PaymentDetailResponse> =>
      authRequest<PaymentDetailResponse>(`/api/v1/payments/${encodeURIComponent(paymentId)}/cancel`, { method: 'POST', ...(signal === undefined ? {} : { signal }) }, isPaymentDetailResponse),
    getAdminDashboard: (signal?: AbortSignal): Promise<AdminDashboardResponse> =>
      authRequest<AdminDashboardResponse>('/api/v1/admin/dashboard', signal === undefined ? {} : { signal }, isAdminDashboardResponse),
    getAdminAccounts: (query = {}, signal?: AbortSignal): Promise<AdminAccountsResponse> =>
      authRequest<AdminAccountsResponse>(`/api/v1/admin/accounts${adminQuery(query)}`, signal === undefined ? {} : { signal }, isAdminAccountsResponse),
    getAdminScans: (query = {}, signal?: AbortSignal): Promise<AdminScansResponse> =>
      authRequest<AdminScansResponse>(`/api/v1/admin/scans${adminQuery(query)}`, signal === undefined ? {} : { signal }, isAdminScansResponse),
    getAdminFindings: (query = {}, signal?: AbortSignal): Promise<AdminFindingsResponse> =>
      authRequest<AdminFindingsResponse>(`/api/v1/admin/findings${adminQuery(query)}`, signal === undefined ? {} : { signal }, isAdminFindingsResponse),
    getAdminAudit: (query = {}, signal?: AbortSignal): Promise<AdminAuditResponse> =>
      authRequest<AdminAuditResponse>(`/api/v1/admin/audit${adminQuery(query)}`, signal === undefined ? {} : { signal }, isAdminAuditResponse),
    getAdminPayments: (page = 1, pageSize = 20, status, signal?: AbortSignal): Promise<AdminPaymentsResponse> => {
      const params = new URLSearchParams({ page: String(page), pageSize: String(pageSize) });
      if (status !== undefined) params.set('status', status);
      return authRequest<AdminPaymentsResponse>(`/api/v1/admin/payments?${params.toString()}`, signal === undefined ? {} : { signal }, isAdminPaymentsResponse);
    },
    startPaymentReview: (paymentId, signal?: AbortSignal): Promise<PaymentDetailResponse> =>
      authRequest<PaymentDetailResponse>(`/api/v1/admin/payments/${encodeURIComponent(paymentId)}/review`, { method: 'POST', ...(signal === undefined ? {} : { signal }) }, isPaymentDetailResponse),
    approvePayment: (paymentId, signal?: AbortSignal): Promise<PaymentDetailResponse> =>
      authRequest<PaymentDetailResponse>(`/api/v1/admin/payments/${encodeURIComponent(paymentId)}/approve`, { method: 'POST', ...(signal === undefined ? {} : { signal }) }, isPaymentDetailResponse),
    rejectPayment: (paymentId, reason, signal?: AbortSignal): Promise<PaymentDetailResponse> =>
      authRequest<PaymentDetailResponse>(`/api/v1/admin/payments/${encodeURIComponent(paymentId)}/reject`, {
        method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ reason }),
        ...(signal === undefined ? {} : { signal }),
      }, isPaymentDetailResponse),
    getPaymentAudit: (paymentId, signal?: AbortSignal): Promise<PaymentAuditResponse> =>
      authRequest<PaymentAuditResponse>(`/api/v1/admin/payments/${encodeURIComponent(paymentId)}/audit`, signal === undefined ? {} : { signal }, isPaymentAuditResponse),
    getUsage: (signal?: AbortSignal): Promise<UsageResponse> =>
      authRequest<UsageResponse>(
        '/api/v1/usage',
        signal === undefined ? {} : { signal },
        isUsageResponse,
      ),
    getSecurityOverview: (signal?: AbortSignal): Promise<WorkspaceSecurityOverviewResponse> =>
      authRequest<WorkspaceSecurityOverviewResponse>(
        '/api/v1/me/security-overview',
        signal === undefined ? {} : { signal },
        isWorkspaceSecurityOverviewResponse,
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
    setDastTarget: (projectId: string, targetUrl: string, signal?: AbortSignal): Promise<ProjectResponse> =>
      authRequest<ProjectResponse>(
        `/api/v1/projects/${encodeURIComponent(projectId)}/dast-target`,
        {
          method: 'PUT',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ targetUrl }),
          ...(signal === undefined ? {} : { signal }),
        },
        isProjectResponse,
      ),
    clearDastTarget: (projectId: string, signal?: AbortSignal): Promise<ProjectResponse> =>
      authRequest<ProjectResponse>(
        `/api/v1/projects/${encodeURIComponent(projectId)}/dast-target`,
        { method: 'DELETE', ...(signal === undefined ? {} : { signal }) },
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
    getScans: (projectId: string, signal?: AbortSignal): Promise<ScansResponse> =>
      authRequest<ScansResponse>(
        `/api/v1/projects/${encodeURIComponent(projectId)}/scans`,
        signal === undefined ? {} : { signal },
        isScansResponse,
      ),
    createScan: (
      projectId: string,
      scanType: ScanType,
      idempotencyKey: string,
      signal?: AbortSignal,
    ): Promise<ScanResponse> =>
      authRequest<ScanResponse>(
        `/api/v1/projects/${encodeURIComponent(projectId)}/scans`,
        {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            'idempotency-key': idempotencyKey,
          },
          body: JSON.stringify({ scanType }),
          ...(signal === undefined ? {} : { signal }),
        },
        isScanResponse,
      ),
    getScan: (
      projectId: string,
      scanId: string,
      signal?: AbortSignal,
    ): Promise<ScanDetailResponse> =>
      authRequest<ScanDetailResponse>(
        `/api/v1/projects/${encodeURIComponent(projectId)}/scans/${encodeURIComponent(scanId)}`,
        signal === undefined ? {} : { signal },
        isScanDetailResponse,
      ),
    getFindings: (
      projectId: string,
      scanId: string,
      filters: { severity?: FindingSeverity; scanner?: ScanType; page?: number; pageSize?: number } = {},
      signal?: AbortSignal,
    ): Promise<FindingsPageResponse> => {
      const query = new URLSearchParams();
      if (filters.severity !== undefined) query.set('severity', filters.severity);
      if (filters.scanner !== undefined) query.set('scanner', filters.scanner);
      if (filters.page !== undefined) query.set('page', String(filters.page));
      if (filters.pageSize !== undefined) query.set('pageSize', String(filters.pageSize));
      const suffix = query.size === 0 ? '' : `?${query.toString()}`;
      return authRequest<FindingsPageResponse>(
        `/api/v1/projects/${encodeURIComponent(projectId)}/scans/${encodeURIComponent(scanId)}/findings${suffix}`,
        signal === undefined ? {} : { signal },
        isFindingsPageResponse,
      );
    },
    getFinding: (projectId: string, scanId: string, findingId: string, signal?: AbortSignal): Promise<FindingDetailResponse> =>
      authRequest<FindingDetailResponse>(
        `/api/v1/projects/${encodeURIComponent(projectId)}/scans/${encodeURIComponent(scanId)}/findings/${encodeURIComponent(findingId)}`,
        signal === undefined ? {} : { signal },
        isFindingDetailResponse,
      ),
    setFindingLifecycle: (projectId: string, scanId: string, findingId: string, state: FindingLifecycleState, signal?: AbortSignal): Promise<FindingWorkflowResponse> =>
      authRequest<FindingWorkflowResponse>(
        `/api/v1/projects/${encodeURIComponent(projectId)}/scans/${encodeURIComponent(scanId)}/findings/${encodeURIComponent(findingId)}/lifecycle`,
        { method: 'PATCH', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ state }), ...(signal === undefined ? {} : { signal }) },
        isFindingWorkflowResponse,
      ),
    addFindingNote: (projectId: string, scanId: string, findingId: string, note: string, signal?: AbortSignal): Promise<FindingWorkflowResponse> =>
      authRequest<FindingWorkflowResponse>(
        `/api/v1/projects/${encodeURIComponent(projectId)}/scans/${encodeURIComponent(scanId)}/findings/${encodeURIComponent(findingId)}/notes`,
        { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ note }), ...(signal === undefined ? {} : { signal }) },
        isFindingWorkflowResponse,
      ),
    getFindingHistory: (projectId: string, scanId: string, findingId: string, page = 1, pageSize = 20, signal?: AbortSignal): Promise<FindingHistoryResponse> => {
      const query = new URLSearchParams({ page: String(page), pageSize: String(pageSize) });
      return authRequest<FindingHistoryResponse>(
        `/api/v1/projects/${encodeURIComponent(projectId)}/scans/${encodeURIComponent(scanId)}/findings/${encodeURIComponent(findingId)}/history?${query.toString()}`,
        signal === undefined ? {} : { signal },
        isFindingHistoryResponse,
      );
    },
    createReport: (projectId: string, scanId: string, signal?: AbortSignal): Promise<SecurityReportResponse> =>
      authRequest<SecurityReportResponse>(
        `/api/v1/projects/${encodeURIComponent(projectId)}/scans/${encodeURIComponent(scanId)}/report`,
        {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({}),
          ...(signal === undefined ? {} : { signal }),
        },
        isSecurityReportResponse,
      ),
    getReport: (projectId: string, scanId: string, signal?: AbortSignal): Promise<SecurityReportResponse> =>
      authRequest<SecurityReportResponse>(
        `/api/v1/projects/${encodeURIComponent(projectId)}/scans/${encodeURIComponent(scanId)}/report`,
        signal === undefined ? {} : { signal },
        isSecurityReportResponse,
      ),
    downloadReport: (projectId: string, scanId: string, format: 'json' | 'markdown', signal?: AbortSignal): Promise<ReportDownload> =>
      requestReportDownload(
        `/api/v1/projects/${encodeURIComponent(projectId)}/scans/${encodeURIComponent(scanId)}/report/download?format=${format}`,
        format,
        signal,
      ),
    getAssistantStatus: (signal?: AbortSignal): Promise<AssistantStatusResponse> =>
      authRequest<AssistantStatusResponse>(
        '/api/v1/assistant/status',
        signal === undefined ? {} : { signal },
        isAssistantStatusResponse,
      ),
    askAssistant: (projectId: string, input: AssistantQuestionRequest, signal?: AbortSignal): Promise<AssistantResponse> =>
      authRequest<AssistantResponse>(
        `/api/v1/projects/${encodeURIComponent(projectId)}/assistant/ask`,
        { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(input), ...(signal === undefined ? {} : { signal }) },
        isAssistantResponse,
      ),
    getSources: (projectId: string, signal?: AbortSignal): Promise<SourceSnapshotResponse> =>
      authRequest<SourceSnapshotResponse>(
        `/api/v1/projects/${encodeURIComponent(projectId)}/sources`,
        signal === undefined ? {} : { signal },
        isSourceSnapshotResponse,
      ),
    uploadSources: (
      projectId: string,
      files: SourceFileInput[],
      signal?: AbortSignal,
    ): Promise<SourceSnapshotResponse> =>
      authRequest<SourceSnapshotResponse>(
        `/api/v1/projects/${encodeURIComponent(projectId)}/sources`,
        {
          method: 'PUT',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ files }),
          ...(signal === undefined ? {} : { signal }),
        },
        isSourceSnapshotResponse,
      ),
  };
}
