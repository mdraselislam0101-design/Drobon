import { act, render } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { vi } from 'vitest';
import type {
  AssessmentResponse,
  AssessmentDetailResponse,
  AssessmentsResponse,
  AssistantQuestionRequest,
  AssistantResponse,
  AssistantStatusResponse,
  AuthResponse,
  CapabilityResponse,
  CurrentUserResponse,
  HealthResponse,
  FindingsPageResponse,
  FindingDetailResponse,
  FindingHistoryResponse,
  FindingWorkflowResponse,
  SecurityReportResponse,
  LogoutResponse,
  ProjectResponse,
  ProjectsResponse,
  ScanDetailResponse,
  ScanResponse,
  ScansResponse,
  SourceSnapshotResponse,
  StatusResponse,
  SubscriptionResponse,
  UsageResponse,
  PaymentConfigResponse,
  PaymentHistoryResponse,
  PaymentDetailResponse,
  AdminPaymentsResponse,
  AdminDashboardResponse,
  AdminAccountsResponse,
  AdminScansResponse,
  AdminFindingsResponse,
  AdminAuditResponse,
  PaymentAuditResponse,
  WorkspaceSecurityOverviewResponse,
} from '@drobon/shared';
import { ApiClientError, type ApiClient, type ReportDownload } from '../src/api/client.js';
import { AppRoutes } from '../src/routes.js';

/** A 401 ApiClientError, as the API returns for anonymous requests. */
export function unauthorizedError(message = 'Authentication required.'): ApiClientError {
  return new ApiClientError({
    kind: 'http',
    message,
    status: 401,
    code: 'UNAUTHORIZED',
    requestId: 'req-test-401',
  });
}

/** A 403 ApiClientError, as the API returns for denied capabilities. */
export function forbiddenError(
  message = 'You do not have access to this resource.',
): ApiClientError {
  return new ApiClientError({
    kind: 'http',
    message,
    status: 403,
    code: 'FORBIDDEN',
    requestId: 'req-test-403',
  });
}

export const TEST_USER = {
  id: 'usr_test_1',
  email: 'user@example.test',
  createdAt: '2026-01-01T00:00:00.000Z',
  role: 'MEMBER',
  userType: null,
} as const;

/**
 * Full ApiClient double. Defaults model the anonymous world (GET /me →
 * 401); individual suites override the methods they exercise.
 */
export function stubClient(overrides: Partial<ApiClient> = {}): ApiClient {
  return {
    getStatus: vi.fn(async (): Promise<StatusResponse> => ({
      service: 'drobon-aegis-api',
      version: '0.1.0-test',
      environment: 'test',
      time: '2026-01-01T00:00:00.000Z',
    })),
    getLivez: vi.fn(async (): Promise<HealthResponse> => ({
      status: 'ok',
      service: 's',
      version: 'v',
    })),
    postEcho: vi.fn(async (message: string) => ({
      message,
      length: message.length,
      receivedAt: '2026-01-01T00:00:00.000Z',
    })),
    getMe: vi.fn(async (): Promise<CurrentUserResponse> => {
      throw unauthorizedError();
    }),
    postRegister: vi.fn(
      async (email: string): Promise<AuthResponse> => ({ user: { ...TEST_USER, email } }),
    ),
    postLogin: vi.fn(
      async (email: string): Promise<AuthResponse> => ({ user: { ...TEST_USER, email } }),
    ),
    postLogout: vi.fn(async (): Promise<LogoutResponse> => ({ loggedOut: true })),
    // Pump 3 defaults: a MEMBER world — member capability granted,
    // higher capabilities denied, privileged lookup denied.
    getCapability: vi.fn(
      async (level: 'member' | 'admin' | 'owner'): Promise<CapabilityResponse> => {
        if (level !== 'member') {
          throw forbiddenError();
        }
        return { capability: 'member' };
      },
    ),
    getUserById: vi.fn(async () => {
      throw forbiddenError();
    }),
    // Pump 4 default: the FREE world — FREE + ACTIVE, no PRO entitlement.
    getSubscription: vi.fn(async (): Promise<SubscriptionResponse> => ({
      subscription: {
        plan: 'FREE',
        status: 'ACTIVE',
        createdAt: '2026-01-01T00:00:00.000Z',
        updatedAt: '2026-01-01T00:00:00.000Z',
      },
      entitlements: ['plan:view'],
    })),
    getPaymentConfig: vi.fn(async (): Promise<PaymentConfigResponse> => ({
      currentPlan: 'FREE', proPriceMinorUnits: 100_000, currency: 'BDT',
      manualPaymentMethods: ['MANUAL_TRANSFER'],
      manualPaymentInstructions: 'Payment instructions are not configured. Contact support before sending funds.',
      onlineGateway: 'UNAVAILABLE', coupons: 'NOT_IMPLEMENTED',
    })),
    getPaymentHistory: vi.fn(async (): Promise<PaymentHistoryResponse> => ({ payments: [], page: 1, pageSize: 20, total: 0 })),
    createPayment: vi.fn(async (): Promise<PaymentDetailResponse> => { throw new Error('not stubbed'); }),
    getPayment: vi.fn(async (): Promise<PaymentDetailResponse> => { throw new Error('not stubbed'); }),
    cancelPayment: vi.fn(async (): Promise<PaymentDetailResponse> => { throw new Error('not stubbed'); }),
    getAdminDashboard: vi.fn(async (): Promise<AdminDashboardResponse> => { throw forbiddenError(); }),
    getAdminAccounts: vi.fn(async (): Promise<AdminAccountsResponse> => ({ accounts: [], page: 1, pageSize: 25, total: 0 })),
    getAdminScans: vi.fn(async (): Promise<AdminScansResponse> => ({ scans: [], page: 1, pageSize: 25, total: 0 })),
    getAdminFindings: vi.fn(async (): Promise<AdminFindingsResponse> => ({ findings: [], page: 1, pageSize: 25, total: 0 })),
    getAdminAudit: vi.fn(async (): Promise<AdminAuditResponse> => ({ events: [], page: 1, pageSize: 50, total: 0, coverage: 'PAYMENT_EVENTS_ONLY' })),
    getAdminPayments: vi.fn(async (): Promise<AdminPaymentsResponse> => { throw forbiddenError(); }),
    startPaymentReview: vi.fn(async (): Promise<PaymentDetailResponse> => { throw new Error('not stubbed'); }),
    approvePayment: vi.fn(async (): Promise<PaymentDetailResponse> => { throw new Error('not stubbed'); }),
    rejectPayment: vi.fn(async (): Promise<PaymentDetailResponse> => { throw new Error('not stubbed'); }),
    getPaymentAudit: vi.fn(async (): Promise<PaymentAuditResponse> => ({ events: [] })),
    // Pump 5 default: a fresh FREE usage view (nothing consumed this
    // UTC month). Suites override it to model exhaustion or PRO.
    getUsage: vi.fn(async (): Promise<UsageResponse> => ({
      plan: 'FREE',
      period: {
        period: '2026-09',
        startUtc: '2026-09-01T00:00:00.000Z',
        endUtc: '2026-10-01T00:00:00.000Z',
      },
      used: 0,
      limit: 3,
      remaining: 3,
      quotaStatus: 'OK',
    })),
    getSecurityOverview: vi.fn(async (): Promise<WorkspaceSecurityOverviewResponse> => ({ overview: {
      generatedAt: '2026-09-01T00:00:00.000Z',
      projects: { total: 0, active: 0, archived: 0, dastTargetsConfigured: 0, recent: [] },
      scans: { total: 0, byStatus: { QUEUED: 0, RUNNING: 0, COMPLETED: 0, FAILED: 0, TIMED_OUT: 0 }, recent: [] },
      findings: {
        currentObserved: 0, unresolved: 0,
        unresolvedBySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
        byLifecycleState: { OPEN: 0, ACKNOWLEDGED: 0, IN_PROGRESS: 0, RESOLVED: 0, REOPENED: 0 },
        byVerificationState: { OBSERVED: 0, NOT_OBSERVED_IN_LATEST_SCAN: 0 }, recent: [],
      },
      reports: { availableCount: 0, recent: [] },
    } })),
    // Pump 6 default: no projects yet (the honest empty world). Suites
    // override these to model owned/foreign/lifecycle states.
    getProjects: vi.fn(async (): Promise<ProjectsResponse> => ({ projects: [] })),
    getProject: vi.fn(async (): Promise<ProjectResponse> => {
      throw forbiddenError();
    }),
    createProject: vi.fn(async (): Promise<ProjectResponse> => {
      throw new Error('not stubbed');
    }),
    updateProject: vi.fn(async (): Promise<ProjectResponse> => {
      throw new Error('not stubbed');
    }),
    setDastTarget: vi.fn(async (): Promise<ProjectResponse> => {
      throw new Error('not stubbed');
    }),
    clearDastTarget: vi.fn(async (): Promise<ProjectResponse> => {
      throw new Error('not stubbed');
    }),
    getAssessments: vi.fn(async (): Promise<AssessmentsResponse> => ({ assessments: [] })),
    getAssessment: vi.fn(async (): Promise<AssessmentDetailResponse> => { throw new Error('not stubbed'); }),
    createAssessment: vi.fn(async (): Promise<AssessmentResponse> => { throw new Error('not stubbed'); }),
    updateAssessment: vi.fn(async (): Promise<AssessmentResponse> => { throw new Error('not stubbed'); }),
    setAssessmentStatus: vi.fn(async (): Promise<AssessmentResponse> => { throw new Error('not stubbed'); }),
    recordAssessmentAuthorization: vi.fn(async (): Promise<AssessmentResponse> => { throw new Error('not stubbed'); }),
    archiveProject: vi.fn(async (): Promise<ProjectResponse> => {
      throw new Error('not stubbed');
    }),
    unarchiveProject: vi.fn(async (): Promise<ProjectResponse> => {
      throw new Error('not stubbed');
    }),
    // Pump 7 defaults: no scans yet (the honest empty world); scan
    // requests are not stubbed (suites that exercise them override).
    getScans: vi.fn(async (): Promise<ScansResponse> => ({ scans: [] })),
    createScan: vi.fn(async (): Promise<ScanResponse> => {
      throw new Error('not stubbed');
    }),
    // Pump 8 defaults: scan detail and source snapshots start empty; a
    // missing snapshot reads as the honest 404-shaped error.
    getScan: vi.fn(async (): Promise<ScanDetailResponse> => {
      throw new ApiClientError({
        kind: 'http',
        message: 'Not found.',
        status: 404,
        requestId: 'test',
      });
    }),
    getFindings: vi.fn(async (): Promise<FindingsPageResponse> => ({ findings: [], page: 1, pageSize: 20, total: 0, totalPages: 0 })),
    getFinding: vi.fn(async (): Promise<FindingDetailResponse> => { throw new Error('not stubbed'); }),
    setFindingLifecycle: vi.fn(async (): Promise<FindingWorkflowResponse> => { throw new Error('not stubbed'); }),
    addFindingNote: vi.fn(async (): Promise<FindingWorkflowResponse> => { throw new Error('not stubbed'); }),
    getFindingHistory: vi.fn(async (): Promise<FindingHistoryResponse> => { throw new Error('not stubbed'); }),
    createReport: vi.fn(async (): Promise<SecurityReportResponse> => { throw new Error('not stubbed'); }),
    getReport: vi.fn(async (): Promise<SecurityReportResponse> => { throw new Error('not stubbed'); }),
    downloadReport: vi.fn(async (): Promise<ReportDownload> => { throw new Error('not stubbed'); }),
    getAssistantStatus: vi.fn(async (): Promise<AssistantStatusResponse> => ({ providerState: 'NONE', providerId: null, deterministicQuestionsAvailable: true, conversationPersistence: 'NOT_IMPLEMENTED', toolsEnabled: false })),
    askAssistant: vi.fn(async (_projectId: string, _input: AssistantQuestionRequest): Promise<AssistantResponse> => { throw new Error('not stubbed'); }),
    getSources: vi.fn(async (): Promise<SourceSnapshotResponse> => {
      throw new ApiClientError({
        kind: 'http',
        message: 'Not found.',
        status: 404,
        requestId: 'test',
      });
    }),
    uploadSources: vi.fn(async (): Promise<SourceSnapshotResponse> => {
      throw new Error('not stubbed');
    }),
    ...overrides,
  };
}

/** Mount the real route tree at `path` and flush the session probe. */
export async function renderAt(
  path: string,
  client: ApiClient = stubClient(),
  locationState?: unknown,
): Promise<void> {
  render(
    <MemoryRouter
      initialEntries={[
        locationState === undefined ? path : { pathname: path, state: locationState },
      ]}
    >
      <AppRoutes client={client} appName="Test App" appVersion="0.1.0-test" />
    </MemoryRouter>,
  );
  await act(async () => {
    await Promise.resolve();
  });
}
