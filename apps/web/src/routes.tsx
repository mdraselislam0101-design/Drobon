import { Route, Routes } from 'react-router-dom';
import { ApiClientProvider } from './api/context.js';
import type { ApiClient } from './api/client.js';
import { AuthProvider } from './auth/context.js';
import { ErrorBoundary } from './components/ErrorBoundary.js';
import { Layout } from './components/Layout.js';
import { DeveloperDashboardRoute, PentesterDashboardRoute, ProtectedRoute, PublicOnlyRoute, SecurityProfessionalDashboardRoute, StudentDashboardRoute } from './components/RouteGuards.js';
import { AccountPage } from './pages/AccountPage.js';
import { AdminPaymentsPage } from './pages/AdminPaymentsPage.js';
import { AdminPartnersPage } from './pages/AdminPartnersPage.js';
import { AdminOperationsPage } from './pages/AdminOperationsPage.js';
import { PartnerDashboardPage } from './pages/PartnerDashboardPage.js';
import { HomePage } from './pages/HomePage.js';
import { DeveloperDashboardPage } from './pages/DeveloperDashboardPage.js';
import { StudentLearnPage } from './pages/StudentLearnPage.js';
import { ProjectDetailPage } from './pages/ProjectDetailPage.js';
import { ProjectsPage } from './pages/ProjectsPage.js';
import { LoginPage } from './pages/LoginPage.js';
import { NotFoundPage } from './pages/NotFoundPage.js';
import { RegisterPage } from './pages/RegisterPage.js';
import { StatusPage } from './pages/StatusPage.js';
import { PricingPage } from './pages/PricingPage.js';

export const APP_ROUTES = {
  home: '/',
  status: '/status',
  pricing: '/pricing',
  login: '/login',
  register: '/register',
  account: '/account',
  dashboard: '/dashboard',
  studentDashboard: '/student/dashboard',
  securityProfessionalDashboard: '/security-professional/dashboard',
  pentesterDashboard: '/pentester/dashboard',
  adminOperations: '/admin/operations',
  adminPayments: '/admin/payments',
  adminPartners: '/admin/partners',
  partnerDashboard: '/partner/dashboard',
  projects: '/projects',
  project: (projectId: string): string => `/projects/${projectId}`,
} as const;

/**
 * Route tree without the history wrapper, so tests can mount it in a
 * MemoryRouter while production uses a BrowserRouter (see App).
 *
 * One API client, one router, one auth provider — Pump 2 extends the
 * Pump 1 tree instead of standing up parallel systems.
 */
export function AppRoutes({
  client,
  appName,
  appVersion,
}: {
  client: ApiClient;
  appName: string;
  appVersion: string;
}): React.JSX.Element {
  return (
    <ApiClientProvider client={client}>
      <AuthProvider>
        <ErrorBoundary>
          <Routes>
            <Route element={<Layout appName={appName} appVersion={appVersion} />}>
              <Route index element={<HomePage />} />
              <Route path="pricing" element={<PricingPage />} />
              <Route path="status" element={<StatusPage />} />
              <Route
                path="login"
                element={
                  <PublicOnlyRoute>
                    <LoginPage />
                  </PublicOnlyRoute>
                }
              />
              <Route
                path="register"
                element={
                  <PublicOnlyRoute>
                    <RegisterPage />
                  </PublicOnlyRoute>
                }
              />
              {/* minRole wires the role-aware guard into the real tree:
                  MEMBER is the floor for /account (every signed-in
                  account), while the API independently enforces the
                  same boundary on every request. */}
              <Route element={<ProtectedRoute minRole="MEMBER" />}>
                <Route path="account" element={<AccountPage />} />
                <Route path="projects" element={<ProjectsPage />} />
                <Route path="projects/:projectId" element={<ProjectDetailPage />} />
                <Route element={<DeveloperDashboardRoute />}>
                  <Route path="dashboard" element={<DeveloperDashboardPage />} />
                </Route>
                <Route element={<StudentDashboardRoute />}>
                  <Route path="student/dashboard" element={<DeveloperDashboardPage />} />
                  <Route path="student/learn" element={<StudentLearnPage />} />
                </Route>
                <Route element={<SecurityProfessionalDashboardRoute />}>
                  <Route path="security-professional/dashboard" element={<DeveloperDashboardPage />} />
                </Route>
                <Route element={<PentesterDashboardRoute />}>
                  <Route path="pentester/dashboard" element={<DeveloperDashboardPage />} />
                </Route>
              </Route>
              <Route path="partner/dashboard" element={<PartnerDashboardPage />} />
              <Route element={<ProtectedRoute minRole="ADMIN" />}>
                <Route path="admin/operations" element={<AdminOperationsPage />} />
                <Route path="admin/payments" element={<AdminPaymentsPage />} />
                <Route path="admin/partners" element={<AdminPartnersPage />} />
              </Route>
              <Route path="*" element={<NotFoundPage />} />
            </Route>
          </Routes>
        </ErrorBoundary>
      </AuthProvider>
    </ApiClientProvider>
  );
}
