import { Route, Routes } from 'react-router-dom';
import { ApiClientProvider } from './api/context.js';
import type { ApiClient } from './api/client.js';
import { AuthProvider } from './auth/context.js';
import { ErrorBoundary } from './components/ErrorBoundary.js';
import { Layout } from './components/Layout.js';
import { ProtectedRoute, PublicOnlyRoute } from './components/RouteGuards.js';
import { AccountPage } from './pages/AccountPage.js';
import { HomePage } from './pages/HomePage.js';
import { LoginPage } from './pages/LoginPage.js';
import { NotFoundPage } from './pages/NotFoundPage.js';
import { RegisterPage } from './pages/RegisterPage.js';
import { StatusPage } from './pages/StatusPage.js';

export const APP_ROUTES = {
  home: '/',
  status: '/status',
  login: '/login',
  register: '/register',
  account: '/account',
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
              <Route element={<ProtectedRoute />}>
                <Route path="account" element={<AccountPage />} />
              </Route>
              <Route path="*" element={<NotFoundPage />} />
            </Route>
          </Routes>
        </ErrorBoundary>
      </AuthProvider>
    </ApiClientProvider>
  );
}
