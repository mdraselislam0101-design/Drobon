import { Route, Routes } from 'react-router-dom';
import { ApiClientProvider } from './api/context.js';
import type { ApiClient } from './api/client.js';
import { ErrorBoundary } from './components/ErrorBoundary.js';
import { Layout } from './components/Layout.js';
import { HomePage } from './pages/HomePage.js';
import { NotFoundPage } from './pages/NotFoundPage.js';
import { StatusPage } from './pages/StatusPage.js';

export const APP_ROUTES = {
  home: '/',
  status: '/status',
} as const;

/**
 * Route tree without the history wrapper, so tests can mount it in a
 * MemoryRouter while production uses a BrowserRouter (see App).
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
      <ErrorBoundary>
        <Routes>
          <Route element={<Layout appName={appName} appVersion={appVersion} />}>
            <Route index element={<HomePage />} />
            <Route path="status" element={<StatusPage />} />
            <Route path="*" element={<NotFoundPage />} />
          </Route>
        </Routes>
      </ErrorBoundary>
    </ApiClientProvider>
  );
}
