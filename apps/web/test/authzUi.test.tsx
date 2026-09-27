import { act, render, screen, within, fireEvent } from '@testing-library/react';
import { describe, expect, test, vi } from 'vitest';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import type { AuthUser, CurrentUserResponse } from '@drobon/shared';
import { ApiClientProvider } from '../src/api/context.js';
import { ApiClientError, type ApiClient } from '../src/api/client.js';
import { AuthProvider } from '../src/auth/context.js';
import { ProtectedRoute } from '../src/components/RouteGuards.js';
import {
  TEST_USER,
  forbiddenError,
  renderAt,
  stubClient,
  unauthorizedError,
} from './appFixtures.js';

/**
 * Web authorization (Pump 3): role-aware rendering, capability verdicts
 * driven by the API (not client state), forbidden vs unauthorized states,
 * and permission-aware UI visibility. Remember: hiding UI is UX only —
 * these tests always pair with the API suites that prove the real 403.
 */

function authedClient(
  user: Partial<AuthUser> = {},
  overrides: Partial<ApiClient> = {},
): ApiClient {
  const full: AuthUser = { ...TEST_USER, ...user };
  return stubClient({
    getMe: vi.fn(async (): Promise<CurrentUserResponse> => ({ user: full })),
    ...overrides,
  });
}

describe('account page authorization views', () => {
  test('shows the server-assigned role and user type badges', async () => {
    const client = authedClient({ role: 'ADMIN', userType: 'SECURITY_PROFESSIONAL' });
    await renderAt('/account', client);
    const roleBadge = await screen.findByTestId('role-badge');
    expect(roleBadge).toHaveTextContent('Role: ADMIN');
    const typeBadge = screen.getByTestId('usertype-badge');
    expect(typeBadge).toHaveTextContent('Type: SECURITY_PROFESSIONAL');
    // Profile facts still render (Pump 2 contract intact).
    const region = screen.getByRole('region', { name: /your account/i });
    expect(within(region).getByText('user@example.test')).toBeInTheDocument();
  });

  test('hides the user-type badge when none is set', async () => {
    await renderAt('/account', authedClient());
    await screen.findByTestId('role-badge');
    expect(screen.queryByTestId('usertype-badge')).toBeNull();
    expect(screen.getByTestId('role-badge')).toHaveTextContent('Role: MEMBER');
  });

  test('capability verdicts come from the API, not from client role guesses', async () => {
    // Default stub: MEMBER world — member granted, admin/owner denied.
    await renderAt('/account', authedClient());
    await screen.findByTestId('verdict-granted');
    expect(screen.getByTestId('capability-member')).toHaveTextContent('Member capability');
    expect(screen.getByTestId('verdict-granted')).toBeInTheDocument();
    // Two denied verdicts (admin + owner), each tied to its row.
    expect(screen.getByTestId('capability-admin')).toHaveTextContent('Denied (403)');
    expect(screen.getByTestId('capability-owner')).toHaveTextContent('Denied (403)');
  });

  test('a member user with ADMIN-shaped expectations still gets API denials (forced-open UI proves nothing)', async () => {
    // Even a client that "thinks" it is admin: if the API answers 403,
    // the page renders denial. (The inverse — role claims on the client —
    // is proven by the API suite.)
    const client = authedClient({ role: 'ADMIN' }, {
      getCapability: vi.fn(async () => {
        throw forbiddenError();
      }),
    });
    await renderAt('/account', client);
    const denied = await screen.findAllByTestId('verdict-denied');
    expect(denied.length).toBe(3);
    expect(screen.getAllByText('Denied (403)').length).toBe(3);
  });

  test('404 from the probes (production gating) renders as unavailable, not a crash', async () => {
    const client = authedClient({}, {
      getCapability: vi.fn(async () => {
        throw new ApiClientError({
          kind: 'http',
          message: 'Not Found.',
          status: 404,
          code: 'NOT_FOUND',
        });
      }),
    });
    await renderAt('/account', client);
    const unavailable = await screen.findAllByTestId('verdict-unavailable');
    expect(unavailable.length).toBe(3);
    expect(screen.getAllByText('Not available here').length).toBe(3);
  });
});

describe('privileged lookup visibility (UX defense-in-depth)', () => {
  test('MEMBER does not see the privileged lookup section', async () => {
    await renderAt('/account', authedClient());
    await screen.findByTestId('role-badge');
    expect(screen.queryByTestId('privileged-lookup')).toBeNull();
  });

  test('ADMIN sees it, and a denied lookup renders the forbidden message', async () => {
    const client = authedClient({ role: 'ADMIN' }, {
      // API still refuses — e.g. target id unknown or rights revoked.
      getUserById: vi.fn(async () => {
        throw forbiddenError();
      }),
    });
    await renderAt('/account', client);
    const lookup = await screen.findByTestId('privileged-lookup');
    const input = within(lookup).getByLabelText('Account ID');
    // Type an id and submit — the API's 403 is what the UI shows.
    fireEvent.change(input, { target: { value: 'usr_someone-else' } });
    fireEvent.click(within(lookup).getByRole('button', { name: 'Look up' }));
    const denied = await screen.findByTestId('lookup-denied');
    expect(denied).toHaveTextContent("You don't have access to this resource.");
  });
});

describe('ProtectedRoute role gating', () => {
  // The guard reads useAuth() — mount inside ApiClientProvider +
  // AuthProvider exactly like the app, then flush the session probe.
  async function renderGuarded(
    minRole: 'MEMBER' | 'ADMIN' | 'ACCOUNT_OWNER',
    client: ApiClient,
  ): Promise<void> {
    render(
      <ApiClientProvider client={client}>
        <AuthProvider>
          <MemoryRouter initialEntries={['/secret']}>
            <Routes>
              <Route element={<ProtectedRoute minRole={minRole} />}>
                <Route path="/secret" element={<p>secret-page</p>} />
              </Route>
              <Route path="/login" element={<p>login-page</p>} />
              <Route path="/" element={<p>home-page</p>} />
            </Routes>
          </MemoryRouter>
        </AuthProvider>
      </ApiClientProvider>,
    );
    await act(async () => {
      await Promise.resolve();
    });
  }

  test('authenticated user below minRole sees the forbidden state, not a login redirect', async () => {
    await renderGuarded('ADMIN', authedClient());
    const forbidden = await screen.findByTestId('forbidden-state');
    expect(forbidden).toBeInTheDocument();
    expect(forbidden).toHaveTextContent('Access denied');
    // The session is FINE — the user must NOT be bounced to login.
    expect(screen.queryByText('login-page')).toBeNull();
    expect(screen.queryByText('secret-page')).toBeNull();
  });

  test('authenticated user meeting minRole sees the protected content', async () => {
    await renderGuarded('ADMIN', authedClient({ role: 'ADMIN' }));
    expect(await screen.findByText('secret-page')).toBeInTheDocument();
    expect(screen.queryByTestId('forbidden-state')).toBeNull();
  });

  test('anonymous visitors still go to login (401 semantics preserved)', async () => {
    const anon = stubClient({
      getMe: vi.fn(async () => {
        throw unauthorizedError();
      }),
    });
    await renderGuarded('MEMBER', anon);
    expect(await screen.findByText('login-page')).toBeInTheDocument();
    expect(screen.queryByTestId('forbidden-state')).toBeNull();
  });
});
