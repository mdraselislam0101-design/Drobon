import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, test, vi } from 'vitest';
import { ApiClientError } from '../src/api/client.js';
import { readSafePath } from '../src/components/RouteGuards.js';
import { renderAt, stubClient, TEST_USER, unauthorizedError } from './appFixtures.js';

describe('protected routes', () => {
  test('anonymous visitors are redirected to login, remembering the target', async () => {
    await renderAt('/account');
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Sign in' })).toBeInTheDocument();
    });
    // No "expired" notice for someone who was never signed in.
    expect(screen.queryByText('Your session expired. Please sign in again.')).toBeNull();
  });

  test('the loading probe shows a spinner, not a wrong guess', async () => {
    let failProbe!: (error: unknown) => void;
    const gate = new Promise((_resolve, reject) => {
      failProbe = reject;
    });
    const client = stubClient({
      getMe: vi.fn(() => gate as never),
    });
    await renderAt('/account', client);
    expect(screen.getByRole('status')).toHaveTextContent('Checking your session…');
    // Neither auth nav set is shown while the probe is pending.
    expect(screen.queryByRole('link', { name: 'Sign in' })).toBeNull();
    expect(screen.queryByRole('link', { name: 'Account' })).toBeNull();
    failProbe(unauthorizedError());
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Sign in' })).toBeInTheDocument();
    });
  });

  test('authenticated visitors reach the account page', async () => {
    const client = stubClient({
      getMe: vi.fn(async () => ({ user: TEST_USER })),
    });
    await renderAt('/account', client);
    expect(screen.getByRole('heading', { name: 'Your account' })).toBeInTheDocument();
    expect(screen.getByText('user@example.test')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Account' })).toBeInTheDocument();
  });

  test('session expiry mid-visit redirects to login with the notice', async () => {
    const user = userEvent.setup();
    // Two successful probes (initial load + AccountPage's mount re-check),
    // then the server stops honoring the session on the next refresh.
    const client = stubClient({
      getMe: vi
        .fn()
        .mockResolvedValueOnce({ user: TEST_USER })
        .mockResolvedValueOnce({ user: TEST_USER })
        .mockRejectedValue(
          new ApiClientError({
            kind: 'http',
            message: 'Authentication required.',
            status: 401,
            code: 'UNAUTHORIZED',
            requestId: 'req-expired-1',
          }),
        ),
    });
    await renderAt('/account', client);
    expect(screen.getByRole('heading', { name: 'Your account' })).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Refresh session' }));
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Sign in' })).toBeInTheDocument();
    });
    expect(
      screen.getByText('Your session expired. Please sign in again.'),
    ).toBeInTheDocument();
    expect(client.getMe).toHaveBeenCalledTimes(3);
  });

  test('a session probe failure (network) offers retry instead of fake logout', async () => {
    const client = stubClient({
      getMe: vi
        .fn()
        .mockRejectedValueOnce(
          new ApiClientError({
            kind: 'network',
            message: 'Could not reach the server. Check your connection and try again.',
            requestId: 'req-offline-1',
          }),
        )
        .mockResolvedValue({ user: TEST_USER }),
    });
    await renderAt('/account', client);
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('Could not reach the server');
    // Not redirected to login — the session may still be valid.
    expect(screen.queryByRole('heading', { name: 'Sign in' })).toBeNull();
    await userEvent.click(screen.getByRole('button', { name: 'Try again' }));
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Your account' })).toBeInTheDocument();
    });
  });
});

describe('logout flow', () => {
  test('signing out returns the user to the home page and anonymous nav', async () => {
    const user = userEvent.setup();
    const client = stubClient({
      getMe: vi.fn(async () => ({ user: TEST_USER })),
      postLogout: vi.fn(async () => ({ loggedOut: true })),
    });
    await renderAt('/account', client);
    await user.click(screen.getByRole('button', { name: 'Sign out' }));
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Drobon Aegis AI' })).toBeInTheDocument();
    });
    expect(client.postLogout).toHaveBeenCalledTimes(1);
    // Anonymous nav is back; the authenticated link is gone.
    expect(screen.getByRole('link', { name: 'Sign in' })).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Account' })).toBeNull();
  });

  test('a failed logout keeps the user signed in and reports the error', async () => {
    const user = userEvent.setup();
    const client = stubClient({
      getMe: vi.fn(async () => ({ user: TEST_USER })),
      postLogout: vi.fn(async () => {
        throw new ApiClientError({
          kind: 'network',
          message: 'Could not reach the server. Check your connection and try again.',
        });
      }),
    });
    await renderAt('/account', client);
    await user.click(screen.getByRole('button', { name: 'Sign out' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Could not reach the server',
    );
    // Still signed in — honest state, no fake logout.
    expect(screen.getByRole('heading', { name: 'Your account' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Account' })).toBeInTheDocument();
  });
});

describe('post-login navigation is confined to internal paths', () => {
  test.each([
    ['/account', '/account'],
    ['/status', '/status'],
    ['//evil.example.test', undefined],
    ['https://evil.example.test', undefined],
    ['/\\evil.example.test', undefined],
    ['/path\r\nLocation: https://evil.example.test', undefined],
    [undefined, undefined],
  ])('readSafePath(%j) → %j', (input, expected) => {
    expect(readSafePath(input === undefined ? undefined : { from: input })).toBe(expected);
  });

  test('non-object states are ignored', () => {
    expect(readSafePath(null)).toBeUndefined();
    expect(readSafePath('string-state')).toBeUndefined();
    expect(readSafePath({})).toBeUndefined();
    expect(readSafePath({ from: 42 })).toBeUndefined();
  });
});
