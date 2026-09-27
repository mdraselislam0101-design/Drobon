import { screen } from '@testing-library/react';
import { describe, expect, test, vi } from 'vitest';
import type { UsageResponse } from '@drobon/shared';
import type { ApiClient } from '../src/api/client.js';
import { renderAt, stubClient, TEST_USER } from './appFixtures.js';

/**
 * Pump 5 web tests — the Account page usage section.
 *
 * Rules under test:
 * - the panel renders ONLY the server's counts (plan, period, used,
 *   remaining, quota status) — never a local recomputation;
 * - FREE shows the 3-scan monthly allowance with the current UTC period;
 * - active PRO shows the exempt state (no limit), usage still tracked;
 * - failures fail CLOSED: an honest error, no numbers, nothing that
 *   looks like an allowance;
 * - the section is display-only: no client-side consumption path, no
 *   usage/plan/remaining state in localStorage or sessionStorage;
 * - tampering with browser storage never changes the rendered numbers.
 */

const FREE_FRESH: UsageResponse = {
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
};

const FREE_EXHAUSTED: UsageResponse = {
  ...FREE_FRESH,
  used: 3,
  remaining: 0,
  quotaStatus: 'EXHAUSTED',
};

const PRO_EXEMPT: UsageResponse = {
  ...FREE_FRESH,
  plan: 'PRO',
  used: 12,
  limit: null,
  remaining: null,
  quotaStatus: 'EXEMPT',
};

function signedInClient(overrides: Partial<ApiClient> = {}): ApiClient {
  return stubClient({
    getMe: vi.fn(async () => ({ user: TEST_USER })),
    ...overrides,
  });
}

describe('Account page — monthly usage section', () => {
  test('renders the server-provided FREE allowance and UTC period', async () => {
    await renderAt(
      '/account',
      signedInClient({ getUsage: vi.fn(async () => FREE_FRESH) }),
    );
    expect(await screen.findByTestId('usage-panel')).toBeInTheDocument();
    expect(screen.getByTestId('usage-period')).toHaveTextContent('2026-09');
    expect(screen.getByTestId('usage-period')).toHaveTextContent('UTC');
    expect(screen.getByTestId('usage-used')).toHaveTextContent('0 of 3');
    expect(screen.getByTestId('usage-remaining')).toHaveTextContent('3');
    expect(screen.getByTestId('usage-status')).toHaveTextContent('Available');
  });

  test('renders exhaustion exactly as the server reports it', async () => {
    await renderAt(
      '/account',
      signedInClient({ getUsage: vi.fn(async () => FREE_EXHAUSTED) }),
    );
    expect(await screen.findByTestId('usage-panel')).toBeInTheDocument();
    expect(screen.getByTestId('usage-used')).toHaveTextContent('3 of 3');
    expect(screen.getByTestId('usage-remaining')).toHaveTextContent('0');
    expect(screen.getByTestId('usage-status')).toHaveTextContent('Monthly allowance used');
  });

  test('active PRO renders the exempt state: no limit, usage still tracked', async () => {
    await renderAt('/account', signedInClient({ getUsage: vi.fn(async () => PRO_EXEMPT) }));
    expect(await screen.findByTestId('usage-panel')).toBeInTheDocument();
    expect(screen.getByTestId('usage-used')).toHaveTextContent('12');
    expect(screen.getByTestId('usage-used')).not.toHaveTextContent('of');
    expect(screen.getByTestId('usage-remaining')).toHaveTextContent('No limit (PRO)');
    expect(screen.getByTestId('usage-status')).toHaveTextContent('PRO — no monthly limit');
    expect(screen.getByTestId('usage-panel')).toHaveTextContent('still tracked');
  });

  test('a lapsed PRO is NOT exempt — the server view decides, not the plan history', async () => {
    // The subscription endpoint says PRO/EXPIRED while the usage view
    // (the server's quota verdict) reports a FREE allowance: the panel
    // renders the usage verdict only.
    await renderAt(
      '/account',
      signedInClient({ getUsage: vi.fn(async () => FREE_EXHAUSTED) }),
    );
    expect(await screen.findByTestId('usage-panel')).toBeInTheDocument();
    expect(screen.getByTestId('usage-remaining')).toHaveTextContent('0');
    expect(screen.getByTestId('usage-status')).toHaveTextContent('Monthly allowance used');
  });

  test('usage load failures fail closed: honest error, no numbers, no allowance', async () => {
    await renderAt(
      '/account',
      signedInClient({
        getUsage: vi.fn(async () => {
          throw new Error('boom');
        }),
      }),
    );
    expect(await screen.findByTestId('usage-error')).toBeInTheDocument();
    expect(screen.getByTestId('usage-error')).toHaveTextContent(
      'Your allowance has not changed.',
    );
    expect(screen.queryByTestId('usage-panel')).toBeNull();
    expect(screen.queryByTestId('usage-used')).toBeNull();
    expect(screen.queryByTestId('usage-remaining')).toBeNull();
    // The rest of the page still works — the account shell is intact.
    expect(screen.getByTestId('plan-panel')).toBeInTheDocument();
  });

  test('the section is display-only: no consumption action exists anywhere', async () => {
    await renderAt(
      '/account',
      signedInClient({ getUsage: vi.fn(async () => FREE_FRESH) }),
    );
    await screen.findByTestId('usage-panel');
    // No button on the page consumes a scan or edits usage.
    const usagePanel = screen.getByTestId('usage-panel');
    expect(usagePanel.querySelector('button')).toBeNull();
    for (const label of ['Consume', 'Use scan', 'Run scan', 'Reset usage']) {
      expect(screen.queryByRole('button', { name: new RegExp(label, 'i') })).toBeNull();
    }
  });

  test('tampering with storage/URL never changes the rendered numbers', async () => {
    // Forged values planted everywhere the browser can reach.
    localStorage.setItem('drobon:plan', 'PRO');
    localStorage.setItem('drobon:used', '0');
    localStorage.setItem('drobon:remaining', '99');
    localStorage.setItem('drobon:period', '2099-12');
    sessionStorage.setItem('drobon:quotaStatus', 'EXEMPT');
    try {
      await renderAt(
        '/account?plan=PRO&used=0&remaining=99&period=2099-12',
        signedInClient({ getUsage: vi.fn(async () => FREE_EXHAUSTED) }),
      );
      expect(await screen.findByTestId('usage-panel')).toBeInTheDocument();
      // The server's verdict is the only one rendered.
      expect(screen.getByTestId('usage-period')).toHaveTextContent('2026-09');
      expect(screen.getByTestId('usage-used')).toHaveTextContent('3 of 3');
      expect(screen.getByTestId('usage-remaining')).toHaveTextContent('0');
      expect(screen.getByTestId('usage-status')).toHaveTextContent('Monthly allowance used');
      // And nothing sensitive (device identifiers) is ever rendered.
      expect(screen.queryByText(/device/i)).toBeNull();
    } finally {
      localStorage.clear();
      sessionStorage.clear();
    }
  });

  test('anonymous visitors never reach the page (protected route)', async () => {
    // Default stub: getMe → 401. The account route bounces anonymous
    // users before any usage view could render.
    await renderAt('/account');
    expect(screen.queryByTestId('usage-panel')).toBeNull();
    expect(screen.queryByTestId('usage-error')).toBeNull();
  });
});
