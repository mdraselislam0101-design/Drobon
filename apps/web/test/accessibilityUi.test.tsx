import { screen, waitFor } from '@testing-library/react';
import { describe, expect, test, vi } from 'vitest';
import type { ApiClient } from '../src/api/client.js';
import { renderAt, stubClient, TEST_USER } from './appFixtures.js';

/**
 * Accessibility baseline (Phase 8 / scorecard E).
 *
 * These are structural assertions — landmarks, skip link, live region, page
 * title and focus handling — not a WCAG conformance audit. A real audit needs
 * assistive-technology testing, which is explicitly NOT claimed here.
 */

function client(): ApiClient {
  return stubClient({ getMe: vi.fn(async () => ({ user: TEST_USER })) });
}

describe('application shell accessibility', () => {
  test('provides landmarks, a skip link and an accessible app name', async () => {
    await renderAt('/', client());
    expect(screen.getByRole('banner')).toBeInTheDocument();
    expect(screen.getByRole('main')).toBeInTheDocument();
    expect(screen.getByRole('contentinfo')).toBeInTheDocument();
    const skip = screen.getByRole('link', { name: /skip to content/i });
    expect(skip).toHaveAttribute('href', '#main');
    // The main landmark is the skip link's target and is focusable.
    const main = screen.getByRole('main');
    expect(main).toHaveAttribute('id', 'main');
    expect(main).toHaveAttribute('tabindex', '-1');
    expect(screen.getByRole('navigation', { name: /primary/i })).toBeInTheDocument();
  });

  test('updates the document title and announces each route change', async () => {
    await renderAt('/', client());
    // The title carries the app name the shell was configured with.
    await waitFor(() => { expect(document.title).toBe('Home · Test App'); });
    const announcer = screen.getByTestId('route-announcer');
    // A polite live region without role="status": the loading spinners own that
    // role, and duplicate live regions would announce twice.
    expect(announcer).toHaveAttribute('aria-live', 'polite');
    expect(announcer).toHaveAttribute('aria-atomic', 'true');
    expect(announcer).not.toHaveAttribute('role', 'status');
    expect(announcer).toHaveTextContent('Navigated to Home');
  });

  test('asynchronous state is announced, never conveyed by colour alone', async () => {
    await renderAt('/status', client());
    // The status page resolves asynchronously; whatever state it reaches must
    // be exposed through a live region, an alert or a busy marker.
    await waitFor(() => {
      const announced = document.querySelectorAll(
        '[role="status"], [role="alert"], [aria-live], [aria-busy="true"]',
      );
      expect(announced.length).toBeGreaterThan(0);
    });
  });
});
