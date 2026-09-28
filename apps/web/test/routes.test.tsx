import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, test, vi } from 'vitest';
import { renderAt, stubClient } from './appFixtures.js';

describe('routing', () => {
  test('home renders the hero and foundation grid', async () => {
    await renderAt('/');
    expect(screen.getByRole('heading', { name: 'Drobon Aegis AI' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Check service status' })).toHaveAttribute(
      'href',
      '/status',
    );
    expect(screen.getByText('Projects & source')).toBeInTheDocument();
    expect(screen.getByText(/SCA\/SBOM inventory/)).toBeInTheDocument();
  });

  test('unknown routes render the 404 page', async () => {
    await renderAt('/missing');
    expect(screen.getByRole('heading', { name: 'Page not found.' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Back to home' })).toHaveAttribute('href', '/');
  });

  test('status page shows loading, then service facts', async () => {
    let release!: (value: unknown) => void;
    const gate = new Promise((resolve) => {
      release = resolve;
    });
    const client = stubClient({ getStatus: vi.fn(() => gate as never) });
    await renderAt('/status', client);
    expect(screen.getByRole('status')).toHaveTextContent('Loading service status…');
    release({
      service: 'drobon-aegis-api',
      version: '0.1.0-test',
      environment: 'test',
      time: '2026-01-01T00:00:00.000Z',
    });
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Service status' })).toBeInTheDocument();
    });
    expect(screen.getByText('Reachable')).toBeInTheDocument();
    expect(screen.getByText('drobon-aegis-api')).toBeInTheDocument();
  });

  test('status page shows an error with retry that refetches', async () => {
    const user = userEvent.setup();
    const getStatus = vi
      .fn()
      .mockRejectedValueOnce(new Error('boom'))
      .mockResolvedValueOnce({
        service: 'drobon-aegis-api',
        version: '0.1.0-test',
        environment: 'test',
        time: '2026-01-01T00:00:00.000Z',
      });
    const client = stubClient({ getStatus: getStatus as never });
    await renderAt('/status', client);
    await waitFor(() => {
      expect(screen.getByRole('alert')).toBeInTheDocument();
    });
    await user.click(screen.getByRole('button', { name: 'Try again' }));
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Service status' })).toBeInTheDocument();
    });
    expect(getStatus).toHaveBeenCalledTimes(2);
  });

  test('navigation highlights the active link', async () => {
    const user = userEvent.setup();
    await renderAt('/');
    await user.click(screen.getByRole('link', { name: 'Service status' }));
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Service status' })).toBeInTheDocument();
    });
    expect(screen.getByRole('link', { name: 'Service status' })).toHaveClass('active');
  });
});
