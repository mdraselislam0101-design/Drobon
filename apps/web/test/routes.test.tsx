import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, test, vi } from 'vitest';
import { renderAt, stubClient, TEST_USER } from './appFixtures.js';

describe('routing', () => {
  test('an existing Student session visiting login is routed to the Student dashboard', async () => {
    const client = stubClient({
      getMe: vi.fn(async () => ({ user: { ...TEST_USER, userType: 'STUDENT' as const } })),
    });
    await renderAt('/login', client);
    expect(await screen.findByRole('heading', { name: 'Student security dashboard' })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Sign in' })).toBeNull();
    expect(client.getSecurityOverview).toHaveBeenCalledTimes(1);
  });

  test('an existing Security Professional session visiting login lands on the professional dashboard', async () => {
    const client = stubClient({
      getMe: vi.fn(async () => ({ user: { ...TEST_USER, userType: 'SECURITY_PROFESSIONAL' as const } })),
    });
    await renderAt('/login', client);
    expect(await screen.findByRole('heading', { name: 'Security Professional dashboard' })).toBeInTheDocument();
    expect(client.getSecurityOverview).toHaveBeenCalledTimes(1);
  });

  test('home renders the hero and foundation grid', async () => {
    await renderAt('/');
    expect(screen.getByRole('heading', { name: 'Drobon Aegis AI' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Check service status' })).toHaveAttribute(
      'href',
      '/status',
    );
    expect(screen.getByText('Projects & source')).toBeInTheDocument();
    expect(screen.getByText(/SCA\/SBOM inventory/)).toBeInTheDocument();
    expect(screen.getByText('Professional assessments')).toBeInTheDocument();
    expect(screen.getByText(/developers, students and security professionals/)).toBeInTheDocument();
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
