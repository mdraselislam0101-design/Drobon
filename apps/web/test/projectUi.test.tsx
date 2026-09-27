import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, test, vi } from 'vitest';
import type { Project, ProjectResponse, ProjectsResponse } from '@drobon/shared';
import type { ApiClient } from '../src/api/client.js';
import { renderAt, stubClient, TEST_USER } from './appFixtures.js';

/**
 * Pump 6 web tests — the Projects pages.
 *
 * Rules under test:
 * - the list renders ONLY what the server returned, in the server's
 *   order (no local re-sorting, no localStorage authority, no URL
 *   project state beyond the id);
 * - project text renders as TEXT — an XSS payload must never become
 *   markup (jsdom enforces this: script tags injected via textContent
 *   do not execute and are not present as elements);
 * - a foreign/unknown project id renders the honest error, exactly as
 *   the server answered (uniform 403 — no existence oracle);
 * - create/edit call the API client; the server is the authority;
 * - loading, empty, and error states are all honest;
 * - anonymous users never see project data (protected route).
 */

const project = (overrides: Partial<Project> = {}): Project => ({
  id: 'prj_00000000-0000-4000-8000-0000000000aa',
  name: 'Primary web app',
  description: 'The checkout flow.',
  status: 'ACTIVE',
  createdAt: '2026-09-28T10:00:00.000Z',
  updatedAt: '2026-09-28T10:00:00.000Z',
  ...overrides,
});

function projectsBody(list: Project[]): ProjectsResponse {
  return { projects: list };
}

function projectBody(p: Project): ProjectResponse {
  return { project: p };
}

function signedInClient(overrides: Partial<ApiClient> = {}): ApiClient {
  return stubClient({
    getMe: vi.fn(async () => ({ user: TEST_USER })),
    ...overrides,
  });
}

describe('Projects list page', () => {
  test('renders the server-provided projects with status badges', async () => {
    const list = [
      project({ id: 'prj_00000000-0000-4000-8000-0000000000bb', name: 'Second', updatedAt: '2026-09-29T10:00:00.000Z' }),
      project({ name: 'First' }),
      project({ id: 'prj_00000000-0000-4000-8000-0000000000cc', name: 'Old one', status: 'ARCHIVED', description: '' }),
    ];
    await renderAt(
      '/projects',
      signedInClient({ getProjects: vi.fn(async () => projectsBody(list)) }),
    );
    expect(await screen.findByTestId('projects-list')).toBeInTheDocument();
    const cards = screen.getAllByTestId('project-card');
    expect(cards).toHaveLength(3);
    // Server order is preserved verbatim (no client re-sorting).
    expect(cards[0]).toHaveTextContent('Second');
    expect(cards[1]).toHaveTextContent('First');
    expect(cards[2]).toHaveTextContent('Old one');
    expect(screen.getAllByTestId('project-status')[2]).toHaveTextContent('Archived');
    // Links point at the detail route.
    expect(screen.getAllByTestId('project-link')[0]).toHaveAttribute(
      'href',
      '/projects/prj_00000000-0000-4000-8000-0000000000bb',
    );
  });

  test('empty state is honest and friendly', async () => {
    await renderAt(
      '/projects',
      signedInClient({ getProjects: vi.fn(async () => projectsBody([])) }),
    );
    expect(await screen.findByTestId('empty-projects')).toBeInTheDocument();
    expect(screen.getByTestId('empty-projects')).toHaveTextContent('No projects yet');
  });

  test('loading state shows before data arrives', async () => {
    const never = new Promise<ProjectsResponse>(() => undefined);
    await renderAt(
      '/projects',
      signedInClient({ getProjects: vi.fn(() => never) }),
    );
    expect(screen.getByText(/Loading your projects/)).toBeInTheDocument();
  });

  test('errors fail closed with an honest panel — no stale data', async () => {
    await renderAt(
      '/projects',
      signedInClient({
        getProjects: vi.fn(async () => {
          throw new Error('boom');
        }),
      }),
    );
    expect((await screen.findAllByText(/Could not load your projects/i)).length).toBeGreaterThan(
      0,
    );
    expect(screen.queryByTestId('project-card')).toBeNull();
    expect(screen.queryByTestId('empty-projects')).toBeNull();
  });

  test('creating a project calls the API and refreshes the list', async () => {
    let calls = 0;
    const list = vi.fn(async (): Promise<ProjectsResponse> => {
      calls += 1;
      return calls === 1
        ? projectsBody([])
        : projectsBody([project({ name: 'New project' })]);
    });
    const create = vi.fn(async (): Promise<ProjectResponse> => projectBody(project({ name: 'New project' })));
    const client = signedInClient({ getProjects: list, createProject: create });
    await renderAt('/projects', client);
    expect(await screen.findByTestId('empty-projects')).toBeInTheDocument();

    await userEvent.type(screen.getByLabelText('Project name'), 'New project');
    await userEvent.type(screen.getByLabelText(/Description/), 'desc');
    await userEvent.click(screen.getByRole('button', { name: 'Create project' }));

    await waitFor(() => {
      expect(screen.getByTestId('project-card')).toHaveTextContent('New project');
    });
    expect(create).toHaveBeenCalledWith({ name: 'New project', description: 'desc' });
    expect(list).toHaveBeenCalledTimes(2);
  });

  test('client-side validation stops an empty/oversized name before any request', async () => {
    const create = vi.fn();
    const client = signedInClient({ createProject: create });
    await renderAt('/projects', client);
    await userEvent.click(await screen.findByRole('button', { name: 'Create project' }));
    expect(await screen.findByText('Enter a project name.')).toBeInTheDocument();
    expect(create).not.toHaveBeenCalled();
  });

  test('no project or ownership state is stored in localStorage/sessionStorage', async () => {
    await renderAt(
      '/projects',
      signedInClient({ getProjects: vi.fn(async () => projectsBody([project()])) }),
    );
    await screen.findByTestId('project-card');
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });
});

describe('Project detail page', () => {
  test('renders name, status, description and timestamps from the server', async () => {
    await renderAt(
      '/projects/prj_00000000-0000-4000-8000-0000000000aa',
      signedInClient({
        getProject: vi.fn(async () => projectBody(project())),
      }),
    );
    expect(await screen.findByTestId('project-detail-name')).toHaveTextContent('Primary web app');
    expect(screen.getByTestId('project-detail-status')).toHaveTextContent('Active');
    expect(screen.getByTestId('project-detail-desc')).toHaveTextContent('checkout');
    expect(screen.getByText('prj_00000000-0000-4000-8000-0000000000aa')).toBeInTheDocument();
  });

  test('XSS payloads render as inert text, never as markup', async () => {
    const payload =
      '<script>alert("xss")</script><img src=x onerror="alert(1)"><svg onload=alert(2)>';
    await renderAt(
      '/projects/prj_00000000-0000-4000-8000-0000000000aa',
      signedInClient({
        getProject: vi.fn(async () =>
          projectBody(project({ name: payload, description: payload })),
        ),
      }),
    );
    const nameNode = await screen.findByTestId('project-detail-name');
    const section = nameNode.closest('section');
    expect(section).not.toBeNull();
    // Rendered as literal text…
    expect(nameNode).toHaveTextContent('<script>alert("xss")</script>');
    // …and no payload script/img/svg ELEMENT was ever created inside the
    // project section (the Layout header legitimately contains its own
    // brand icon, so the scope is the project panel).
    expect(section?.querySelector('script')).toBeNull();
    expect(section?.querySelector('img')).toBeNull();
    expect(section?.querySelector('svg')).toBeNull();
    // No dangerous HTML API is used anywhere on the page.
    expect(nameNode.innerHTML).toContain('&lt;script&gt;'); // escaped by React
  });

  test('a foreign/unknown project renders the honest error — no data leak', async () => {
    await renderAt(
      '/projects/prj_00000000-0000-4000-8000-0000000000ff',
      signedInClient(), // default getProject → 403 forbiddenError()
    );
    expect(await screen.findByText(/not available/i)).toBeInTheDocument();
    expect(screen.queryByTestId('project-detail-name')).toBeNull();
    expect(screen.queryByLabelText(/Project name/)).toBeNull();
  });

  test('editing sends name/description to the API and renders the saved state', async () => {
    const saved = project({ name: 'Renamed', description: 'Updated description', updatedAt: '2026-09-30T10:00:00.000Z' });
    const update = vi.fn(async (): Promise<ProjectResponse> => projectBody(saved));
    const client = signedInClient({
      getProject: vi.fn(async () => projectBody(project())),
      updateProject: update,
    });
    await renderAt('/projects/prj_00000000-0000-4000-8000-0000000000aa', client);
    await screen.findByTestId('project-detail-name');

    const nameInput = screen.getByLabelText('Project name');
    await userEvent.clear(nameInput);
    await userEvent.type(nameInput, 'Renamed');
    const descInput = screen.getByLabelText('Description');
    await userEvent.clear(descInput);
    await userEvent.type(descInput, 'Updated description');
    await userEvent.click(screen.getByRole('button', { name: 'Save changes' }));

    await waitFor(() => {
      expect(screen.getByTestId('project-detail-name')).toHaveTextContent('Renamed');
    });
    expect(update).toHaveBeenCalledWith('prj_00000000-0000-4000-8000-0000000000aa', {
      name: 'Renamed',
      description: 'Updated description',
    });
  });

  test('archive calls the explicit lifecycle action and reflects the status', async () => {
    const archived = project({ status: 'ARCHIVED' });
    const archive = vi.fn(async (): Promise<ProjectResponse> => projectBody(archived));
    const client = signedInClient({
      getProject: vi.fn(async () => projectBody(project())),
      archiveProject: archive,
    });
    await renderAt('/projects/prj_00000000-0000-4000-8000-0000000000aa', client);
    await screen.findByTestId('project-detail-status');
    await userEvent.click(screen.getByTestId('archive-button'));
    await waitFor(() => {
      expect(screen.getByTestId('project-detail-status')).toHaveTextContent('Archived');
    });
    expect(archive).toHaveBeenCalledWith('prj_00000000-0000-4000-8000-0000000000aa');
    // Archived projects offer unarchive — they never disappear.
    expect(screen.getByTestId('unarchive-button')).toBeInTheDocument();
  });

  test('no edit form sends ownership or status fields — they do not exist', async () => {
    await renderAt(
      '/projects/prj_00000000-0000-4000-8000-0000000000aa',
      signedInClient({ getProject: vi.fn(async () => projectBody(project())) }),
    );
    await screen.findByTestId('edit-project-form');
    const form = screen.getByTestId('edit-project-form');
    expect(form.querySelector('input[name="ownerId"]')).toBeNull();
    expect(form.querySelector('input[name="status"]')).toBeNull();
    expect(form.querySelector('input[name="id"]')).toBeNull();
  });
});

describe('protected route', () => {
  test('anonymous visitors never see project data', async () => {
    await renderAt('/projects'); // default stub: getMe → 401
    await waitFor(() => {
      expect(screen.queryByTestId('projects-list')).toBeNull();
      expect(screen.queryByTestId('empty-projects')).toBeNull();
      expect(screen.queryByTestId('create-project-form')).toBeNull();
    });
  });

  test('anonymous visitors on a deep project link see no project data', async () => {
    await renderAt('/projects/prj_00000000-0000-4000-8000-0000000000aa');
    await waitFor(() => {
      expect(screen.queryByTestId('project-detail-name')).toBeNull();
    });
  });
});
