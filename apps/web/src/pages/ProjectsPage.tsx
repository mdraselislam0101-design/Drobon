import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { Link } from 'react-router-dom';
import { PROJECT_DESCRIPTION_MAX_LENGTH, PROJECT_NAME_MAX_LENGTH } from '@drobon/shared';
import { ApiClientError } from '../api/client.js';
import { useApiClient } from '../api/context.js';
import { useAuth } from '../auth/context.js';
import { ErrorState } from '../components/ErrorState.js';
import { LoadingState } from '../components/LoadingState.js';

/**
 * Projects list + creation (Pump 6).
 *
 * Rules mirrored from the API (which is the authority):
 * - the list shows ONLY the server's response for the authenticated
 *   account — no local filtering, no localStorage, no URL state;
 * - project text is rendered as TEXT (React escapes it); there is no
 *   HTML rendering anywhere on this page;
 * - ordering is the server's documented contract (updatedAt DESC, then
 *   id ASC) and is never recomputed here;
 * - creating or listing projects never consumes a scan (that boundary
 *   belongs to the future scan engine — see docs/USAGE.md);
 * - failures fail honestly: error panel + retry, never stale data.
 */

type ListState =
  | { status: 'loading' }
  | { status: 'ready'; projects: ProjectView[] }
  | { status: 'error'; message: string; requestId?: string };

interface ProjectView {
  id: string;
  name: string;
  description: string;
  status: string;
  updatedAt: string;
}

export function ProjectsPage(): React.JSX.Element {
  const { state } = useAuth();
  const client = useApiClient();
  const [list, setList] = useState<ListState>({ status: 'loading' });
  const [reloadToken, setReloadToken] = useState(0);

  const load = useCallback(async (): Promise<void> => {
    setList({ status: 'loading' });
    try {
      const data = await client.getProjects();
      setList({ status: 'ready', projects: data.projects });
    } catch (error: unknown) {
      if (error instanceof ApiClientError) {
        setList({
          status: 'error',
          message: error.message,
          ...(error.requestId === undefined ? {} : { requestId: error.requestId }),
        });
      } else {
        setList({ status: 'error', message: 'Could not load your projects.' });
      }
    }
  }, [client]);

  useEffect(() => {
    if (state.status === 'ready') {
      void load();
    }
  }, [state.status, load, reloadToken]);

  return (
    <section className="panel" aria-labelledby="projects-title">
      <h1 id="projects-title">Projects</h1>
      <p className="muted">
        Projects are the containers your future security scans, findings
        and reports will attach to. Only you can see your projects — the
        server enforces this on every request.
      </p>

      <CreateProjectForm onCreated={() => setReloadToken((token) => token + 1)} />

      {list.status === 'loading' && <LoadingState label="Loading your projects…" />}
      {list.status === 'error' && (
        <ErrorState
          title="Could not load your projects."
          message={list.message}
          {...(list.requestId === undefined ? {} : { requestId: list.requestId })}
          onRetry={() => setReloadToken((token) => token + 1)}
        />
      )}
      {list.status === 'ready' && list.projects.length === 0 && (
        <div className="form-alert" role="status" data-testid="empty-projects">
          <p>No projects yet. Create your first project above to get started.</p>
        </div>
      )}
      {list.status === 'ready' && list.projects.length > 0 && (
        <ul className="projects-list" aria-label="Your projects" data-testid="projects-list">
          {list.projects.map((project) => (
            <li key={project.id} className="card project-card" data-testid="project-card">
              <div className="project-card-head">
                <Link to={`/projects/${project.id}`} data-testid="project-link">
                  <span data-testid="project-name">{project.name}</span>
                </Link>
                <span className={project.status === 'ACTIVE' ? 'pill pill-ok' : 'pill'} data-testid="project-status">
                  {project.status === 'ACTIVE' ? 'Active' : 'Archived'}
                </span>
              </div>
              {project.description.length > 0 && (
                <p className="muted project-desc" data-testid="project-desc">
                  {project.description}
                </p>
              )}
              <p className="muted project-meta">Updated {project.updatedAt}</p>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

/**
 * The create form. Client-side bounds mirror the shared contract for
 * instant feedback; the server re-validates everything (its 422 issues
 * are rendered field by field) and assigns id, ownership, status and
 * timestamps. Nothing about ownership is ever sent from here.
 */
function CreateProjectForm({ onCreated }: { onCreated: () => void }): React.JSX.Element {
  const client = useApiClient();
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [fieldErrors, setFieldErrors] = useState<{ name?: string; description?: string }>({});
  const [formError, setFormError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const onSubmit = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault();
    const trimmedName = name.trim();
    const trimmedDescription = description.trim();
    const errors: { name?: string; description?: string } = {};
    if (trimmedName.length === 0) {
      errors.name = 'Enter a project name.';
    } else if (trimmedName.length > PROJECT_NAME_MAX_LENGTH) {
      errors.name = `Must be at most ${PROJECT_NAME_MAX_LENGTH} characters.`;
    }
    if (trimmedDescription.length > PROJECT_DESCRIPTION_MAX_LENGTH) {
      errors.description = `Must be at most ${PROJECT_DESCRIPTION_MAX_LENGTH} characters.`;
    }
    setFieldErrors(errors);
    setFormError(null);
    if (Object.keys(errors).length > 0) {
      return;
    }
    setSubmitting(true);
    try {
      await client.createProject({
        name: trimmedName,
        ...(trimmedDescription.length === 0 ? {} : { description: trimmedDescription }),
      });
      setName('');
      setDescription('');
      onCreated();
    } catch (error: unknown) {
      if (error instanceof ApiClientError) {
        if (error.code === 'VALIDATION_ERROR' && Array.isArray(error.details)) {
          const next: { name?: string; description?: string } = {};
          for (const issue of error.details) {
            if (typeof issue === 'object' && issue !== null && 'path' in issue && 'message' in issue) {
              const path = String((issue as { path: unknown }).path);
              const message = String((issue as { message: unknown }).message);
              if (path === 'name' || path === 'description') {
                next[path] = message;
              }
            }
          }
          setFieldErrors(next);
        }
        setFormError(error.message);
      } else {
        setFormError('Could not create the project. Please try again.');
      }
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <form className="auth-form" onSubmit={(event) => void onSubmit(event)} noValidate data-testid="create-project-form">
      <div className="field">
        <label htmlFor="project-name">Project name</label>
        <input
          id="project-name"
          name="name"
          type="text"
          value={name}
          autoComplete="off"
          maxLength={PROJECT_NAME_MAX_LENGTH}
          onChange={(event) => setName(event.target.value)}
          aria-invalid={fieldErrors.name !== undefined}
          aria-describedby={fieldErrors.name !== undefined ? 'project-name-error' : undefined}
          placeholder="My application"
        />
        {fieldErrors.name !== undefined && (
          <p className="field-error" id="project-name-error" role="alert">
            {fieldErrors.name}
          </p>
        )}
      </div>
      <div className="field">
        <label htmlFor="project-description">Description (optional)</label>
        <textarea
          id="project-description"
          name="description"
          value={description}
          rows={3}
          maxLength={PROJECT_DESCRIPTION_MAX_LENGTH}
          onChange={(event) => setDescription(event.target.value)}
          aria-invalid={fieldErrors.description !== undefined}
          aria-describedby={fieldErrors.description !== undefined ? 'project-description-error' : undefined}
          placeholder="What this project covers"
        />
        {fieldErrors.description !== undefined && (
          <p className="field-error" id="project-description-error" role="alert">
            {fieldErrors.description}
          </p>
        )}
      </div>
      {formError !== null && (
        <div className="form-alert" role="alert">
          <p>{formError}</p>
        </div>
      )}
      <button type="submit" className="button button-secondary" disabled={submitting} aria-busy={submitting}>
        {submitting ? 'Creating…' : 'Create project'}
      </button>
    </form>
  );
}
