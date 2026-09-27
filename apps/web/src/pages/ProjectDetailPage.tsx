import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { Link, useParams } from 'react-router-dom';
import {
  PROJECT_DESCRIPTION_MAX_LENGTH,
  PROJECT_NAME_MAX_LENGTH,
  SCAN_TYPES,
  type ScanType,
  type Scan,
  type UsageResponse,
} from '@drobon/shared';
import { ApiClientError } from '../api/client.js';
import { useApiClient } from '../api/context.js';
import { useAuth } from '../auth/context.js';
import { ErrorState } from '../components/ErrorState.js';
import { LoadingState } from '../components/LoadingState.js';

/**
 * One project: view, edit, archive/unarchive (Pump 6).
 *
 * - the project comes from the server for the authenticated account; a
 *   foreign, unknown or malformed id renders the SAME honest error (the
 *   API answers a uniform 403 — no existence oracle, mirrored here by
 *   rendering the error verbatim and nothing else);
 * - edits are limited to name/description; the lifecycle status changes
 *   ONLY through the explicit archive/unarchive operations below;
 * - all project text renders as text (React escaping) — never HTML;
 * - nothing here consumes a scan (that is the future scan engine's
 *   boundary);
 * - no localStorage, no URL-derived project state beyond the id.
 */

type ProjectState =
  | { status: 'loading' }
  | { status: 'ready'; project: ProjectView }
  | { status: 'error'; message: string; requestId?: string };

interface ProjectView {
  id: string;
  name: string;
  description: string;
  status: string;
  createdAt: string;
  updatedAt: string;
}

export function ProjectDetailPage(): React.JSX.Element {
  const { projectId } = useParams<{ projectId: string }>();
  const { state } = useAuth();
  const client = useApiClient();
  const [project, setProject] = useState<ProjectState>({ status: 'loading' });
  const [reloadToken, setReloadToken] = useState(0);
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionBusy, setActionBusy] = useState(false);

  const load = useCallback(async (): Promise<void> => {
    if (projectId === undefined) {
      setProject({ status: 'error', message: 'No project id in the URL.' });
      return;
    }
    setProject({ status: 'loading' });
    try {
      const data = await client.getProject(projectId);
      setProject({ status: 'ready', project: data.project });
    } catch (error: unknown) {
      if (error instanceof ApiClientError) {
        setProject({
          status: 'error',
          message: error.message,
          ...(error.requestId === undefined ? {} : { requestId: error.requestId }),
        });
      } else {
        setProject({ status: 'error', message: 'Could not load the project.' });
      }
    }
  }, [client, projectId]);

  useEffect(() => {
    if (state.status === 'ready') {
      void load();
    }
  }, [state.status, load, reloadToken]);

  const lifecycleAction = async (
    action: 'archiveProject' | 'unarchiveProject',
  ): Promise<void> => {
    if (project.status !== 'ready') {
      return;
    }
    setActionError(null);
    setActionBusy(true);
    try {
      const data = await client[action](project.project.id);
      setProject({ status: 'ready', project: data.project });
    } catch (error: unknown) {
      setActionError(
        error instanceof ApiClientError
          ? error.message
          : 'The operation failed. Please try again.',
      );
    } finally {
      setActionBusy(false);
    }
  };

  return (
    <section className="panel" aria-labelledby="project-title">
      <p>
        <Link to="/projects" className="nav-link">
          ← All projects
        </Link>
      </p>
      {project.status === 'loading' && (
        <LoadingState label="Loading the project…" />
      )}
      {project.status === 'error' && (
        <ErrorState
          title="This project is not available."
          message={project.message}
          {...(project.requestId === undefined ? {} : { requestId: project.requestId })}
          onRetry={() => setReloadToken((token) => token + 1)}
        />
      )}
      {project.status === 'ready' && (
        <>
          <h1 id="project-title" data-testid="project-detail-name">
            {project.project.name}
          </h1>
          <p className="badges">
            <span
              className={project.project.status === 'ACTIVE' ? 'pill pill-ok' : 'pill'}
              data-testid="project-detail-status"
            >
              {project.project.status === 'ACTIVE' ? 'Active' : 'Archived'}
            </span>
          </p>
          <dl className="facts">
            <div className="fact">
              <dt>Project ID</dt>
              <dd>
                <code>{project.project.id}</code>
              </dd>
            </div>
            <div className="fact">
              <dt>Created</dt>
              <dd>
                <code>{project.project.createdAt}</code>
              </dd>
            </div>
            <div className="fact">
              <dt>Updated</dt>
              <dd>
                <code>{project.project.updatedAt}</code>
              </dd>
            </div>
          </dl>
          {project.project.description.length > 0 && (
            <p className="muted" data-testid="project-detail-desc">
              {project.project.description}
            </p>
          )}

          <h2>Edit project</h2>
          <EditProjectForm
            key={`${project.project.id}:${project.project.updatedAt}`}
            project={project.project}
            onSaved={(updated) => setProject({ status: 'ready', project: updated })}
          />

          <h2>Lifecycle</h2>
          <p className="muted">
            Archiving keeps the project readable and listed — it simply
            marks it as inactive. This is the only way the status ever
            changes; it never happens through editing.
          </p>
          {actionError !== null && (
            <div className="form-alert" role="alert">
              <p>{actionError}</p>
            </div>
          )}
          <div className="hero-actions">
            {project.project.status === 'ACTIVE' ? (
              <button
                type="button"
                className="button button-ghost"
                onClick={() => void lifecycleAction('archiveProject')}
                disabled={actionBusy}
                aria-busy={actionBusy}
                data-testid="archive-button"
              >
                {actionBusy ? 'Archiving…' : 'Archive project'}
              </button>
            ) : (
              <button
                type="button"
                className="button button-secondary"
                onClick={() => void lifecycleAction('unarchiveProject')}
                disabled={actionBusy}
                aria-busy={actionBusy}
                data-testid="unarchive-button"
              >
                {actionBusy ? 'Unarchiving…' : 'Unarchive project'}
              </button>
            )}
          </div>

          <ScansSection projectId={project.project.id} projectStatus={project.project.status} />
        </>
      )}
    </section>
  );
}

/**
 * Security scans (Pump 7) — the orchestration surface, honestly:
 * - scans are requested for THIS project only; the server derives
 *   ownership, quota, ids, status and timestamps (the client sends
 *   only the scan type + an idempotency key that makes retries safe);
 * - NO scanner engine exists yet, so requested scans fail with
 *   SCAN_ENGINE_NOT_IMPLEMENTED — shown verbatim, never faked as
 *   complete, no fabricated findings;
 * - quota/entitlement display comes from the server's usage view,
 *   never local state;
 * - archived projects cannot START new scans (the server enforces it;
 *   the form is hidden) but their historical scans stay listed;
 * - every value renders as text (React escaping) — no HTML injection.
 */
function ScansSection({
  projectId,
  projectStatus,
}: {
  projectId: string;
  projectStatus: string;
}): React.JSX.Element {
  const client = useApiClient();
  const [scans, setScans] = useState<Scan[] | null>(null);
  const [scansError, setScansError] = useState<string | null>(null);
  const [usage, setUsage] = useState<UsageResponse | null>(null);
  const [scanType, setScanType] = useState<ScanType>('SAST');
  const [formError, setFormError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [reloadToken, setReloadToken] = useState(0);

  const load = useCallback(async (): Promise<void> => {
    setScansError(null);
    try {
      const [scansData, usageData] = await Promise.all([
        client.getScans(projectId),
        client.getUsage(),
      ]);
      setScans(scansData.scans);
      setUsage(usageData);
    } catch (error: unknown) {
      // Fail closed: no partial scan data — the honest error instead.
      setScans(null);
      setScansError(
        error instanceof ApiClientError ? error.message : 'Could not load the scans.',
      );
    }
  }, [client, projectId]);

  useEffect(() => {
    void load();
  }, [load, reloadToken]);

  const requestScan = async (): Promise<void> => {
    setFormError(null);
    setSubmitting(true);
    try {
      // The key scopes this logical request: a network retry returns
      // the ORIGINAL scan instead of creating (and charging) another.
      const key =
        typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
          ? crypto.randomUUID()
          : `web-${Date.now()}-${Math.random().toString(36).slice(2, 14)}`;
      await client.createScan(projectId, scanType, key);
      await load();
    } catch (error: unknown) {
      setFormError(
        error instanceof ApiClientError
          ? error.message
          : 'Could not request the scan. Please try again.',
      );
      // The project may have been archived elsewhere — reflect server
      // truth on the next full load.
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <>
      <h2>Security scans</h2>
      {usage !== null && (
        <p className="muted" data-testid="quota-hint">
          {usage.quotaStatus === 'EXEMPT'
            ? 'Pro plan: unlimited scans.'
            : `Free plan: ${usage.remaining ?? 0} of ${usage.limit ?? 0} scans remaining this month.`}
        </p>
      )}
      {projectStatus !== 'ACTIVE' ? (
        <p className="muted" data-testid="archived-scan-note">
          Archived projects cannot start new scans. Unarchive the project
          to request new ones — the scans below remain readable.
        </p>
      ) : (
        <form
          className="scan-form"
          onSubmit={(event) => {
            event.preventDefault();
            void requestScan();
          }}
          data-testid="scan-form"
        >
          <div className="field">
            <label htmlFor="scan-type">Scan type</label>
            <select
              id="scan-type"
              name="scanType"
              value={scanType}
              onChange={(event) => setScanType(event.target.value as ScanType)}
              data-testid="scan-type-select"
            >
              {SCAN_TYPES.map((type) => (
                <option key={type} value={type}>
                  {type}
                </option>
              ))}
            </select>
          </div>
          <button
            type="submit"
            className="button button-secondary"
            disabled={submitting}
            aria-busy={submitting}
            data-testid="request-scan-button"
          >
            {submitting ? 'Requesting…' : 'Request scan'}
          </button>
          <p className="muted">
            Scanner engines are not implemented yet — requested scans are
            recorded and fail honestly with SCAN_ENGINE_NOT_IMPLEMENTED.
          </p>
          {formError !== null && (
            <div className="form-alert" role="alert">
              <p data-testid="scan-form-error">{formError}</p>
            </div>
          )}
        </form>
      )}
      {scansError !== null ? (
        <div>
          <div className="form-alert" role="alert">
            <p>{scansError}</p>
          </div>
          <button
            type="button"
            className="button button-ghost"
            onClick={() => setReloadToken((token) => token + 1)}
            data-testid="scans-retry"
          >
            Retry
          </button>
        </div>
      ) : scans === null ? (
        <LoadingState label="Loading the scans…" />
      ) : scans.length === 0 ? (
        <p className="muted" data-testid="scans-empty">
          No scans requested for this project yet.
        </p>
      ) : (
        <ul className="scan-list" data-testid="scans-list">
          {scans.map((scan) => (
            <li key={scan.id} className="scan-item" data-testid="scan-item">
              <div className="scan-item-head">
                <strong data-testid="scan-type">{scan.scanType}</strong>
                <span
                  className={
                    scan.status === 'COMPLETED'
                      ? 'pill pill-ok'
                      : scan.status === 'FAILED'
                        ? 'pill pill-danger'
                        : 'pill'
                  }
                  data-testid="scan-status"
                >
                  {scan.status}
                </span>
              </div>
              <dl className="facts">
                <div className="fact">
                  <dt>Requested</dt>
                  <dd>
                    <code>{scan.createdAt}</code>
                  </dd>
                </div>
                {scan.completedAt !== undefined && (
                  <div className="fact">
                    <dt>Finished</dt>
                    <dd>
                      <code>{scan.completedAt}</code>
                    </dd>
                  </div>
                )}
              </dl>
              {scan.status === 'FAILED' && scan.failureMessage !== undefined && (
                <p className="muted" data-testid="scan-failure">
                  {scan.failureCode !== undefined ? `${scan.failureCode}: ` : ''}
                  {scan.failureMessage}
                </p>
              )}
              {scan.status === 'COMPLETED' && scan.resultSummary !== undefined && (
                <p className="muted" data-testid="scan-result">
                  Findings: {scan.resultSummary.findingsTotal}
                </p>
              )}
            </li>
          ))}
        </ul>
      )}
      <div className="hero-actions">
        <button
          type="button"
          className="button button-ghost"
          onClick={() => setReloadToken((token) => token + 1)}
          data-testid="refresh-scans"
        >
          Refresh scans
        </button>
      </div>
    </>
  );
}

/** Edit form: name/description only — status and ownership are not editable. */
function EditProjectForm({
  project,
  onSaved,
}: {
  project: ProjectView;
  onSaved: (updated: ProjectView) => void;
}): React.JSX.Element {
  const client = useApiClient();
  const [name, setName] = useState(project.name);
  const [description, setDescription] = useState(project.description);
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
      const data = await client.updateProject(project.id, {
        name: trimmedName,
        description: trimmedDescription,
      });
      onSaved(data.project);
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
        setFormError('Could not save the project. Please try again.');
      }
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <form className="auth-form" onSubmit={(event) => void onSubmit(event)} noValidate data-testid="edit-project-form">
      <div className="field">
        <label htmlFor="edit-project-name">Project name</label>
        <input
          id="edit-project-name"
          name="name"
          type="text"
          value={name}
          autoComplete="off"
          maxLength={PROJECT_NAME_MAX_LENGTH}
          onChange={(event) => setName(event.target.value)}
          aria-invalid={fieldErrors.name !== undefined}
          aria-describedby={fieldErrors.name !== undefined ? 'edit-project-name-error' : undefined}
        />
        {fieldErrors.name !== undefined && (
          <p className="field-error" id="edit-project-name-error" role="alert">
            {fieldErrors.name}
          </p>
        )}
      </div>
      <div className="field">
        <label htmlFor="edit-project-description">Description</label>
        <textarea
          id="edit-project-description"
          name="description"
          value={description}
          rows={3}
          maxLength={PROJECT_DESCRIPTION_MAX_LENGTH}
          onChange={(event) => setDescription(event.target.value)}
          aria-invalid={fieldErrors.description !== undefined}
          aria-describedby={
            fieldErrors.description !== undefined ? 'edit-project-description-error' : undefined
          }
        />
        {fieldErrors.description !== undefined && (
          <p className="field-error" id="edit-project-description-error" role="alert">
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
        {submitting ? 'Saving…' : 'Save changes'}
      </button>
    </form>
  );
}
