import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { Link, useParams } from 'react-router-dom';
import {
  PROJECT_DESCRIPTION_MAX_LENGTH,
  PROJECT_NAME_MAX_LENGTH,
  SCAN_TYPES,
  type Finding,
  type ScanDetailResponse,
  type ScanType,
  type Scan,
  type FindingSeverity,
  type ScaEcosystem,
  type SourceSnapshotResponse,
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
 * - the SAST engine (Pump 8) analyzes the project's uploaded source
 *   snapshot — analysis only, sources are never executed; findings come
 *   from the scan detail route and render as text.
 * - the SCA engine (Pump 9) analyzes the same snapshot's dependency
 *   manifests — again analysis only. Its inventory/manifest/SBOM
 *   payload renders from the SAME detail route, clearly separated
 *   from SAST findings, and states honestly when the vulnerability
 *   intelligence dataset is unavailable (not assessed, zero advisories).
 * - the SECRETS engine (Pump 10) scans the same snapshot for hardcoded
 *   secrets — analysis only, no execution, no verification. Findings
 *   render through the SAME findings surface with rule, severity,
 *   DETECTION confidence, location, redacted evidence and remediation;
 *   the raw secret values never reach the client (server-side
 *   redaction is enforced before any serialization).
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
  dastTargetUrl?: string;
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

          <DastTargetSection
            projectId={project.project.id}
            targetUrl={project.project.dastTargetUrl}
            onChanged={(updated) => setProject({ status: 'ready', project: updated })}
          />

          <SourcesSection projectId={project.project.id} projectStatus={project.project.status} />

          <ScansSection
            projectId={project.project.id}
            projectStatus={project.project.status}
            dastTargetUrl={project.project.dastTargetUrl}
          />
        </>
      )}
    </section>
  );
}

/**
 * Security scans (Pump 7 + 8) — the orchestration surface, honestly:
 * - scans are requested for THIS project only; the server derives
 *   ownership, quota, ids, status and timestamps (the client sends
 *   only the scan type + an idempotency key that makes retries safe);
 * - SAST (Pump 8) analyzes the uploaded source snapshot server-side —
 *   real findings with evidence and remediation, rendered as text;
 * - SCA (Pump 9), SECRETS (Pump 10), and passive DAST (Pump 11) have
 *   dedicated honest result views; DAST is one bounded project URL only;
 * - quota/entitlement display comes from the server's usage view,
 *   never local state;
 * - archived projects cannot START new scans (the server enforces it;
 *   the form is hidden) but their historical scans stay listed;
 * - every value renders as text (React escaping) — no HTML injection.
 */
function DastTargetSection({
  projectId,
  targetUrl,
  onChanged,
}: {
  projectId: string;
  targetUrl: string | undefined;
  onChanged: (updated: ProjectView) => void;
}): React.JSX.Element {
  const client = useApiClient();
  const [value, setValue] = useState(targetUrl ?? '');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const save = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const response = await client.setDastTarget(projectId, value);
      setValue(response.project.dastTargetUrl ?? '');
      onChanged(response.project);
    } catch (caught: unknown) {
      setError(caught instanceof ApiClientError ? caught.message : 'Could not configure this target.');
    } finally {
      setBusy(false);
    }
  };

  const clear = async (): Promise<void> => {
    setError(null);
    setBusy(true);
    try {
      const response = await client.clearDastTarget(projectId);
      setValue('');
      onChanged(response.project);
    } catch (caught: unknown) {
      setError(caught instanceof ApiClientError ? caught.message : 'Could not remove this target.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="dast-target" data-testid="dast-target-section">
      <h2>Passive DAST target</h2>
      <p className="muted">
        Configure one HTTP(S) URL owned or authorized for this project. The server rejects local, private,
        reserved, or unsafe destinations and rechecks DNS at scan time. This is a bounded GET-only passive
        check: no browser, JavaScript execution, login, crawling, fuzzing, or exploit attempts.
      </p>
      {targetUrl !== undefined && (
        <p data-testid="dast-configured-target">Configured target: <code>{targetUrl}</code></p>
      )}
      <form className="auth-form" onSubmit={(event) => void save(event)} data-testid="dast-target-form">
        <div className="field">
          <label htmlFor="dast-target-url">Authorized target URL</label>
          <input
            id="dast-target-url"
            name="targetUrl"
            type="url"
            value={value}
            maxLength={2048}
            autoComplete="url"
            onChange={(event) => setValue(event.target.value)}
            placeholder="https://example.org/"
            aria-describedby="dast-target-hint"
          />
          <p className="muted" id="dast-target-hint">
            No credentials, query string, fragment, custom port, or non-public address. Only the project owner can change this setting.
          </p>
        </div>
        {error !== null && <div className="form-alert" role="alert"><p>{error}</p></div>}
        <div className="hero-actions">
          <button type="submit" className="button button-secondary" disabled={busy || value.length === 0} aria-busy={busy}>
            {busy ? 'Validating…' : 'Save target'}
          </button>
          {targetUrl !== undefined && (
            <button type="button" className="button button-ghost" onClick={() => void clear()} disabled={busy}>
              Remove target
            </button>
          )}
        </div>
      </form>
    </div>
  );
}

function ScansSection({
  projectId,
  projectStatus,
  dastTargetUrl,
}: {
  projectId: string;
  projectStatus: string;
  dastTargetUrl: string | undefined;
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
                <option key={type} value={type} disabled={type === 'DAST' && dastTargetUrl === undefined}>
                  {type === 'DAST' && dastTargetUrl === undefined ? 'DAST — configure target first' : type}
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
            SAST, Secrets and SCA analyze the uploaded source snapshot; files are never executed, credentials are never verified, and secret evidence is redacted before persistence.
            SCA advisories remain not assessed without a vulnerability dataset. DAST is a limited passive check of the one
            configured project URL: bounded GET requests, validated same-host redirects and observed response headers/body only.
            It does not use a browser, execute JavaScript, authenticate, crawl, fuzz, or exploit. Configure a target above to enable DAST.
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
                      : scan.status === 'FAILED' || scan.status === 'TIMED_OUT'
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
              {(scan.status === 'FAILED' || scan.status === 'TIMED_OUT') && scan.failureMessage !== undefined && (
                <p className="muted" data-testid="scan-failure">
                  {scan.failureCode !== undefined ? `${scan.failureCode}: ` : ''}
                  {scan.failureMessage}
                </p>
              )}
              {scan.status === 'COMPLETED' && scan.resultSummary !== undefined && (
                <p className="muted" data-testid="scan-result">
                  {scan.scanType === 'SCA'
                    ? `Dependencies: ${scan.resultSummary.dependenciesTotal ?? 0} (${scan.resultSummary.directDependencies ?? 0} direct)`
                    : scan.scanType === 'DAST'
                      ? `Requests: ${scan.resultSummary.requestsMade ?? 0} · redirects: ${scan.resultSummary.redirectsFollowed ?? 0} · passive findings: ${scan.resultSummary.findingsTotal}${scan.resultSummary.partial === true ? ' · partial' : ''}`
                      : `Findings: ${scan.resultSummary.findingsTotal}${
                          scan.resultSummary.partial === true
                            ? ` — partial scan: ${scan.resultSummary.partialReason ?? 'some content was not inspected'}`
                            : scan.resultSummary.truncated === true
                              ? ' (findings truncated)'
                              : ''
                        }`}
                </p>
              )}
              {(scan.status === 'COMPLETED' &&
                (scan.scanType === 'SAST' || scan.scanType === 'SECRETS' || scan.scanType === 'DAST')) && (
                <FindingsView projectId={projectId} scanId={scan.id} />
              )}
              {scan.status === 'COMPLETED' && scan.scanType === 'SCA' && (
                <ScaView projectId={projectId} scanId={scan.id} />
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

/**
 * Source snapshot (Pump 8) — the SAST scan target:
 * - the snapshot is PROJECT-scoped, server-validated and replaces
 *   wholesale on upload (the last upload is the scan target);
 * - the client sends exactly { files: [{ path, content }] } — file
 *   NAMES become paths; the server's path policy is the only policy
 *   (invalid uploads are rejected and reported verbatim);
 * - metadata only ever comes back (file count, bytes, updatedAt) —
 *   uploaded source content is never re-fetched or rendered;
 * - a missing snapshot is the honest 404: "no snapshot yet";
 * - archived projects cannot replace the snapshot (server-enforced;
 *   the form is hidden) but the metadata stays visible.
 */
function SourcesSection({
  projectId,
  projectStatus,
}: {
  projectId: string;
  projectStatus: string;
}): React.JSX.Element {
  const client = useApiClient();
  const [snapshot, setSnapshot] = useState<SourceSnapshotResponse['snapshot'] | null>(
    null,
  );
  const [missing, setMissing] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [uploading, setUploading] = useState(false);
  const [reloadToken, setReloadToken] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setLoadError(null);
    setMissing(false);
    client
      .getSources(projectId)
      .then((data) => {
        if (!cancelled) {
          setSnapshot(data.snapshot);
        }
      })
      .catch((error: unknown) => {
        if (cancelled) {
          return;
        }
        if (error instanceof ApiClientError && error.status === 404) {
          // No snapshot yet — the honest empty state, not an error.
          setMissing(true);
          setSnapshot(null);
        } else {
          setLoadError(
            error instanceof ApiClientError
              ? error.message
              : 'Could not load the source snapshot.',
          );
        }
      });
    return () => {
      cancelled = true;
    };
  }, [client, projectId, reloadToken]);

  const upload = async (fileList: FileList | null): Promise<void> => {
    if (fileList === null || fileList.length === 0) {
      return;
    }
    setUploadError(null);
    setUploading(true);
    try {
      // Read each picked file as text; the FILE NAME becomes the path
      // and the server's path policy validates it. Binary files are
      // rejected below — the API is text-only by design. (FileReader,
      // not File.text(): the oldest, most portable read in browsers.)
      const files: Array<{ path: string; content: string }> = [];
      for (const file of Array.from(fileList)) {
        files.push({ path: file.name, content: await readFileAsText(file) });
      }
      await client.uploadSources(projectId, files);
      setReloadToken((token) => token + 1);
    } catch (error: unknown) {
      setUploadError(
        error instanceof ApiClientError
          ? error.message
          : 'Could not upload the source snapshot. Please try again.',
      );
    } finally {
      setUploading(false);
    }
  };

  return (
    <>
      <h2>Source snapshot</h2>
      {loadError !== null ? (
        <div className="form-alert" role="alert">
          <p>{loadError}</p>
        </div>
      ) : missing ? (
        <p className="muted" data-testid="snapshot-empty">
          No source snapshot uploaded yet. Upload one to enable SAST,
          SCA and SECRETS scans.
        </p>
      ) : snapshot !== null ? (
        <p className="muted" data-testid="snapshot-meta">
          {snapshot.fileCount} {snapshot.fileCount === 1 ? 'file' : 'files'},{' '}
          {snapshot.totalBytes} bytes — uploaded{' '}
          <code>{snapshot.updatedAt}</code>. The latest upload replaces the
          previous snapshot and is what SAST, SCA and SECRETS scans
          analyze.
        </p>
      ) : (
        <LoadingState label="Loading the source snapshot…" />
      )}
      {projectStatus !== 'ACTIVE' ? (
        <p className="muted" data-testid="archived-source-note">
          Archived projects cannot replace the source snapshot. Unarchive
          the project to upload a new one.
        </p>
      ) : (
        <form
          className="scan-form"
          onSubmit={(event) => {
            event.preventDefault();
          }}
          data-testid="source-form"
        >
          <div className="field">
            <label htmlFor="source-files">Source files (text only)</label>
            <input
              id="source-files"
              name="files"
              type="file"
              multiple
              onChange={(event) => void upload(event.target.files)}
              disabled={uploading}
              data-testid="source-file-input"
            />
            <p className="muted">
              At most 200 files, 256 KiB per file, 768 KiB total. Paths are
              file names; .env and key files are rejected by the server.
            </p>
          </div>
          {uploading && (
            <p className="muted" data-testid="source-uploading">
              Uploading…
            </p>
          )}
          {uploadError !== null && (
            <div className="form-alert" role="alert">
              <p data-testid="source-upload-error">{uploadError}</p>
            </div>
          )}
        </form>
      )}
    </>
  );
}

/**
 * One completed scan's findings (Pump 8 SAST + Pump 10 SECRETS) — the
 * only findings read surface. Lazy: the list stays cheap until the
 * user asks.
 * - server-ordered (most severe first), rendered as text;
 * - the severity filter is display-only (client-side over the SAME
 *   bounded response) — it never triggers another request;
 * - evidence is ALREADY redacted server-side; rendering it as text
 *   (never HTML) keeps it non-executing on both ends;
 * - SECRETS findings additionally carry a rule-defined DETECTION
 *   confidence (how certain the RULE is of the match — never a
 *   liveness claim), shown as a badge next to the severity.
 */
function FindingsView({
  projectId,
  scanId,
}: {
  projectId: string;
  scanId: string;
}): React.JSX.Element {
  const client = useApiClient();
  const [detail, setDetail] = useState<ScanDetailResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [severity, setSeverity] = useState<'ALL' | FindingSeverity>('ALL');

  const load = async (): Promise<void> => {
    setError(null);
    setLoading(true);
    try {
      const data = await client.getScan(projectId, scanId);
      setDetail(data);
    } catch (error: unknown) {
      setError(
        error instanceof ApiClientError
          ? error.message
          : 'Could not load the findings.',
      );
    } finally {
      setLoading(false);
    }
  };

  const findings: Finding[] = detail?.scan.findings ?? [];
  const visible =
    severity === 'ALL' ? findings : findings.filter((f) => f.severity === severity);

  return (
    <div className="findings">
      {detail === null && error === null && !loading && (
        <button
          type="button"
          className="button button-ghost"
          onClick={() => void load()}
          data-testid="view-findings"
        >
          View findings
        </button>
      )}
      {loading && <LoadingState label="Loading the findings…" />}
      {error !== null && (
        <div>
          <div className="form-alert" role="alert">
            <p data-testid="findings-error">{error}</p>
          </div>
          <button
            type="button"
            className="button button-ghost"
            onClick={() => void load()}
            data-testid="findings-retry"
          >
            Retry
          </button>
        </div>
      )}
      {detail !== null && (
        <>
          {detail.scan.dast !== undefined && (
            <section className="dast-observations" data-testid="dast-observations">
              <h4>Observed responses</h4>
              <p className="muted">
                Passive GET observations only; response content was bounded and never executed. No browser, JavaScript, authentication, or crawling was used.
              </p>
              <p data-testid="dast-target-url">Target: <code>{detail.scan.dast.targetUrl}</code></p>
              {detail.scan.dast.partial && (
                <p className="muted" data-testid="dast-partial-note">
                  Partial result: {detail.scan.dast.partialReason ?? 'some response checks were not completed'}
                </p>
              )}
              <ul className="scan-list">
                {detail.scan.dast.observations.map((observation, index) => (
                  <li key={`${observation.endpoint}-${index}`} data-testid="dast-observation">
                    <strong>{observation.method} · HTTP {observation.status}</strong>{' '}
                    <code>{observation.endpoint}</code>
                    <p className="muted">
                      {observation.responseTimeMs} ms · {observation.bodyBytes} bytes inspected
                      {observation.bodyTruncated ? ' · body truncated' : ''}
                      {observation.contentType !== undefined ? ` · ${observation.contentType}` : ''}
                    </p>
                    {observation.headers.length > 0 && (
                      <ul>{observation.headers.map((header, headerIndex) => <li key={`${header}-${headerIndex}`}>{header}</li>)}</ul>
                    )}
                  </li>
                ))}
              </ul>
            </section>
          )}
          <div className="field">
            <label htmlFor={`findings-filter-${scanId}`}>Severity</label>
            <select
              id={`findings-filter-${scanId}`}
              value={severity}
              onChange={(event) =>
                setSeverity(event.target.value as 'ALL' | FindingSeverity)
              }
              data-testid="findings-filter"
            >
              <option value="ALL">All severities</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
              <option value="INFO">INFO</option>
            </select>
          </div>
          {visible.length === 0 ? (
            <p className="muted" data-testid="findings-empty">
              {detail.scan.scanType === 'DAST'
                ? 'None of the supported passive checks produced findings for the observed responses.'
                : 'No findings at this severity.'}
            </p>
          ) : (
            <ul className="findings-list" data-testid="findings-list">
              {visible.map((finding) => (
                <li key={finding.id} className="finding-item" data-testid="finding-item">
                  <div className="scan-item-head">
                    <span
                      className={
                        finding.severity === 'CRITICAL' || finding.severity === 'HIGH'
                          ? 'pill pill-danger'
                          : finding.severity === 'MEDIUM'
                            ? 'pill'
                            : 'pill pill-ok'
                      }
                      data-testid="finding-severity"
                    >
                      {finding.severity}
                    </span>
                    <strong data-testid="finding-rule">{finding.ruleId}</strong>
                    {finding.confidence !== undefined && (
                      <span className="pill" data-testid="finding-confidence">
                        {finding.confidence} confidence
                      </span>
                    )}
                  </div>
                  <p data-testid="finding-title">{finding.title}</p>
                  <p className="muted" data-testid="finding-location">
                    {finding.scanner === 'DAST'
                      ? `${finding.method} ${finding.endpoint} · HTTP ${finding.responseStatus}`
                      : `${finding.file}:${finding.line}`}
                    {finding.cwe !== undefined ? ` · ${finding.cwe}` : ''}
                  </p>
                  <pre>
                    <code data-testid="finding-evidence">{finding.evidence}</code>
                  </pre>
                  <p className="muted" data-testid="finding-remediation">
                    {finding.remediation}
                  </p>
                </li>
              ))}
            </ul>
          )}
        </>
      )}
    </div>
  );
}

/**
 * One completed SCA scan's dependency analysis (Pump 9) — the SCA read
 * surface, lazy like FindingsView and clearly separated from it.
 * - the assessment banner is HONEST by construction: with no loaded
 *   dataset it says "not assessed", and zero advisories are shown as
 *   exactly that (the server never fabricates any);
 * - the inventory renders as TEXT (React escaping) — names, versions,
 *   purls come from the validated shared contract, never raw files;
 * - the ecosystem filter is display-only (client-side over the SAME
 *   bounded response) — it never triggers another request;
 * - manifests list what was analyzed/partial/unsupported/invalid, so
 *   the limits of the analysis are visible, not hidden.
 */
function ScaView({
  projectId,
  scanId,
}: {
  projectId: string;
  scanId: string;
}): React.JSX.Element {
  const client = useApiClient();
  const [detail, setDetail] = useState<ScanDetailResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [ecosystem, setEcosystem] = useState<'ALL' | ScaEcosystem>('ALL');

  const load = async (): Promise<void> => {
    setError(null);
    setLoading(true);
    try {
      const data = await client.getScan(projectId, scanId);
      setDetail(data);
    } catch (error: unknown) {
      setError(
        error instanceof ApiClientError ? error.message : 'Could not load the dependency analysis.',
      );
    } finally {
      setLoading(false);
    }
  };

  const sca = detail?.scan.sca;
  const visibleDeps =
    sca === undefined ? [] : ecosystem === 'ALL' ? sca.dependencies : sca.dependencies.filter((d) => d.ecosystem === ecosystem);

  return (
    <div className="findings">
      {detail === null && error === null && !loading && (
        <button
          type="button"
          className="button button-ghost"
          onClick={() => void load()}
          data-testid="view-sca"
        >
          View dependency analysis
        </button>
      )}
      {loading && <LoadingState label="Loading the dependency analysis…" />}
      {error !== null && (
        <div>
          <div className="form-alert" role="alert">
            <p data-testid="sca-error">{error}</p>
          </div>
          <button
            type="button"
            className="button button-ghost"
            onClick={() => void load()}
            data-testid="sca-retry"
          >
            Retry
          </button>
        </div>
      )}
      {sca !== undefined && (
        <>
          <p className="muted" data-testid="sca-assessment">
            {sca.summary.assessmentState === 'ASSESSED'
              ? `Assessed by ${sca.summary.providerId}: ${sca.summary.advisoriesTotal} advisories.`
              : 'Not assessed — vulnerability intelligence dataset unavailable. The dependency inventory and SBOM below are complete; no vulnerability claims are made without a loaded dataset.'}
          </p>
          <dl className="facts" data-testid="sca-summary">
            <div className="fact">
              <dt>Dependencies</dt>
              <dd>
                {sca.summary.truncated
                  ? `${sca.dependencies.length} of ${sca.summary.dependenciesTotal} (truncated)`
                  : sca.summary.dependenciesTotal}
              </dd>
            </div>
            <div className="fact">
              <dt>Direct</dt>
              <dd>{sca.summary.directDependencies}</dd>
            </div>
            <div className="fact">
              <dt>Transitive</dt>
              <dd>{sca.summary.transitiveDependencies}</dd>
            </div>
            <div className="fact">
              <dt>Unknown class</dt>
              <dd>{sca.summary.unclassifiedDependencies}</dd>
            </div>
            <div className="fact">
              <dt>Transitive graph</dt>
              <dd data-testid="sca-graph">
                {sca.summary.transitiveGraph === 'AVAILABLE'
                  ? 'Available (lockfile evidence)'
                  : 'Unavailable (no lockfile closure)'}
              </dd>
            </div>
            <div className="fact">
              <dt>SBOM</dt>
              <dd data-testid="sca-sbom">
                CycloneDX 1.5 · {sca.sbom.components.length} components
              </dd>
            </div>
          </dl>
          <div className="field">
            <label htmlFor={`sca-filter-${scanId}`}>Ecosystem</label>
            <select
              id={`sca-filter-${scanId}`}
              value={ecosystem}
              onChange={(event) => setEcosystem(event.target.value as 'ALL' | ScaEcosystem)}
              data-testid="sca-filter"
            >
              <option value="ALL">All ecosystems</option>
              <option value="npm">npm</option>
              <option value="pypi">pypi</option>
            </select>
          </div>
          <h4>Manifests</h4>
          <ul className="scan-list" data-testid="sca-manifests">
            {sca.manifests.map((manifest) => (
              <li key={manifest.path} data-testid="sca-manifest-item">
                <span
                  className={
                    manifest.status === 'ANALYZED'
                      ? 'pill pill-ok'
                      : manifest.status === 'PARTIAL'
                        ? 'pill'
                        : 'pill pill-danger'
                  }
                  data-testid="sca-manifest-status"
                >
                  {manifest.status}
                </span>{' '}
                <code>{manifest.path}</code> · {manifest.ecosystem} ·{' '}
                {manifest.dependencyCount} dependencies
                {manifest.note !== undefined ? ` · ${manifest.note}` : ''}
              </li>
            ))}
          </ul>
          <h4>Dependency inventory</h4>
          {visibleDeps.length === 0 ? (
            <p className="muted" data-testid="sca-empty">
              No dependencies at this ecosystem.
            </p>
          ) : (
            <ul className="findings-list" data-testid="sca-dependencies">
              {visibleDeps.map((dependency) => (
                <li key={dependency.dependencyId} data-testid="sca-dep-item">
                  <div className="scan-item-head">
                    <strong data-testid="sca-dep-name">{dependency.name}</strong>
                    <span className="pill" data-testid="sca-dep-class">
                      {dependency.dependencyClass}
                      {dependency.dependencyType !== 'unknown' ? ` · ${dependency.dependencyType}` : ''}
                    </span>
                  </div>
                  <p className="muted" data-testid="sca-dep-version">
                    {dependency.ecosystem} ·{' '}
                    {dependency.resolvedVersion !== undefined
                      ? `resolved ${dependency.resolvedVersion}`
                      : dependency.declaredVersion !== undefined
                        ? `declared ${dependency.declaredVersion}`
                        : 'no version evidence'}
                    {dependency.resolvedVersion !== undefined &&
                    dependency.declaredVersion !== undefined
                      ? ` (declared ${dependency.declaredVersion})`
                      : ''}
                    {dependency.purl !== undefined ? ` · ${dependency.purl}` : ''}
                  </p>
                  <p className="muted" data-testid="sca-dep-evidence">
                    {dependency.manifestPath}
                    {dependency.lockfilePath !== undefined ? ` · ${dependency.lockfilePath}` : ''}
                  </p>
                </li>
              ))}
            </ul>
          )}
          {sca.advisories.length > 0 && (
            <>
              <h4>Advisories</h4>
              <ul className="findings-list" data-testid="sca-advisories">
                {sca.advisories.map((advisory) => (
                  <li key={`${advisory.id}-${advisory.dependencyId}`} data-testid="sca-advisory-item">
                    <span
                      className={
                        advisory.severity === 'CRITICAL' || advisory.severity === 'HIGH'
                          ? 'pill pill-danger'
                          : advisory.severity === 'MEDIUM'
                            ? 'pill'
                            : 'pill pill-ok'
                      }
                    >
                      {advisory.severity}
                    </span>{' '}
                    <strong>{advisory.id}</strong> — {advisory.name}
                    {advisory.version !== undefined ? `@${advisory.version}` : ''}:{' '}
                    {advisory.summary}
                  </li>
                ))}
              </ul>
            </>
          )}
        </>
      )}
    </div>
  );
}

/** Read a File as text via the classic API (portable everywhere). */
function readFileAsText(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.addEventListener('load', () => {
      resolve(typeof reader.result === 'string' ? reader.result : '');
    });
    reader.addEventListener('error', () => {
      reject(new Error(`Could not read ${file.name}.`));
    });
    reader.readAsText(file);
  });
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
