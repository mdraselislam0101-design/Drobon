import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { Link, useParams } from 'react-router-dom';
import {
  PROJECT_DESCRIPTION_MAX_LENGTH,
  PROJECT_NAME_MAX_LENGTH,
  SCAN_TYPES,
  findingScanner,
  type FindingDetailResponse,
  type FindingHistoryResponse,
  type FindingLifecycleState,
  type FindingsPageResponse,
  type SecurityReportResponse,
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
      {scans !== null && scans.length > 0 && (
        <section className="security-overview" data-testid="project-security-overview">
          <h3>Project security overview</h3>
          {(() => {
            const completed = scans.filter((scan) => scan.status === 'COMPLETED');
            const findingsTotal = completed.reduce((sum, scan) => sum + (scan.resultSummary?.findingsTotal ?? 0), 0);
            const severityTotals = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const;
            return completed.length === 0 ? (
              <p className="muted">No completed scans yet.</p>
            ) : (
              <>
                <p data-testid="project-findings-total">{findingsTotal} persisted finding{findingsTotal === 1 ? '' : 's'} across {completed.length} completed scan{completed.length === 1 ? '' : 's'}.</p>
                <p className="muted">These are scan findings, not a cross-scan deduplicated issue count. Dependency vulnerability status is reported separately and may be NOT ASSESSED.</p>
                <dl className="facts">
                  {SCAN_TYPES.map((type) => <div className="fact" key={type}><dt>{type} runs</dt><dd>{completed.filter((scan) => scan.scanType === type).length}</dd></div>)}
                  {severityTotals.map((severity) => <div className="fact" key={severity}><dt>{severity}</dt><dd>{completed.reduce((sum, scan) => sum + (scan.resultSummary?.findingsBySeverity?.[severity] ?? 0), 0)}</dd></div>)}
                </dl>
              </>
            );
          })()}
        </section>
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
              {scan.status === 'COMPLETED' && (
                <FindingsView projectId={projectId} scanId={scan.id} scanType={scan.scanType} />
              )}
              {scan.status === 'COMPLETED' && scan.scanType === 'SCA' && (
                <ScaView projectId={projectId} scanId={scan.id} />
              )}
              {scan.status === 'COMPLETED' && <ReportView projectId={projectId} scanId={scan.id} />}
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
 * One completed scan's server-filtered findings. Pages are bounded by the
 * API; detail retrieval is separately project/scan scoped and evidence is
 * rendered only as escaped text.
 */
const FINDING_TRANSITIONS: Readonly<Record<FindingLifecycleState, readonly FindingLifecycleState[]>> = {
  OPEN: ['ACKNOWLEDGED', 'IN_PROGRESS', 'RESOLVED'],
  ACKNOWLEDGED: ['IN_PROGRESS', 'RESOLVED'],
  IN_PROGRESS: ['ACKNOWLEDGED', 'RESOLVED'],
  RESOLVED: [],
  REOPENED: ['ACKNOWLEDGED', 'IN_PROGRESS', 'RESOLVED'],
};

function FindingsView({
  projectId,
  scanId,
  scanType,
}: {
  projectId: string;
  scanId: string;
  scanType: ScanType;
}): React.JSX.Element {
  const client = useApiClient();
  const [pageData, setPageData] = useState<FindingsPageResponse | null>(null);
  const [scanDetail, setScanDetail] = useState<ScanDetailResponse | null>(null);
  const [selected, setSelected] = useState<FindingDetailResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [opened, setOpened] = useState(false);
  const [severity, setSeverity] = useState<'ALL' | FindingSeverity>('ALL');
  const [scanner, setScanner] = useState<'ALL' | ScanType>('ALL');
  const [workflowTarget, setWorkflowTarget] = useState<FindingLifecycleState | ''>('');
  const [workflowBusy, setWorkflowBusy] = useState(false);
  const [workflowError, setWorkflowError] = useState<string | null>(null);
  const [noteDraft, setNoteDraft] = useState('');
  const [history, setHistory] = useState<FindingHistoryResponse | null>(null);
  const [historyError, setHistoryError] = useState<string | null>(null);

  const loadPage = async (
    nextPage: number,
    nextSeverity: 'ALL' | FindingSeverity = severity,
    nextScanner: 'ALL' | ScanType = scanner,
  ): Promise<void> => {
    setOpened(true);
    setError(null);
    setLoading(true);
    try {
      const filters: { severity?: FindingSeverity; scanner?: ScanType; page: number; pageSize: number } = {
        page: nextPage,
        pageSize: 20,
      };
      if (nextSeverity !== 'ALL') filters.severity = nextSeverity;
      if (nextScanner !== 'ALL') filters.scanner = nextScanner;
      const [data, observations] = await Promise.all([
        client.getFindings(projectId, scanId, filters),
        scanType === 'DAST' ? client.getScan(projectId, scanId) : Promise.resolve(null),
      ]);
      setPageData(data);
      setScanDetail(observations);
      setSelected(null);
      setDetailError(null);
    } catch (caught: unknown) {
      setError(caught instanceof ApiClientError ? caught.message : 'Could not load this findings page.');
    } finally {
      setLoading(false);
    }
  };

  const openFinding = async (findingId: string): Promise<void> => {
    setDetailError(null);
    setWorkflowError(null);
    setHistory(null);
    setHistoryError(null);
    setWorkflowTarget('');
    try {
      setSelected(await client.getFinding(projectId, scanId, findingId));
    } catch (caught: unknown) {
      setDetailError(caught instanceof ApiClientError ? caught.message : 'Could not load this finding.');
    }
  };

  const submitWorkflow = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault();
    if (selected?.workflow === undefined || workflowTarget === '') return;
    setWorkflowBusy(true);
    setWorkflowError(null);
    try {
      await client.setFindingLifecycle(projectId, scanId, selected.finding.id, workflowTarget);
      setSelected(await client.getFinding(projectId, scanId, selected.finding.id));
      setWorkflowTarget('');
      setHistory(null);
    } catch (caught: unknown) {
      setWorkflowError(caught instanceof ApiClientError ? caught.message : 'Could not update finding workflow.');
    } finally {
      setWorkflowBusy(false);
    }
  };

  const submitNote = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault();
    if (selected?.workflow === undefined || noteDraft.trim() === '') return;
    setWorkflowBusy(true);
    setWorkflowError(null);
    try {
      await client.addFindingNote(projectId, scanId, selected.finding.id, noteDraft);
      setNoteDraft('');
      setSelected(await client.getFinding(projectId, scanId, selected.finding.id));
      setHistory(null);
    } catch (caught: unknown) {
      setWorkflowError(caught instanceof ApiClientError ? caught.message : 'Could not save this remediation note.');
    } finally {
      setWorkflowBusy(false);
    }
  };

  const loadHistory = async (page = 1): Promise<void> => {
    if (selected === null) return;
    setHistoryError(null);
    try {
      setHistory(await client.getFindingHistory(projectId, scanId, selected.finding.id, page, 20));
    } catch (caught: unknown) {
      setHistoryError(caught instanceof ApiClientError ? caught.message : 'Could not load finding history.');
    }
  };

  const findings = pageData?.findings ?? [];
  const selectedFinding = selected?.finding;

  return (
    <div className="findings">
      {!opened && (
        <button type="button" className="button button-ghost" onClick={() => void loadPage(1)} data-testid="view-findings">
          View findings
        </button>
      )}
      {opened && (
        <>
          <div className="hero-actions">
            <div className="field">
              <label htmlFor={`findings-severity-${scanId}`}>Severity</label>
              <select
                id={`findings-severity-${scanId}`}
                value={severity}
                onChange={(event) => {
                  const next = event.target.value as 'ALL' | FindingSeverity;
                  setSeverity(next);
                  void loadPage(1, next, scanner);
                }}
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
            <div className="field">
              <label htmlFor={`findings-scanner-${scanId}`}>Scanner / source</label>
              <select
                id={`findings-scanner-${scanId}`}
                value={scanner}
                onChange={(event) => {
                  const next = event.target.value as 'ALL' | ScanType;
                  setScanner(next);
                  void loadPage(1, severity, next);
                }}
                data-testid="findings-scanner-filter"
              >
                <option value="ALL">All scanners</option>
                {SCAN_TYPES.map((type) => <option key={type} value={type}>{type}</option>)}
              </select>
            </div>
          </div>
          {loading && <LoadingState label="Loading findings…" />}
          {error !== null && (
            <div>
              <div className="form-alert" role="alert"><p data-testid="findings-error">{error}</p></div>
              <button type="button" className="button button-ghost" onClick={() => void loadPage(pageData?.page ?? 1)} data-testid="findings-retry">Retry findings</button>
            </div>
          )}
          {scanDetail?.scan.dast !== undefined && (
            <section className="dast-observations" data-testid="dast-observations">
              <h4>Observed responses</h4>
              <p className="muted">Passive GET observations only; response content was bounded and never executed. No browser, JavaScript, authentication, or crawling was used.</p>
              <p data-testid="dast-target-url">Target: <code>{scanDetail.scan.dast.targetUrl}</code></p>
              {scanDetail.scan.dast.partial && <p className="muted" data-testid="dast-partial-note">Partial result: {scanDetail.scan.dast.partialReason ?? 'some response checks were not completed'}</p>}
              <ul className="scan-list">
                {scanDetail.scan.dast.observations.map((observation, index) => (
                  <li key={`${observation.endpoint}-${index}`} data-testid="dast-observation">
                    <strong>{observation.method} · HTTP {observation.status}</strong>{' '}<code>{observation.endpoint}</code>
                    <p className="muted">{observation.responseTimeMs} ms · {observation.bodyBytes} bytes inspected{observation.bodyTruncated ? ' · body truncated' : ''}{observation.contentType !== undefined ? ` · ${observation.contentType}` : ''}</p>
                    {observation.headers.length > 0 && <ul>{observation.headers.map((header, headerIndex) => <li key={`${header}-${headerIndex}`}>{header}</li>)}</ul>}
                  </li>
                ))}
              </ul>
            </section>
          )}
          {!loading && error === null && pageData !== null && (
            <>
              <p className="muted" data-testid="findings-page-summary">{pageData.total} matching finding{pageData.total === 1 ? '' : 's'} · page {pageData.page} of {pageData.totalPages}</p>
              {findings.length === 0 ? (
                <p className="muted" data-testid="findings-empty">
                  {scanType === 'SCA'
                    ? 'This SCA result has no common Finding records. Review dependency analysis for the inventory, SBOM and provider advisory state; NOT ASSESSED is not a zero-vulnerability verdict.'
                    : `No findings match these filters. This is limited to the ${scanType} scan and does not represent scanners that did not run.`}
                </p>
              ) : (
                <ul className="findings-list" data-testid="findings-list">
                  {findings.map((finding) => (
                    <li key={finding.id} className="finding-item" data-testid="finding-item">
                      <div className="scan-item-head">
                        <span className={finding.severity === 'CRITICAL' || finding.severity === 'HIGH' ? 'pill pill-danger' : finding.severity === 'MEDIUM' ? 'pill' : 'pill pill-ok'} data-testid="finding-severity">{finding.severity}</span>
                        <strong data-testid="finding-rule">{finding.ruleId}</strong>
                        <span className="pill" data-testid="finding-scanner">{findingScanner(finding) ?? 'Unknown scanner'}</span>
                        {finding.confidence !== undefined && <span className="pill" data-testid="finding-confidence">{finding.confidence} detection confidence</span>}
                      </div>
                      <p data-testid="finding-title">{finding.title}</p>
                      <p className="muted" data-testid="finding-location">{finding.scanner === 'DAST' ? `${finding.method} ${finding.endpoint} · HTTP ${finding.responseStatus}` : `${finding.file}:${finding.line}:${finding.column}`}{finding.cwe !== undefined ? ` · ${finding.cwe}` : ''}</p>
                      <button type="button" className="button button-ghost" onClick={() => void openFinding(finding.id)} data-testid="finding-detail-button">Finding details</button>
                    </li>
                  ))}
                </ul>
              )}
              <div className="hero-actions" aria-label="Findings pagination">
                <button type="button" className="button button-ghost" disabled={pageData.page <= 1 || loading} onClick={() => void loadPage(pageData.page - 1)} data-testid="findings-previous">Previous</button>
                <button type="button" className="button button-ghost" disabled={pageData.page >= pageData.totalPages || loading} onClick={() => void loadPage(pageData.page + 1)} data-testid="findings-next">Next</button>
              </div>
            </>
          )}
          {detailError !== null && <div className="form-alert" role="alert"><p data-testid="finding-detail-error">{detailError}</p></div>}
          {selected !== null && selectedFinding !== undefined && (
            <section className="finding-detail" aria-label="Finding detail" data-testid="finding-detail">
              <h4>{selectedFinding.title}</h4>
              <dl className="facts">
                <div className="fact"><dt>Severity</dt><dd>{selectedFinding.severity}</dd></div>
                <div className="fact"><dt>Scanner</dt><dd>{findingScanner(selectedFinding) ?? 'Unknown scanner'}</dd></div>
                <div className="fact"><dt>Finding ID</dt><dd><code>{selectedFinding.id}</code></dd></div>
                <div className="fact"><dt>Fingerprint</dt><dd><code data-testid="finding-fingerprint">{selectedFinding.fingerprint}</code></dd></div>
                <div className="fact"><dt>Project</dt><dd>{selected.project.name} · <code>{selected.project.id}</code></dd></div>
                <div className="fact"><dt>Scan</dt><dd>{selected.scan.scanType} · <code>{selected.scan.id}</code></dd></div>
                <div className="fact"><dt>Observed</dt><dd>{selectedFinding.scanner === 'DAST' ? selectedFinding.observedAt : selected.scan.completedAt ?? selected.scan.createdAt}</dd></div>
                {selectedFinding.cwe !== undefined && <div className="fact"><dt>CWE</dt><dd>{selectedFinding.cwe}</dd></div>}
                <div className="fact"><dt>Location</dt><dd>{selectedFinding.scanner === 'DAST' ? `${selectedFinding.method} ${selectedFinding.endpoint}` : `${selectedFinding.file}:${selectedFinding.line}:${selectedFinding.column}`}</dd></div>
              </dl>
              <p>{selectedFinding.description}</p>
              <p><strong>Observed evidence</strong></p><pre><code data-testid="finding-evidence">{selectedFinding.evidence}</code></pre>
              <p><strong>Scanner remediation</strong></p><p data-testid="finding-remediation">{selectedFinding.remediation}</p>
              {selected.guidance !== undefined && (
                <section className="workflow-guidance" aria-label="Remediation guidance" data-testid="finding-guidance">
                  <h5>Rule-specific guidance · {selected.guidance.status.replaceAll('_', ' ')}</h5>
                  <p>{selected.guidance.whyItMatters}</p>
                  <ul>{selected.guidance.actions.map((action, index) => <li key={`${selected.guidance?.ruleId}-${index}`}>{action}</li>)}</ul>
                  <p><strong>Verification:</strong> {selected.guidance.verification}</p>
                  {selected.guidance.standardId !== undefined && <p className="muted">Scanner rule identifier: {selected.guidance.standardId}</p>}
                  {selected.guidance.example !== undefined && (
                    <div className="guidance-example">
                      <p><strong>Illustrative pattern only — review in application context.</strong></p>
                      <p>Before: <code>{selected.guidance.example.before}</code></p>
                      <p>After: <code>{selected.guidance.example.after}</code></p>
                      {selected.guidance.example.caveat !== undefined && <p className="muted">{selected.guidance.example.caveat}</p>}
                    </div>
                  )}
                </section>
              )}
              {selected.workflow !== undefined && (
                <section className="finding-workflow" aria-label="Finding remediation workflow" data-testid="finding-workflow">
                  <h5>Remediation workflow</h5>
                  <p className="muted">User-managed status is separate from scanner evidence. Marking a finding resolved does not verify a fix; only a later completed same-scanner scan with complete finding details updates observation status.</p>
                  <dl className="facts">
                    <div className="fact"><dt>Lifecycle</dt><dd data-testid="finding-lifecycle-state">{selected.workflow.state}</dd></div>
                    <div className="fact"><dt>Verification</dt><dd data-testid="finding-verification-state">{selected.workflow.verificationState === 'NOT_OBSERVED_IN_LATEST_SCAN' ? 'Not observed in latest completed same-scanner scan with complete finding details' : 'Observed in latest completed same-scanner scan with complete finding details'}</dd></div>
                    <div className="fact"><dt>Latest verification scan</dt><dd><code>{selected.workflow.lastVerificationScanId}</code> · {selected.workflow.lastVerificationAt}</dd></div>
                  </dl>
                  {selected.project.status === 'ARCHIVED' ? (
                    <p className="muted">Archived projects are read-only; lifecycle changes and notes are disabled.</p>
                  ) : FINDING_TRANSITIONS[selected.workflow.state].length > 0 ? (
                    <form className="workflow-form" onSubmit={(event) => void submitWorkflow(event)}>
                      <label htmlFor={`finding-state-${selectedFinding.id}`}>Change lifecycle state</label>
                      <div className="hero-actions">
                        <select id={`finding-state-${selectedFinding.id}`} value={workflowTarget} onChange={(event) => setWorkflowTarget(event.target.value as FindingLifecycleState | '')} disabled={workflowBusy}>
                          <option value="">Select a valid next state</option>
                          {FINDING_TRANSITIONS[selected.workflow.state].map((state) => <option key={state} value={state}>{state}</option>)}
                        </select>
                        <button type="submit" className="button button-secondary" disabled={workflowBusy || workflowTarget === ''}>{workflowBusy ? 'Saving…' : 'Update status'}</button>
                      </div>
                    </form>
                  ) : <p className="muted">No manual transition is available from this state. A future matching scan may automatically reopen a resolved finding.</p>}
                  {selected.project.status !== 'ARCHIVED' && (
                    <form className="workflow-form" onSubmit={(event) => void submitNote(event)}>
                      <label htmlFor={`finding-note-${selectedFinding.id}`}>Remediation note (plain text; secrets are redacted)</label>
                      <textarea id={`finding-note-${selectedFinding.id}`} value={noteDraft} onChange={(event) => setNoteDraft(event.target.value)} maxLength={1000} rows={3} disabled={workflowBusy} />
                      <button type="submit" className="button button-ghost" disabled={workflowBusy || noteDraft.trim() === ''}>Add note</button>
                    </form>
                  )}
                  {workflowError !== null && <div className="form-alert" role="alert"><p data-testid="finding-workflow-error">{workflowError}</p></div>}
                  <h6>Remediation notes</h6>
                  {selected.workflow.notes.length === 0 ? <p className="muted">No notes have been added.</p> : (
                    <ul className="workflow-notes" data-testid="finding-notes">
                      {selected.workflow.notes.map((note) => <li key={note.id}><p>{note.text}</p><small>{note.createdAt}{note.redacted ? ' · credential-like content redacted' : ''}</small></li>)}
                    </ul>
                  )}
                  <div className="hero-actions">
                    <button type="button" className="button button-ghost" onClick={() => void loadHistory(1)} data-testid="load-finding-history">{history === null ? 'Load workflow history' : 'Refresh workflow history'}</button>
                    {history !== null && <span className="muted">{history.total} events · page {history.page} of {history.totalPages}</span>}
                  </div>
                  {historyError !== null && <div className="form-alert" role="alert"><p data-testid="finding-history-error">{historyError}</p></div>}
                  {history !== null && (
                    <>
                      <ol className="workflow-history" data-testid="finding-history">
                        {history.events.map((entry) => <li key={entry.id}><strong>{entry.action.replaceAll('_', ' ')}</strong> · {entry.previousState ?? '—'} → {entry.newState} · {entry.at}</li>)}
                      </ol>
                      <div className="hero-actions" aria-label="Workflow history pagination">
                        <button type="button" className="button button-ghost" disabled={history.page <= 1} onClick={() => void loadHistory(history.page - 1)}>Previous events</button>
                        <button type="button" className="button button-ghost" disabled={history.page >= history.totalPages} onClick={() => void loadHistory(history.page + 1)}>Next events</button>
                      </div>
                    </>
                  )}
                </section>
              )}
            </section>
          )}
        </>
      )}
    </div>
  );
}

function ReportView({ projectId, scanId }: { projectId: string; scanId: string }): React.JSX.Element {
  const client = useApiClient();
  const [report, setReport] = useState<SecurityReportResponse['report'] | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const generate = async (): Promise<void> => {
    setBusy(true);
    setError(null);
    try { setReport((await client.createReport(projectId, scanId)).report); }
    catch (caught: unknown) { setError(caught instanceof ApiClientError ? caught.message : 'Could not generate the report.'); }
    finally { setBusy(false); }
  };
  const retrieve = async (): Promise<void> => {
    setBusy(true);
    setError(null);
    try { setReport((await client.getReport(projectId, scanId)).report); }
    catch (caught: unknown) { setError(caught instanceof ApiClientError ? caught.message : 'Could not retrieve the report.'); }
    finally { setBusy(false); }
  };
  const download = async (format: 'json' | 'markdown'): Promise<void> => {
    setBusy(true);
    setError(null);
    try {
      const file = await client.downloadReport(projectId, scanId, format);
      const href = URL.createObjectURL(file.blob);
      const anchor = document.createElement('a');
      anchor.href = href;
      anchor.download = file.filename;
      anchor.rel = 'noopener';
      anchor.click();
      window.setTimeout(() => URL.revokeObjectURL(href), 0);
    } catch (caught: unknown) {
      setError(caught instanceof ApiClientError ? caught.message : 'Could not download the report.');
    } finally { setBusy(false); }
  };

  return (
    <section className="report-panel" data-testid="report-panel">
      <h4>Security assessment report</h4>
      {report === null ? (
        <div className="hero-actions">
          <button type="button" className="button button-secondary" onClick={() => void generate()} disabled={busy} data-testid="generate-report">{busy ? 'Generating…' : 'Generate / retrieve report'}</button>
          <button type="button" className="button button-ghost" onClick={() => void retrieve()} disabled={busy} data-testid="retrieve-report">Retrieve saved report</button>
        </div>
      ) : (
        <>
          <p data-testid="report-id">Report <code>{report.reportId}</code> · generated {report.generatedAt}</p>
          <p className="muted">{report.findingSummary.total} persisted findings · content SHA-256 <code data-testid="report-content-digest">{report.contentDigest}</code></p>
          {report.dependencyIntelligence.status === 'NOT_ASSESSED' ? (
            <p className="muted" data-testid="report-not-assessed">Dependency vulnerability intelligence: NOT ASSESSED. {report.dependencyIntelligence.reason}</p>
          ) : (
            <p className="muted">Dependency vulnerability intelligence: ASSESSED by {report.dependencyIntelligence.providerId}; matched advisories: {report.dependencyIntelligence.advisoriesTotal}.</p>
          )}
          <p className="muted" data-testid="report-inventory-summary">
            {report.inventory.status === 'INCLUDED'
              ? `Inventory included: ${report.inventory.sca.dependencies.length} persisted of ${report.inventory.sca.summary.dependenciesTotal} observed dependencies; CycloneDX ${report.inventory.sca.sbom.specVersion} subset with ${report.inventory.sca.sbom.components.length} components.`
              : `Inventory / SBOM: NOT INCLUDED. ${report.inventory.reason}`}
          </p>
          {report.findingWorkflows === undefined ? (
            <p className="muted" data-testid="report-workflow-legacy">This saved Pump 12 report predates lifecycle snapshots. Regenerate it to include current remediation workflow observations.</p>
          ) : (
            <section className="report-workflows" data-testid="report-workflow-snapshot">
              <h5>Point-in-time remediation workflow snapshot</h5>
              <p className="muted">A user-selected RESOLVED state is not technical verification. Absence means only not observed in the latest completed same-scanner scan with complete finding details.</p>
              {report.findingWorkflows.length === 0 ? <p className="muted">No findings were present in this report snapshot.</p> : (
                <ul>{report.findingWorkflows.map((workflow) => (
                  <li key={workflow.id}>
                    <code>{workflow.findingId}</code> · {workflow.state} · {workflow.verificationState.replaceAll('_', ' ')} · last scan <code>{workflow.lastVerificationScanId}</code> ({workflow.lastVerificationAt})
                  </li>
                ))}</ul>
              )}
            </section>
          )}
          <p className="muted">Severity counts: {Object.entries(report.findingSummary.bySeverity).map(([severity, count]) => `${severity} ${count}`).join(' · ')}</p>
          <ul className="report-coverage" data-testid="report-scanner-coverage">
            {report.scannerCoverage.map((entry) => <li key={entry.scanner}>{entry.scanner}: {entry.status}{entry.reason === undefined ? '' : ` — ${entry.reason}`}</li>)}
          </ul>
          {report.dast !== undefined && <p className="muted">Passive DAST observations: {report.dast.observations.length}; bounded response metadata only.</p>}
          <div className="hero-actions">
            <button type="button" className="button button-ghost" onClick={() => void download('json')} disabled={busy} data-testid="download-report-json">Download JSON</button>
            <button type="button" className="button button-ghost" onClick={() => void download('markdown')} disabled={busy} data-testid="download-report-markdown">Download Markdown</button>
            <button type="button" className="button button-ghost" onClick={() => void retrieve()} disabled={busy} data-testid="refresh-report">Retrieve saved report</button>
            <button type="button" className="button button-secondary" onClick={() => void generate()} disabled={busy} data-testid="refresh-report-snapshot">Regenerate current snapshot</button>
          </div>
        </>
      )}
      {error !== null && <div className="form-alert" role="alert"><p data-testid="report-error">{error}</p></div>}
    </section>
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
          <section className="sca-guidance" data-testid="sca-remediation-guidance">
            <h4>Dependency review guidance</h4>
            {sca.summary.assessmentState === 'NOT_ASSESSED' ? (
              <p>Vulnerability intelligence remains NOT ASSESSED; no package is declared safe or vulnerable and no upgrade is recommended. Use only the observed dependency name and version below to consult an approved provider out of band. After any intentional change, review the lockfile and rerun SCA when authorized intelligence is available.</p>
            ) : (
              <p>Review only advisories returned by the configured provider for the observed dependency coordinates. Drobon does not infer additional advisories or choose an unverified upgrade; after an intentional change, rerun SCA and review the new assessment and SBOM.</p>
            )}
          </section>
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
