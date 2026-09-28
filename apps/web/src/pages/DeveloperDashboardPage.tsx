import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import type {
  SubscriptionResponse,
  UsageResponse,
  WorkspaceSecurityOverview,
} from '@drobon/shared';
import { ApiClientError } from '../api/client.js';
import { useApiClient } from '../api/context.js';
import { useAuth } from '../auth/context.js';
import { ErrorState } from '../components/ErrorState.js';
import { LoadingState } from '../components/LoadingState.js';

type DashboardState =
  | { status: 'loading' }
  | {
      status: 'ready';
      overview: WorkspaceSecurityOverview;
      usage: UsageResponse;
      subscription: SubscriptionResponse;
    }
  | { status: 'error'; message: string; requestId?: string };

function displayState(value: string): string {
  return value.replaceAll('_', ' ');
}

function countEntries<T extends Record<string, number>>(counts: T): Array<[keyof T, number]> {
  return Object.entries(counts).filter((entry) => entry[1] > 0) as Array<[keyof T, number]>;
}

export function DeveloperDashboardPage(): React.JSX.Element {
  const { state: authState } = useAuth();
  const client = useApiClient();
  const [dashboard, setDashboard] = useState<DashboardState>({ status: 'loading' });
  const [reloadToken, setReloadToken] = useState(0);

  const load = useCallback(async (): Promise<void> => {
    setDashboard({ status: 'loading' });
    try {
      // Each value is from its existing server-authoritative endpoint. This
      // page never calculates a plan, entitlement, quota, or security result.
      const [overview, usage, subscription] = await Promise.all([
        client.getSecurityOverview(),
        client.getUsage(),
        client.getSubscription(),
      ]);
      setDashboard({ status: 'ready', overview: overview.overview, usage, subscription });
    } catch (error: unknown) {
      if (error instanceof ApiClientError) {
        setDashboard({
          status: 'error',
          message: error.message,
          ...(error.requestId === undefined ? {} : { requestId: error.requestId }),
        });
      } else {
        setDashboard({ status: 'error', message: 'Could not load the account security overview.' });
      }
    }
  }, [client]);

  useEffect(() => {
    if (authState.status === 'ready') void load();
  }, [authState.status, load, reloadToken]);

  return (
    <section className="panel developer-dashboard" aria-labelledby="developer-dashboard-title">
      <p className="eyebrow">Developer workspace</p>
      <h1 id="developer-dashboard-title">Security overview</h1>
      <p className="muted">
        An account-owned summary of persisted projects, scans, finding workflows and reports.
        It is activity history—not a claim that every security area is clear or assessed.
      </p>
      {dashboard.status === 'loading' && <LoadingState label="Loading your security overview…" />}
      {dashboard.status === 'error' && (
        <ErrorState
          title="Could not load your security overview."
          message={dashboard.message}
          {...(dashboard.requestId === undefined ? {} : { requestId: dashboard.requestId })}
          onRetry={() => setReloadToken((token) => token + 1)}
        />
      )}
      {dashboard.status === 'ready' && (
        <>
          <div className="grid" aria-label="Account security summary">
            <article className="card">
              <h2>Projects</h2>
              <p><strong>{dashboard.overview.projects.total}</strong> total · {dashboard.overview.projects.active} active · {dashboard.overview.projects.archived} archived</p>
              <Link to="/projects">Open my projects</Link>
            </article>
            <article className="card">
              <h2>Scans</h2>
              <p><strong>{dashboard.overview.scans.total}</strong> recorded</p>
              <p className="muted">{countEntries(dashboard.overview.scans.byStatus).map(([status, count]) => `${displayState(String(status))}: ${count}`).join(' · ') || 'No scans recorded yet.'}</p>
            </article>
            <article className="card">
              <h2>Plan &amp; usage</h2>
              <p>Server-reported plan: <strong>{dashboard.subscription.subscription.plan}</strong> ({displayState(dashboard.subscription.subscription.status)})</p>
              <p>Current period: {dashboard.usage.used} used{dashboard.usage.limit === null ? ' · quota exempt' : ` of ${dashboard.usage.limit} · ${dashboard.usage.remaining} remaining`}</p>
              <p className="muted">PRO entitlement: {dashboard.subscription.entitlements.includes('feature:pro') ? 'granted by server' : 'not granted'}</p>
              <Link to="/account">Account details</Link>
            </article>
          </div>

          <section className="dashboard-section" aria-labelledby="workspace-projects-title">
            <div className="section-heading-row">
              <h2 id="workspace-projects-title">My projects</h2>
              <Link to="/projects">All projects</Link>
            </div>
            {dashboard.overview.projects.recent.length === 0 ? (
              <p className="form-alert" role="status">No projects yet. Create a project to submit source and run a security scan.</p>
            ) : (
              <ul className="projects-list" aria-label="Recent projects">
                {dashboard.overview.projects.recent.map((project) => (
                  <li key={project.id} className="card project-card">
                    <div className="project-card-head">
                      <Link to={`/projects/${project.id}`}>{project.name}</Link>
                      <span className={project.status === 'ACTIVE' ? 'pill pill-ok' : 'pill'}>{project.status === 'ACTIVE' ? 'Active' : 'Archived'}</span>
                    </div>
                    <p className="muted project-meta">Updated {project.updatedAt}</p>
                  </li>
                ))}
              </ul>
            )}
          </section>

          <section className="dashboard-section" aria-labelledby="security-history-title">
            <div className="section-heading-row">
              <h2 id="security-history-title">Recent security history</h2>
              <span className="muted">Updated {dashboard.overview.generatedAt}</span>
            </div>
            {dashboard.overview.scans.recent.length === 0 ? (
              <p className="form-alert" role="status">No scans have been recorded. Submit source to a project and start with a SAST scan.</p>
            ) : (
              <ul className="projects-list" aria-label="Recent scans">
                {dashboard.overview.scans.recent.map((scan) => (
                  <li key={scan.scanId} className="card">
                    <div className="project-card-head">
                      <strong>{scan.scanType} · {displayState(scan.status)}</strong>
                      <Link to={`/projects/${scan.projectId}`}>Open project</Link>
                    </div>
                    <p className="muted">Created {scan.createdAt}{scan.completedAt === null ? '' : ` · completed ${scan.completedAt}`}</p>
                    <p>
                      Findings reported: {scan.findingsTotal === null ? 'not available in this record' : scan.findingsTotal}
                      {scan.partial === true && <span className="pill">Partial coverage</span>}
                      {scan.status === 'COMPLETED' && <span className="pill">Report {scan.reportAvailable ? 'available' : 'not generated'}</span>}
                    </p>
                  </li>
                ))}
              </ul>
            )}
          </section>

          <section className="dashboard-section" aria-labelledby="finding-workflows-title">
            <div className="section-heading-row">
              <h2 id="finding-workflows-title">Finding &amp; remediation status</h2>
              <span className="pill">{dashboard.overview.findings.unresolved} unresolved</span>
            </div>
            <p className="muted">Counts use the latest persisted observation per project and finding identity. “Not observed” is not a remediation confirmation; lifecycle state and scan evidence remain available in the project.</p>
            <p>
              {countEntries(dashboard.overview.findings.unresolvedBySeverity).map(([severity, count]) => `${displayState(String(severity))}: ${count}`).join(' · ') || 'No unresolved finding records are currently present in the overview.'}
            </p>
            <p className="muted">
              Lifecycle: {countEntries(dashboard.overview.findings.byLifecycleState).map(([status, count]) => `${displayState(String(status))}: ${count}`).join(' · ') || 'no workflow records'}
              {' · '}
              Verification: {countEntries(dashboard.overview.findings.byVerificationState).map(([status, count]) => `${displayState(String(status))}: ${count}`).join(' · ') || 'no verification records'}
            </p>
            {dashboard.overview.findings.recent.length > 0 && (
              <ul className="projects-list" aria-label="Recent finding workflows">
                {dashboard.overview.findings.recent.map((finding) => (
                  <li key={`${finding.projectId}:${finding.findingId}`} className="card">
                    <div className="project-card-head">
                      <strong>{finding.severity} · {finding.scanner} · {finding.ruleId}</strong>
                      <Link to={`/projects/${finding.projectId}`}>Open finding in project</Link>
                    </div>
                    <p className="muted">{displayState(finding.lifecycleState)} · {displayState(finding.verificationState)} · observed {finding.observedAt} · workflow updated {finding.workflowUpdatedAt}</p>
                  </li>
                ))}
              </ul>
            )}
          </section>

          <section className="dashboard-section" aria-labelledby="reports-title">
            <div className="section-heading-row">
              <h2 id="reports-title">Reports</h2>
              <span>{dashboard.overview.reports.availableCount} persisted</span>
            </div>
            {dashboard.overview.reports.recent.length === 0 ? (
              <p className="muted">No persisted reports yet. Reports are created from completed scans in a project.</p>
            ) : (
              <ul className="projects-list" aria-label="Recent reports">
                {dashboard.overview.reports.recent.map((report) => (
                  <li key={report.reportId} className="card">
                    <div className="project-card-head">
                      <strong>Report {report.reportId}</strong>
                      <Link to={`/projects/${report.projectId}`}>Open report in project</Link>
                    </div>
                    <p className="muted">Scan {report.scanId} · generated {report.generatedAt}</p>
                  </li>
                ))}
              </ul>
            )}
          </section>

          <aside className="form-alert" role="note">
            SCA inventory and dependency intelligence are shown per scan. When no vulnerability data provider is configured, results remain explicitly NOT_ASSESSED / NO_DATA_LOADED; this overview does not turn that into a zero-vulnerability claim.
          </aside>
        </>
      )}
    </section>
  );
}
