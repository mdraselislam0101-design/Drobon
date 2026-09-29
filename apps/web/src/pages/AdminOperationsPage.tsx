import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import type {
  AdminAccountSummary,
  AdminAuditRecord,
  AdminDashboardResponse,
  AdminFindingSummary,
  AdminScanSummary,
} from '@drobon/shared';
import { ApiClientError } from '../api/client.js';
import { useApiClient } from '../api/context.js';

type Section = 'overview' | 'accounts' | 'scans' | 'findings' | 'audit';
const SECTIONS: Array<{ id: Section; label: string }> = [
  { id: 'overview', label: 'Overview' }, { id: 'accounts', label: 'Accounts' },
  { id: 'scans', label: 'Scans' }, { id: 'findings', label: 'Findings' }, { id: 'audit', label: 'Payment audit' },
];

function errorMessage(cause: unknown): string {
  if (cause instanceof ApiClientError && cause.status === 403) {
    return 'Platform operations access is denied. A live ADMIN role and the server-configured platform administrator allowlist are both required.';
  }
  return cause instanceof ApiClientError ? cause.message : 'Operational data is unavailable. Please retry.';
}

function money(minorUnits: number): string {
  return new Intl.NumberFormat('en-BD', { style: 'currency', currency: 'BDT' }).format(minorUnits / 100);
}

function Metric({ label, value, note }: { label: string; value: string | number; note?: string }): React.JSX.Element {
  return <article className="admin-metric"><span className="muted">{label}</span><strong>{value}</strong>{note !== undefined && <small>{note}</small>}</article>;
}

export function AdminOperationsPage(): React.JSX.Element {
  const client = useApiClient();
  const [section, setSection] = useState<Section>('overview');
  const [dashboard, setDashboard] = useState<AdminDashboardResponse | null>(null);
  const [accounts, setAccounts] = useState<{ rows: AdminAccountSummary[]; total: number } | null>(null);
  const [scans, setScans] = useState<{ rows: AdminScanSummary[]; total: number } | null>(null);
  const [findings, setFindings] = useState<{ rows: AdminFindingSummary[]; total: number } | null>(null);
  const [audit, setAudit] = useState<{ rows: AdminAuditRecord[]; total: number } | null>(null);
  const [dashboardLoading, setDashboardLoading] = useState(false);
  const [sectionLoading, setSectionLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [searchInput, setSearchInput] = useState('');
  const [search, setSearch] = useState('');
  const [refreshKey, setRefreshKey] = useState(0);

  const refresh = useCallback((): void => setRefreshKey((value) => value + 1), []);

  useEffect(() => {
    const controller = new AbortController();
    setDashboardLoading(true);
    setError(null);
    client.getAdminDashboard(controller.signal).then((value) => {
      if (!controller.signal.aborted) setDashboard(value);
    }).catch((cause: unknown) => {
      if (!controller.signal.aborted) {
        setError(errorMessage(cause));
        if (cause instanceof ApiClientError && cause.status === 403) setDashboard(null);
      }
    }).finally(() => { if (!controller.signal.aborted) setDashboardLoading(false); });
    return () => controller.abort();
  }, [client, refreshKey]);

  useEffect(() => {
    if (section === 'overview') return;
    const controller = new AbortController();
    setSectionLoading(true);
    setError(null);
    if (section === 'accounts') setAccounts(null);
    if (section === 'scans') setScans(null);
    if (section === 'findings') setFindings(null);
    if (section === 'audit') setAudit(null);
    const request = async (): Promise<void> => {
      try {
        if (section === 'accounts') {
          const result = await client.getAdminAccounts({ page, pageSize: 25, ...(search === '' ? {} : { search }) }, controller.signal);
          if (!controller.signal.aborted) setAccounts({ rows: result.accounts, total: result.total });
        } else if (section === 'scans') {
          const result = await client.getAdminScans({ page, pageSize: 25 }, controller.signal);
          if (!controller.signal.aborted) setScans({ rows: result.scans, total: result.total });
        } else if (section === 'findings') {
          const result = await client.getAdminFindings({ page, pageSize: 25 }, controller.signal);
          if (!controller.signal.aborted) setFindings({ rows: result.findings, total: result.total });
        } else {
          const result = await client.getAdminAudit({ page, pageSize: 50 }, controller.signal);
          if (!controller.signal.aborted) setAudit({ rows: result.events, total: result.total });
        }
      } catch (cause: unknown) {
        if (!controller.signal.aborted) {
          setError(errorMessage(cause));
          if (cause instanceof ApiClientError && cause.status === 403) {
            setDashboard(null); setAccounts(null); setScans(null); setFindings(null); setAudit(null);
          }
        }
      } finally {
        if (!controller.signal.aborted) setSectionLoading(false);
      }
    };
    void request();
    return () => controller.abort();
  }, [client, section, page, search, refreshKey]);

  const changeSection = (next: Section): void => { setSection(next); setPage(1); setError(null); };
  const submitSearch = (event: React.FormEvent<HTMLFormElement>): void => {
    event.preventDefault(); setPage(1); setSearch(searchInput.trim());
  };
  const total = section === 'accounts' ? accounts?.total : section === 'scans' ? scans?.total : section === 'findings' ? findings?.total : section === 'audit' ? audit?.total : 0;
  const pageSize = section === 'audit' ? 50 : 25;
  const maxPage = Math.max(1, Math.ceil((total ?? 0) / pageSize));
  const loading = section === 'overview' ? dashboardLoading : sectionLoading;

  return (
    <section className="panel admin-operations" aria-labelledby="admin-operations-title">
      <p className="eyebrow">Restricted platform operations</p>
      <h1 id="admin-operations-title">Operations dashboard</h1>
      <p className="muted">Read-only business and security operations visibility. Every API request is authorized server-side using the live account role and the configured platform administrator list.</p>
      <p className="form-alert" role="note">Account status and administrative account mutations are not supported. Payment totals below describe submitted requests, not verified receipts or revenue. Scan and finding lists omit source content, evidence, private paths, target URLs, and fingerprint hashes.</p>

      <div className="admin-tabs" role="group" aria-label="Platform operations sections">
        {SECTIONS.map((item) => <button key={item.id} type="button" aria-pressed={section === item.id} className={section === item.id ? 'button button-primary' : 'button button-ghost'} onClick={() => changeSection(item.id)}>{item.label}</button>)}
        <Link className="button button-ghost" to="/admin/payments">Payment review</Link>
      </div>
      {error !== null && <div className="form-alert" role="alert"><p>{error}</p><button type="button" className="button button-ghost" onClick={refresh}>Retry</button></div>}
      {loading && <p role="status">Loading persisted operational data…</p>}

      {section === 'overview' && dashboard !== null && <>
        <p className="muted">Snapshot as of <time dateTime={dashboard.asOf}>{dashboard.asOf}</time>. Counts are from the currently loaded account, project, scan, and payment stores.</p>
        <div className="admin-metrics">
          <Metric label="Accounts" value={dashboard.accounts.state === 'AVAILABLE' ? dashboard.accounts.total : 'UNAVAILABLE'} note={dashboard.accounts.state === 'AVAILABLE' ? `${dashboard.accounts.free} FREE · ${dashboard.accounts.pro} PRO` : 'Account aggregates unavailable'} />
          <Metric label="Projects" value={dashboard.projects.state === 'AVAILABLE' ? dashboard.projects.total : 'UNAVAILABLE'} note={dashboard.projects.state === 'AVAILABLE' ? `${dashboard.projects.active} active · ${dashboard.projects.archived} archived` : 'Project aggregates unavailable'} />
          <Metric label="Scans" value={dashboard.scans.state === 'AVAILABLE' ? dashboard.scans.total : 'UNAVAILABLE'} note={dashboard.scans.state === 'AVAILABLE' ? `${dashboard.scans.recentlyCompleted} completed in the last 30 days` : 'Scan aggregates unavailable'} />
          <Metric label="Findings not resolved" value={dashboard.findings.state === 'AVAILABLE' ? dashboard.findings.unresolved : 'UNAVAILABLE'} note={dashboard.findings.state === 'AVAILABLE' ? `${dashboard.findings.dastObservations} DAST observations · ${dashboard.findings.scaNotAssessed} SCA scans not assessed` : 'Finding aggregates unavailable'} />
          <Metric label="Payment requests" value={dashboard.payments.state === 'AVAILABLE' ? dashboard.payments.total : 'UNAVAILABLE'} note="Submitted requests; not revenue or independent payment verification" />
          <Metric label="Submitted amount" value={dashboard.payments.state === 'AVAILABLE' ? money(dashboard.payments.submittedAmountMinorUnits) : 'UNAVAILABLE'} note="Aggregate of user-submitted payment requests" />
          <Metric label="Approved requests amount" value={dashboard.payments.state === 'AVAILABLE' ? money(dashboard.payments.approvedAmountMinorUnits) : 'UNAVAILABLE'} note="Manual review status only; not independently verified revenue" />
        </div>
        <h2>Persisted states</h2>
        <dl className="admin-status-grid">
          <div><dt>Scans by status</dt><dd>{dashboard.scans.state === 'AVAILABLE' ? Object.entries(dashboard.scans.byStatus).map(([key, value]) => `${key}: ${value}`).join(' · ') : 'UNAVAILABLE'}</dd></div>
          <div><dt>Payments by status</dt><dd>{dashboard.payments.state === 'AVAILABLE' ? Object.entries(dashboard.payments.byStatus).map(([key, value]) => `${key}: ${value}`).join(' · ') : 'UNAVAILABLE'}</dd></div>
          <div><dt>Findings by severity</dt><dd>{dashboard.findings.state === 'AVAILABLE' ? Object.entries(dashboard.findings.bySeverity).map(([key, value]) => `${key}: ${value}`).join(' · ') : 'UNAVAILABLE'}</dd></div>
          <div><dt>Findings lifecycle</dt><dd>{dashboard.findings.state === 'AVAILABLE' ? Object.entries(dashboard.findings.byLifecycleState).map(([key, value]) => `${key}: ${value}`).join(' · ') : 'UNAVAILABLE'}</dd></div>
        </dl>
        <h2>System status</h2>
        <dl className="admin-status-grid">
          <div><dt>API</dt><dd>{dashboard.system.api}</dd></div><div><dt>Web assessment</dt><dd>{dashboard.system.web}</dd></div>
          <div><dt>Account persistence</dt><dd>{dashboard.system.accountPersistence}</dd></div><div><dt>Payment persistence</dt><dd>{dashboard.system.paymentPersistence}</dd></div>
          <div><dt>API-attached scan processor</dt><dd>{dashboard.system.apiAttachedScanProcessor}</dd></div><div><dt>Separate worker</dt><dd>{dashboard.system.separateWorker}</dd></div>
          <div><dt>Assistant / AI provider</dt><dd>{dashboard.system.assistantFeature} / {dashboard.system.aiProvider}</dd></div><div><dt>Payment gateway</dt><dd>{dashboard.system.paymentGateway}</dd></div>
          <div><dt>Vulnerability dataset</dt><dd>{dashboard.system.vulnerabilityDataset}</dd></div><div><dt>Separate security dataset</dt><dd>{dashboard.system.securityDataset}</dd></div>
        </dl>
      </>}

      {section === 'accounts' && <>
        <h2>Account visibility</h2><p className="muted">Read only. Account status is unavailable in the current persistence model; no account role, UserType, or subscription mutation is offered here.</p>
        <form className="admin-search" onSubmit={submitSearch}><label htmlFor="admin-account-search">Email search</label><input id="admin-account-search" maxLength={100} value={searchInput} onChange={(event) => setSearchInput(event.target.value)} /><button type="submit" className="button button-ghost">Search</button></form>
        {accounts !== null && <div className="table-wrap"><table className="payment-table"><thead><tr><th>Account</th><th>Role / UserType</th><th>Plan</th><th>Account status</th><th>Payment requests</th></tr></thead><tbody>{accounts.rows.map((account) => <tr key={account.accountId}><td>{account.email}<br /><code>{account.accountId}</code></td><td>{account.role} / {account.userType ?? 'NONE'}</td><td>{account.plan} · {account.subscriptionStatus}</td><td>{account.accountStatus}</td><td>{account.paymentRequestCount} · latest {account.latestPaymentStatus ?? 'NO_DATA'}</td></tr>)}</tbody></table></div>}
      </>}

      {section === 'scans' && <><h2>Scan operations</h2><p className="muted">Metadata-only list. Target URLs and source information are not included.</p>{scans !== null && <div className="table-wrap"><table className="payment-table"><thead><tr><th>Scan</th><th>Project / account</th><th>Type</th><th>Status</th><th>Created</th><th>Findings</th></tr></thead><tbody>{scans.rows.map((scan) => <tr key={scan.scanId}><td><code>{scan.scanId}</code></td><td><code>{scan.projectId}</code><br /><code>{scan.accountId}</code></td><td>{scan.scanType}</td><td>{scan.status}</td><td>{scan.createdAt}</td><td>{scan.findingsTotal}</td></tr>)}</tbody></table></div>}</>}

      {section === 'findings' && <><h2>Finding index</h2><p className="muted">Redacted index only; no finding description, source path, evidence, remediation text, or fingerprint hash is exposed.</p>{findings !== null && <div className="table-wrap"><table className="payment-table"><thead><tr><th>Finding #</th><th>Project / scan</th><th>Scanner / rule</th><th>Severity</th><th>Lifecycle</th><th>Observed</th></tr></thead><tbody>{findings.rows.map((finding) => <tr key={`${finding.scanId}:${finding.findingNumber}`}><td>{finding.findingNumber}</td><td><code>{finding.projectId}</code><br /><code>{finding.scanId}</code></td><td>{finding.scanner} · {finding.ruleId}</td><td>{finding.severity}</td><td>{finding.lifecycleState}</td><td>{finding.observedAt}</td></tr>)}</tbody></table></div>}</>}

      {section === 'audit' && <><h2>Payment audit events</h2><p className="muted">Coverage: payment events only. The log is append-only within the payment store; this is not a claim of cryptographic immutability or complete system-wide audit coverage.</p>{audit !== null && <div className="table-wrap"><table className="payment-table"><thead><tr><th>Event</th><th>Payment / account</th><th>Action</th><th>Status change</th><th>Actor / time</th></tr></thead><tbody>{audit.rows.map((event) => <tr key={event.eventId}><td><code>{event.eventId}</code></td><td><code>{event.paymentId}</code><br /><code>{event.accountId}</code></td><td>{event.action}</td><td>{event.previousStatus ?? '—'} → {event.newStatus}</td><td><code>{event.actorId}</code><br />{event.timestamp}</td></tr>)}</tbody></table></div>}</>}

      {section !== 'overview' && <div className="admin-pagination"><span>Page {page} of {maxPage} · {total ?? '—'} records</span><button className="button button-ghost" type="button" disabled={page <= 1 || loading} onClick={() => setPage((value) => Math.max(1, value - 1))}>Previous</button><button className="button button-ghost" type="button" disabled={page >= maxPage || loading} onClick={() => setPage((value) => Math.min(maxPage, value + 1))}>Next</button></div>}
    </section>
  );
}
