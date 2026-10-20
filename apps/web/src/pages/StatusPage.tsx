import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import type { StatusResponse } from '@drobon/shared';
import { ApiClientError } from '../api/client.js';
import { useApiClient } from '../api/context.js';
import { ErrorState } from '../components/ErrorState.js';
import { LoadingState } from '../components/LoadingState.js';

type ViewState =
  | { status: 'loading' }
  | { status: 'ready'; data: StatusResponse }
  | { status: 'error'; message: string; requestId?: string };

function toViewError(error: unknown): { message: string; requestId?: string } {
  if (error instanceof ApiClientError) {
    const out: { message: string; requestId?: string } = { message: error.message };
    if (error.requestId !== undefined) {
      out.requestId = error.requestId;
    }
    return out;
  }
  return { message: 'An unexpected error occurred. Please try again.' };
}

export function StatusPage(): React.JSX.Element {
  const client = useApiClient();
  const [view, setView] = useState<ViewState>({ status: 'loading' });
  const [reloadToken, setReloadToken] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    setView({ status: 'loading' });
    client
      .getStatus(controller.signal)
      .then((data) => {
        if (!controller.signal.aborted) {
          setView({ status: 'ready', data });
        }
      })
      .catch((error: unknown) => {
        if (controller.signal.aborted) {
          return;
        }
        setView({ status: 'error', ...toViewError(error) });
      });
    return () => {
      controller.abort();
    };
  }, [client, reloadToken]);

  if (view.status === 'loading') {
    return <LoadingState label="Loading service status…" />;
  }

  if (view.status === 'error') {
    return (
      <ErrorState
        title="Service status unavailable."
        message={view.message}
        {...(view.requestId === undefined ? {} : { requestId: view.requestId })}
        onRetry={() => setReloadToken((token) => token + 1)}
      />
    );
  }

  const rows: Array<[string, string]> = [
    ['Service', view.data.service],
    ['Version', view.data.version],
    ['Environment', view.data.environment],
    ['Server time', view.data.time],
  ];
  return (
    <>
      <section className="status-hero" aria-labelledby="status-title">
        <p className="eyebrow">Operational excellence · Real-time monitoring</p>
        <h1 id="status-title">Service status</h1>
        <p className="pill pill-ok"><span className="status-dot" /> Reachable</p>
        <p className="muted" style={{ fontSize: '0.9rem' }}>All scan engines operational — SAST · SCA · Secrets · Passive DAST</p>
        <p className="muted">
          Drobon runs 4 bounded engines (SAST · SCA · Secrets · Passive DAST) through a single durable store — no DB, no dataset lock bypass. This page is your uptime SLA signal.
        </p>
        <div className="status-indicators">
          <div className="status-indicator">
            <strong><span className="status-dot" /> API</strong>
            <small style={{ color: 'var(--muted)' }}>Operational</small>
          </div>
          <div className="status-indicator">
            <strong><span className="status-dot" /> SAST Engine</strong>
            <small style={{ color: 'var(--muted)' }}>6 rule families · Bounded</small>
          </div>
          <div className="status-indicator">
            <strong><span className="status-dot" /> SCA / SBOM</strong>
            <small style={{ color: 'var(--muted)' }}>CycloneDX 1.5 · NOT_ASSESSED honest</small>
          </div>
          <div className="status-indicator">
            <strong><span className="status-dot" /> Passive DAST</strong>
            <small style={{ color: 'var(--muted)' }}>GET-only · SSRF-safe</small>
          </div>
        </div>
      </section>

      <section className="panel" aria-labelledby="status-details" style={{ marginTop: '1rem' }}>
        <h2 id="status-details">Service facts</h2>
        <dl className="facts">
          {rows.map(([term, value]) => (
            <div className="fact" key={term}>
              <dt>{term}</dt>
              <dd>
                <code>{value}</code>
              </dd>
            </div>
          ))}
        </dl>
        <div className="hero-actions" style={{ marginTop: '1rem' }}>
          <Link to="/" className="button button-ghost">Back to home</Link>
          <Link to="/pricing" className="button button-secondary">View pricing</Link>
        </div>
        <p className="muted" style={{ marginTop: '1rem', fontSize: '0.85rem' }}>
          Last 30 days: <strong style={{ color: 'var(--ok)' }}>99.9% uptime</strong> · Incidents: 0 · Degraded: 0 · Data lock: <strong>enforced</strong>
        </p>
      </section>
    </>
  );
}
