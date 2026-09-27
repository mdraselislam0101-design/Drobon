import { useEffect, useState } from 'react';
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
    <section className="panel" aria-labelledby="status-title">
      <h1 id="status-title">Service status</h1>
      <p className="pill pill-ok">Reachable</p>
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
    </section>
  );
}
