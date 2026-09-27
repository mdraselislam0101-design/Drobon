import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ApiClientError } from '../api/client.js';
import { useAuth } from '../auth/context.js';
import { ErrorState } from '../components/ErrorState.js';
import { LoadingState } from '../components/LoadingState.js';

/**
 * The protected account page. It re-verifies the session on mount (rather
 * than trusting long-lived provider state), so a session that expired or
 * was revoked elsewhere is discovered here: `GET /me` returns 401 → the
 * provider flips to anonymous → `ProtectedRoute` bounces to /login with an
 * "expired" notice.
 */
export function AccountPage(): React.JSX.Element {
  const { state, refresh, logout } = useAuth();
  const navigate = useNavigate();
  const [loggingOut, setLoggingOut] = useState(false);
  const [logoutError, setLogoutError] = useState<string | null>(null);
  const [reloadToken, setReloadToken] = useState(0);

  useEffect(() => {
    void refresh();
  }, [refresh, reloadToken]);

  const onLogout = async (): Promise<void> => {
    setLogoutError(null);
    setLoggingOut(true);
    try {
      await logout();
      navigate('/', { replace: true });
    } catch (error: unknown) {
      if (error instanceof ApiClientError) {
        setLogoutError(error.message);
      } else {
        setLogoutError('Logout failed. Please try again.');
      }
      setLoggingOut(false);
    }
  };

  if (state.status === 'loading') {
    return <LoadingState label="Loading your account…" />;
  }
  if (state.status === 'error') {
    return (
      <ErrorState
        title="Could not load your account."
        message={state.message}
        {...(state.requestId === undefined ? {} : { requestId: state.requestId })}
        onRetry={() => setReloadToken((token) => token + 1)}
      />
    );
  }
  if (state.status === 'anonymous') {
    // Caught by ProtectedRoute on the next render; keep the shell quiet.
    return <LoadingState label="Session ended. Redirecting…" />;
  }

  const { user } = state;
  const rows: Array<[string, string]> = [
    ['Email', user.email],
    ['Account ID', user.id],
    ['Member since', user.createdAt],
  ];
  return (
    <section className="panel" aria-labelledby="account-title">
      <h1 id="account-title">Your account</h1>
      <p className="pill pill-ok">Signed in</p>
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
      {logoutError !== null && (
        <div className="form-alert" role="alert">
          <p>{logoutError}</p>
        </div>
      )}
      <div className="hero-actions account-actions">
        <button
          type="button"
          className="button button-secondary"
          onClick={() => void onLogout()}
          disabled={loggingOut}
          aria-busy={loggingOut}
        >
          {loggingOut ? 'Signing out…' : 'Sign out'}
        </button>
        <button
          type="button"
          className="button button-ghost"
          onClick={() => setReloadToken((token) => token + 1)}
        >
          Refresh session
        </button>
      </div>
    </section>
  );
}
