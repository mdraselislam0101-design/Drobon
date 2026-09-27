import { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import type { AuthzCapability, Permission } from '@drobon/shared';
import { hasPermission } from '@drobon/shared';
import { ApiClientError } from '../api/client.js';
import { useApiClient } from '../api/context.js';
import { useAuth } from '../auth/context.js';
import { ErrorState } from '../components/ErrorState.js';
import { LoadingState } from '../components/LoadingState.js';

/**
 * The protected account page. It re-verifies the session on mount (rather
 * than trusting long-lived provider state), so a session that expired or
 * was revoked elsewhere is discovered here: `GET /me` returns 401 → the
 * provider flips to anonymous → `ProtectedRoute` bounces to /login with an
 * "expired" notice.
 *
 * Pump 3 adds authorization views:
 * - role/userType badges (server-assigned values from the session);
 * - live capability checks — each row asks the API, which answers 200 or
 *   403; the page only renders the verdict (UI hiding is never the rule);
 * - a privileged-only lookup section (visibility via the shared permission
 *   table) — even if forced open, the API still enforces 403.
 */

type CheckState =
  | { status: 'checking' }
  | { status: 'granted' }
  | { status: 'denied'; status403: 403 }
  | { status: 'unavailable' }
  | { status: 'error'; message: string };

const CAPABILITY_CHECKS: Array<{
  level: AuthzCapability;
  label: string;
  permission: Permission;
}> = [
  { level: 'member', label: 'Member capability', permission: 'authz:capability:member' },
  { level: 'admin', label: 'Admin capability', permission: 'authz:capability:admin' },
  { level: 'owner', label: 'Owner capability', permission: 'authz:capability:owner' },
];

export function AccountPage(): React.JSX.Element {
  const { state, refresh, logout } = useAuth();
  const client = useApiClient();
  const navigate = useNavigate();
  const [loggingOut, setLoggingOut] = useState(false);
  const [logoutError, setLogoutError] = useState<string | null>(null);
  const [reloadToken, setReloadToken] = useState(0);

  useEffect(() => {
    void refresh();
  }, [refresh, reloadToken]);

  // Live capability verdicts — fetched from the API regardless of what
  // the client believes about roles: the API is the boundary.
  const [checks, setChecks] = useState<Record<AuthzCapability, CheckState>>({
    member: { status: 'checking' },
    admin: { status: 'checking' },
    owner: { status: 'checking' },
  });

  const runChecks = useCallback(async (): Promise<void> => {
    setChecks({ member: { status: 'checking' }, admin: { status: 'checking' }, owner: { status: 'checking' } });
    const results = await Promise.all(
      CAPABILITY_CHECKS.map(async ({ level }) => {
        try {
          await client.getCapability(level);
          return [level, { status: 'granted' } as CheckState] as const;
        } catch (error: unknown) {
          if (error instanceof ApiClientError) {
            if (error.status === 403) {
              return [level, { status: 'denied', status403: 403 } as CheckState] as const;
            }
            if (error.status === 404) {
              return [level, { status: 'unavailable' } as CheckState] as const;
            }
            return [level, { status: 'error', message: error.message } as CheckState] as const;
          }
          return [
            level,
            { status: 'error', message: 'Could not reach the API.' } as CheckState,
          ] as const;
        }
      }),
    );
    setChecks(Object.fromEntries(results) as Record<AuthzCapability, CheckState>);
  }, [client]);

  useEffect(() => {
    if (state.status === 'ready') {
      void runChecks();
    }
  }, [state.status, runChecks]);

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
  const privilegedRead = hasPermission(user.role, 'users:read:others');
  const rows: Array<[string, string]> = [
    ['Email', user.email],
    ['Account ID', user.id],
    ['Member since', user.createdAt],
  ];
  return (
    <section className="panel" aria-labelledby="account-title">
      <h1 id="account-title">Your account</h1>
      <p className="pill pill-ok">Signed in</p>
      <p className="badges">
        <span className="pill" data-testid="role-badge">
          Role: {user.role}
        </span>
        {user.userType !== null && (
          <span className="pill" data-testid="usertype-badge">
            Type: {user.userType}
          </span>
        )}
      </p>
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

      <h2>Access checks</h2>
      <p className="muted">
        Each check asks the API directly — the verdict below comes from the
        server, not from the page.
      </p>
      <ul className="access-checks" aria-label="Capability checks">
        {CAPABILITY_CHECKS.map(({ level, label }) => {
          const check = checks[level];
          return (
            <li key={level} data-testid={`capability-${level}`}>
              <span className="capability-label">{label}</span>
              <CapabilityVerdict check={check} />
            </li>
          );
        })}
      </ul>
      <button
        type="button"
        className="button button-ghost"
        onClick={() => void runChecks()}
      >
        Re-run checks
      </button>

      {privilegedRead && (
        <PrivilegedLookup client={client} />
      )}

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

function CapabilityVerdict({ check }: { check: CheckState }): React.JSX.Element {
  if (check === undefined || check.status === 'checking') {
    return (
      <span className="capability-verdict" role="status">
        Checking…
      </span>
    );
  }
  switch (check.status) {
    case 'granted':
      return (
        <span className="capability-verdict granted" data-testid="verdict-granted">
          Granted
        </span>
      );
    case 'denied':
      return (
        <span className="capability-verdict denied" data-testid="verdict-denied">
          Denied (403)
        </span>
      );
    case 'unavailable':
      return (
        <span className="capability-verdict" data-testid="verdict-unavailable">
          Not available here
        </span>
      );
    case 'error':
      return (
        <span className="capability-verdict error" role="alert">
          {check.message}
        </span>
      );
  }
}

/**
 * Permission-aware UI visibility (UX only): the lookup tool renders for
 * roles holding `users:read:others`. If anything forces it open, the API
 * still answers 403 for a MEMBER — proven by the API tests, mirrored here.
 */
function PrivilegedLookup({ client }: { client: ReturnType<typeof useApiClient> }): React.JSX.Element {
  const [id, setId] = useState('');
  const [busy, setBusy] = useState(false);
  const [outcome, setOutcome] = useState<
    | { kind: 'idle' }
    | { kind: 'found'; email: string; role: string }
    | { kind: 'denied' }
    | { kind: 'error'; message: string }
  >({ kind: 'idle' });

  const lookup = async (): Promise<void> => {
    if (id.trim().length === 0) {
      return;
    }
    setBusy(true);
    setOutcome({ kind: 'idle' });
    try {
      const result = await client.getUserById(id.trim());
      setOutcome({
        kind: 'found',
        email: result.user.email,
        role: result.user.role,
      });
    } catch (error: unknown) {
      if (error instanceof ApiClientError && error.status === 403) {
        setOutcome({ kind: 'denied' });
      } else if (error instanceof ApiClientError) {
        setOutcome({ kind: 'error', message: error.message });
      } else {
        setOutcome({ kind: 'error', message: 'Lookup failed. Please try again.' });
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="lookup-panel" data-testid="privileged-lookup">
      <h2>Privileged: account lookup (ADMIN+)</h2>
      <p className="muted">
        Visibility follows the shared permission table — the API enforces
        the same rule independently.
      </p>
      <label htmlFor="lookup-id">Account ID</label>
      <div className="lookup-row">
        <input
          id="lookup-id"
          type="text"
          value={id}
          autoComplete="off"
          onChange={(event) => setId(event.target.value)}
          placeholder="usr_…"
        />
        <button
          type="button"
          className="button button-secondary"
          onClick={() => void lookup()}
          disabled={busy || id.trim().length === 0}
          aria-busy={busy}
        >
          {busy ? 'Looking up…' : 'Look up'}
        </button>
      </div>
      {outcome.kind === 'found' && (
        <p className="notice" role="status">
          Found: <code>{outcome.email}</code> (role {outcome.role})
        </p>
      )}
      {outcome.kind === 'denied' && (
        <div className="form-alert" role="alert" data-testid="lookup-denied">
          <p>You don&#39;t have access to this resource.</p>
        </div>
      )}
      {outcome.kind === 'error' && (
        <div className="form-alert" role="alert">
          <p>{outcome.message}</p>
        </div>
      )}
    </div>
  );
}
