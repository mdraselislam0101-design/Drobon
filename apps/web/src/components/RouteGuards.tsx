import { useEffect, useRef, type ReactElement } from 'react';
import { Navigate, Outlet, useLocation } from 'react-router-dom';
import { useAuth } from '../auth/context.js';
import { ErrorState } from './ErrorState.js';
import { LoadingState } from './LoadingState.js';

/** Only render the wrapped element while anonymous (login/register pages). */
export function PublicOnlyRoute({ children }: { children: ReactElement }): React.JSX.Element {
  const { state } = useAuth();
  const location = useLocation();
  if (state.status === 'loading') {
    return <LoadingState label="Checking your session…" />;
  }
  if (state.status === 'ready') {
    const from = readSafePath(location.state);
    return <Navigate to={from ?? '/account'} replace />;
  }
  // `error` on the session probe falls through to the form: logging in is
  // still a meaningful action (and likely fixes the connectivity issue).
  return children;
}

/**
 * Route guard for authenticated pages. Handles the three states honestly:
 * loading (spinner), anonymous (redirect to login, remembering where the
 * user was going), probe failure (retryable error instead of a fake
 * logout).
 */
export function ProtectedRoute(): React.JSX.Element {
  const { state, refresh } = useAuth();
  const location = useLocation();
  const sawReady = useRef(false);
  useEffect(() => {
    if (state.status === 'ready') {
      sawReady.current = true;
    }
  }, [state.status]);

  if (state.status === 'loading') {
    return <LoadingState label="Checking your session…" />;
  }
  if (state.status === 'error') {
    return (
      <ErrorState
        title="Could not verify your session."
        message={state.message}
        {...(state.requestId === undefined ? {} : { requestId: state.requestId })}
        onRetry={() => void refresh()}
      />
    );
  }
  if (state.status === 'anonymous') {
    // A transition from `ready` means the session died while the page was
    // open (expiry, logout elsewhere, server restart) — surface that.
    const expired = sawReady.current;
    return (
      <Navigate
        to="/login"
        replace
        state={{
          from: location.pathname,
          ...(expired ? { reason: 'expired' } : {}),
        }}
      />
    );
  }
  return <Outlet />;
}

/**
 * Internal-path sanitizer for post-login redirects: rejects protocol-relative
 * URLs, backslash tricks and absolute URLs so an attacker-controlled `from`
 * can never send the browser off-site (open-redirect defense).
 */
export function readSafePath(state: unknown): string | undefined {
  if (typeof state !== 'object' || state === null) {
    return undefined;
  }
  const from = (state as { from?: unknown }).from;
  if (
    typeof from !== 'string' ||
    !from.startsWith('/') ||
    from.startsWith('//') ||
    from.includes('\\') ||
    from.includes('\n') ||
    from.includes('\r')
  ) {
    return undefined;
  }
  return from;
}
