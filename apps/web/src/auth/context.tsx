import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { isAuthUser, type AuthUser } from '@drobon/shared';
import { ApiClientError } from '../api/client.js';
import { useApiClient } from '../api/context.js';

/**
 * Web-side authentication state. One provider, one source of truth:
 *
 * - `loading` — the initial `GET /me` is in flight (no flash of the wrong UI);
 * - `ready` — an authenticated user (cookie session confirmed by the API);
 * - `anonymous` — no session (also the destination of a 401 anywhere);
 * - `error` — `/me` failed for a non-auth reason (offline, server down);
 *   the user can retry instead of being silently logged out.
 *
 * The session token itself is never held in JavaScript — the browser
 * stores the `httpOnly` cookie and the client sends it automatically.
 */

export type AuthState =
  | { status: 'loading' }
  | { status: 'ready'; user: AuthUser }
  | { status: 'anonymous' }
  | { status: 'error'; message: string; requestId?: string };

export interface AuthContextValue {
  state: AuthState;
  /** Re-check the session against the API (`GET /me`). */
  refresh: () => Promise<void>;
  /** Authenticate and adopt the returned user. Rejects with ApiClientError. */
  login: (email: string, password: string) => Promise<AuthUser>;
  /** Create an account (auto-login) and adopt the returned user. */
  register: (email: string, password: string) => Promise<AuthUser>;
  /** Revoke the session server-side, then clear local state. */
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

function toErrorState(error: unknown): AuthState {
  if (error instanceof ApiClientError) {
    const out: { status: 'error'; message: string; requestId?: string } = {
      status: 'error',
      message: error.message,
    };
    if (error.requestId !== undefined) {
      out.requestId = error.requestId;
    }
    return out;
  }
  return { status: 'error', message: 'An unexpected error occurred. Please try again.' };
}

export function AuthProvider({ children }: { children: ReactNode }): React.JSX.Element {
  const client = useApiClient();
  const [state, setState] = useState<AuthState>({ status: 'loading' });
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const refresh = useCallback(async (): Promise<void> => {
    try {
      const data = await client.getMe();
      // Defense in depth: never adopt a user the shared guard rejects
      // (missing fields, credential material smuggled in, wrong shape).
      if (!isAuthUser(data?.user)) {
        setState({
          status: 'error',
          message: 'The server returned an unexpected session response.',
        });
        return;
      }
      if (mounted.current) {
        setState({ status: 'ready', user: data.user });
      }
    } catch (error: unknown) {
      if (!mounted.current) {
        return;
      }
      if (error instanceof ApiClientError && (error.status === 401 || error.code === 'UNAUTHORIZED')) {
        // No session (or it expired): that is a normal outcome, not an error.
        setState({ status: 'anonymous' });
        return;
      }
      setState(toErrorState(error));
    }
  }, [client]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const login = useCallback(
    async (email: string, password: string): Promise<AuthUser> => {
      const { user } = await client.postLogin(email, password);
      if (mounted.current) {
        setState({ status: 'ready', user });
      }
      return user;
    },
    [client],
  );

  const register = useCallback(
    async (email: string, password: string): Promise<AuthUser> => {
      const { user } = await client.postRegister(email, password);
      if (mounted.current) {
        setState({ status: 'ready', user });
      }
      return user;
    },
    [client],
  );

  const logout = useCallback(async (): Promise<void> => {
    // Only clear local state once the server confirmed revocation — if the
    // request fails, the session is still live and the UI must say so.
    await client.postLogout();
    if (mounted.current) {
      setState({ status: 'anonymous' });
    }
  }, [client]);

  const value = useMemo<AuthContextValue>(
    () => ({ state, refresh, login, register, logout }),
    [state, refresh, login, register, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const value = useContext(AuthContext);
  if (value === null) {
    throw new Error('useAuth must be used inside <AuthProvider>.');
  }
  return value;
}
