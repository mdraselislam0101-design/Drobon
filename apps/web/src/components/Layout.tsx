import { useEffect, useRef } from 'react';
import { Link, NavLink, Outlet, useLocation } from 'react-router-dom';
import { roleAtLeast } from '@drobon/shared';
import { useAuth } from '../auth/context.js';

/**
 * Human page names for the routes the app actually renders. Unknown paths fall
 * back to the first segment, so a new route still gets a sane document title.
 */
const PAGE_TITLES: Readonly<Record<string, string>> = {
  '/': 'Home',
  '/status': 'Service status',
  '/pricing': 'Pricing',
  '/login': 'Sign in',
  '/register': 'Create account',
  '/account': 'Account',
  '/dashboard': 'Developer dashboard',
  '/student/dashboard': 'Student dashboard',
  '/student/learn': 'Learning path',
  '/security-professional/dashboard': 'Security Professional dashboard',
  '/pentester/dashboard': 'Pentester dashboard',
  '/admin/operations': 'Admin operations',
  '/admin/payments': 'Admin payments',
  '/admin/partners': 'Admin partners',
  '/partner/dashboard': 'Partner dashboard',
  '/projects': 'Projects',
};

function pageTitleFor(pathname: string): string {
  const direct = PAGE_TITLES[pathname];
  if (direct !== undefined) return direct;
  if (/^\/projects\/[^/]+$/.test(pathname)) return 'Project detail';
  const segment = pathname.split('/').filter((part) => part.length > 0)[0];
  return segment === undefined ? 'Page' : segment;
}

export function Layout({
  appName,
  appVersion,
}: {
  appName: string;
  appVersion: string;
}): React.JSX.Element {
  const { state } = useAuth();
  const location = useLocation();
  const mainRef = useRef<HTMLElement | null>(null);
  const announcement = `Navigated to ${pageTitleFor(location.pathname)}`;

  // Single-page-app accessibility: a route change is not a page load, so the
  // title must be updated and the change announced (WCAG 2.4.2 / 4.1.3). Focus
  // moves to the main landmark so keyboard users start at the new content
  // instead of at the top of the navigation they just left.
  useEffect(() => {
    document.title = `${pageTitleFor(location.pathname)} · ${appName}`;
    mainRef.current?.focus();
  }, [location.pathname, appName]);

  return (
    <div className="shell">
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <header className="site-header">
        <div className="container header-inner">
          <Link className="brand" to="/" aria-label={`${appName} home`}>
            <svg
              className="brand-mark"
              viewBox="0 0 32 32"
              aria-hidden="true"
              focusable="false"
            >
              <path
                d="M16 4l9 3.6v6.2c0 5.6-3.8 9.6-9 12.2-5.2-2.6-9-6.6-9-12.2V7.6L16 4z"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinejoin="round"
              />
              <path d="M16 10v12M10 16h12" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
            </svg>
            <span className="brand-name">{appName}</span>
          </Link>
          <nav aria-label="Primary">
            <NavLink className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')} to="/">
              Home
            </NavLink>
            <NavLink
              className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}
              to="/pricing"
            >
              Pricing
            </NavLink>
            <NavLink
              className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}
              to="/status"
            >
              Service status
            </NavLink>
            {state.status === 'ready' && (
              <>
                {state.user.userType === 'DEVELOPER' && (
                  <NavLink
                    className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}
                    to="/dashboard"
                  >
                    Developer dashboard
                  </NavLink>
                )}
                {state.user.userType === 'STUDENT' && (
                  <NavLink
                    className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}
                    to="/student/dashboard"
                  >
                    Student dashboard
                  </NavLink>
                )}
                {state.user.userType === 'STUDENT' && (
                  <NavLink
                    className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}
                    to="/student/learn"
                  >
                    Learning path
                  </NavLink>
                )}
                {state.user.userType === 'SECURITY_PROFESSIONAL' && (
                  <NavLink
                    className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}
                    to="/security-professional/dashboard"
                  >
                    Security Professional dashboard
                  </NavLink>
                )}
                {state.user.userType === 'PENTESTER' && (
                  <NavLink
                    className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}
                    to="/pentester/dashboard"
                  >
                    Pentester dashboard
                  </NavLink>
                )}
                <NavLink
                  className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}
                  to="/projects"
                >
                  {state.user.userType === 'DEVELOPER' || state.user.userType === 'STUDENT' || state.user.userType === 'SECURITY_PROFESSIONAL' || state.user.userType === 'PENTESTER' ? 'My projects' : 'Projects'}
                </NavLink>
                <NavLink
                  className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}
                  to="/account"
                >
                  Account
                </NavLink>
                <NavLink
                  className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}
                  to="/partner/dashboard"
                >
                  Partner dashboard
                </NavLink>
                {roleAtLeast(state.user.role, 'ADMIN') && (
                  <>
                    <NavLink
                      className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}
                      to="/admin/operations"
                    >
                      Platform operations
                    </NavLink>
                    <NavLink
                      className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}
                      to="/admin/payments"
                    >
                      Payment review
                    </NavLink>
                    <NavLink
                      className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}
                      to="/admin/partners"
                    >
                      Partners &amp; commissions
                    </NavLink>
                  </>
                )}
              </>
            )}
            {state.status === 'anonymous' && (
              <>
                <NavLink
                  className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}
                  to="/login"
                >
                  Sign in
                </NavLink>
                <NavLink
                  className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}
                  to="/register"
                >
                  Sign up
                </NavLink>
              </>
            )}
            {/* `loading`/`error`: show neither set — a wrong guess would
                flash misleading links before the session probe settles. */}
          </nav>
        </div>
      </header>
      <main id="main" className="container main" ref={mainRef} tabIndex={-1}>
        <Outlet />
      </main>
      {/* Polite live region: announces the destination without stealing focus.
          Deliberately NOT role="status" — loading spinners already use that
          role, and two live regions racing would double-announce. */}
      <p className="visually-hidden" aria-live="polite" aria-atomic="true" data-testid="route-announcer">
        {announcement}
      </p>
      <footer className="site-footer">
        <div className="container footer-premium">
          <div className="footer-inner" style={{ paddingBottom: 0 }}>
            <span>
              {appName} · v{appVersion} · Built for security teams — evidence over promises
            </span>
            <span style={{ color: 'var(--muted)', fontSize: '0.85rem' }}>
              <span className="status-dot" /> All systems operational
            </span>
          </div>
          <div className="footer-links">
            <Link to="/pricing">Pricing</Link>
            <Link to="/status">Status</Link>
            <a href="https://github.com/mdraselislam0101-design/Drobon" target="_blank" rel="noreferrer">GitHub</a>
            <span style={{ color: 'var(--muted)' }}>SAST · SCA · Secrets · Passive DAST</span>
            <span style={{ color: 'var(--muted)' }}>© {new Date().getFullYear()} Drobon Aegis</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
