import { Link, NavLink, Outlet } from 'react-router-dom';
import { roleAtLeast } from '@drobon/shared';
import { useAuth } from '../auth/context.js';

export function Layout({
  appName,
  appVersion,
}: {
  appName: string;
  appVersion: string;
}): React.JSX.Element {
  const { state } = useAuth();
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
      <main id="main" className="container main">
        <Outlet />
      </main>
      <footer className="site-footer">
        <div className="container footer-inner">
          <span>
            {appName} · v{appVersion}
          </span>
        </div>
      </footer>
    </div>
  );
}
