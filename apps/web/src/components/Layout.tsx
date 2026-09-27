import { Link, NavLink, Outlet } from 'react-router-dom';

export function Layout({
  appName,
  appVersion,
}: {
  appName: string;
  appVersion: string;
}): React.JSX.Element {
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
          <span className="footer-note">Foundation build — Pump 1</span>
        </div>
      </footer>
    </div>
  );
}
