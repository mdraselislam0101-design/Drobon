import { Link } from 'react-router-dom';

const FOUNDATION = [
  {
    title: 'Web',
    body: 'Application shell, routing, typed API boundary, loading and error states.',
  },
  {
    title: 'API',
    body: 'Validated requests, consistent envelopes, correlation IDs, security headers.',
  },
  {
    title: 'Authentication',
    body: 'Registration, login, logout, httpOnly sessions and protected routes — end to end.',
  },
  {
    title: 'Worker',
    body: 'Job contracts, timeouts, cancellation and retry over an in-memory queue.',
  },
  {
    title: 'Shared contracts',
    body: 'One vocabulary for responses, errors, jobs, auth and config across all three.',
  },
  {
    title: 'Security',
    body: 'CORS allowlist, rate limiting, CSRF origin guard, secret hygiene, tested defaults.',
  },
] as const;

export function HomePage(): React.JSX.Element {
  return (
    <>
      <section className="hero" aria-labelledby="hero-title">
        <p className="eyebrow">Cybersecurity platform</p>
        <h1 id="hero-title">Drobon Aegis AI</h1>
        <p className="lede">
          Pump 2 is live: the Pump 1 foundation now has real user accounts —
          registration, login, sessions and protected pages wired end to end.
          Product capabilities — scanning, findings, reports, AI assistance —
          arrive in later Pumps.
        </p>
        <div className="hero-actions">
          <Link className="button" to="/register">
            Create an account
          </Link>
          <Link className="button button-secondary" to="/status">
            Check service status
          </Link>
        </div>
      </section>
      <section className="grid" aria-label="Foundation areas">
        {FOUNDATION.map((area) => (
          <article className="card" key={area.title}>
            <h2>{area.title}</h2>
            <p>{area.body}</p>
            <p className="pill">Ready</p>
          </article>
        ))}
      </section>
    </>
  );
}
