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
    title: 'Worker',
    body: 'Job contracts, timeouts, cancellation and retry over an in-memory queue.',
  },
  {
    title: 'Shared contracts',
    body: 'One vocabulary for responses, errors, jobs and config across all three.',
  },
  {
    title: 'Security',
    body: 'CORS allowlist, rate limiting, secret hygiene and tested safe defaults.',
  },
  {
    title: 'Testing',
    body: 'Unit, integration and security tests with a one-command verifier.',
  },
] as const;

export function HomePage(): React.JSX.Element {
  return (
    <>
      <section className="hero" aria-labelledby="hero-title">
        <p className="eyebrow">Cybersecurity platform</p>
        <h1 id="hero-title">Drobon Aegis AI</h1>
        <p className="lede">
          The Pump 1 foundation is live: a secure, tested base for the Web app, API and
          background worker. Product capabilities — scanning, findings, reports, AI
          assistance — arrive in later Pumps.
        </p>
        <div className="hero-actions">
          <Link className="button" to="/status">
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
