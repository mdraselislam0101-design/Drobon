import { Link } from 'react-router-dom';

const FOUNDATION = [
  {
    title: 'Projects & source',
    body: 'Create account-owned projects and submit bounded source snapshots for analysis.',
  },
  {
    title: 'SAST & dependency inventory',
    body: 'Reuse the shared scan lifecycle, static analysis and SCA/SBOM inventory. Unavailable vulnerability intelligence remains NOT_ASSESSED.',
  },
  {
    title: 'Secrets & passive DAST',
    body: 'Redacted secret findings and tightly bounded passive HTTP checks with server-side target policy.',
  },
  {
    title: 'Finding workflows & reports',
    body: 'Review evidence, record remediation, track verification, and export persisted JSON or Markdown reports.',
  },
  {
    title: 'Project assistant',
    body: 'Ask bounded, project-scoped questions. No provider means unsupported generation stays unavailable.',
  },
  {
    title: 'Account security',
    body: 'Authentication, ownership, plan entitlements, FREE quota and rate limits remain server-enforced.',
  },
] as const;

export function HomePage(): React.JSX.Element {
  return (
    <>
      <section className="hero" aria-labelledby="hero-title">
        <p className="eyebrow">Cybersecurity platform</p>
        <h1 id="hero-title">Drobon Aegis AI</h1>
        <p className="lede">
          A project-centered security workflow for developers: submit source, run the existing security engines, review findings and reports, and track remediation. Register as a Developer to open your account-scoped security overview. Classification changes navigation only—not access, plan, quota or ownership.
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
