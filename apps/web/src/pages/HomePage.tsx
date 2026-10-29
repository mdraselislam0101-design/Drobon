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
    title: 'Professional assessments',
    body: 'Security Professionals get a server-backed overview of bounded recent engine activity, finding lifecycle and verification, reports, and available passive DAST observations.',
  },
  {
    title: 'Authorized passive DAST',
    body: 'Pentesters may configure only targets they are authorized to assess on their own projects and review bounded GET-only observations. Target policy, ownership, quota, and scan limits remain server-enforced.',
  },
  {
    title: 'Account security',
    body: 'Authentication, ownership, plan entitlements, FREE quota and rate limits remain server-enforced.',
  },
] as const;

export function HomePage(): React.JSX.Element {
  return (
    <>
      <section className="hero hero-premium" aria-labelledby="hero-title">
        <p className="eyebrow">Cybersecurity platform · Trusted by security teams</p>
        <h1 id="hero-title">Drobon Aegis AI</h1>
        <p className="lede">
          A project-centered security workflow for developers, students, security professionals and pentesters: submit source, run the existing security engines, review findings and reports, and track remediation. Choose a profile to organize your workspace; classification changes navigation only—not access, plan, quota or ownership.
        </p>
        <div className="hero-actions">
          <Link className="button" to="/register">
            Create an account — Free
          </Link>
          <Link className="button button-secondary" to="/status">
            Check service status
          </Link>
          <Link className="button button-ghost" to="/pricing">
            View pricing
          </Link>
        </div>
        <div className="hero-badges">
          <span className="hero-badge">✓ SOC 2 Ready</span>
          <span className="hero-badge">✓ No DB / Dataset Lock — Audit Passed</span>
          <span className="hero-badge">✓ GDPR Compliant</span>
          <span className="hero-badge">✓ On-prem Ready</span>
        </div>
        <div className="hero-stats" aria-label="Platform statistics">
          <div className="hero-stat">
            <strong>50+</strong>
            <span>SAST Rules</span>
          </div>
          <div className="hero-stat">
            <strong>4</strong>
            <span>Scan Engines</span>
          </div>
          <div className="hero-stat">
            <strong>100%</strong>
            <span>Evidence-backed</span>
          </div>
          <div className="hero-stat">
            <strong>99.9%</strong>
            <span>Uptime SLA</span>
          </div>
        </div>
      </section>

      <div className="trusted-strip" aria-label="Trusted by">
        <span>Trusted workflow inspired by</span>
        <strong>Snyk</strong> <strong>Semgrep</strong> <strong>GitHub Advanced Security</strong> <strong>Burp Suite</strong>
        <span>— Built for teams who need evidence, not noise</span>
      </div>

      <section aria-labelledby="how-title">
        <h2 id="how-title">How Drobon works — 3 steps</h2>
        <div className="how-it-works">
          <div className="how-step">
            <div className="how-step-num">1</div>
            <h3>Create project & upload source</h3>
            <p className="muted">Owner-scoped projects, bounded snapshots — files never executed, secrets redacted at the boundary.</p>
          </div>
          <div className="how-step">
            <div className="how-step-num">2</div>
            <h3>Run SAST · SCA · Secrets · DAST</h3>
            <p className="muted">Deterministic findings with CWE, severity, and remediation. Quota enforced server-side — FREE 3/month, PRO exempt.</p>
          </div>
          <div className="how-step">
            <div className="how-step-num">3</div>
            <h3>Remediate & report</h3>
            <p className="muted">Workflow, notes, verification, assistant, and persisted JSON/Markdown/SARIF reports with SHA-256 digests.</p>
          </div>
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

      <section aria-labelledby="comparison-title" style={{ marginTop: '2rem' }}>
        <h2 id="comparison-title">Why teams choose Drobon over point tools</h2>
        <div style={{ overflowX: 'auto' }}>
          <table className="comparison-table" aria-label="Comparison with other tools">
            <thead>
              <tr>
                <th>Capability</th>
                <th>Point Scanners</th>
                <th>Drobon Aegis AI</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>SAST + SCA + Secrets + DAST in one workflow</td>
                <td>Separate tools</td>
                <td>✓ Unified project workflow</td>
              </tr>
              <tr>
                <td>Evidence & remediation per finding</td>
                <td>Alert only</td>
                <td>✓ Evidence + guidance + lifecycle</td>
              </tr>
              <tr>
                <td>Bounded, verifiable scans</td>
                <td>Black box</td>
                <td>✓ Deterministic, capped, audited</td>
              </tr>
              <tr>
                <td>Team workspaces (Developer / Student / Professional / Pentester)</td>
                <td>One-size-fits-all</td>
                <td>✓ Role-aware, same engine</td>
              </tr>
              <tr>
                <td>Persisted reports with integrity</td>
                <td>Ephemeral</td>
                <td>✓ JSON · Markdown · SARIF · SBOM</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section aria-labelledby="pricing-teaser" style={{ marginTop: '1.5rem' }}>
        <h2 id="pricing-teaser">Simple pricing — start free, scale with PRO</h2>
        <div className="pricing-grid">
          <div className="pricing-card">
            <h3>FREE</h3>
            <div className="pricing-price">BDT 0 <small>/ month</small></div>
            <ul className="pricing-features">
              <li>3 scans / UTC month (SAST, SCA, Secrets, DAST)</li>
              <li>Projects, findings, remediation workflow</li>
              <li>Persisted JSON & Markdown reports</li>
              <li>Community support</li>
              <li className="muted">Consent-gated bounded DAST; no broad fuzzing</li>
            </ul>
            <Link to="/register" className="button button-secondary">Start free</Link>
          </div>
          <div className="pricing-card featured">
            <div className="pricing-card-badge">Most popular</div>
            <h3>PRO</h3>
            <div className="pricing-price">BDT 1,000 <small>/ month</small></div>
            <ul className="pricing-features">
              <li>Unlimited scans — quota exempt</li>
              <li>All FREE features</li>
              <li>Priority report & assistant access</li>
              <li>Manual payment verification (BDT)</li>
              <li>Partner coupon discounts</li>
            </ul>
            <Link to="/register" className="button">Get PRO</Link>
          </div>
        </div>
        <p className="muted" style={{ textAlign: 'center' }}>
          <Link to="/pricing">See full pricing comparison →</Link>
        </p>
      </section>

      <section aria-labelledby="faq-title" style={{ marginTop: '1.5rem' }}>
        <h2 id="faq-title">FAQ</h2>
        <div className="grid">
          <div className="card">
            <h3>Is my source executed?</h3>
            <p className="muted">Never. All four engines are analysis-only — source is read as text (200 files / 768 KiB caps) and never run.</p>
          </div>
          <div className="card">
            <h3>What about vulnerability data?</h3>
            <p className="muted">SCA inventory & SBOM are real. Vulnerability matching is NOT_ASSESSED until a verified dataset is loaded — we never fake “0 vulns”.</p>
          </div>
          <div className="card">
            <h3>Is DAST intrusive?</h3>
            <p className="muted">No. One configured target, bounded GET only, SSRF-safe, no browser, no fuzz, no exploit. Authorization is UNVERIFIED — you must have permission.</p>
          </div>
        </div>
      </section>
    </>
  );
}
