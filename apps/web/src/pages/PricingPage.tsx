import { Link } from 'react-router-dom';

export function PricingPage(): React.JSX.Element {
  return (
    <section className="panel" aria-labelledby="pricing-title">
      <p className="eyebrow">Pricing — Evidence over promises</p>
      <h1 id="pricing-title">Simple, audit-friendly pricing</h1>
      <p className="lede">
        Start free with real engines. Upgrade to PRO when you need unlimited scans — no hidden limits, no fake “clean” verdicts, server-enforced quota & entitlements.
      </p>

      <div className="pricing-grid">
        <article className="pricing-card">
          <h2>FREE</h2>
          <div className="pricing-price">BDT 0 <small>/ month</small></div>
          <p className="muted">For individual developers & students</p>
          <ul className="pricing-features">
            <li>3 scans / UTC month — any engine (SAST, SCA, Secrets, DAST)</li>
            <li>Unlimited projects, findings, remediation workflow</li>
            <li>Fingerprinted findings with CWE & guidance</li>
            <li>Persisted JSON / Markdown / SARIF / SBOM reports</li>
            <li>AI Security Assistant (deterministic, read-only)</li>
            <li>Account-owned overview & scan history</li>
            <li className="muted">Community support</li>
          </ul>
          <Link to="/register" className="button button-secondary">Create free account</Link>
          <p className="muted" style={{ fontSize: '0.82rem' }}>FREE quota resets on the 1st of each UTC month. Shared-device allowance enforced.</p>
        </article>

        <article className="pricing-card featured">
          <div className="pricing-card-badge">Recommended for teams</div>
          <h2>PRO</h2>
          <div className="pricing-price">BDT 1,000 <small>/ month · BDT 10.00 minor units 100000</small></div>
          <p className="muted">For security professionals & pentesters</p>
          <ul className="pricing-features">
            <li>Unlimited scans — quota exempt (server-enforced)</li>
            <li>All FREE features included</li>
            <li>Structured assessments (objectives, scope, lifecycle, history)</li>
            <li>Assessment-linked scans & engagement summaries</li>
            <li>Regression compare & verification workflow</li>
            <li>Manual payment verification — no gateway lock-in</li>
            <li>Partner coupons & complimentary grants (entitlement)</li>
            <li>Priority operations visibility (admin-gated)</li>
          </ul>
          <Link to="/register" className="button">Get PRO — Manual verification</Link>
          <p className="muted" style={{ fontSize: '0.82rem' }}>Price set server-side. Submitting a reference is not verification — admin reviews manually.</p>
        </article>
      </div>

      <h2>Feature comparison — Drobon vs point tools</h2>
      <div style={{ overflowX: 'auto' }}>
        <table className="comparison-table">
          <thead>
            <tr>
              <th>Capability</th>
              <th>FREE</th>
              <th>PRO</th>
            </tr>
          </thead>
          <tbody>
            <tr><td>SAST (6 rule families, bounded, no execution)</td><td>✓</td><td>✓ Unlimited</td></tr>
            <tr><td>SCA inventory + CycloneDX SBOM</td><td>✓</td><td>✓ Unlimited</td></tr>
            <tr><td>Secrets (6 rules, redacted)</td><td>✓</td><td>✓ Unlimited</td></tr>
            <tr><td>Passive DAST (bounded GET, SSRF-safe)</td><td>✓ (1 target / project)</td><td>✓ (1 target / project)</td></tr>
            <tr><td>Finding fingerprint & lifecycle (OPEN→RESOLVED etc)</td><td>✓</td><td>✓</td></tr>
            <tr><td>Reports (JSON/Markdown/SARIF/SBOM, SHA-256)</td><td>✓</td><td>✓</td></tr>
            <tr><td>AI Assistant (deterministic, no provider)</td><td>✓</td><td>✓</td></tr>
            <tr><td>Assessments & engagement summaries</td><td>✓</td><td>✓</td></tr>
            <tr><td>Monthly quota</td><td>3 / UTC month</td><td>Exempt</td></tr>
            <tr><td>Platform operations (admin-gated)</td><td>—</td><td>Read-only + review</td></tr>
          </tbody>
        </table>
      </div>

      <div className="card" style={{ marginTop: '1.5rem' }}>
        <h3>Why Drobon’s pricing is honest</h3>
        <ul style={{ margin: 0, paddingLeft: '1.25rem', color: 'var(--muted)' }}>
          <li><strong style={{ color: 'var(--text)' }}>No “0 vulnerabilities” lie:</strong> Without a loaded dataset, SCA says NOT_ASSESSED — never “clean”.</li>
          <li><strong style={{ color: 'var(--text)' }}>No execution:</strong> Source files are never run — safety over “reachability” theatre.</li>
          <li><strong style={{ color: 'var(--text)' }}>No intrusive DAST by default:</strong> Bounded passive GET only — safe for learning & reporting.</li>
          <li><strong style={{ color: 'var(--text)' }}>Server-authoritative:</strong> Plan, entitlement & quota come from the API — not localStorage.</li>
        </ul>
      </div>

      <div className="hero-actions" style={{ marginTop: '1.5rem', justifyContent: 'center' }}>
        <Link to="/register" className="button">Start free — Create account</Link>
        <Link to="/status" className="button button-ghost">Check service status</Link>
      </div>
    </section>
  );
}
