import { describe, expect, test } from 'vitest';
import { evaluateDastObservation } from '../src/scans/dast/rules.js';

const HTTPS_URL = 'https://app.example.org/';

function observation(overrides: Partial<Parameters<typeof evaluateDastObservation>[0]> = {}) {
  return {
    url: HTTPS_URL,
    status: 200,
    headers: {},
    body: '',
    ...overrides,
  };
}

describe('passive DAST response rules', () => {
  test('a response with the checked controls produces no findings', () => {
    const findings = evaluateDastObservation(observation({
      headers: {
        'strict-transport-security': 'max-age=31536000; includeSubDomains',
        'x-content-type-options': 'nosniff',
        'x-frame-options': 'DENY',
        'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
      },
      contentType: 'text/html',
      body: '<html><body>ok</body></html>',
    }));
    expect(findings).toEqual([]);
  });

  test('uses actual header/body observations and emits only stable passive rule identifiers', () => {
    const findings = evaluateDastObservation(observation({
      headers: {
        'access-control-allow-origin': 'https://drobon-aegis.invalid',
        'access-control-allow-credentials': 'true',
        'server': 'private-server-version-9.1',
        'x-powered-by': 'private-framework-version',
        'set-cookie': ['session=COOKIE_VALUE_MUST_NOT_LEAK; Path=/'],
      },
      contentType: 'text/html',
      body: '<script src="http://app.example.org/app.js"></script>',
    }));
    expect(findings.map((finding) => finding.ruleId)).toEqual([
      'DG-DAST-002', 'DG-DAST-003', 'DG-DAST-004', 'DG-DAST-005', 'DG-DAST-006', 'DG-DAST-007', 'DG-DAST-008',
    ]);
    const serialized = JSON.stringify(findings);
    expect(serialized).not.toContain('COOKIE_VALUE_MUST_NOT_LEAK');
    expect(serialized).not.toContain('private-server-version-9.1');
    expect(serialized).not.toContain('private-framework-version');
    expect(findings.every((finding) => finding.severity.length > 0)).toBe(true);
    expect(findings.find((finding) => finding.ruleId === 'DG-DAST-006')?.cwe).toBeUndefined();
  });

  test('does not treat malformed, zero, or duplicate HSTS max-age directives as effective', () => {
    for (const value of ['max-age=0', 'max-age=not-a-number', 'max-age=1; max-age=2']) {
      const findings = evaluateDastObservation(observation({ headers: { 'strict-transport-security': value } }));
      expect(findings.map((finding) => finding.ruleId), value).toContain('DG-DAST-002');
    }
  });

  test('reports cleartext HTTP from the observed URL, but does not label HTTP markup as mixed content', () => {
    const findings = evaluateDastObservation(observation({
      url: 'http://app.example.org/',
      contentType: 'text/html',
      body: '<script src="http://other.example.org/a.js"></script>',
    }));
    expect(findings.map((finding) => finding.ruleId)).toContain('DG-DAST-001');
    expect(findings.map((finding) => finding.ruleId)).not.toContain('DG-DAST-008');
  });

  test('static mixed-content inspection is restricted to HTML/XHTML and never executes markup', () => {
    const html = evaluateDastObservation(observation({
      contentType: 'text/html',
      body: '<img src="http://cdn.example.org/image.png">',
    }));
    const xhtml = evaluateDastObservation(observation({
      contentType: 'application/xhtml+xml',
      body: '<link href="http://cdn.example.org/style.css">',
    }));
    const json = evaluateDastObservation(observation({
      contentType: 'application/json',
      body: '{"html":"<script src=\\"http://cdn.example.org/a.js\\"></script>"}',
    }));
    expect(html.map((finding) => finding.ruleId)).toContain('DG-DAST-008');
    expect(xhtml.map((finding) => finding.ruleId)).toContain('DG-DAST-008');
    expect(json.map((finding) => finding.ruleId)).not.toContain('DG-DAST-008');
  });

  test('safe CORS values do not produce the broad/reflected credential finding', () => {
    const findings = evaluateDastObservation(observation({
      headers: {
        'access-control-allow-origin': 'https://trusted.example.org',
        'access-control-allow-credentials': 'true',
      },
    }));
    expect(findings.map((finding) => finding.ruleId)).not.toContain('DG-DAST-005');
  });

  test('cookie attribute evidence retains neither cookie names nor values', () => {
    const findings = evaluateDastObservation(observation({
      headers: { 'set-cookie': 'sensitive_session_name=sensitive_cookie_value; Path=/' },
    }));
    const cookieFinding = findings.find((finding) => finding.ruleId === 'DG-DAST-007');
    expect(cookieFinding).toBeDefined();
    expect(JSON.stringify(cookieFinding)).not.toContain('sensitive_session_name');
    expect(JSON.stringify(cookieFinding)).not.toContain('sensitive_cookie_value');
    expect(cookieFinding?.evidence).toContain('HttpOnly');
    expect(cookieFinding?.evidence).toContain('SameSite');
    expect(cookieFinding?.evidence).toContain('Secure');
  });
});
