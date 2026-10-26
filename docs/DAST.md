# Passive DAST foundation (Pump 11)

Drobon includes a **limited, deterministic, passive HTTP DAST engine** for one explicitly configured project URL. It complements the source-only SAST, SCA/SBOM, and Secrets engines; it is not a browser scanner or a general-purpose crawler.

## Capability boundary

The engine issues a bounded `GET` to the configured URL and may follow at most two redirects on the same hostname. The total request limit is three, with a 5-second per-request timeout, a 15-second scan deadline, and at most 32 KiB of response body inspection per request. It does not use cookies, credentials, a browser, a JavaScript runtime, or shell commands. It does not crawl links, execute page content, submit forms, authenticate, fuzz, inject payloads, or exploit anything.

Current passive checks report only observed properties:

- HTTP instead of HTTPS and selected missing/insecure response security headers;
- frame-embedding restrictions and content-type sniffing policy;
- broad/reflected credentialed CORS responses observed using a fixed synthetic `Origin`;
- incomplete cookie attributes, without retaining cookie names or values;
- implementation-identifying headers, reporting presence only;
- static HTTP subresource references found in a bounded HTML response (no parsing or execution).

Findings use the shared Finding contract, stable rule IDs/fingerprints, conservative severities, bounded evidence and rule-specific remediation. CWE is included only where a mapping is defensible; no CVSS/exploitability score is generated. Response bodies and arbitrary header values are not persisted. A result contains bounded request/response metadata and allowlisted header summaries. Cookie values, credentials, raw `Set-Cookie` values, and arbitrary response text are not included in findings or scan payloads.

Results are observed facts, not proof of exploitability. Response-based checks can be affected by the target's routing, edge/CDN behavior, or dynamic responses. A `PARTIAL` result explicitly reports a body, redirect, or request limit. A clean result means only that these limited checks did not observe a configured condition in the inspected responses.

## Project target authorization and SSRF defense

Targets are stored on the caller-owned project—not accepted as scan request fields. The authenticated project owner may set or remove one URL:

- `PUT /api/v1/projects/:projectId/dast-target` with exactly `{ "targetUrl": "https://…/" }`
- `DELETE /api/v1/projects/:projectId/dast-target`

The write routes reuse existing authentication, project ownership, validation, and public project response contracts. They do not accept owner, plan, role, UserType, project-ID, or scan-state claims. A rejected target is rejected before scan quota is consumed. Scan creation remains the existing atomic scan/quota path; FREE remains three scans per month under the existing account/device controls, and PRO exemption remains server-authoritative.

The server enforces URL and address policy when configuring a target and again immediately before each request. Only HTTP(S), canonical URLs without credentials, query strings, fragments, or custom ports are accepted. Loopback, private, link-local, carrier-grade NAT, documentation, multicast, reserved, unspecified, IPv4-mapped private, local/internal, and metadata destinations are blocked. All DNS answers must be public; the resolver is bounded and mixed public/private answers fail closed. IP literals are evaluated as literals and cannot be replaced by resolver output. The HTTP socket uses a vetted address directly (DNS pinning), while preserving the hostname for HTTP Host and TLS verification. Redirects are resolved and validated independently, must retain the original hostname, and cannot downgrade HTTPS to HTTP. DNS is rechecked before every request to reduce rebinding risk.

**Pump 17 addendum:** an owner may now attach a bounded, append-only
**engagement record** to an assessment (exact hosts, allowed scan types,
validity window, path scope and a written statement). Once at least one
engagement exists it gates every linked scan *before quota consumption*.
This is an auditable workspace record, NOT independent legal verification —
see [`ENGAGEMENTS.md`](ENGAGEMENTS.md).

The project UI explicitly displays target authorization as `UNVERIFIED`. Drobon verifies project ownership and network destination safety, not engagement letters or third-party legal permission. The owner must configure only targets they are permitted to assess; saving a URL does not change that state or create an authorization claim.

Pump 22 assessments can record bounded engagement metadata and a user-authored target declaration, but do not change this authorization boundary. A DAST scan associated with an assessment must have the exact configured target hostname explicitly listed in that assessment's in-scope hostnames (and not excluded); subdomains are not inherited. The assessment does not grant project/target/DAST access and does not relax any network policy. The owner may append a timestamped `USER_DECLARED` statement for the exact currently configured target URL, or withdraw it; Drobon has no independent mechanism to verify third-party permission. Without a current exact-URL statement the UI remains `UNVERIFIED`, and even `USER_DECLARED` is not verified authorization. A linked DAST scan is not gated on that statement, matching the existing project DAST behavior; ordinary authenticated ownership, quota, target and passive-scan controls still apply. See `SECURITY_PROFESSIONAL.md` for the assessment lifecycle, store bounds and API workflow.

No URL-based system can guarantee network isolation against every routing, proxy, DNS, or future address-registry edge case. Deployments should also apply network egress controls appropriate to their environment. The DAST engine itself never uses ambient proxy variables or follows redirects automatically.

## Findings and lifecycle integration

DAST runs through the existing authenticated project scans route, scan engine registry, processor, store, quota and idempotency behavior. A DAST scan request supplies only `scanType: "DAST"`; the processor takes the target from the server-owned project record. The scan detail route returns the DAST result and its actual findings using shared guards. Project, scan, target configuration, observations, summaries, and findings survive durable store restart validation. Target changes affect future scans only; an existing scan retains its captured canonical target and result.

The project UI makes target configuration explicit, disables the DAST option until the server confirms a target, and displays the server's observed request summary, observations, partial status, and bounded findings as text. It does not imply broader coverage.

The Pentester workspace (Pump 20) is a classification/presentation over this same project route and scan lifecycle, not a DAST privilege or separate engine. Its dashboard target count and per-project configured indicators are derived from the authenticated account's server-side project records; they do not assert that the user has legal permission from a third party. Only a project owner can save that project's target. The scan API ignores no policy based on UserType and never accepts a client authorization flag, target override, owner ID, account/project selector, plan, quota, or entitlement claim. Login/route guards remain UI behavior; existing server authentication, owner checks, account/device quota, entitlements, rate limits, and DAST target policy apply unchanged.

## Not implemented

Browser/DOM analysis, JavaScript execution, authenticated crawling, link discovery, unrestricted spidering, form submission, injection, fuzzing, active exploit checks, port scanning, TLS-certificate grading, vulnerability-database matching, CVSS scoring, scheduling, and out-of-process DAST workers are **NOT_IMPLEMENTED**. Pump 12 reports can include the existing bounded DAST result and findings; they do not add DAST coverage. SCA vulnerability data remains unavailable without a loaded provider dataset; this pump adds no security dataset or import.

## Verification boundary

Unit and API tests use synthetic resolver/transport fixtures and controlled local loopback HTTP fixtures only. The API lifecycle/restart test uses a synthetic transport response; it proves API integration and persistence, not a real public-target scan. Production loopback/private-address rejection is not relaxed for tests. See `docs/TESTING.md` and `apps/api/test/dastHttp.test.ts`.
