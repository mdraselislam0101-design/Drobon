# Developer workflow (Pump 17)

Pump 17 completes the existing Developer-facing workflow by adding a
registration classification selector, Developer-first routing/navigation,
and a bounded account-scoped security overview. It reuses the shared
project, scan, finding, lifecycle, report, entitlement, quota and assistant
systems from Pumps 1–16; it does not add a parallel scanner or authorization
model.

## Capability gap matrix (source review)

| Developer workflow capability | Baseline found in Pumps 1–16 | Pump 17 result |
| --- | --- | --- |
| Registration / classification | API accepted an optional validated `UserType`; Web registration omitted the selector. | Added optional selector; role and plan remain server-assigned. |
| Login / Developer routing | Session and protected-route flow existed; no Developer dashboard route. | Added Developer-first login/register landing and UX-only dashboard route. |
| Project dashboard / security history | Account-owned project CRUD and per-project scan history existed; no bounded cross-project summary. | Added a fixed-cap self-only overview for projects, scans, findings/workflows, and persisted reports. |
| Project/source/scanning workflow | Existing owner-scoped project, source, quota, idempotency, lifecycle and shared engine APIs. | Reused; added only simple project-workflow anchor navigation. |
| SAST / SCA / SBOM / Secrets / DAST | Existing SAST, dependency inventory/SBOM, redacted Secrets, and bounded passive DAST implementations. SCA intelligence has no loaded dataset. | Reused unchanged. SCA remains `NOT_ASSESSED` / `NO_DATA_LOADED`; no catalog or feed added. |
| Finding evidence / remediation / reverification | Existing authorized detail, immutable scanner evidence, redacted notes, lifecycle history and rescan-based verification. | Reused unchanged; dashboard exposes summary metadata only and makes no remediation claims. |
| JSON/Markdown reports | Existing persisted, integrity-checked single-scan reports and exports. | Reused; dashboard indicates persisted availability without copying report bodies. |
| Project-scoped assistant | Existing bounded deterministic, read-only evidence path; provider unavailable. | Reused; no provider, fabricated answer, or duplicate assistant added. |
| Developer navigation / unrelated controls | Header showed platform operations to every signed-in account; Admin routes had no Web role guard. | Developer navigation added; Admin pages use a role UX guard and existing APIs still enforce operator authority. No Pentest-specific control was added. |
| Account enabled/disabled state | No account-state model in current architecture. | Intentionally not invented or displayed. |

## Registration and authority

The registration form optionally records one validated `UserType`:
`DEVELOPER`, `STUDENT`, `SECURITY_PROFESSIONAL`, or `PENTESTER`. It is a
profile classification, not an access request. Self-registration continues
to create `MEMBER` + `FREE` + `ACTIVE` on the server. A client cannot select
its role, plan, subscription, entitlement, quota, owner, or account state.
The session/account record is authoritative on every API request.

- Authentication remains required.
- Role/permission checks and project ownership remain server-enforced.
- Plan and entitlement remain server-derived; UserType cannot grant PRO.
- FREE remains three scans per UTC month per account with the existing
  device anti-abuse allowance. PRO exemption is granted only by the existing
  server subscription/entitlement logic.
- No account enabled/disabled state exists in this architecture. No such
  state is inferred or presented by the Developer dashboard.
- The dashboard API does not require a Developer classification; it exposes
  only the current authenticated account's own summary. The Web route and
  navigation use the server-reported classification for UX only.

See `AUTHORIZATION.md`, `SUBSCRIPTIONS.md`, and `USAGE.md` for the governing
security and commercial boundaries.

## Workflow

1. Register, optionally selecting **Developer**, then sign in. A Developer
   account is routed to `/dashboard`; other account types retain their
   existing account flow.
2. Use **My projects** to create or open an owned project.
3. In project workflow navigation, edit project metadata/lifecycle, set an
   explicit DAST target if needed, submit a source snapshot, and request a
   scan through the existing API.
4. Review scan status and results in the project. SAST findings, SCA
   inventory/SBOM, redacted Secrets findings, and bounded passive DAST
   observations are produced by the existing engines. Scanning and report
   creation continue to use the existing quota/idempotency/ownership path.
5. Review finding details and rule guidance, record lifecycle changes or
   redacted remediation notes, and run a new scan for evidence-based
   reverification. A user-entered `RESOLVED` state is workflow metadata,
   not proof that code was fixed. “Not observed” is not a remediation claim.
6. Create/retrieve the persisted report for a completed scan and download
   JSON or escaped Markdown from the project. Digests identify report
   content; they are not signatures.
7. Ask the project-scoped assistant only about saved evidence. Current
   provider state is `NONE`; unsupported generation remains unavailable and
   no model output is fabricated.

The dashboard is an overview and history surface. It offers direct links
back to project-owned details rather than duplicating each feature or
serializing every finding/report into the browser.

## Bounded security overview

`GET /api/v1/me/security-overview` requires the normal authenticated
session. It derives owner scope exclusively from that session and accepts no
account, project, plan, role, user-type, or pagination selector. The response
contains compact project, scan, finding-workflow, and persisted-report
projections with fixed output caps: at most 6 projects, 8 scans, 8 finding
identities, and 5 reports. Counts are computed from server-side stores;
missing result summaries remain unavailable rather than becoming zero.

- Findings in the overview are unique identities using the latest persisted
  observation per project. Workflow and verification states are copied from
  the existing lifecycle store; evidence, fingerprints and source content
  are not included.
- Report availability means a persisted report is present for the owned
  completed scan; it is not a claim that every scan has a report.
- Scan and finding activity is not a global security verdict. A zero in a
  workflow count does not mean all scanner coverage is complete or that the
  project is secure.
- Plan/entitlement and current quota are fetched from the existing
  `/api/v1/subscription` and `/api/v1/usage` endpoints. The UI only renders
  the server's values; it does not implement its own entitlement/quota
  decision.

## Engine, dataset, AI and persistence limits

- SCA dependency inventory and the supported SBOM subset come from the
  actual uploaded manifests. No vulnerability catalog/feed is loaded.
  Without provider data the scan/report remains `NOT_ASSESSED` and
  `NO_DATA_LOADED`; an empty advisory set is not a zero-vulnerability
  result.
- Secrets evidence is redacted before persistence/serialization. There is
  no credential verification, rotation, network check, or attempt to use
  detected material.
- DAST is an explicitly configured, bounded passive GET-only check with
  server-side target/DNS/redirect policy. It is not a browser crawler,
  authenticated scan, fuzzing or exploit test.
- Assistant context is project-owned persisted evidence, bounded and
  redacted; user-controlled project/source/evidence text is untrusted data,
  never instructions. No provider is active, no assistant history is
  persisted, and no tool execution or source mutation is implemented.
- Current persistence is the repository's durable JSON store. There is no
  PostgreSQL or production database in this pump. External AEGIS intelligence
  remains separate; no CVE/NVD/GHSA/OSV/KEV/EPSS catalog, feed, or bundled
  dataset is introduced.

## Verification map

- Registration, login routing, UserType/plan mass-assignment and FREE/PRO
  behavior: `apps/api/test/reportsApi.test.ts`,
  `apps/web/test/authPages.test.tsx`, `apps/web/test/authClient.test.ts`.
- Self-scoped overview, account-type neutrality, IDOR/query rejection and
  bounded response/secret redaction: `apps/api/test/workspaceApi.test.ts`,
  `apps/api/test/reportsApi.test.ts`,
  `apps/web/test/workspaceDashboardUi.test.tsx`.
- Existing engine, quota, scan, finding lifecycle, report/restart, assistant
  and redaction coverage remains in `docs/TESTING.md` and
  `docs/BUILD_VERIFICATION.md`.
- These are controlled synthetic/local fixtures, not fabricated production
  state, public-target testing, external intelligence validation, or a
  browser-based full E2E test.
