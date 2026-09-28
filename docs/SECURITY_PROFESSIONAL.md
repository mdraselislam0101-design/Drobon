# Security Professional workflow (Pump 19)

Pump 19 adds a Security Professional dashboard and login/register destination over the existing authenticated security platform. It is a presentation and workflow entry point, not a new scanner, project store, entitlement system, report service, assistant, or elevated role.

## Capability-gap matrix

| Capability | Existing shared behavior before Pump 19 | Pump 19 outcome |
| --- | --- | --- |
| Registration and login | Optional validated `SECURITY_PROFESSIONAL` classification was already accepted; register/login success fell back to Account. | Registration, login, and an existing Professional session land on `/security-professional/dashboard`. Registration still creates a `MEMBER` + `FREE` account; the classification grants no authority. |
| Professional dashboard and navigation | The account-owned overview and Developer/Student dashboard presentations existed; there was no Professional route or professional-oriented links. | The Professional route reuses the existing overview, subscription, and usage APIs. It presents owned projects, severity/lifecycle/verification counts, report availability, and a recent capped assessment history. Workflow links lead back to shared projects, source, SAST, SCA/SBOM, Secrets, passive DAST, findings, remediation/verification, reports, assistant, and settings. |
| Bounded DAST and SCA dashboard status | Project detail contained full saved results, but the cross-project overview scan card did not identify bounded DAST observations or SCA intelligence state. | Overview scan cards now include DAST observation count for a completed DAST scan and assessment/dataset state for completed SCA, otherwise `null`. The UI labels DAST observations as bounded metadata and SCA `NOT_ASSESSED` / `NO_DATA_LOADED` honestly. Existing project detail remains the source for full scan results. |
| FREE and PRO journey | Shared account/plan/quota enforcement served every UserType; the controlled FREE/PRO API journey was Student-scoped. | The Professional-classified HTTP journey independently verifies FREE registration and a three-scan limit, fourth-scan denial, same-device anti-abuse, a separately seeded server-side PRO Professional entitlement, quota exemption, and server-side rejection of client role/plan/entitlement tampering. |
| Projects and all engines | One owner-scoped project/source/scan lifecycle and shared SAST, SCA/SBOM, Secrets, and passive DAST engines existed. | The Professional journey runs all four engines on controlled synthetic source and injected DAST transport fixtures. No engine, result store, or transport policy is duplicated. |
| Findings, evidence, remediation, retest | Shared scanner findings, evidence redaction, notes/history, lifecycle, and verification were already available in project detail. | The Professional journey exercises finding details and guidance, audited lifecycle transitions, a note, same-scanner re-observation/reopen, and a subsequent clean completed scan that records `NOT_OBSERVED_IN_LATEST_SCAN`. This is not a claim that code was technically repaired. |
| Reports | Existing persisted JSON/Markdown reports and integrity checks operated independently of UserType. | The Professional journey creates SAST/SCA/DAST reports, checks inventory/intelligence status and restores a persisted report after API restart. Reports remain point-in-time snapshots. |
| Professional assistant questions | Deterministic handlers already answered selected-finding, report, latest scan, comparison, dependency/SBOM and related bounded questions. Aggregate assessment, unresolved workflow, verification, attention, and explicit DAST observation questions were not all directly supported. | Added deterministic, evidence-only handling for assessment summaries, unresolved workflow summaries, aggregate verification state, attention items, and bounded DAST observation summaries. Assessment/DAST use latest completed scans per engine; project-wide unresolved/verification/attention summaries reuse the existing store's project-filtered persisted workflow counts. An explicit scan selector narrows the answer to that scan. Partial/missing data and limitations are disclosed. Existing selected-finding explanation/remediation and SCA inventory handlers are reused. |
| Authorization, isolation, account state | Authentication, role, ownership, entitlement, quota, rate limiting, and passive DAST controls were server-authoritative. No enabled/disabled account model exists. | UI route checks remain classification-only. API journey verifies a Professional member cannot access admin operations and cannot cross account/project boundaries for project, DAST target, scan, finding, report, or assistant evidence. No account enabled/disabled state or authority is invented. |

## Overview semantics

The dashboard uses the same authenticated `GET /api/v1/me/security-overview`, subscription, and usage endpoints as the existing account workspaces. Its fixed-cap recent activity is history, not complete coverage. Scan cards contain only persisted summary metadata: findings total, partial-result flag, persisted-report availability, completed DAST observation count, and SCA assessment/dataset state. Detailed evidence and scan results stay in the authorized project workflow.

- Dashboard finding severity, lifecycle and verification summaries describe persisted latest observations per unique finding identity; they are not a global security score or remediation certification.
- DAST observations describe a small bounded passive request set. They do not imply route discovery, browser behavior, full application coverage, or vulnerability absence.
- SCA inventory is separate from vulnerability intelligence. No dataset/provider remains `NOT_ASSESSED` / `NO_DATA_LOADED`; that is never displayed as zero vulnerabilities.
- `SECURITY_PROFESSIONAL` changes navigation and overview presentation only. Role-based admin capability remains governed by the account role; UserType never grants or suppresses authority.

## Assistant scope and safety

The assistant remains deterministic, read-only and project-scoped. With provider state `NONE`, supported questions use saved records only; unsupported/open-ended requests remain unavailable. Assessment and DAST summaries use the latest completed scan per available engine. Project-wide unresolved/verification/attention questions reuse the existing persisted summary query with a server-derived project filter, so a finding absent from the newest scan can still retain its latest verification state. An explicit scan ID narrows these workflow answers to that authorized scan and its bounded finding details.

DAST answers report only persisted observation counts/status summaries and say that these are not vulnerability verdicts. Lifecycle `RESOLVED` remains user-managed; `NOT_OBSERVED_IN_LATEST_SCAN` is not proof of remediation. Missing details, partial/truncated results and incomplete workflow records are disclosed. Project/source/finding/DAST text remains untrusted data; it is not executed as instructions. No LLM output, source edits, arbitrary networking, external credential verification, or new scan action is added.

## FREE/PRO and security boundaries

- FREE remains three scans per UTC month under the existing account/device policy. PRO quota exemption comes only from the server subscription/entitlement authority.
- UserType, role, plan, entitlement, owner and resource IDs supplied by a client are not trusted. The API checks session identity, project ownership and supported request shape.
- The Professional UI uses existing workflows and contracts. It adds no Admin or payment-review controls.
- DAST remains one configured target with the existing SSRF, DNS, redirect, transport and request-bound protections; tests use synthetic local fixtures.
- No PostgreSQL, production database, vulnerability/security data feed, bundled catalog, fabricated evidence/score/finding, or external secret verification is introduced.
- Account enabled/disabled state is not modeled.

## Verification map

- Professional dashboard, bounded DAST/SCA overview metadata, FREE/PRO journey, all four engines, ownership/tampering, reports/restart and deterministic Professional assistant questions: `apps/web/test/workspaceDashboardUi.test.tsx`, `apps/web/test/authPages.test.tsx`, `apps/web/test/routes.test.tsx`, and the Security Professional scenario in `apps/api/test/reportsApi.test.ts`.
- Assistant classifier/service coverage: `apps/api/test/assistantService.test.ts`; HTTP ownership and evidence coverage remains in `apps/api/test/assistantApi.test.ts`.
- Shared Student and Developer journeys and historical scanner/SSRF/redaction/security tests remain required in the full repository verification.
- API integration uses temporary JSON stores and test-injected scanner/DAST fixtures. UI component tests are not browser E2E.
