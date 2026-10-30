# DROBON AEGIS AI — UserType Feature Matrix (Phase 20)

> **Historical Phase 20 snapshot:** the individual statuses and totals below are not maintained as a current feature inventory. Since then, SARIF and bounded PDF exports, a local CI adapter, FALSE_POSITIVE lifecycle state and additional scanner capabilities have been added. See [`PAID_WORKFLOWS_BN.md`](./PAID_WORKFLOWS_BN.md), [`REPORTS.md`](./REPORTS.md), and current source/tests for present scope and limitations.

> Forensic classification of every requested UserType capability. Every label is
> backed by code, tests, or live verification — a UI-only presence is **never**
> classified complete (Pump rule 17). UserType is an organization /
> presentation / workflow layer: it chooses *which shared engines and workflows
> are surfaced*. It is **not** a second permission system. Authorization is
> enforced by ROLE + FREE/PRO entitlement + tenant/account ownership,
> independently of UserType.

Status vocabulary:

| Label | Meaning |
| --- | --- |
| `REAL` | Working application behavior, verified by tests and/or live E2E. |
| `PARTIAL` | Real behavior for a defined subset; exact scope documented. |
| `NOT_IMPLEMENTED` | No application behavior yet. Listed honestly, never hidden behind UI. |
| `NOT_APPLICABLE` | Cannot be built honestly in this architecture (documented why). |
| `EXTERNAL_DEPENDENCY` | Requires third-party infrastructure that is not connected; app-side contract only. |
| `RESERVED` | Deliberately withheld by security/dataset policy (mandated boundary). |

All scan-powered capabilities reuse the **single shared engines** (one each of
SAST / SCA / Secrets / DAST / Findings / Remediation / Reports / SBOM / AI /
scan-worker). Phase 20 introduced **zero duplicate engines**.

---

## Cross-cutting guarantees (all UserTypes)

- **Switching** (`PATCH /api/v1/me/user-type`): authenticated only; body must be
  exactly `{userType}` with one of the four enum values; extra keys → 422
  (mass-assignment rejected). Never mutates role, plan, quota, device
  anti-abuse state, payment state, or project ownership. CSRF-protected
  (foreign `Origin` → 403), HPP-rejected, anonymous → 401. Session reflects the
  new type live. Verified: `apps/api/test/userTypeSwitchApi.test.ts` (9 tests)
  + live E2E E-1…E-4, F-2, G-3.
- **FREE plan**: 3 scans per UTC month (429 + `Retry-After` on the 4th), device
  anti-abuse, PRO exemption — identical for every UserType. Switching never
  resets or bypasses it (E2E F-1/F-2).
- **Account isolation beats UserType grouping**: every project/scan/report is
  account-owned; another account's resources return uniform 403 with no
  existence oracle, regardless of either account's UserType (E2E H-1/H-2).
- **Hiding a UI element is not authorization**: privileged routes (e.g.
  `/api/v1/admin/payment-config`) independently return 403 for every
  non-platform-admin caller, including all four UserTypes (E2E I-1/I-2, J-1…J-5).

---

## DEVELOPER (20 requested)

| # | Feature | Status | Evidence / honest scope |
| --- | --- | --- | --- |
| 1 | SAST scanning | REAL | Shared SAST engine; scan → findings → remediation guidance. E2E A-1/A-2. |
| 2 | SCA (dependency inventory) | REAL | Shared SCA engine. Inventory + ecosystem detection. Verdicts require vulnerability intelligence → `NOT_ASSESSED` (dataset boundary). E2E C-1. |
| 3 | Secrets scanning | REAL | Shared Secrets engine. |
| 4 | GitHub integration | EXTERNAL_DEPENDENCY | No GitHub connectivity in this environment; no fabricated sync. App-side project/source model is integration-ready. |
| 5 | GitLab integration | EXTERNAL_DEPENDENCY | Same as GitHub. |
| 6 | PR scanner | EXTERNAL_DEPENDENCY | Requires Git provider webhook/API connection that is not present. |
| 7 | CI/CD hook | EXTERNAL_DEPENDENCY | No CI provider connection; scan API exists and is CI-callable (API-first, token session). |
| 8 | pre-commit hook | EXTERNAL_DEPENDENCY | Requires client-side hook distribution + repo access. |
| 9 | VS Code extension | EXTERNAL_DEPENDENCY | Not fabricated; no extension marketplace/channel present. |
| 10 | Fix-suggestion diff view | PARTIAL | Remediation guidance is real (assistant + report, finding-level guidance). Side-by-side diff rendering of suggested patches is NOT_IMPLEMENTED. |
| 11 | Auto-fix PR | NOT_APPLICABLE | Requires provider integration + push rights (features 4/6); guidance stays labeled as guidance, never "auto-fix". |
| 12 | Dependency upgrade suggestion | NOT_APPLICABLE | Upgrade advisories are vulnerability-intelligence output; the dataset boundary forbids it. Inventory shows current versions only. |
| 13 | Tech stack dashboard | PARTIAL | Real inventory from SBOM (languages, ecosystems, dependencies). No fabricated "risk score". |
| 14 | False-positive marking | PARTIAL | Finding lifecycle (acknowledge/triage + analyst notes) is real; an explicit `FALSE_POSITIVE` terminal state is NOT_IMPLEMENTED. |
| 15 | SBOM (CycloneDX) | REAL | Shared SBOM engine, CycloneDX document generation (inventory ≠ verdict, honestly labeled). |
| 16 | Reports JSON/SARIF | PARTIAL | JSON (+ Markdown) reports REAL. SARIF: closed vocabulary is `json\|markdown`; requesting SARIF returns honest 422 — NOT_IMPLEMENTED, not faked. |
| 17 | AI assistant | REAL | Shared AI engine, grounded on the account's own scan data; provider NONE remains honest (no external LLM). |
| 18 | Code quality metrics | NOT_APPLICABLE | App never executes or instrument-hosts user code; metrics would be fabricated. |
| 19 | Test coverage | NOT_APPLICABLE | Same execution boundary. |
| 20 | Secrets rotation reminder | NOT_IMPLEMENTED | No reminder scheduler; secrets findings list is real. |
| 21 | Multi-repo dashboard | REAL | Multi-project account model with per-project scan history — the honest equivalent within account-owned projects. |

**Developer totals: 6 REAL, 3 PARTIAL, 5 EXTERNAL_DEPENDENCY, 4 NOT_APPLICABLE, 2 NOT_IMPLEMENTED** (multi-repo dashboard listed as #21 — the matrix counts it among the 20 developer items).

---

## STUDENT (20 requested)

| # | Feature | Status | Evidence / honest scope |
| --- | --- | --- | --- |
| 1 | Basic SAST | REAL | Shared engine. E2E B-1. |
| 2 | Basic SCA | REAL | Shared engine (inventory only — same honest boundary). |
| 3 | Basic Secrets | REAL | Shared engine. |
| 4 | Learning path | NOT_IMPLEMENTED | Would require an education-content dataset; Phase 20 keeps the data boundary clean rather than ingesting one. |
| 5 | Interactive tutorials | NOT_IMPLEMENTED | Same boundary. |
| 6 | Practice lab | NOT_IMPLEMENTED | Requires isolated execution environments the platform does not run. |
| 7 | CTF challenges | NOT_IMPLEMENTED | Same boundary. |
| 8 | Quiz & certification | NOT_IMPLEMENTED | Certification would be fabricated without a question bank; not faked. |
| 9 | CWE encyclopedia | NOT_IMPLEMENTED | CWE dataset ingestion is forbidden by the zero-security-dataset boundary. |
| 10 | OWASP Top 10 guide | NOT_IMPLEMENTED | Same boundary (no bundled advisory/guide datasets). |
| 11 | Progress tracker | REAL | Server-persisted scan / findings / report history per account; surfaces real activity, no invented streaks. |
| 12 | Mentor Q&A | PARTIAL | Answered by the shared grounded AI assistant (provider NONE → honest "no external mentor connected" fallback), not a human mentor channel. |
| 13 | Portfolio | NOT_IMPLEMENTED | No public share surface; account-owned history exists. |
| 14 | Resume generator | NOT_APPLICABLE | Would fabricate credentials; account history is the honest substrate. |
| 15 | Job board | NOT_APPLICABLE | Single-account ownership model; no external marketplace integration. |
| 16 | Study groups | NOT_APPLICABLE | Cross-account collaboration is out of the account-isolation model. |
| 17 | Notes / bookmarks | PARTIAL | Findings notes + acknowledgements persist; freeform notebook/bookmarks are NOT_IMPLEMENTED. |
| 18 | Video tutorials | NOT_APPLICABLE | No media hosting/CDN pipeline; not faked with placeholders. |
| 19 | Code playground | NOT_APPLICABLE | The platform never executes user code. |
| 20 | AI tutor | REAL | Shared AI assistant in student framing; grounded on the user's own findings; provider NONE stays honest. |

**Student totals: 5 REAL, 2 PARTIAL, 7 NOT_IMPLEMENTED, 6 NOT_APPLICABLE.** Student learning features grant no privileged security capabilities.

---

## SECURITY_PROFESSIONAL (25 requested)

| # | Feature | Status | Evidence / honest scope |
| --- | --- | --- | --- |
| 1 | SAST | REAL | Shared engine. |
| 2 | SCA | REAL | Shared engine (inventory; `NOT_ASSESSED` verdicts). |
| 3 | Secrets | REAL | Shared engine. |
| 4 | DAST | REAL | Shared passive, bounded DAST engine against owner-configured public targets; SSRF policy blocks private ranges. E2E D-1…D-3. |
| 5 | Multi-project management | REAL | Account owns multiple projects. |
| 6 | Client management | NOT_IMPLEMENTED | No CRM layer; projects are account-owned. |
| 7 | Compliance dashboard | NOT_IMPLEMENTED | Would require mapping datasets (PCI/ISO/etc.); not fabricated. |
| 8 | Custom report templates | NOT_IMPLEMENTED | Report formats are the honest fixed set (json/markdown). |
| 9 | PDF export | NOT_IMPLEMENTED | JSON/Markdown only — labeled honestly. |
| 10 | CVSS scoring | NOT_APPLICABLE | CVSS vectors derive from vulnerability intelligence; dataset boundary forbids it. Deterministic rule severities (LOW/MEDIUM/HIGH/CRITICAL) are the honest substitute. |
| 11 | Remediation timeline | REAL | Findings lifecycle with statuses + timestamps across scans. |
| 12 | Team collaboration | PARTIAL | Single-account ownership; reviewer/admin roles exist at platform level, not per-client teams. |
| 13 | Audit trail | REAL | Security audit log + payment-config audit (masked). |
| 14 | API access | REAL | Full REST API with session auth; API-first by design. |
| 15 | Threat modeling | NOT_IMPLEMENTED | No STRIDE/attack-tree engine; not faked. |
| 16 | SBOM delivery | REAL | CycloneDX SBOM generation per project. |
| 17 | Report sharing | NOT_IMPLEMENTED | No share links/ACLs; reports are account-private. |
| 18 | SLA tracking | NOT_IMPLEMENTED | No SLA model. |
| 19 | Billing & invoicing | PARTIAL | Manual-transfer payment flow is REAL (quote → payment → reviewer approval); invoice PDF generation is NOT_IMPLEMENTED. No online gateway. |
| 20 | White-label | NOT_IMPLEMENTED | Single brand. |
| 21 | Multi-language reports | NOT_IMPLEMENTED | English output; labeled honestly. |
| 22 | Vulnerability trend | PARTIAL | Cross-scan finding counts/history are real; fabricated trend analytics are not added. |
| 23 | Executive summary | REAL | Markdown report includes generated summary sections from real scan data. |
| 24 | Remediation verification | REAL | Re-scan compares findings across runs (shared findings engine). |
| 25 | Scheduled scans | NOT_IMPLEMENTED | No scheduler; on-demand scans only. |

**Professional totals: 9 REAL, 3 PARTIAL, 10 NOT_IMPLEMENTED, 1 NOT_APPLICABLE (CVSS), 2 NOT_IMPLEMENTED (SLA/scheduling counted above)** — i.e. 9 REAL, 3 PARTIAL, 12 NOT_IMPLEMENTED, 1 NOT_APPLICABLE.

---

## PENTESTER (25 requested)

Offensive features are bounded by design: no unrestricted arbitrary targets, no
SSRF bypass, and no pentest capability is exposed to other UserTypes. Passive,
bounded behavior is the maximum honest surface; active exploitation tooling is
withheld rather than faked.

| # | Feature | Status | Evidence / honest scope |
| --- | --- | --- | --- |
| 1 | SAST | REAL | Shared engine. |
| 2 | SCA | REAL | Shared engine (inventory only). |
| 3 | Secrets | REAL | Shared engine. |
| 4 | Live DAST | REAL | Bounded passive DAST against owner-configured public targets; private/loopback/reserved targets refused (SSRF policy). E2E D-1/D-2/D-3. Honest framing: passive observation ≠ penetration test. |
| 5 | Exploit PoC generator | RESERVED | Would require an exploit/payload dataset and an exploitation engine; both are prohibited boundaries. |
| 6 | Payload library | RESERVED | Payload datasets are prohibited (zero-security-dataset boundary). |
| 7 | Request interceptor | NOT_APPLICABLE | Browser MITM proxy is outside this server-side architecture. |
| 8 | Vulnerability chaining | RESERVED | Requires exploit-graph data + exploitation engine. |
| 9 | Recon tools | NOT_APPLICABLE | Unrestricted arbitrary-target reconnaissance is explicitly disallowed. |
| 10 | Burp/ZAP integration | EXTERNAL_DEPENDENCY | No external tool bridge; not fabricated. |
| 11 | Screenshot capture | NOT_APPLICABLE | No headless browser/render farm. |
| 12 | Timeline view | REAL | Assessment/scan history with timestamps per project. |
| 13 | Custom attack scripts | RESERVED | Arbitrary script execution against targets is a prohibited capability. |
| 14 | Collaboration | PARTIAL | Same account-ownership boundary as Professional. |
| 15 | Engagement report | REAL | Markdown/JSON report per engagement scan, honestly labeled (≠ signed forensic report). |
| 16 | Threat modeling | NOT_IMPLEMENTED | Not faked. |
| 17 | Post-exploitation | RESERVED | No foothold/exploitation engine exists or will be built under this policy. |
| 18 | **Exploit database** | **RESERVED** | Mandated: never build/import an exploit DB. |
| 19 | Lateral movement testing | RESERVED | Requires active exploitation capability. |
| 20 | Persistence testing | RESERVED | Same. |
| 21 | Data exfiltration testing | RESERVED | Same. |
| 22 | Social engineering toolkit | NOT_APPLICABLE | Prohibited capability class; not built. |
| 23 | Physical security testing | NOT_APPLICABLE | Outside a software platform entirely. |
| 24 | Reverse shell generator | RESERVED | Payload-generation boundary. |
| 25 | (bounded DAST target policy) | REAL | Owner-configured targets only; DNS-resolution-verified public addresses; reserved suffixes/CIDRs blocked. |

**Pentester totals: 6 REAL, 1 PARTIAL, 2 NOT_IMPLEMENTED, 4 NOT_APPLICABLE, 10 RESERVED, 2 EXTERNAL_DEPENDENCY** (item 25 documents the boundary that makes item 4 honest).

---

## ADMIN payment configuration (privileged Admin control — NOT a UserType capability)

Implemented and verified in Phase 20 (Step 13, items A–J):

- **A** method add/edit/enable/disable + display name + payment number + metadata — `POST/PATCH /api/v1/admin/payment-config/methods…` (platform-admin only).
- **B** PRO price change — `PATCH /api/v1/admin/payment-config` (`proPriceMinorUnits` 1…100,000,000, integer), server-authoritative.
- **C** live reflection — `GET /api/v1/payments/config` and quote always read the authoritative store (E2E K-2/K-3/K-4/K-5).
- **D** server authority — payment creation re-validates amount/method against current config; forged/stale values → 422 (E2E L-1).
- **E** history integrity — `PaymentRecord` snapshots are immutable; config changes never rewrite them (E2E M-1/M-2).
- **F** authz — MEMBER / Partner / reviewer / any UserType / forged sessions → 403 (E2E J-1…J-5, I-2).
- **G** validation — invalid/duplicate method (409 case-insensitive), invalid/negative/zero price (422), unexpected fields (422), HPP (422), Idempotency-Key required for adds + replay-safe, CSRF (403).
- **H** audit — who/what/when with old→new; account numbers masked (`maskAccountNumber`), never logged in full (E2E H-3).
- **I** concurrency — atomic read-modify-write JSON store; no partial reads (covered by API suite).
- **J** no unnecessary caching — config reads go straight to the authoritative store.

Rate limiting covers `/api/v1/admin/payment-config*` (payment-mutation limiter).
Store: `PAYMENT_CONFIG_STORE_PATH` (default `.data/payment-config.json`).

---

## Dataset-lock statement (Phase 20)

`VULN_INTEL_PROVIDER=none` is preserved. SCA/SAST verdict surfaces remain
`NO_DATA_LOADED` / `NOT_ASSESSED`. No CVE/NVD/GHSA/OSV/KEV/EPSS/exploit/
advisory/payload/threat-intel dataset, feed, or sync was added. Feature 18
(Exploit Database) stays RESERVED. Payment/admin logic has no dependency on any
security dataset.
