# SAST (Pump 8 — the real static-analysis engine)

Pump 8 delivers the first REAL scanner engine: **static analysis of an
uploaded source snapshot**. SAST scans complete with genuine findings —
rule id, severity, location, bounded evidence, remediation — produced
entirely server-side by deterministic code. **Analysis only: source
files are read and matched, NEVER parsed into execution, NEVER
imported, NEVER run.**

SCA (Pump 9), SECRETS (Pump 10), and limited passive DAST (Pump 11)
are also real engines now (see `docs/SCA.md`, `docs/SECRETS.md`, and
`docs/DAST.md`).

## Threat model (why the design looks this way)

The uploaded snapshot is **attacker-controlled input**. Every design
decision below follows from that:

- **Never executed.** The engine reads files as text and applies
  regular expressions with a hard line cap. There is no `eval`, no
  `new Function`, no `require`/`import` of snapshot content, no shell,
  no `vm`, no worker that could touch the code. A file containing
  `exec('touch /tmp/pwned')` is *reported as a finding* (rule
  DG-SAST-001) — it is never executed. This is verified end-to-end by
  tests (the marker file does not exist after the scan).
- **Bounded work.** Every dimension is capped: 200 files, 256 KiB per
  file, 1 MiB total, 200 findings, a 10 s processing deadline. Oversize
  files are skipped (counted), over-limit scans fail closed with
  `SAST_FILE_LIMIT_EXCEEDED` / `SAST_TARGET_TOO_LARGE`; a deadline
  breach or abort fails with `SAST_SCAN_TIMEOUT`. All rules are
  linear-time — the rule suite pins ReDoS-shaped patterns out and a
  timing test guards the whole corpus.
- **No exfiltration channel.** Findings evidence is windowed to
  ≤ 200 characters, control-character-free, and **credential values are
  redacted before persistence** (length-neutral: the structure stays,
  the value does not). Uploaded content is NEVER echoed back: the
  sources read API returns metadata only (file count, bytes per file,
  timestamps). Logs carry counts and ids, never content or secrets.
- **Fail closed.** Unknown failure modes, malformed stored snapshots,
  traversal-shaped paths in a stored file list, owner mismatches and
  findings injected into non-terminal records all refuse to start or
  fail the scan — never a silent repair, never a fabricated result.

## The rule set (6 rules, deliberately small)

Rules live in `apps/api/src/scans/sast/rules.ts` — pure data (id,
pattern, severity, CWE, title, description, remediation), no closures.
Rule ids are stable (`DG-SAST-###`), documented here, never reused.
Severities are rule-fixed — never client-influenced.

| Rule | Severity | CWE | Detects |
| ---- | -------- | --- | ------- |
| `DG-SAST-001` | HIGH | CWE-78 | Shell commands built from untrusted/interpolated input (`exec`, `spawn` with template literals or concatenation). |
| `DG-SAST-002` | HIGH | CWE-89 | SQL queries built by string concatenation/interpolation instead of parameterized statements. |
| `DG-SAST-003` | MEDIUM | CWE-79 | `dangerouslySetInnerHTML` (or equivalent raw-HTML sinks) fed with dynamic values. |
| `DG-SAST-004` | HIGH | CWE-95 | `eval` / `new Function` on anything other than a literal string. |
| `DG-SAST-005` | HIGH | CWE-798 | Hardcoded credentials (literal assigned to a credential-named variable/property), with a placeholder denylist to keep guidance text out of findings. |
| `DG-SAST-006` | LOW | CWE-327 | Weak hashes (`md5`, `sha1`) used for anything that looks security-relevant. |

Honest limitations (documented, not hidden):

- Analysis is **line-oriented and pattern-based** — a finding is a
  *review pointer*, not a proof. Multi-line taint flows, framework
  auto-escaping and SCREAMING_SNAKE credential names beyond the
  covered shapes are not fully modeled.
- Only text files are scanned; binary-looking files (NUL byte in the
  first 8 KiB) are skipped and counted, as are files over 256 KiB and
  well-known non-source directories (`node_modules`, `dist`, `build`,
  `coverage`, `.git`, vendor trees).
- A scan of a snapshot with **zero analyzable files** completes
  honestly with `filesScanned: 0` — it does not pretend work happened.

### Finding identity (deterministic)

`fingerprint = sha256(ruleId \n file \n line \n sha256(evidence))`; the
finding id is `fnd_` + the first 24 hex chars. Rescanning the same
snapshot yields the SAME ids — a re-scan is diffable, not duplicative;
moving a line changes the fingerprint (it is a new fact). Findings are
ordered most-severe-first (`CRITICAL → HIGH → MEDIUM → LOW → INFO`),
then rule id, then location.

## Source snapshots (the scan target)

- `PUT /api/v1/projects/:projectId/sources` replaces the project's
  snapshot wholesale: body exactly `{ files: [{ path, content }] }`.
  The last upload is what a SAST scan analyzes. `GET` returns metadata
  only; there is deliberately **no read-back of content**.
- **Path policy (server-authoritative, single implementation):**
  relative POSIX-ish paths only — no `..`, no absolute paths, no
  drive letters, no backslashes, no leading `/`, no dotfiles, no
  empty segments; length ≤ 160, segment ≤ 64, depth ≤ 16; ASCII
  alphanumerics plus `._-/`. Extension must be a known text/source
  type; `.env` and key material extensions (`.pem`, `.key`, `.p12`,
  `.pfx`, `.jks`, `.kdbx`, `.keystore`) are rejected outright —
  key material never belongs in an upload.
- **Content caps:** 200 files, 256 KiB per file (bytes, not chars —
  multibyte content is measured correctly), 768 KiB total. Binary
  content (NUL byte) is rejected.
- Duplicates, unknown properties (e.g. `ownerId` in a file entry) and
  prototype-chain keys are 422 — structurally impossible to inject.
- Snapshots are project-scoped and inherit the project ownership
  policy (uniform 403 for foreign/unknown project ids; the sources
  store refuses to load foreign material).
- Storage: one JSON document per deployment (`SOURCE_STORE_PATH`,
  default `.data/sources.json`, 0600, gitignored) with the same
  atomic-write/fail-fast discipline as every other store. A corrupt
  document or a traversal-shaped stored path **refuses to start**.

## Engine flow (`apps/api/src/scans/sast/engine.ts`)

```
snapshot (owner-checked) ─→ discovery (path policy, caps, binary skip)
                        ─→ per-file line scan (≤ 10 000 lines, all rules)
                        ─→ evidence windowing (≤ 200 chars, control-char free)
                        ─→ credential redaction (length-neutral)
                        ─→ finding caps + ordering
                        ─→ COMPLETED { resultSummary, findings }
```

- The engine implements the Pump 7 `ScanEngine` boundary — zero route
  or store changes; the processor forwards findings to
  `completeScan(id, summary, findings)` atomically with the terminal
  transition.
- `resultSummary`: `findingsTotal`, `findingsBySeverity` (all five
  keys always), `filesScanned`, `filesSkipped`.
- Findings persist **only on COMPLETED** scans (the store rejects
  findings on any other state — a stored cross-scan finding is
  corruption and refuses to load).
- The scan detail route (`GET .../scans/:scanId`) is the ONLY findings
  read surface; the list route stays lean (summaries only).

## Quota, idempotency, lifecycle

Unchanged from Pump 7 (`docs/SCANS.md`): creation consumes quota
atomically, idempotency keys replay the original scan, SAST scans
drain through the same durable processor. A SAST request against a
project with **no snapshot** is rejected pre-flight with
`409 CONFLICT` ("Upload a source snapshot before requesting a SAST
scan.") — **before** quota consumption, so a FREE account cannot burn
its monthly allowance on a scan that could only fail
(verified by tests).

## Web

The project detail page gained a **Source snapshot** section (upload →
metadata, honest empty state, archived projects cannot replace) and
per-completed-SAST-scan **View findings** (lazy; server-ordered;
severity filter is client-side over the same bounded response).
Evidence renders as literal text (React escaping) — a command-
injection payload in evidence is displayed, never executed, and
redacted secrets stay redacted in the UI.

## What this is NOT

- Not a dataset product: no CVE/NVD/GHSA/OSV/KEV/EPSS data — the
  dataset lock holds (rules are hand-written heuristics, not feeds).
- Not a sandbox escape risk: analysis-only, bounded, no execution.
- Not a secrets *scanner*: DG-SAST-005 finds hardcoded credential
  *patterns*; a dedicated SECRETS engine is a future pump.
