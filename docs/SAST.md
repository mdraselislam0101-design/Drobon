# SAST (Pump 8 engine; v2 — the universal language & platform catalog)

Pump 8 delivers the first REAL scanner engine: **static analysis of an
uploaded source snapshot**. SAST scans complete with genuine findings —
rule id, severity, location, bounded evidence, remediation — produced
entirely server-side by deterministic code. **Analysis only: source
files are read and matched, NEVER parsed into execution, NEVER
imported, NEVER run.**

SCA (Pump 9), SECRETS (Pump 10), and limited passive DAST (Pump 11)
are also real engines now (see `docs/SCA.md`, `docs/SECRETS.md`, and
`docs/DAST.md`).

> **CURRENT STATE (2026-10-26) — read this first.** The embedded `DG-SAST-*`
> rule catalog described in the historical sections below was **removed** by
> the dataset-decoupling work. `apps/api/src/scans/sast/rules.ts` now exports
> an empty registry; all 1,000 SAST rules come from the external
> `Drobon-Dataset` `packs/sast/v1/rules/*.json` at runtime (see
> `docs/DATASET_CONNECTION.md`). With no dataset configured the engine
> produces **0 findings** and startup logs a warning — it does not silently
> fall back to the 50 rules described below. Sections that enumerate
> `DG-SAST-###` ids are kept as design history for the engine/flow layer,
> not as a description of shipped data.
>
> Loader conformance: every pack rule is closed-field validated, ReDoS-linted
> and its declared tests are executed before it reaches the engine
> (`apps/api/src/external/conformance.ts`). Pack language ids are resolved
> through `apps/api/src/external/languageAliases.ts`; files of a catalog
> family marked `SYNTAX_ONLY`/`UNSUPPORTED` are analyzed **only when a loaded
> dataset rule targets that family** (see `engine.ts` `ruleFamilies`).

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

## The rule set (50 rules, one shared engine)

Rules live in `apps/api/src/scans/sast/rules.ts` — pure data (id,
pattern, severity, CWE, title, description, remediation), no closures,
no runtime imports (guarded by `staticSafety.test.ts`). Rule ids are
stable (`DG-SAST-###`), never reused. Severities are rule-fixed — never
client-influenced. Each rule declares the language families it applies
to (`languages`); the engine gates per file, so a Python rule never
runs on a Kotlin file. `DG-SAST-005` (hardcoded credentials) is the one
universal rule and runs on every analyzed file.

- **DG-SAST-001…006 (v1, JavaScript/TypeScript family):** command
  injection (`exec`), code evaluation (`eval`/`new Function`), SQL
  construction, raw-HTML sinks (incl. React `__html`), hardcoded
  credentials (universal), weak hash (`createHash`).
- **DG-SAST-007…012 (Python):** dynamic `eval`/`exec`, `os.system`/
  `os.popen`, unsafe deserialization (pickle/marshal/`yaml.load`), weak
  hash, Django raw SQL, Flask debug mode.
- **DG-SAST-013…017 (JVM + Android):** `Runtime.exec`/`ProcessBuilder`
  concat, JDBC concat, weak `MessageDigest`, `MODE_WORLD_*` storage,
  risky WebView settings.
- **DG-SAST-018 (C/C++/Objective-C):** dangerous memory functions
  (`gets`/`strcpy`/`strcat`/`sprintf`/`vsprintf`).
- **DG-SAST-019…022 (C#/VB.NET):** `Process.Start` concat, `SqlCommand`
  concat, weak MD5/SHA-1 providers, VB `Shell()` concat.
- **DG-SAST-023…028 (PHP/Go/Ruby/Rust):** shell execution
  (`shell_exec`/backticks), SQL concat, `exec.Command`+`fmt.Sprintf`,
  weak hashes, Ruby `system`/backticks with `#{…}`, `Command::new`
  with `format!`.
- **DG-SAST-029…039 (more languages):** Swift weak crypto, Dart
  `Process` concat, Lua `os.execute`/`io.popen`, Perl interpolation,
  Solidity `delegatecall`/`selfdestruct`, shell `eval`, PowerShell
  `Invoke-Expression`, Apex SOQL concat, Elixir `Code.eval_*`/Erlang
  `os:cmd`, R `system(paste(…))`, Julia `run(`…`)`.
- **DG-SAST-040…047 (configuration/infrastructure/platform):** dynamic
  SQL (`EXEC(@…)`/`EXECUTE IMMEDIATE … ||`), XXE external entities,
  privileged containers, GitHub Actions `permissions: write-all`,
  Dockerfile pipe-to-shell, Terraform open-world ingress, Electron
  `nodeIntegration`/`contextIsolation`, exported Android components.
- **DG-SAST-048…050 (bounded taint flows, deep-semantic pump):** the
  first flow-driven rules — untrusted input reaching command execution
  (CWE-78), SQL execution (CWE-89) or HTML rendering (CWE-79) through
  assignments in the SAME file. They are intentionally pattern-less
  (`patterns: []`): the line matcher never fires them; they are driven
  by the bounded semantic layer below and land at the SINK line with
  the same finding identity/lifecycle/report/SARIF behavior as every
  other rule.

Every rule has at least one positive synthetic fixture and safe-form
negative coverage in `apps/api/test/sastLanguages.test.ts` (per-rule
unit tests for the v1 six live in `sastRules.test.ts`).

### Honest maturity model (v2 — never faked)

The engine is **lexical, line-based pattern analysis (analysis depth
LEVEL 1–2)**: no parser, no AST, no dataflow, no cross-file analysis.
Therefore **no language family is labelled FULL** — that would be a
fabrication. The catalog (`apps/api/src/scans/sast/languages.ts`)
states the truthful maturity of every family:

| Maturity | Meaning | Families |
| -------- | ------- | -------- |
| `FULL` | parser + AST + semantic/dataflow depth | **0** (reached by none) |
| `PARTIAL` | real deterministic security rules + evidence + fingerprint + remediation + retest + report/SARIF + tests (pattern depth) | 32: JavaScript, TypeScript, JSX, TSX, Python, Java, Kotlin, Groovy, Scala, C, C++, Objective-C, Objective-C++, C#, VB.NET, PHP, Go, Rust, Ruby, Swift, Dart, Lua, Perl, Solidity, Bash, POSIX Shell, PowerShell, Apex, Elixir, Erlang, R, Julia |
| `CONFIG_ANALYSIS` | configuration security analysis in the same pipeline | 9: SQL, XML, YAML, JSON, Dockerfile, Terraform/HCL, GitHub Actions YAML, AndroidManifest.xml, `config-file` (shared family for 60+ dataset config ids) |
| `SYNTAX_ONLY` | detected and catalogued; no built-in rules; skipped unless a loaded dataset rule targets the family | 2: HTML, CSS |
| `UNSUPPORTED` | honest refusal with no built-in rules; skipped unless a loaded dataset rule targets the family | 11: Clojure, Haskell, OCaml, Assembly, MATLAB, Fortran, COBOL, Crystal, Zig, Nim, V |

**Total: 54 language/configuration families across web / backend /
mobile / desktop / native / config / infra / data platforms.** Counts
are DERIVED from the catalog (`sastMaturityCounts()`), never
hand-written.

**Detection** uses extension, exact filename (`Dockerfile`,
`AndroidManifest.xml`, `Gemfile`), shebang (`#!/usr/bin/env python3`)
and two documented content tie-breaks: `.m` (Objective-C vs MATLAB —
deterministic markers) and YAML vs GitHub Actions workflow
(`runs-on:` + `jobs:`/`on:` markers — snapshot paths cannot contain
dotfile segments, so workflows are recognized by content shape). A
polyglot repository (e.g. Kotlin + Java + XML + Gradle + C/C++) is
analyzed as ONE snapshot with ONE unified result; unknown files are
skipped and counted, never claimed as scanned.

**Framework support (honest scope):** deterministic framework
DETECTION over manifest/build files (`detectFrameworks`: package.json →
React/Next.js/Angular/Vue/Express/Fastify/NestJS/Koa/Electron/React
Native; requirements.txt → Django/Flask/FastAPI/Tornado/aiohttp;
pom.xml/build.gradle → Spring Boot/Android; composer.json →
Laravel/Symfony; go.mod → Gin/Echo/Fiber; Gemfile → Rails; .csproj →
ASP.NET Core; pubspec.yaml → Flutter) is unit-tested. Framework-AWARE
RULES are self-contained file-level shapes (Electron `nodeIntegration`,
Django `.raw()`, Flask `debug=True`, React `__html` sink) — also
unit-tested and live-tested. Cross-file framework dataflow (routes →
handlers → sinks) is NOT implemented and NOT claimed.

### Android / desktop / native / configuration coverage (honest)

- **Android:** AndroidManifest.xml exported-component detection,
  `MODE_WORLD_READABLE/WRITABLE` insecure storage, risky WebView
  settings (Java/Kotlin). No runtime mobile testing is performed or
  claimed; no APK/IPA binary analysis.
- **Desktop:** C#/VB.NET/VoltBrowser(Electron)/JVM/C-family process and
  crypto shapes covered by the rules above; update-mechanism and
  IPC-boundary analysis is NOT implemented.
- **Native/system:** C/C++/Objective-C dangerous memory functions.
  No binary exploitability claims are made from source SAST.
- **Configuration/infrastructure:** SQL, XML, YAML, JSON, Dockerfile,
  Terraform/HCL, GitHub Actions, shell, PowerShell — the CONFIG_ANALYSIS
  families above.


### The bounded semantic layer (deep-semantic pump)

`apps/api/src/scans/sast/semantic.ts` adds two honest capabilities on
top of the line matcher WITHOUT a parser dependency or a second engine:

**1. Literal masking.** Before flow analysis, comments and string-literal
contents are replaced with spaces (character offsets and line counts are
preserved exactly). Text inside comments or strings can therefore never
produce a flow finding — a false-positive class pure lexical matching
cannot avoid. Rust single quotes are NOT treated as string delimiters
(lifetimes) — a documented under-approximation.

**2. Bounded intra-file taint flow (single forward pass).** Small,
explicit, per-language tables drive `source → variable → sink` reasoning
across lines of one file:

- **Sources** (examples): `req.body/query/params`, `process.argv`
  (JS/TS); `input()`, `request.args/form/json`, `sys.argv` (Python);
  `$_GET/$_POST/$_REQUEST` (PHP); `params[]` (Ruby); `Query().Get()`,
  `FormValue` (Go); `getParameter`, `getStringExtra` (JVM);
  `Request[...]`, `ReadLine` (C#). Anything not listed is NOT a source.
- **Sinks** (examples): `exec/spawn` family (JS), `os.system`,
  `subprocess.*` (Python), `shell_exec/system/passthru` (PHP),
  `system/spawn` (Ruby), `exec.Command` (Go), `Runtime.exec`,
  `ProcessBuilder` (JVM), `Process.Start` (C#); `cursor.execute`,
  `mysqli_query`, `executeQuery`, `SqlCommand`, `.Query/.Exec` (SQL);
  `innerHTML=`, `document.write`, `dangerouslySetInnerHTML`,
  `render_template_string` (HTML).
- **Sanitizers** are an EXPLICIT bounded allowlist (`encodeURIComponent`,
  `parseInt`, `Number`, DOMPurify, `textContent=`, `shlex.quote`,
  `escapeshellarg`, `intval`, `Shellwords`, `strconv.Atoi`, `html.escape`,
  `bleach.clean`, parameterized `?`/`%s` placeholders, bound parameters).
  Anything outside the list is treated as unsanitized — conservative,
  never silently suppressed.
- **Hard bounds (tested):** at most 512 tainted variables, 64 identifier
  tokens inspected per snippet, 3 findings per rule per file, a 300-char
  sink-argument window; strictly single-pass, linear time, NO recursion,
  NO fixpoint iteration, NO call graph, NO cross-file resolution.

**Known limitations (honest):** use-before-assignment ordering, loop-
carried values, flows through local helper functions, cross-file flows
and branch-sensitive joins are NOT tracked; template-interpolated sink
arguments are invisible to the flow layer (masked as string contents —
the line rules still catch the same-line interpolated shapes); the
source/sink/sanitizer tables under-approximate by design. **This is
why every family stays PARTIAL and FULL stays 0** — the engine has
bounded flow reasoning, not parser/AST/dataflow depth.

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
- The scan detail route carries the bounded full result; Pump 12 adds
  project/scan-scoped, server-filtered findings pages and per-finding
  detail routes without making the scan list unbounded. List responses
  remain lean (summaries only). New source findings persist explicit
  project context, with legacy rows still linked through their scan ID.

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
per-completed-scan **View findings** (lazy; server-side severity/scanner
filters and bounded pagination), safe per-finding detail, a project
security overview, and persisted report controls. Evidence renders as
literal text (React escaping) — an injection payload is displayed, never
executed, and redacted secrets stay redacted in the UI. SCA advisory
records remain distinct from the common Finding contract.

## What this is NOT

- Not a dataset product: no CVE/NVD/GHSA/OSV/KEV/EPSS data — the
  dataset lock holds (rules are hand-written heuristics, not feeds).
- Not a sandbox escape risk: analysis-only, bounded, no execution.
- SAST's DG-SAST-005 remains a lexical hardcoded-credential heuristic;
  the separate SECRETS engine is implemented with its own rules and
  mandatory redaction (see `docs/SECRETS.md`).
- **No language support is FULL.** The engine is pattern-based
  (LEVEL 1–2): a finding is a review pointer, never a proven exploit,
  and no family is advertised as fully analyzed. SYNTAX_ONLY and
  UNSUPPORTED families are reported as skipped, never "scanned".
- **No build/dependency execution:** build-aware analysis would require
  an execution sandbox that does not exist; the engine never runs
  compilers, package managers or project scripts.
