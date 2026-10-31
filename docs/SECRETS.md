# Secrets Detection (Pump 10 — the third real engine)

> **Current boundary (2026-10-31):** the production embedded rule registry is empty; rules come from a configured, accepted Dataset pack. The `DG-SEC-*` table below describes historical/test-only fixtures, not an always-available production rule set. With no rules the scan is partial. New source-finding evidence is withheld as a whole, not selectively excerpted. Raw uploaded source and some historical evidence may remain in JSON files at rest; no universal secret-free or encryption guarantee is established.

`SECRETS` scans detect **hardcoded secrets** in a project's uploaded
source snapshot: private-key PEM headers, known-prefix service
credentials, bearer tokens, credential URLs, API-key-shaped
assignments and strong password literals. The engine is REAL —
deterministic pattern analysis of actual snapshot content, with
**mandatory evidence redaction enforced at every layer**.

Like SAST (Pump 8) and SCA (Pump 9), the engine reuses the Pump 8
snapshot architecture only: there is no second storage, discovery or
upload path.

## The core honesty contract

- **DETECTED_SECRET ≠ VERIFIED_LIVE_CREDENTIAL.** A finding proves the
  *string* has a credential's shape — nothing more. No rule, title,
  description, remediation or UI text may claim the credential is
  *valid*, *active*, *compromised* or *revoked*.
- **No verification, no network.** The engine never contacts any
  service, validates a credential or uses key material. It matches source
  lines and a narrowly bounded, non-executing literal-concatenation view.
- **No match = no finding.** A configured rule must match an original line
  or a statically reconstructed literal expression at a source location.
  A reconstruction is a candidate, not proof that a credential is live.
- **Severity and confidence are rule-defined constants** — never
  runtime-guessed, never client- or UI-influenced.

## Historical test-only rule examples

These examples live in `apps/api/test/fixtures/testData.ts`. Actual Dataset pack rules and severity/confidence values can differ. `apps/api/src/scans/secrets/rules.ts` contains an empty production registry and the rule interface/matcher, not these rule records.

| Rule | Category | Severity | Confidence | Fires on |
| --- | --- | --- | --- | --- |
| `DG-SEC-001` | private-key | HIGH | HIGH | `-----BEGIN … PRIVATE KEY-----` PEM header lines |
| `DG-SEC-002` | known-prefix | HIGH | HIGH | AWS `AKIA…`, GitHub `ghp_…`, Stripe `sk_live_…`, Slack `xoxb-…`, Google `AIza…` shapes |
| `DG-SEC-003` | bearer-token | HIGH | MEDIUM | `Authorization: Bearer <20+ mixed-class token>` and `bearer_token` assignments |
| `DG-SEC-004` | credential-url | HIGH | MEDIUM | `postgres://`, `mysql://`, `mongodb(+srv)://`, `redis(s)://`, `amqp(s)://`, `ftp(s)://` URLs with an inline `user:password@` |
| `DG-SEC-005` | api-key | HIGH | MEDIUM | `apiKey`/`api_key`/`x-api-key`-named settings assigned a 20+ character mixed-class literal |
| `DG-SEC-006` | generic-secret | MEDIUM | LOW | `password`/`passwd`/`pwd`/`client_secret`/`secret` assignments with a 12+ character, ≥2-class, ≥3.5-entropy literal |

These six historical fixtures map to **CWE-798** (Use of Hard-coded Credentials).

Historical fixture severity policy (documented, deterministic): **no CRITICAL** in v1 —
even a private-key match does not prove the key is real, current or
authorized for anything. HIGH = credential-shaped material is present
in source; MEDIUM = heuristic rules where shape alone is weaker
evidence.

Confidence (`HIGH`/`MEDIUM`/`LOW`, closed vocabulary) is the RULE's
detection certainty — HIGH for structural/known formats, MEDIUM for
shape heuristics, LOW for the generic password rule. It is never a
liveness or exploitability claim.

## Evidence withholding and its limits

- New SAST and Secrets findings use a fixed withheld-source marker instead of
  copying any source line, including adjacent unknown credentials. Rule, file
  and line metadata remain available for an authorized reviewer.
- Legacy source-finding evidence is withheld in current read/export projections;
  this does **not** rewrite or erase historical stored records. Recognized
  sensitive legacy SCA/DAST evidence is also withheld; an arbitrary secret is
  not guaranteed to be recognized.
- A source-finding v2 fingerprint is based on scanner, project, rule, file and
  line, not raw evidence. Moving a line can change identity.
- Source snapshots are stored as raw content and historical data may contain
  sensitive evidence. File modes are not encryption. Filenames, notes, rule
  metadata and other arbitrary fields cannot be proven universally secret-free;
  operators must protect, review and plan historical-data handling separately.
- Tests verify selected synthetic leak scenarios, not every possible value or
  every future field. Do not treat a passing test as a privacy guarantee.

## Historical fixture false-positive defenses (tested, not universal)

These examples depend on the selected rule and do not guarantee that every Dataset rule implements the same filters.

- **Placeholder/template denylist** (substring, case-insensitive):
  `changeme`, `example`, `dummy`, `sample`, `your`, `placeholder`,
  `<YOUR_API_KEY>`, `${…}`, `{{…}}`, plus the self-referential docs
  values `password`/`secret`/`token` as *values*.
- **Known documentation values**: the AWS docs example key
  `AKIAIOSFODNN7EXAMPLE`, Stripe *test-mode* keys (`sk_test_…`), etc.
- **Structure gates**: minimum length, ≥2 character classes, entropy
  ≥ 3.5 (one input among several — "high entropy = secret" alone is
  never a rule), UUID-shape exclusion, plain-hex-digest exclusion
  (MD5/SHA-1/SHA-256/… checksums and commit ids are not credentials).
- **Not suppressed merely because a file is named "test"** — content
  and context decide, per the spec.
- **Non-literal values are not matched**: `process.env.API_KEY`,
  interpolations, function calls.

Note the deliberate asymmetry: an `sk_live_…`-shaped 20-character
value *fires* even in a file named `docs.md`, because the shape is the
evidence; a value containing placeholder markers does not fire even in
`prod.ts`, because documentation intent is the evidence.

## Scope and limits (the engine's honest boundaries)

- **Supported formats**: `.js .ts .jsx .tsx .mjs .cjs .py .java .go
  .rs .php .rb .cs .json .yaml .yml .toml .ini .cfg .conf
  .properties .sh .bash .zsh` (and `.env`-style paths, which the
  upload path in fact refuses — see below). Unsupported extensions are
  skipped and counted (`filesSkipped`), never interpreted.
- **Credential-material files never enter a snapshot**: the Pump 8
  upload policy already blocks `.pem .key .p12 .pfx .jks .kdbx
  .keystore .env` — uploading a private key would move the secret
  *into* the application's stores. Consequently `DG-SEC-001` fires on
  PEM headers pasted **into code/config files**, the realistic case.
- **Ignored directories**: `node_modules`, `dist`, `build`, `out`,
  `coverage`, `vendor`, `target`, `cache` (dependency trees, build
  output, caches — out of scope, not partial).
- **Snapshot only**: the engine inspects the uploaded snapshot — never
  git history, remotes or branches.
- **Never executes** snapshot content; binaries cannot enter a
  snapshot at all (text-only upload validation).
- **Per-rule one match per line**: the first matching pattern wins;
  duplicates on the same line collapse into one finding per
  (rule, file, line). Different rules on the same line stay distinct.

## Bounded static literal reconstruction

The existing isolated syntax worker can identify same-line JS/TS/JSX/TSX
`+` expressions made entirely of 2–16 unescaped, simple ASCII string
literals (at most 1,024 joined characters). Parentheses and empty pieces are
allowed. The main engine transiently joins the pieces and reuses the same
configured rule, validation and denylist; a new match must cross a joining
seam. Source is never executed. The worker returns coordinates only; findings
withhold the source and explicitly say the candidate was reconstructed, not
verified. Deduplication, ordering, finding caps and fingerprints are retained.

This is **not** general constant propagation: other languages, escaped
literals, dynamic expressions, interpolated templates and multiline joins are
not reconstructed. There are at most 32 eligible files, 64 concatenation
records per file, 4,096 characters per candidate line and 32,000 rule checks
per scan. `astSupplement.status` records incomplete/skipped optional syntax
work; the base lexical scan's `partial` field retains its existing meaning.
A `RAN` supplement does not mean unsupported expression types were checked.
Check both fields before interpreting a negative. Source snapshots may still
contain raw values at rest.

## Limits and failure semantics

Defaults (`DEFAULT_SECRETS_LIMITS`): 200 files, 256 KiB per file,
1 MiB total, `MAX_FINDINGS_PER_SCAN` (200) findings, 10 s deadline.
Deterministic file order (path ASC). Duplicate control via
`(ruleId, file, line)`.

Failure codes (closed set, tested): `SECRETS_TARGET_NOT_FOUND`,
`SECRETS_INPUT_INVALID` (owner mismatch, corrupt path — fail closed),
`SECRETS_FILE_LIMIT_EXCEEDED`, `SECRETS_TARGET_TOO_LARGE`,
`SECRETS_SCAN_TIMEOUT` (deadline or cancellation).

**PARTIAL honesty:** files skipped for size are reported with
`partial: true` and a bounded `partialReason`; reaching the findings
cap sets `truncated: true` plus partial. **A partial scan with 0
findings is "nothing found in what was inspected", never "no
secrets"** — the UI renders the reason inline. A FAILED scan never
reports findings at all.

## API and UI

- Pre-flight (quota protection): requesting a SECRETS scan without an
  uploaded snapshot → `409 CONFLICT`, nothing consumed.
- Findings ride the existing detail route and contract (`findings`
  array; `resultSummary` counts) — no second format. SECRETS findings
  additionally carry the rule-defined `confidence`.
- The web findings view is shared with SAST and renders rule id,
  severity, the **detection-confidence badge**, location (`file:line`
  + CWE), withheld source evidence and remediation — all as text. Synthetic
  DOM sweeps cover selected cases; arbitrary filenames and other text fields
  are not proven secret-free.
- DAST is a separate limited passive HTTP engine (Pump 11); it does not
  inspect source snapshots. See `docs/DAST.md`.

## Remediation wording

Generic, actionable, honest: move the secret to the environment or a
secret manager, rotate the exposed value, invalidate where relevant.
The system **never** claims "this credential has been revoked" — it
cannot know that.

## Tests

- `apps/api/test/secretsRules.test.ts` — registry integrity, per-rule
  positive/false-positive matrices, pattern linearity (ReDoS bound),
  cross-rule honesty, concatenated-PEM fixtures.
- `apps/api/test/secretsEngine.test.ts` — redaction (long lines, tabs,
  neighbours, fail-closed), determinism, dedupe, partial/truncation,
  ignored dirs, all failure modes, no-execution invariant.
- `apps/api/test/secretStaticConcat.test.ts` — literal-only reconstruction,
  denylist, limits, comments/dynamic/escaped controls and coordinate-only
  worker output, with synthetic values.
- `apps/api/test/secretsApi.test.ts` — §29 adversarial file and §30
  no-fake snapshot over real HTTP, three-layer redaction sweep
  (response/store/logs), findings cap, cross-account isolation,
  restart determinism, tamper fail-fast, SAST/SCA regression.
- `apps/web/test/secretsUi.test.tsx` — findings surface, confidence
  badge, partial rendering, whole-DOM no-leak sweep, DAST honesty.
