# CI, release flow, and engineering security

## Automated CI

`.github/workflows/ci.yml` is the repository's only CI workflow. It runs on
pushes to `main` and `arena/**`, ordinary pull requests targeting `main`, and
manual dispatch. Every run uses Node 22 from `.nvmrc`, performs `npm ci` from
the committed lockfile with lifecycle scripts disabled, and invokes the
existing authoritative `npm run verify` pipeline. It does not reimplement or
selectively skip the project gates.

The verification job covers, in order:

1. Application dependency/import/filename boundaries (including database,
shell and vulnerability-dataset exclusions).
2. Repository integrity: npm lockfile/workspace declarations, denied direct
and transitive database/dataset packages, credential-bearing lockfile
references, committed credential/environment/private-key file paths,
generated-output exclusion, and CI workflow policy.
3. Release-evidence checksum/mismatch self-test, secret matcher self-test,
and source/config secret scan.
4. Typechecks, whole-repository lint, complete shared/API/worker/Web tests,
and production builds for shared, API, worker and Web.
5. Secret scan including generated builds and `npm audit --audit-level=high`.

Every gate is fail-closed. A failed command, audit finding, or registry outage
fails `npm run verify`; there is no warn-and-pass path. `npm ci` validates the
lockfile and exact dependency graph. `--ignore-scripts` avoids executing
third-party lifecycle hooks during CI installation; the current locked tree
has been verified to build and test without install scripts.

Actions are pinned to full commit SHAs; workflow and job token permissions are
read-only `contents`. Checkout does not persist its token. Pull-request code
uses the unprivileged `pull_request` event, not `pull_request_target`; no
secrets, OIDC, write permission, cache, deployment environment, or production
deployment is configured. Workflow interpolation does not pass event text or
manual inputs into shell commands. Repository-integrity checks enforce these
properties so accidental workflow changes fail verification.

## Artifact and release-evidence flow

For non-PR workflow runs, a second job starts only after the verification job
succeeds. It checks that the checkout SHA is exactly `GITHUB_SHA`, confirms a
clean source tree, performs two clean shared/API/worker/Web production builds,
and requires every output file, byte length, and SHA-256 to match across both
builds. It then uploads `artifacts/release-evidence` as a 14-day workflow
artifact. This happens for branch pushes as well as `main`; an Arena-branch
artifact is build evidence, not a production release.

The bundle contains:

- `release-manifest.json`: source commit and tree, GitHub ref/event, package
  name/version, lockfile SHA-256, successful `npm run verify` job status and
  named required gates, Node/npm versions, repeat-build result, and per-file
  artifact hashes/sizes.
- `payload/shared`, `payload/api`, `payload/worker`, and `payload/web`: the
  production build outputs whose bytes were compared.
- `SHA256SUMS`: SHA-256 checksums for every payload file and the manifest.

The script refuses to run outside GitHub Actions or without a successful
upstream verification result and exact checked-out revision match. Workflow
artifacts are short-lived CI evidence, not a signed release. The workflow does
not create version tags or GitHub Releases, sign artifacts, issue certificates,
create attestations/provenance, promote between environments, or deploy. The
project package version remains manually maintained. Release/version/tag
approval and any later production deployment are separate human-governed work.

A successful workflow is not by itself a GitHub branch-protection rule. The
repository owner must configure required status checks, review requirements,
and merge policy in GitHub settings if those controls are desired; this code
does not change or claim those external settings. Normal mainline integration
should happen through a reviewed PR after required CI checks pass.

## Secret and environment safety

- Real `.env`, `.env.*`, `*.env`, credential files, private-key/container
  formats, common `.netrc`/`.pypirc`/Docker auth files, and known
  service-account/credential filenames are prohibited from the tracked
  repository. `.env.example` is the only environment-file exception
and must contain placeholders, never production values.
- Local `.env` remains gitignored. The general secret scanner can skip local
  environment inputs to avoid exposing developer values in logs; the separate
  Git inventory check rejects staged/committed environment-file paths
  regardless of contents. Lockfile registry URLs and auth-token fields receive
  targeted checks because package integrity hashes are intentionally not
  treated as credentials.
- CI receives no production or deployment credentials. Do not add secrets to
  PR workflows, test fixtures, source maps, build outputs, release manifests,
  or `.npmrc`.
- Dependency review consists of lockfile integrity/workspace agreement,
  explicit scope exclusions, and `npm audit` at the high threshold. This is
  not a complete supply-chain attestation, malware review, or guarantee that
  every dependency is safe.

## Absolute vulnerability-dataset boundary

No CVE, NVD, GHSA, OSV, KEV, EPSS or other vulnerability catalog/feed is
imported, downloaded, embedded, committed, bundled, or required at runtime.
The repository boundary and file-inventory checks reject known catalog/data
filenames and package dependencies. `npm audit` checks the application's
locked dependencies against npm's advisory service; it does not provide
vulnerability intelligence to the application or SCA scanner. The SCA
provider remains `none`; results remain honestly `NO_DATA_LOADED` and
`NOT_ASSESSED` where applicable. Security fixtures are synthetic and tests do
not download real datasets or use production credentials.

## Verification and browser-testing limits

`npm run verify` runs the full regression suite: auth, ownership/IDOR,
role-versus-UserType separation, entitlements/quota/device anti-abuse,
projects, SAST/SCA/Secrets/passive DAST, findings/remediation, assessments,
reports, assistant, manual payments, admin/platform operations, profiles,
secret/config safety, lint/typechecks, builds, and dependency audit.
Relevant API E2E uses local HTTP servers and controlled/synthetic fixtures;
it is not a test of public targets. The Web uses component/route tests and a
Vite production-preview test, but this repository does not configure or run a
real browser automation runner. No browser E2E claim is made by this pipeline.

The local preview is for manual product/UI review only. HTTP/API smoke and
production bundle checks are reported separately from browser-driven E2E.
