# Agent Storage Cutover — Design (proposal, NOT executed)

**Date:** 2026-11-01
**Status:** design only. Nothing in this document has been applied to production, a host, a service unit, a UID, a database, or the Dataset.
**Related code:** `apps/api/src/lib/storageBoundary.ts`, `apps/api/src/server.ts`, `apps/api/src/scans/store.ts` (`beforePersist`), `apps/api/src/agent/execution.ts`
**Related evidence:** `scripts/verify-agent-downgrade.mjs`, `scripts/verify-agent-os-boundary.mjs`, `scripts/verify-agent-server-coexistence.mjs`, `scripts/verify-agent-store-migration.mjs`

---

## 1. The problem this design is for

The store is a JSON document protected by an advisory lease, a snapshot fence and an attestation gate. All three are *cooperative and in-process*. A **legacy process running as the same UID** can:

1. read the current document and rewrite it without the agent fields (downgrade), or
2. replace the file before the fence's rename, or
3. delete or displace the private directory when a writable ancestor exists.

Reproduced today: `verify-agent-downgrade.mjs` (`separateProcessLoss: true`), `verify-agent-os-boundary.mjs` (`sameUidWriterDestroysJobs: true`, `namespaceMappedWriterDestroysJobs: true`), `verify-agent-server-coexistence.mjs` (`oldServerDropsBothAgentJobs: true`).

Code cannot fix this from inside the same UID. **Only an operating-system identity boundary can.** Everything added so far
(startup refusal, per-job re-attestation, per-write `beforePersist` re-check, opaque-adapter refusal) is *fail-closed
detection*: it stops the agent from writing once its own boundary is broken, and it refuses to start on an unsafe
path. It does not, and cannot, prevent another same-UID process from destroying data.

## 2. Target topology

| Element | Requirement | Why |
|---|---|---|
| Identity | a dedicated service account, e.g. `drobon-agent`, member of no shared group, no login shell | the legacy writer must not share an EUID |
| Unit | `User=drobon-agent`, `Group=drobon-agent`, `UMask=0077`, `StateDirectory=drobon-agent`, `ProtectSystem=strict`, `PrivateTmp=yes`, `NoNewPrivileges=yes`, `ProtectHome=yes` | makes the private state dir owned `0700` by construction, not by convention |
| State path | `/var/lib/drobon-agent/…`, no writable ancestor, no sticky world-writable parent | ancestor substitution is the second attack in the OS rehearsal |
| Secrets | separate credential file readable only by that UID; never in the JSON store | the store is copied during migration |
| Dataset | read-only mount (`ro`, `nosuid`, `nodev`, `noexec`), unchanged configuration and content | Dataset stays out of scope, only its existing mount is preserved |
| Network | loopback only where possible; DAST egress unchanged and still scope-gated | no new exposure is created by the cutover |
| Hosts | one writer host per store; NFS/overlay is unsupported while the fence is best-effort | distributed writers are out of scope |

If a distinct UID is not acceptable operationally, the alternative is a distinct **mount namespace / host**, not a
code change. There is no third option that keeps the same UID.

## 3. Acceptance gates (all must be demonstrated before cutover is called done)

1. `attestAgentStorage()` returns `STORAGE_READY` for every configured document and directory from a process running as `drobon-agent`.
2. The legacy access path — a process under the old UID — gets `EACCES` on read and on write (proved by an OS-level rehearsal, not by unit tests).
3. The downgrade rehearsal (`verify-agent-downgrade.mjs`) still shows legacy loss on an *unmigrated* copy, and shows **no loss** on the migrated store.
4. The coexistence rehearsal (`verify-agent-server-coexistence.mjs`) shows the old server cannot lease or overwrite the migrated store.
5. The per-write guard fires when the directory is widened after startup (already tested: `storageBoundary.test.ts`).
6. Rollback is executed once, on synthetic data, and verified byte-identical (`verify-agent-store-migration.mjs`, 17 flags).
7. Agent execution stays default-off in production until gates 1–6 are recorded as evidence.

## 4. Migration procedure (to be reviewed before it is ever run)

1. **Freeze** writes: stop the API service (both old and new paths); confirm no live writer via the existing `/proc` scan.
2. **Backup**: copy each JSON document + a SHA-256 manifest to a backup path outside the new state dir; keep the original in place (no move, no delete).
3. **Verify backup**: digests match the source; the source is byte-identical after the copy (rehearsed: `sourceUnchangedAfterBackup`, `backupDigestMatches`).
4. **Stage**: copy the backup into the new state dir with explicit ownership and mode (`install -m 0600 -o drobon-agent -g drobon-agent`), directory `0700`.
5. **Verify staged**: digest equality, schema `version` preserved, record count preserved, agent records preserved, and the store reopens read-only with the same scan ids (all rehearsed).
6. **Cutover**: point configuration at the new path, start the new unit, confirm `STORAGE_READY`, run one canary read and one canary legacy-type scan.
7. **Observe**: keep the backup and the old path untouched for a defined window; any anomaly triggers rollback.
8. **Retire** the old path only after the window passes and the owner signs off. Retirement is a separate, explicitly approved action.

## 5. Rollback

- Stop the new unit.
- Restore the pre-cutover backup over the cutover path (byte compare, digest compare).
- Revert the configuration to the old path; the old path was never modified, so rollback does not depend on the backup.
- Verify: digests, record counts, and one read per API surface.
- Rehearsed today: `rollbackDigestMatches`, `rollbackContentIdentical`.

## 6. What is still unsolved even after this design is applied

- Root / `CAP_DAC_OVERRIDE` can still rewrite the store; only host-level trust and detection help there.
- A writer that acquires the *same* dedicated UID by mistake (misconfigured unit) re-introduces the original problem.
- The JSON document has no signatures; digests are change detectors, not authenticity proofs.
- Cross-host / NFS semantics remain out of scope.
- `verify-agent-server-coexistence.mjs` still shows that an **opaque injected store** (a test seam, not a production config) can bypass path attestation.

## 7. Approval checklist (nothing below has been done)

- [ ] Approve creating the dedicated UID and the unit template on a **test** host.
- [ ] Approve one backup + staged-copy run on a **copy** of a real store.
- [ ] Approve the observation window length and the rollback trigger.
- [ ] Approve the retirement step separately, after the window.
- [ ] Confirm that no production database, VPS, Dataset or customer environment change is implied by any of the above.
