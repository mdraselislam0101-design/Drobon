# Scan Store — Append Journal + Compaction Design (draft for approval)

**Status:** DESIGN ONLY · no code, no format change, no migration has been made.
**Findings targeted:** P1-6 (whole-document rewrite per transition), P1-10 (growth cost).
**Current format:** `.data/scans.json`, `version: 1 | 2`, one JSON object holding
`scans[]`, `idempotency[]`, `reports[]`, `findingWorkflows[]`, written atomically
(`lib/writePrivateJson.ts` + write fence + lease) on **every** transition
(`store.ts` → `persistWith(...)`).

---

## 1. Why this is not a small patch

Every guarantee the scan lifecycle relies on today comes from that one atomic
write: claim is at-most-once, terminal transitions are linearized, findings and
reports are committed with the scan, and startup can refuse a corrupt document.
Replacing it with appends changes the failure model (partial append, torn tail,
compaction crash), so it must be designed and rehearsed, not improvised.

**Cost today (measured shape, not a benchmark):** the bytes rewritten per
transition equal the whole document — exposed live by
`GET /api/v1/metrics` → `store.documentBytes`
(`estimatedFullRewriteBytes`). With N scans of average size S, one transition
costs O(N·S) I/O. Growth is therefore quadratic in scan count.

---

## 2. Target layout

```
.data/
  scans.snapshot.json     # full state at snapshotSeq, format version 3
  scans.journal           # append-only records, one JSON object per line
  scans.journal.lock      # existing writer lease (unchanged)
```

Journal record types (closed vocabulary, each ≤ 64 KiB):

| type | payload | replay effect |
|---|---|---|
| `scan.created` | full scan record | insert |
| `scan.claimed` | id, startedAt, attempt | mutate |
| `scan.requeued` | id, retryAt, attempt | mutate |
| `scan.cancel-requested` | id, at | mutate |
| `scan.completed` | id, resultSummary, findings?, sca?, dast?, completedAt | mutate |
| `scan.failed` / `scan.timed-out` | id, code, message, completedAt | mutate |
| `report.upsert` | full report | upsert |
| `workflow.upsert` | full workflow | upsert |
| `idempotency.add` | entry | append (bounded, oldest evicted on replay) |

Each record carries `seq` (monotonic) and `crc32` over its canonical JSON.

## 3. Write path

1. Serialize the record (`canonicalJson`), compute checksum.
2. `append` to the journal with `O_APPEND`, then `fsync` the file descriptor
   (not the directory) — one small write instead of a full-document rewrite.
3. Apply the mutation to the in-memory maps (as today, inside `runExclusive`).

**No change to the state machine**: `claimNextQueued`, `completeScan`,
`failScan`, `timeoutScan`, `requeueScan`, `requestScanCancellation` keep their
current transitions and guards; only the persistence call changes.

## 4. Read/replay path

1. Load `scans.snapshot.json` (must validate exactly like today's document; a
   corrupt snapshot still refuses startup).
2. Replay `scans.journal` line by line, stopping at the first malformed or
   checksum-failing line.
3. If the tail is torn (crash mid-append), **truncate the journal to the last
   valid record** and log a warning. This is the only destructive recovery
   action, and it only discards a record that was never acknowledged.
4. Rebuild the same in-memory structures, then run the existing validators
   (`parseStoredScan`) on every scan — an invalid record still refuses startup.

## 5. Compaction

Trigger: `journalBytes > max(4 MiB, 2 × snapshotBytes)` **and** no drain active.

1. Write `scans.snapshot.json.tmp` (canonical, validated, `fsync`).
2. `rename` to `scans.snapshot.json` (atomic on the same filesystem).
3. Truncate the journal only **after** the rename succeeds.

A crash between 2 and 3 leaves a snapshot *newer* than the journal start; replay
must therefore record `snapshotSeq` in the snapshot and ignore journal records
with `seq <= snapshotSeq`. That makes compaction idempotent and crash-safe.

## 6. Migration (version 2 → 3)

1. **Backup first**: copy `scans.json` to `scans.json.bak-<timestamp>` (verifiable
   size + SHA-256 recorded in the migration log). No migration runs without it.
2. Read the v2 document with today's loader (unchanged code path).
3. Write `scans.snapshot.json` (version 3) with `snapshotSeq: 0`.
4. Keep `scans.json` **read-only** (never deleted) for one release as the
   rollback artifact.
5. Rollback = delete/rename the new files and restore `scans.json`; both are
   complete, independent states.

## 7. Compatibility rules

- A v3 reader must refuse a document it does not understand (same fail-closed
  posture as today: `unsupported version 2 fields — refusing to start`).
- A v2 binary must **not** silently read a v3 directory: the presence of
  `scans.journal` next to a missing `scans.json` must be a startup error, not an
  empty queue.
- The agent-storage boundary (`lib/storageBoundary.ts`) and the write fence must
  learn the new paths, or the boundary attestation will (correctly) block startup.

## 8. Test plan (must all pass before merge)

| # | Test | Asserts |
|---|---|---|
| 1 | Replay equivalence | 1,000 mixed transitions replayed from journal ≡ same in-memory state as the current full-document store |
| 2 | Torn tail | a half-written final line is truncated, all earlier records survive, process boots |
| 3 | Checksum mismatch | a flipped byte refuses the record, not the file; earlier state intact |
| 4 | Crash during compaction (before rename / after rename / after truncate) | state is always one of the two valid states, never empty |
| 5 | Idempotent compaction | running compaction twice yields the same snapshot |
| 6 | v2 → v3 migration | same scans/reports/workflows/idempotency, backup byte-identical |
| 7 | v3 refusal by v2 binary | explicit startup error naming the unsupported format |
| 8 | Throughput sanity | 10k-scan document: append path writes < 1% of the full-document bytes (measured, not estimated) |

## 9. Estimated effort and risk

| Item | Estimate |
|---|---|
| Journal writer + replay + compaction + tests | 3–5 focused days |
| Migration + rollback rehearsal | 1 day (needs a real backup/restore rehearsal) |
| Risk if rushed | **data loss / silent scan loss** — unacceptable without items 1–7 above |

## 10. Interim mitigation already shipped

`GET /api/v1/metrics` now reports `store.documentBytes`,
`estimatedFullRewriteBytes`, `scans`, `reports`, `findingWorkflows` and
`idempotencyEntries`, so an operator can see growth and plan a maintenance
window instead of discovering it as a slow write. This does **not** fix P1-6.
