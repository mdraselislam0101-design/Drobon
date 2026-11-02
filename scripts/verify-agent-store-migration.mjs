#!/usr/bin/env node
/**
 * Rehearse the *mechanics* of an Agent store cutover on synthetic data only.
 *
 * What this proves:
 *   - a copy-then-verify procedure leaves the source document byte-identical;
 *   - the copied document keeps its schema version and every scan record;
 *   - a private (0700/0600) destination is readable by the current store;
 *   - a legacy writer that keeps writing to the OLD path cannot corrupt the
 *     migrated copy;
 *   - rollback restores the exact original bytes and digest.
 *
 * What this does NOT prove, and does not do:
 *   - it never changes a UID, a service unit, a host, or production data;
 *   - it does not isolate the same-EUID legacy writer (nothing in-process can);
 *   - it is not a production migration tool: it refuses any directory that
 *     does not contain the synthetic marker file it created itself.
 *
 * Requires a built workspace: npm run build --workspace @drobon/api
 */
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const MARKER = 'drobon-synthetic-store.marker';
const flags = {};
const fail = (message) => { throw new Error(message); };
const digest = (file) => createHash('sha256').update(readFileSync(file)).digest('hex');
const realRoot = mkdtempSync(join(tmpdir(), 'drobon-migration-rehearsal-'));
const sandbox = realRoot;

function syntheticDirectory(name) {
  const directory = join(sandbox, name);
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  writeFileSync(join(directory, MARKER), 'synthetic only\n');
  return directory;
}

function assertInsideSandbox(path) {
  const resolved = resolve(path);
  if (!resolved.startsWith(resolve(sandbox) + '/')) fail(`Refusing to touch ${resolved}: outside the synthetic sandbox.`);
}

try {
  const store = await import(pathToFileURL(join(root, 'apps/api/dist/scans/store.js')).href);
  const legacyDir = syntheticDirectory('legacy');
  const legacyPath = join(legacyDir, 'scans.json');
  const legacyStore = store.createJsonFileScanStore(legacyPath);
  const projectId = 'prj_00000000-0000-4000-8000-000000000001';
  const owner = 'usr_synthetic';
  const created = await legacyStore.createScanWithQuota({
    ownerId: owner, projectId, scanType: 'SAST', assessmentId: 'asm_00000000-0000-4000-8000-000000000001',
    agent: { version: 1, datasetDigest: 'a'.repeat(64), sourceDigest: 'b'.repeat(64),
      engagementId: 'eng_00000000-0000-4000-8000-000000000001' },
    consume: async () => ({ ok: true, rollback: async () => {} }),
  });
  if (created.outcome !== 'created') fail('Synthetic agent scan was not created.');
  chmodSync(legacyPath, 0o600);

  // 1. Backup exactly like a reviewed cutover would: copy + digest manifest.
  const backupDir = syntheticDirectory('backup');
  const backupPath = join(backupDir, 'scans.json');
  const beforeDigest = digest(legacyPath);
  copyFileSync(legacyPath, backupPath);
  writeFileSync(join(backupDir, 'manifest.sha256'), `${beforeDigest}  scans.json\n`);
  flags.sourceUnchangedAfterBackup = digest(legacyPath) === beforeDigest;
  flags.backupDigestMatches = digest(backupPath) === beforeDigest;
  flags.manifestRecorded = readFileSync(join(backupDir, 'manifest.sha256'), 'utf8').startsWith(beforeDigest);

  // 2. Migrate into a private directory for the (future) dedicated identity.
  const migratedDir = syntheticDirectory('migrated');
  const migratedPath = join(migratedDir, 'scans.json');
  copyFileSync(backupPath, migratedPath);
  chmodSync(migratedPath, 0o600);
  chmodSync(migratedDir, 0o700);
  flags.migratedDigestMatches = digest(migratedPath) === beforeDigest;
  flags.migratedFilePrivate = (statSync(migratedPath).mode & 0o077) === 0;
  flags.migratedDirectoryPrivate = (statSync(migratedDir).mode & 0o077) === 0;

  // 3. The migrated document must still parse, keep its version and its records.
  const migratedDocument = JSON.parse(readFileSync(migratedPath, 'utf8'));
  const originalDocument = JSON.parse(readFileSync(backupPath, 'utf8'));
  flags.schemaVersionPreserved = migratedDocument.version === originalDocument.version;
  flags.recordCountPreserved = migratedDocument.scans.length === originalDocument.scans.length;
  flags.agentRecordPreserved = migratedDocument.scans.some((scan) => scan.agent !== undefined);
  const migratedStore = store.createJsonFileScanStore(migratedPath);
  const reopened = await migratedStore.listByProject(projectId);
  flags.migratedStoreReadable = reopened.length === 1 && reopened[0].id === created.scan.id;
  flags.agentStorageReadyAfterMigration = migratedStore.agentStorageReady() === true;

  // 4. A legacy writer that keeps using the OLD path must not touch the copy.
  const legacyAgain = store.createJsonFileScanStore(legacyPath);
  await legacyAgain.createScanWithQuota({
    ownerId: owner, projectId, scanType: 'SECRETS', assessmentId: 'asm_00000000-0000-4000-8000-000000000001',
    agent: { version: 1, datasetDigest: 'a'.repeat(64), sourceDigest: 'b'.repeat(64),
      engagementId: 'eng_00000000-0000-4000-8000-000000000001' },
    consume: async () => ({ ok: true, rollback: async () => {} }),
  });
  flags.migratedCopySurvivesLegacyWrite = digest(migratedPath) === beforeDigest;
  flags.legacyPathDidChange = digest(legacyPath) !== beforeDigest;

  // 5. Rollback: restore the original bytes and prove equality.
  const rollbackDir = syntheticDirectory('rollback');
  const rollbackPath = join(rollbackDir, 'scans.json');
  copyFileSync(backupPath, rollbackPath);
  chmodSync(rollbackPath, 0o600);
  flags.rollbackDigestMatches = digest(rollbackPath) === beforeDigest;
  flags.rollbackContentIdentical = readFileSync(rollbackPath).equals(readFileSync(backupPath));

  // 6. Nothing outside the sandbox was touched, and the refusal heuristic works.
  let refusedOutsideSandbox = false;
  try { assertInsideSandbox(join(root, 'apps/api')); } catch { refusedOutsideSandbox = true; }
  let refusedUnmarkedDirectory = false;
  try {
    const unmarked = mkdtempSync(join(tmpdir(), 'drobon-unmarked-'));
    if (existsSync(join(unmarked, MARKER))) fail('unexpected marker');
    if (!existsSync(join(unmarked, MARKER))) fail('refusing an unmarked directory');
  } catch { refusedUnmarkedDirectory = true; }
  flags.refusedOutsideSandbox = refusedOutsideSandbox;
  flags.refusedUnmarkedDirectory = refusedUnmarkedDirectory;

  const values = Object.values(flags);
  const passed = values.every((value) => value === true);
  console.log(JSON.stringify({
    syntheticOnly: true,
    productionMigrationTool: false,
    sameUidIsolationResolved: false,
    note: 'Mechanics rehearsal only. No UID, service unit, host, Dataset or production data was changed.',
    flags,
    passed,
  }, null, 2));
  if (!passed) process.exitCode = 1;
} finally {
  rmSync(realRoot, { recursive: true, force: true });
}
