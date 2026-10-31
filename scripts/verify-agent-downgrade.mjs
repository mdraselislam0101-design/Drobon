#!/usr/bin/env node
/**
 * Reproduce the pre-agent version's lossy reader ONLY on a newly-created,
 * isolated temporary JSON store. Never open real customer data or Dataset.
 * Requires: npm run build --workspace @drobon/shared && npm run build --workspace @drobon/api
 */
import { execFileSync, spawn } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, rmdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import ts from 'typescript';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const oldCommit = 'c01edd460346ad05e5a56a7f5d99d26e5483cf0f';
const distScans = join(root, 'apps/api/dist/scans');
const dir = mkdtempSync(join(tmpdir(), 'drobon-downgrade-synthetic-'));
function waitForChild(child, kind, stderr) {
  return new Promise((resolveMessage, reject) => {
    const timeout = setTimeout(() => { cleanup(); reject(new Error(`Synthetic old process timed out: ${stderr()}`)); }, 15_000);
    const onMessage = (message) => {
      if (message?.kind !== kind) return;
      cleanup(); resolveMessage(message);
    };
    const onExit = () => { cleanup(); reject(new Error(`Synthetic old process exited early: ${stderr()}`)); };
    const cleanup = () => { clearTimeout(timeout); child.off('message', onMessage); child.off('exit', onExit); };
    child.on('message', onMessage);
    child.once('exit', onExit);
  });
}
try {
  const source = execFileSync('git', ['show', `${oldCommit}:apps/api/src/scans/store.ts`], { cwd: root, encoding: 'utf8' });
  let compiled = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.ES2022, target: ts.ScriptTarget.ES2022 } }).outputText;
  // Resolve old relative imports to the current built helper modules. The
  // old scan-store parser and persistence code themselves are from oldCommit.
  compiled = compiled.replace(/(from\s+['"])([^'"]+)(['"])/g, (match, before, specifier, after) => {
    if (specifier.startsWith('.')) return before + pathToFileURL(resolve(distScans, specifier)).href + after;
    if (specifier === '@drobon/shared') return before + pathToFileURL(join(root, 'packages/shared/dist/index.js')).href + after;
    return match;
  });
  const oldModule = join(dir, 'old-scan-store.mjs');
  writeFileSync(oldModule, compiled);
  const current = await import(pathToFileURL(join(distScans, 'store.js')).href);
  const old = await import(pathToFileURL(oldModule).href);
  const path = join(dir, 'synthetic-scans.json');
  const store = current.createJsonFileScanStore(path);
  const projectId = 'prj_00000000-0000-4000-8000-000000000001';
  const create = (scanType) => store.createScanWithQuota({
    ownerId: 'usr_synthetic', projectId, scanType, assessmentId: 'asm_00000000-0000-4000-8000-000000000001',
    agent: { version: 1, datasetDigest: 'a'.repeat(64), sourceDigest: 'b'.repeat(64), engagementId: 'eng_00000000-0000-4000-8000-000000000001' },
    consume: async () => ({ ok: true, rollback: async () => {} }),
  });
  const created = await create('SAST');
  const other = await create('SECRETS');
  if (created.outcome !== 'created' || other.outcome !== 'created') throw new Error('Synthetic jobs were not created.');
  const ids = [created.scan.id, other.scan.id];
  const beforeBytes = readFileSync(path);
  const before = JSON.parse(beforeBytes);
  let oldRejectsVersion2 = false;
  try { old.createJsonFileScanStore(path); } catch { oldRejectsVersion2 = true; }
  // Recreate the earlier unsafe format only in a separate synthetic file.
  // This demonstrates what an old reader does to it, not a real migration.
  const unsafePath = join(dir, 'synthetic-unsafe-version1.json');
  writeFileSync(unsafePath, JSON.stringify({ ...before, version: 1 }));
  let currentRejectsUnsafeV1 = false;
  try { current.createJsonFileScanStore(unsafePath); } catch { currentRejectsUnsafeV1 = true; }
  const oldStore = old.createJsonFileScanStore(unsafePath);
  const oldView = await oldStore.findByProjectAndId(projectId, created.scan.id);
  const claimed = await oldStore.claimNextQueued();
  const after = JSON.parse(readFileSync(unsafePath, 'utf8'));
  const savedClaimed = after.scans.find((scan) => scan.id === claimed?.id);
  const savedOther = after.scans.find((scan) => scan.id !== claimed?.id);
  // A separate scratch-only stale-writer rehearsal: old code loads a v1
  // legacy document before a simulated cutover, then writes its cached v1
  // state after the file has become v2. The original v2 store is untouched.
  const stalePath = join(dir, 'synthetic-stale-writer.json');
  const legacyStore = current.createJsonFileScanStore(stalePath);
  const legacy = await legacyStore.createScanWithQuota({ ownerId: 'usr_synthetic', projectId, scanType: 'SAST',
    consume: async () => ({ ok: true, rollback: async () => {} }) });
  if (legacy.outcome !== 'created') throw new Error('Synthetic legacy job was not created.');
  const legacyDocument = JSON.parse(readFileSync(stalePath, 'utf8'));
  const staleWriter = old.createJsonFileScanStore(stalePath);
  const cutover = { ...legacyDocument, version: 2, scans: [...legacyDocument.scans, ...before.scans] };
  const cutoverBytes = Buffer.from(JSON.stringify(cutover));
  const cutoverBackupPath = join(dir, 'synthetic-v2-backup.json');
  writeFileSync(cutoverBackupPath, cutoverBytes);
  writeFileSync(stalePath, cutoverBytes); // only the fixture-owned scratch path
  const validatedCutover = await current.createJsonFileScanStore(stalePath).listByProject(projectId);
  const staleClaim = await staleWriter.claimNextQueued();
  const afterStaleWrite = JSON.parse(readFileSync(stalePath, 'utf8'));

  // Separate-process coexistence rehearsal. The old process opens v1 first.
  // The parent then simulates a v2 cutover and holds BOTH the standard local
  // socket lease (on Linux) and the new advisory file lock. Old code does
  // not cooperate with either, so it can still publish a stale v1 snapshot.
  const processPath = join(dir, 'synthetic-separate-process.json');
  const processLegacyStore = current.createJsonFileScanStore(processPath);
  const processLegacy = await processLegacyStore.createScanWithQuota({ ownerId: 'usr_synthetic', projectId, scanType: 'SAST',
    consume: async () => ({ ok: true, rollback: async () => {} }) });
  if (processLegacy.outcome !== 'created') throw new Error('Synthetic process fixture was not created.');
  const processLegacyDocument = JSON.parse(readFileSync(processPath, 'utf8'));
  const childScript = `
    import { createJsonFileScanStore } from ${JSON.stringify(pathToFileURL(oldModule).href)};
    const store = createJsonFileScanStore(${JSON.stringify(processPath)});
    process.send({ kind: 'ready' });
    process.on('message', async (message) => {
      if (message !== 'claim') return;
      const scan = await store.claimNextQueued();
      process.send({ kind: 'done', id: scan?.id, status: scan?.status }, () => process.exit(0));
    });
  `;
  const child = spawn(process.execPath, ['--input-type=module', '-e', childScript], { stdio: ['ignore', 'ignore', 'pipe', 'ipc'] });
  let childError = '';
  child.stderr.on('data', (chunk) => { childError += chunk.toString(); });
  const leaseModule = await import(pathToFileURL(join(root, 'apps/api/dist/lib/jsonStoreLease.js')).href);
  let processLease;
  let lockHeld = false;
  const lockPath = join(dir, '.synthetic-separate-process.json.drobon-write-lock');
  let separateOldOverwrote = false;
  let separateOldDropped = false;
  let oldIgnoredAdvisoryLock = false;
  let staleNewFenced = false;
  let standardLeaseGuarded = false;
  let processBackupUnchanged = false;
  let processCutoverContainsThree = false;
  try {
    await waitForChild(child, 'ready', () => childError);
    processLease = await leaseModule.acquireJsonStoreLeases([processPath]);
    standardLeaseGuarded = processLease.guarded;
    const processCutover = { ...processLegacyDocument, version: 2, scans: [...processLegacyDocument.scans, ...before.scans] };
    const processCutoverBytes = Buffer.from(JSON.stringify(processCutover));
    const processBackupPath = join(dir, 'synthetic-separate-process-backup.json');
    writeFileSync(processBackupPath, processCutoverBytes);
    writeFileSync(processPath, processCutoverBytes); // fixture-owned path only; not a real migration
    const staleNew = current.createJsonFileScanStore(processPath);
    processCutoverContainsThree = (await staleNew.listByProject(projectId)).length === 3;
    mkdirSync(lockPath, { mode: 0o700 });
    lockHeld = true;
    const finished = waitForChild(child, 'done', () => childError);
    child.send('claim');
    const oldResult = await finished;
    const processAfter = JSON.parse(readFileSync(processPath, 'utf8'));
    separateOldOverwrote = oldResult.id === processLegacy.scan.id && oldResult.status === 'RUNNING' && processAfter.version === 1;
    separateOldDropped = ids.every((id) => processAfter.scans.every((scan) => scan.id !== id));
    processBackupUnchanged = readFileSync(processBackupPath).equals(processCutoverBytes);
    oldIgnoredAdvisoryLock = lockHeld && existsSync(lockPath) && separateOldOverwrote;
    rmdirSync(lockPath); // this fixture alone created the empty directory
    lockHeld = false;
    try { await staleNew.claimNextQueued(); }
    catch (error) { staleNewFenced = error instanceof Error && /changed|fenced/i.test(error.message); }
  } finally {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    if (lockHeld) rmdirSync(lockPath);
    if (processLease !== undefined) await processLease.release();
  }
  const result = {
    baselineCommit: oldCommit,
    oldCodeScope: 'old scan-store parser and persistence; current built helper modules',
    syntheticOnly: true,
    newAgentStoreVersion2: before.version === 2,
    agentMetadataOnDiskBefore: before.scans.length === 2 && before.scans.every((scan) => scan.agent !== undefined),
    oldReaderRejectsVersion2: oldRejectsVersion2,
    currentReaderRejectsUnsafeVersion1: currentRejectsUnsafeV1,
    safeVersion2BytesUnchanged: readFileSync(path).equals(beforeBytes),
    oldReaderFindsUnsafeV1Scan: oldView?.id === created.scan.id,
    oldReaderExposesAgentMetadata: oldView?.agent !== undefined,
    oldReaderClaimsUnsafeV1Job: claimed !== undefined && ids.includes(claimed.id) && claimed.status === 'RUNNING',
    claimedUnsafeV1JobMetadataLost: savedClaimed?.status === 'RUNNING' && savedClaimed.agent === undefined,
    otherUnsafeV1JobStillQueuedButMetadataLost: savedOther?.status === 'QUEUED' && savedOther.agent === undefined,
    validSyntheticV2CutoverContainsAllThreeJobs: validatedCutover.length === 3,
    staleWriterRewritesV2AsV1: staleClaim?.id === legacy.scan.id && afterStaleWrite.version === 1,
    staleWriterDropsBothAgentJobs: ids.every((id) => afterStaleWrite.scans.every((scan) => scan.id !== id)),
    cutoverBackupAndOriginalV2BytesUnchanged: readFileSync(cutoverBackupPath).equals(cutoverBytes) && readFileSync(path).equals(beforeBytes),
    separateProcessCutoverContainedThreeJobs: processCutoverContainsThree,
    separateProcessBackupBytesUnchanged: processBackupUnchanged,
    separateProcessOldWriterIgnoredAdvisoryLock: oldIgnoredAdvisoryLock,
    standardLocalLeaseHeldOnLinux: process.platform === 'linux' ? standardLeaseGuarded : 'not available on this platform',
    separateProcessOldWriterOverwroteV2AsV1: separateOldOverwrote,
    separateProcessOldWriterDroppedAgentJobs: separateOldDropped,
    staleNewWriterFencedAfterOldOverwrite: staleNewFenced,
  };
  if (!result.newAgentStoreVersion2 || !result.agentMetadataOnDiskBefore || !result.oldReaderRejectsVersion2 ||
      !result.currentReaderRejectsUnsafeVersion1 || !result.safeVersion2BytesUnchanged || !result.oldReaderFindsUnsafeV1Scan ||
      result.oldReaderExposesAgentMetadata || !result.oldReaderClaimsUnsafeV1Job || !result.claimedUnsafeV1JobMetadataLost ||
      !result.otherUnsafeV1JobStillQueuedButMetadataLost || !result.validSyntheticV2CutoverContainsAllThreeJobs ||
      !result.staleWriterRewritesV2AsV1 || !result.staleWriterDropsBothAgentJobs || !result.cutoverBackupAndOriginalV2BytesUnchanged ||
      !result.separateProcessCutoverContainedThreeJobs || !result.separateProcessBackupBytesUnchanged ||
      !result.separateProcessOldWriterIgnoredAdvisoryLock || (process.platform === 'linux' && !standardLeaseGuarded) ||
      !result.separateProcessOldWriterOverwroteV2AsV1 || !result.separateProcessOldWriterDroppedAgentJobs ||
      !result.staleNewWriterFencedAfterOldOverwrite) {
    throw new Error(`Unexpected compatibility result: ${JSON.stringify(result)}`);
  }
  console.log(JSON.stringify(result, null, 2));
} finally {
  // This path was created by this script and contains only synthetic records.
  rmSync(dir, { recursive: true, force: true });
}
