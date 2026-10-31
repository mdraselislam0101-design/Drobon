#!/usr/bin/env node
/**
 * Disposable Linux DAC experiment, NOT an application cutover or a migration.
 * Bundles actual pinned legacy and current scan-store source with local
 * dependencies, without relying on or overwriting an existing API build.
 * One stale writer runs as the current UID, another in a user namespace mapped
 * to that host UID, and another as `nobody` using non-interactive sudo. Only
 * synthetic files under our temp directory are read/written. No Dataset,
 * production store, or remote target is touched.
 *
 * This proves individual permission cases; it does not provision identities,
 * restrict every real writer, or make the Main App production-safe.
 */
import { build } from 'esbuild';
import { execFileSync, spawn } from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';
import fs from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { createInterface } from 'node:readline';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { isDeepStrictEqual } from 'node:util';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const oldCommit = 'c01edd460346ad05e5a56a7f5d99d26e5483cf0f';
const projectId = 'prj_00000000-0000-4000-8000-000000000001';
const assessmentId = 'asm_00000000-0000-4000-8000-000000000001';
const ownerId = 'usr_synthetic';
const agent = { version: 1, datasetDigest: 'a'.repeat(64), sourceDigest: 'b'.repeat(64),
  engagementId: 'eng_00000000-0000-4000-8000-000000000001' };
const consume = async () => ({ ok: true });
const sleepCell = new Int32Array(new SharedArrayBuffer(4));

function requireCondition(condition, message) {
  if (!condition) throw new Error(`Synthetic OS-boundary assertion failed: ${message}`);
}
function identityAsNobody() {
  try {
    const text = execFileSync('sudo', ['-n', '-u', 'nobody', '--', process.execPath, '-p',
      'JSON.stringify({uid:process.getuid(),groups:process.getgroups()})'],
    { cwd: tmpdir(), encoding: 'utf8', timeout: 10_000, stdio: ['ignore', 'pipe', 'pipe'] });
    return JSON.parse(text);
  } catch {
    throw new Error('BLOCKED: this rehearsal needs non-interactive sudo to run a child as the existing nobody UID.');
  }
}

// Line protocol so the child can drop credentials through sudo without IPC fd
// inheritance, and remains a genuinely separate OS process throughout cutover.
function startLegacyWriter(bundle, path, stateDir, signalDir, identity) {
  const source = `
    import { createJsonFileScanStore } from ${JSON.stringify(pathToFileURL(bundle).href)};
    import { chmodSync, closeSync, existsSync, fstatSync, ftruncateSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeFileSync, writeSync } from 'node:fs';
    import { createInterface } from 'node:readline';
    const path = ${JSON.stringify(path)};
    const stateDir = ${JSON.stringify(stateDir)};
    const signalDir = ${JSON.stringify(signalDir)};
    const store = createJsonFileScanStore(path);
    const oldFile = openSync(path, 'r+');
    const oldDirectory = openSync(stateDir, 'r');
    const send = (kind, data = {}) => console.log(JSON.stringify({ kind, ...data }));
    const codeOf = (error) => error && typeof error === 'object' ? (error.code ?? null) : null;
    const call = async (action) => { try { return { ok: true, value: await action() }; }
      catch (error) { return { ok: false, code: codeOf(error), syscall: error?.syscall ?? null }; } };
    const watchdog = setTimeout(() => process.exit(3), 30_000);
    const oldInfo = fstatSync(oldFile, { bigint: true });
    send('ready', { uid: process.getuid(), groups: process.getgroups(), oldInode: String(oldInfo.ino),
      oldDevice: String(oldInfo.dev), uidMap: readFileSync('/proc/self/uid_map', 'utf8').trim() });
    for await (const line of createInterface({ input: process.stdin })) {
      const command = JSON.parse(line).command;
      if (command === 'claim') {
        send('claim', await call(() => store.claimNextQueued()));
      } else if (command === 'inspect') {
        const document = JSON.parse(readFileSync(path, 'utf8'));
        send('inspect', { version: document.version, ids: document.scans.map((scan) => scan.id) });
      } else if (command === 'alternate') {
        const read = await call(() => { const fd = openSync(path, 'r'); closeSync(fd); return true; });
        const inheritedDirectory = await call(() => { const fd = openSync('/proc/self/fd/' + oldDirectory + '/scans.json', 'r+'); closeSync(fd); return true; });
        const injected = await call(() => { createJsonFileScanStore(path); return true; });
        const tmp = signalDir + '/foreign-' + process.pid + '.tmp';
        writeFileSync(tmp, 'synthetic external replacement');
        const rename = await call(() => { renameSync(tmp, path); return true; });
        try { unlinkSync(tmp); } catch { /* The successful control already renamed it. */ }
        send('alternate', { read, inheritedDirectory, injected, rename });
      } else if (command === 'move-directory') {
        // Explicitly adversarial raw filesystem operation, not stock legacy
        // scan-store behavior. Requires a writable parent of stateDir.
        const moved = await call(() => {
          renameSync(stateDir, stateDir + '-displaced');
          mkdirSync(stateDir, { mode: 0o777 });
          chmodSync(stateDir, 0o777);
          return true;
        });
        send('move-directory', moved);
      } else if (command === 'old-fd') {
        ftruncateSync(oldFile, 0);
        writeSync(oldFile, 'synthetic old inode only', 0, 'utf8');
        send('old-fd', { ok: true });
      } else if (command === 'arm-race') {
        let working = false;
        const interval = setInterval(async () => {
          if (working || !existsSync(signalDir + '/go')) return;
          working = true; clearInterval(interval);
          const result = await call(() => store.claimNextQueued());
          writeFileSync(signalDir + '/done', JSON.stringify(result));
          send('race-done', result);
        }, 1);
        send('armed');
      } else if (command === 'stop') {
        break;
      }
    }
    clearTimeout(watchdog);
    closeSync(oldDirectory); closeSync(oldFile);
  `;
  const command = identity === 'nobody' ? 'sudo' : identity === 'namespace' ? 'unshare' : process.execPath;
  const args = identity === 'nobody'
    ? ['-n', '-u', 'nobody', '--', process.execPath, '--input-type=module', '-e', source]
    : identity === 'namespace'
      ? ['-Ur', '--', process.execPath, '--input-type=module', '-e', source]
      : ['--input-type=module', '-e', source];
  const child = spawn(command, args, { cwd: tmpdir(), stdio: ['pipe', 'pipe', 'pipe'] });
  const lines = createInterface({ input: child.stdout });
  const buffered = [];
  const pending = [];
  let stderr = '';
  let closed = false;
  child.stderr.on('data', (chunk) => { stderr += chunk.toString(); });
  lines.on('line', (line) => {
    let message;
    try { message = JSON.parse(line); } catch { return; }
    const index = pending.findIndex((item) => item.kind === message.kind);
    if (index >= 0) {
      const [item] = pending.splice(index, 1);
      clearTimeout(item.timer);
      item.resolve(message);
    } else buffered.push(message);
  });
  child.on('error', (error) => {
    for (const item of pending.splice(0)) { clearTimeout(item.timer); item.reject(error); }
  });
  child.on('exit', (code, signal) => {
    closed = true;
    for (const item of pending.splice(0)) {
      clearTimeout(item.timer);
      item.reject(new Error(`Synthetic legacy child exited ${code ?? signal}: ${stderr.slice(0, 1000)}`));
    }
  });
  return {
    child,
    wait(kind) {
      const index = buffered.findIndex((item) => item.kind === kind);
      if (index >= 0) return Promise.resolve(buffered.splice(index, 1)[0]);
      if (closed) return Promise.reject(new Error(`Synthetic legacy child already exited: ${stderr.slice(0, 1000)}`));
      return new Promise((resolveMessage, reject) => {
        const item = { kind, resolve: resolveMessage, reject, timer: undefined };
        item.timer = setTimeout(() => {
          const position = pending.indexOf(item);
          if (position >= 0) pending.splice(position, 1);
          reject(new Error(`Synthetic legacy child did not respond to ${kind}: ${stderr.slice(0, 1000)}`));
        }, 15_000);
        pending.push(item);
      });
    },
    send(command) { child.stdin.write(`${JSON.stringify({ command })}\n`); },
    async stop() {
      if (closed) return;
      child.stdin.end(`${JSON.stringify({ command: 'stop' })}\n`);
      let timer;
      await Promise.race([
        new Promise((resolveExit) => child.once('exit', resolveExit)),
        new Promise((resolveTimeout) => { timer = setTimeout(() => { child.kill('SIGTERM'); resolveTimeout(); }, 3000); }),
      ]);
      clearTimeout(timer);
    },
  };
}

if (process.platform !== 'linux' || typeof process.getuid !== 'function') {
  throw new Error('BLOCKED: the UID and inherited-directory-fd rehearsal requires Linux.');
}
const differentIdentity = identityAsNobody();
requireCondition(Number.isInteger(differentIdentity.uid) && differentIdentity.uid !== process.getuid(), 'distinct effective UID');
const temp = fs.mkdtempSync(join(tmpdir(), 'drobon-os-boundary-synthetic-'));
fs.chmodSync(temp, 0o711); // traversal only, and the directory contains synthetic fixtures only
const oldRoot = join(temp, 'old-source');
const bundle = join(temp, 'legacy-scan-store.mjs');
const children = [];
let originalRename;
try {
  fs.mkdirSync(oldRoot);
  const archive = execFileSync('git', ['archive', '--format=tar', oldCommit, 'apps/api/src', 'apps/api/package.json',
    'packages/shared/src', 'packages/shared/package.json', 'packages/shared/tsconfig.json',
    'packages/shared/tsconfig.build.json', 'tsconfig.base.json'], { cwd: root, maxBuffer: 32 * 1024 * 1024 });
  const archivePath = join(temp, 'source.tar');
  fs.writeFileSync(archivePath, archive, { mode: 0o600 });
  execFileSync('tar', ['-xf', archivePath, '-C', oldRoot], { timeout: 30_000 });
  const oldModules = join(oldRoot, 'node_modules');
  fs.mkdirSync(oldModules);
  for (const name of fs.readdirSync(join(root, 'node_modules'))) {
    if (name === '@drobon' || name === '.bin') continue;
    fs.symlinkSync(join(root, 'node_modules', name), join(oldModules, name));
  }
  fs.mkdirSync(join(oldModules, '@drobon'));
  fs.symlinkSync(join(oldRoot, 'packages/shared'), join(oldModules, '@drobon/shared'));
  execFileSync(process.execPath, [join(root, 'node_modules/typescript/bin/tsc'), '-p', join(oldRoot, 'packages/shared/tsconfig.build.json')],
    { cwd: oldRoot, stdio: 'pipe', timeout: 60_000 });
  await build({ entryPoints: [join(oldRoot, 'apps/api/src/scans/store.ts')], outfile: bundle,
    bundle: true, platform: 'node', format: 'esm', target: 'node20', logLevel: 'silent' });
  fs.chmodSync(bundle, 0o644); // old child can read synthetic, bundled code
  // Bundle the current source and current shared contracts in this disposable
  // directory, so an old dist build cannot silently become the test subject.
  const currentEntry = join(temp, 'current-entry.ts');
  const currentBundle = join(temp, 'current-scan-store.mjs');
  fs.writeFileSync(currentEntry, `export { createJsonFileScanStore } from ${JSON.stringify(join(root, 'apps/api/src/scans/store.ts'))};\n` +
    `export { writePrivateJson } from ${JSON.stringify(join(root, 'apps/api/src/lib/writePrivateJson.ts'))};\n`);
  await build({ entryPoints: [currentEntry], outfile: currentBundle,
    alias: { '@drobon/shared': join(root, 'packages/shared/src/index.ts') },
    bundle: true, platform: 'node', format: 'esm', target: 'node20', logLevel: 'silent' });
  const current = await import(pathToFileURL(currentBundle).href);
  const privateWrite = current;
  const templatePath = join(temp, 'template.json');
  const template = current.createJsonFileScanStore(templatePath);
  for (const scanType of ['SAST', 'SECRETS']) {
    const created = await template.createScanWithQuota({ ownerId, projectId, assessmentId, scanType, agent, consume });
    requireCondition(created.outcome === 'created', 'two synthetic Agent fixtures created');
  }
  const agentDocument = JSON.parse(fs.readFileSync(templatePath, 'utf8'));
  const agentIds = agentDocument.scans.map((scan) => scan.id);

  async function fixture(name, directoryMode, identity, writableAncestor = false) {
    const ancestor = writableAncestor ? join(temp, `${name}-ancestor`) : temp;
    if (writableAncestor) { fs.mkdirSync(ancestor, { mode: 0o777 }); fs.chmodSync(ancestor, 0o777); }
    const dir = join(ancestor, name);
    const signals = join(temp, `${name}-signals`);
    fs.mkdirSync(dir, { mode: directoryMode }); fs.chmodSync(dir, directoryMode);
    fs.mkdirSync(signals, { mode: 0o777 }); fs.chmodSync(signals, 0o777);
    const path = join(dir, 'scans.json');
    const legacy = current.createJsonFileScanStore(path);
    requireCondition((await legacy.createScanWithQuota({ ownerId, projectId, scanType: 'SAST', consume })).outcome === 'created', 'legacy fixture created');
    const document = JSON.parse(fs.readFileSync(path, 'utf8'));
    // Initial v1 must be readable/writable through a descriptor by the old UID.
    fs.chmodSync(path, identity === 'nobody' ? 0o666 : 0o600);
    const writer = startLegacyWriter(bundle, path, dir, signals, identity);
    children.push(writer);
    const ready = await writer.wait('ready');
    const expectedUid = identity === 'nobody' ? differentIdentity.uid : identity === 'namespace' ? 0 : process.getuid();
    requireCondition(ready.uid === expectedUid, 'legacy writer effective identity');
    return { dir, signals, path, document, writer, ready };
  }
  function publishSyntheticV2(fixture) {
    const bytes = `${JSON.stringify({ ...fixture.document, version: 2,
      scans: [...fixture.document.scans, ...agentDocument.scans] }, null, 2)}\n`;
    // Fresh inode via current atomic writer; NOT a migration implementation.
    privateWrite.writePrivateJson(fixture.path, bytes);
    return Buffer.from(bytes);
  }
  function inspectDamage(path) {
    const result = JSON.parse(fs.readFileSync(path, 'utf8'));
    return { version: result.version, remainingAgentIds: agentIds.filter((id) => result.scans.some((scan) => scan.id === id)).length };
  }

  // Control 1: private directory does not distinguish two processes with the same UID.
  const same = await fixture('same-uid', 0o700, 'same');
  publishSyntheticV2(same);
  const sameLock = join(same.dir, '.scans.json.drobon-write-lock');
  fs.mkdirSync(sameLock, { mode: 0o700 });
  same.writer.send('claim');
  const sameClaim = await same.writer.wait('claim');
  const sameDamage = inspectDamage(same.path);
  const sameUidCanOverwrite = sameClaim.ok && sameDamage.version === 1 && sameDamage.remainingAgentIds === 0 && fs.existsSync(sameLock);
  requireCondition(sameUidCanOverwrite, 'same UID defeats 0700 directory and ignores the advisory lock');
  await same.writer.stop();

  // A different user-namespace UID is not a different host identity: the
  // namespace maps its root to this process's real UID on the filesystem.
  const mapped = await fixture('same-host-uid-namespace', 0o700, 'namespace');
  const [mappedInside, mappedOutside, mappedCount] = mapped.ready.uidMap.split(/\s+/).map(Number);
  requireCondition(mappedInside === 0 && mappedOutside === process.getuid() && mappedCount >= 1,
    'namespace root maps to the original host UID');
  publishSyntheticV2(mapped);
  const mappedLock = join(mapped.dir, '.scans.json.drobon-write-lock');
  fs.mkdirSync(mappedLock, { mode: 0o700 });
  mapped.writer.send('claim');
  const mappedClaim = await mapped.writer.wait('claim');
  const mappedDamage = inspectDamage(mapped.path);
  const namespaceMappedSameUidCanOverwrite = mappedClaim.ok && mappedDamage.version === 1 &&
    mappedDamage.remainingAgentIds === 0 && fs.existsSync(mappedLock);
  requireCondition(namespaceMappedSameUidCanOverwrite, 'UID namespace alone cannot isolate the same host UID');
  await mapped.writer.stop();

  // Control 2: a 0600 file does not block rename by a different UID if its parent is writable.
  const fileOnly = await fixture('file-only', 0o777, 'nobody');
  publishSyntheticV2(fileOnly);
  requireCondition((fs.statSync(fileOnly.path).mode & 0o777) === 0o600, 'new file is owner-only');
  const fileOnlyLock = join(fileOnly.dir, '.scans.json.drobon-write-lock');
  fs.mkdirSync(fileOnlyLock, { mode: 0o700 });
  fileOnly.writer.send('claim');
  const fileOnlyClaim = await fileOnly.writer.wait('claim');
  // A successful rename creates a 0600 file owned by nobody; inspect it in
  // that child instead of escalating or altering the synthetic file's mode.
  fileOnly.writer.send('inspect');
  const fileOnlyDamage = await fileOnly.writer.wait('inspect');
  const privateFileWritableParentCanBeReplaced = fileOnlyClaim.ok && fileOnlyDamage.version === 1 &&
    agentIds.every((id) => !fileOnlyDamage.ids.includes(id)) && fs.existsSync(fileOnlyLock);
  requireCondition(privateFileWritableParentCanBeReplaced, '0600 file alone does not block rename in writable parent');
  await fileOnly.writer.stop();

  // An attacker able to rename the parent entry can displace an otherwise
  // private 0700 directory. This raw filesystem action is not a legacy API call.
  const looseAncestor = await fixture('loose-ancestor', 0o777, 'nobody', true);
  fs.chmodSync(looseAncestor.dir, 0o700);
  const intactBytes = publishSyntheticV2(looseAncestor);
  const originalDirectory = fs.statSync(looseAncestor.dir, { bigint: true });
  looseAncestor.writer.send('move-directory');
  const directoryMove = await looseAncestor.writer.wait('move-directory');
  const displaced = join(`${looseAncestor.dir}-displaced`, 'scans.json');
  const reopened = current.createJsonFileScanStore(looseAncestor.path);
  const reopenedEmpty = await reopened.listByProject(projectId);
  const divergent = await reopened.createScanWithQuota({ ownerId, projectId, assessmentId, scanType: 'SCA', agent, consume });
  const redirectedDoc = JSON.parse(fs.readFileSync(looseAncestor.path, 'utf8'));
  const writableAncestorCanDisplacePrivateDir = directoryMove.ok &&
    fs.statSync(looseAncestor.dir, { bigint: true }).ino !== originalDirectory.ino &&
    fs.readFileSync(displaced).equals(intactBytes) && reopenedEmpty.length === 0 &&
    divergent.outcome === 'created' && redirectedDoc.scans.length === 1 &&
    agentIds.every((id) => redirectedDoc.scans.every((scan) => scan.id !== id));
  requireCondition(writableAncestorCanDisplacePrivateDir,
    'writable parent can redirect a private directory; fresh store creates a divergent document');
  await looseAncestor.writer.stop();

  // Protected case: revoke the separate UID's directory access before publishing
  // a fresh inode. The stale old writer remains alive throughout this cutover.
  const protectedFixture = await fixture('protected', 0o777, 'nobody');
  fs.chmodSync(protectedFixture.dir, 0o700);
  const cutoverBytes = publishSyntheticV2(protectedFixture);
  const protectedLock = join(protectedFixture.dir, '.scans.json.drobon-write-lock');
  fs.mkdirSync(protectedLock, { mode: 0o700 });
  protectedFixture.writer.send('claim');
  const deniedClaim = await protectedFixture.writer.wait('claim');
  const heldLockBlocksNoLegacyCall = fs.existsSync(protectedLock) && !deniedClaim.ok && deniedClaim.code === 'EACCES';
  requireCondition(heldLockBlocksNoLegacyCall, 'cached old writer denied by filesystem with lock present');
  requireCondition(fs.readFileSync(protectedFixture.path).equals(cutoverBytes), 'all v2 bytes preserved after cached writer attempt');
  fs.rmdirSync(protectedLock);
  protectedFixture.writer.send('alternate');
  const alternate = await protectedFixture.writer.wait('alternate');
  requireCondition(!alternate.read.ok && alternate.read.code === 'EACCES', 'direct open denied');
  requireCondition(!alternate.inheritedDirectory.ok && alternate.inheritedDirectory.code === 'EACCES', 'pre-opened directory fd cannot reopen protected path');
  requireCondition(!alternate.injected.ok, 'new injected legacy file-store cannot open protected path');
  requireCondition(!alternate.rename.ok && alternate.rename.code === 'EACCES', 'replacement from alternate path denied');
  const publishedInfo = fs.statSync(protectedFixture.path, { bigint: true });
  requireCondition(String(publishedInfo.ino) !== protectedFixture.ready.oldInode ||
    String(publishedInfo.dev) !== protectedFixture.ready.oldDevice, 'newly published file has a different inode');
  protectedFixture.writer.send('old-fd');
  const oldFdResult = await protectedFixture.writer.wait('old-fd');
  requireCondition(oldFdResult.ok && fs.statSync(protectedFixture.path, { bigint: true }).ino === publishedInfo.ino &&
    fs.readFileSync(protectedFixture.path).equals(cutoverBytes), 'writing old descriptor cannot mutate newly published inode');

  // Deterministic separate-process interleaving: pause the CURRENT writer at
  // rename (after its temp file exists); release a stale legacy claim, wait for
  // EACCES, then allow current publication. The lock remains held at the barrier.
  const newStore = current.createJsonFileScanStore(protectedFixture.path);
  protectedFixture.writer.send('arm-race');
  await protectedFixture.writer.wait('armed');
  let lockPresentAtBarrier = false;
  let raceAttempt;
  originalRename = fs.renameSync;
  fs.renameSync = (from, to) => {
    if (to === protectedFixture.path) {
      lockPresentAtBarrier = fs.existsSync(protectedLock);
      fs.writeFileSync(join(protectedFixture.signals, 'go'), 'go');
      const done = join(protectedFixture.signals, 'done');
      const deadline = Date.now() + 8000;
      while (!fs.existsSync(done) && Date.now() < deadline) Atomics.wait(sleepCell, 0, 0, 10);
      if (!fs.existsSync(done)) throw new Error('Synthetic separate-process race timed out.');
      raceAttempt = JSON.parse(fs.readFileSync(done, 'utf8'));
    }
    return originalRename(from, to);
  };
  syncBuiltinESMExports();
  let created;
  try { created = await newStore.createScanWithQuota({ ownerId, projectId, assessmentId, scanType: 'SCA', agent, consume }); }
  finally { fs.renameSync = originalRename; syncBuiltinESMExports(); originalRename = undefined; }
  const raceDone = await protectedFixture.writer.wait('race-done');
  requireCondition(created.outcome === 'created' && lockPresentAtBarrier && raceAttempt?.code === 'EACCES' &&
    !raceAttempt.ok && !raceDone.ok && raceDone.code === 'EACCES', 'stale legacy claim denied during current pre-rename barrier');
  const finalDoc = JSON.parse(fs.readFileSync(protectedFixture.path, 'utf8'));
  const previousDoc = JSON.parse(cutoverBytes.toString('utf8'));
  const priorRecordsPreserved = previousDoc.scans.every((scan) =>
    isDeepStrictEqual(scan, finalDoc.scans.find((item) => item.id === scan.id))) &&
    ['idempotency', 'reports', 'findingWorkflows'].every((key) => isDeepStrictEqual(previousDoc[key], finalDoc[key]));
  requireCondition(finalDoc.version === 2 && finalDoc.scans.length === 4 && priorRecordsPreserved,
    'all prior records and other synthetic document sections retained after interleaving');
  await protectedFixture.writer.stop();

  console.log(JSON.stringify({ syntheticOnly: true, oldCommit, actualPinnedOldStoreBundled: true,
    parentUid: process.getuid(), distinctOldUid: differentIdentity.uid,
    oldWriterAlreadyRunningBeforeCutover: true, sameUidCanOverwritePrivateDirectory: sameUidCanOverwrite,
    sameHostUidMappedIntoUserNamespaceCanOverwrite: namespaceMappedSameUidCanOverwrite,
    distinctUidCanReplace0600FileInWritableParent: privateFileWritableParentCanBeReplaced,
    writableAncestorCanDisplacePrivateDirectory: writableAncestorCanDisplacePrivateDir,
    displacedPathReopenedAsDivergentNewStore: writableAncestorCanDisplacePrivateDir,
    distinctUidBlockedBy0700OwnedDirectory: heldLockBlocksNoLegacyCall,
    rawReadDenied: !alternate.read.ok && alternate.read.code === 'EACCES',
    preopenedDirectoryFdDenied: !alternate.inheritedDirectory.ok && alternate.inheritedDirectory.code === 'EACCES',
    injectedLegacyStoreRefused: !alternate.injected.ok,
    alternatePathRenameDenied: !alternate.rename.ok && alternate.rename.code === 'EACCES',
    preopenedOldFileFdCannotChangeNewInode: oldFdResult.ok,
    oldWriterDeniedAtNewWriterPreRename: !raceAttempt.ok && raceAttempt.code === 'EACCES',
    advisoryLockPresentDuringRace: lockPresentAtBarrier, allFourJobsPresent: finalDoc.scans.length === 4,
    priorRecordsAndSectionsPreserved: priorRecordsPreserved,
    mainAppProvisioningImplemented: false, productionSafe: false }, null, 2));
} finally {
  if (originalRename !== undefined) { fs.renameSync = originalRename; syncBuiltinESMExports(); }
  await Promise.allSettled(children.map((child) => child.stop()));
  fs.rmSync(temp, { recursive: true, force: true }); // only this script's synthetic test root
}
