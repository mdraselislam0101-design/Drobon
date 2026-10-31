#!/usr/bin/env node
/**
 * Synthetic old/new full-API coexistence rehearsal, never production data.
 * Reads pinned Main App source via git archive into an isolated temp dir; it
 * does not read/copy the separate Dataset. Dependencies come from this local
 * installation. Requires local builds of current @drobon/shared and API.
 */
import { execFileSync, spawn } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, rmdirSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const oldCommit = 'c01edd460346ad05e5a56a7f5d99d26e5483cf0f';
if (process.platform !== 'linux') throw new Error('This synthetic rehearsal requires Linux abstract-socket leases.');
const temp = mkdtempSync(join(tmpdir(), 'drobon-server-coexist-synthetic-'));
const oldRoot = join(temp, 'old-main-app');
function waitMessage(child, kind, stderr) {
  return new Promise((resolveMessage, reject) => {
    const timer = setTimeout(() => { cleanup(); reject(new Error(`Synthetic server timed out: ${stderr()}`)); }, 25_000);
    const onMessage = (message) => { if (message?.kind === kind) { cleanup(); resolveMessage(message); } };
    const onExit = () => { cleanup(); reject(new Error(`Synthetic server exited early: ${stderr()}`)); };
    const cleanup = () => { clearTimeout(timer); child.off('message', onMessage); child.off('exit', onExit); };
    child.on('message', onMessage);
    child.once('exit', onExit);
  });
}
function memoryConfig(base, scanStorePath) {
  return { ...base, host: '127.0.0.1', port: 0, authStorePath: ':memory:', usageStorePath: ':memory:',
    projectStorePath: ':memory:', scanStorePath, assessmentStorePath: ':memory:', studentStorePath: ':memory:',
    sourceStorePath: ':memory:', paymentStorePath: ':memory:', entitlementStorePath: ':memory:',
    partnerStorePath: ':memory:', paymentConfigStorePath: ':memory:' };
}
let oldServer;
let newServer;
let lockHeld = false;
try {
  mkdirSync(oldRoot);
  const archive = execFileSync('git', ['archive', '--format=tar', oldCommit, 'apps/api/src', 'apps/api/package.json',
    'packages/shared/src', 'packages/shared/package.json', 'packages/shared/tsconfig.json',
    'packages/shared/tsconfig.build.json', 'tsconfig.base.json'], { cwd: root, maxBuffer: 32 * 1024 * 1024 });
  const archivePath = join(temp, 'old-main-app.tar');
  writeFileSync(archivePath, archive);
  execFileSync('tar', ['-xf', archivePath, '-C', oldRoot]);
  // Only local installed dependencies are linked. The old shared package is
  // compiled from the pinned commit, not the current shared source.
  const oldModules = join(oldRoot, 'node_modules');
  mkdirSync(oldModules);
  for (const name of readdirSync(join(root, 'node_modules'))) {
    if (name === '@drobon' || name === '.bin') continue;
    symlinkSync(join(root, 'node_modules', name), join(oldModules, name));
  }
  mkdirSync(join(oldModules, '@drobon'));
  symlinkSync(join(oldRoot, 'packages/shared'), join(oldModules, '@drobon/shared'));
  execFileSync(process.execPath, [join(root, 'node_modules/typescript/bin/tsc'), '-p', join(oldRoot, 'packages/shared/tsconfig.build.json')],
    { cwd: oldRoot, stdio: 'pipe', timeout: 60_000 });

  const currentStore = await import(pathToFileURL(join(root, 'apps/api/dist/scans/store.js')).href);
  const currentServer = await import(pathToFileURL(join(root, 'apps/api/dist/server.js')).href);
  const currentConfig = await import(pathToFileURL(join(root, 'apps/api/dist/config.js')).href);
  const currentLogger = await import(pathToFileURL(join(root, 'apps/api/dist/logger.js')).href);
  const path = join(temp, 'shared-scans.json');
  const agentPath = join(temp, 'agent-template.json');
  const lockPath = join(temp, '.shared-scans.json.drobon-write-lock');
  const backupPath = join(temp, 'cutover-backup.json');
  const projectId = 'prj_00000000-0000-4000-8000-000000000001';
  const ownerId = 'usr_synthetic';
  const initial = currentStore.createJsonFileScanStore(path);
  const legacy = await initial.createScanWithQuota({ ownerId, projectId, scanType: 'SAST', consume: async () => ({ ok: true }) });
  if (legacy.outcome !== 'created') throw new Error('Synthetic legacy fixture creation failed.');
  const legacyDocument = JSON.parse(readFileSync(path, 'utf8'));
  const agent = currentStore.createJsonFileScanStore(agentPath);
  for (const scanType of ['SAST', 'SECRETS']) {
    const created = await agent.createScanWithQuota({ ownerId, projectId, scanType,
      assessmentId: 'asm_00000000-0000-4000-8000-000000000001',
      agent: { version: 1, datasetDigest: 'a'.repeat(64), sourceDigest: 'b'.repeat(64),
        engagementId: 'eng_00000000-0000-4000-8000-000000000001' }, consume: async () => ({ ok: true }) });
    if (created.outcome !== 'created') throw new Error('Synthetic Agent fixture creation failed.');
  }
  const agentDocument = JSON.parse(readFileSync(agentPath, 'utf8'));
  const agentIds = agentDocument.scans.map((scan) => scan.id);
  const oldServerUrl = pathToFileURL(join(oldRoot, 'apps/api/src/server.ts')).href;
  const oldConfigUrl = pathToFileURL(join(oldRoot, 'apps/api/src/config.ts')).href;
  const oldLoggerUrl = pathToFileURL(join(oldRoot, 'apps/api/src/logger.ts')).href;
  const oldScript = `
    import { startServer } from ${JSON.stringify(oldServerUrl)};
    import { loadConfig } from ${JSON.stringify(oldConfigUrl)};
    import { createLogger } from ${JSON.stringify(oldLoggerUrl)};
    const config = { ...loadConfig({ NODE_ENV: 'test' }), host: '127.0.0.1', port: 0, authStorePath: ':memory:',
      usageStorePath: ':memory:', projectStorePath: ':memory:', scanStorePath: ${JSON.stringify(path)},
      assessmentStorePath: ':memory:', studentStorePath: ':memory:', sourceStorePath: ':memory:',
      paymentStorePath: ':memory:', entitlementStorePath: ':memory:', partnerStorePath: ':memory:', paymentConfigStorePath: ':memory:' };
    const server = await startServer({ config, logger: createLogger({ out: () => {} }), scanEngines: [], scanProcessorAutoStart: false });
    process.send({ kind: 'ready', url: server.url });
    process.on('message', async (message) => {
      if (message === 'drain') { await server.app.scanProcessor.drain(); process.send({ kind: 'drained' }); }
      if (message === 'stop') { await server.stop(); process.send({ kind: 'stopped' }, () => process.exit(0)); }
    });
  `;
  oldServer = spawn(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', oldScript],
    { cwd: oldRoot, stdio: ['ignore', 'ignore', 'pipe', 'ipc'] });
  let stderr = '';
  oldServer.stderr.on('data', (chunk) => { stderr += chunk.toString(); });
  const ready = await waitMessage(oldServer, 'ready', () => stderr);
  const config = memoryConfig(currentConfig.loadConfig({ NODE_ENV: 'test' }), path);
  const logger = currentLogger.createLogger({ out: () => {} });
  let secondDefaultRefused = false;
  try { await currentServer.startServer({ config, logger, scanEngines: [], scanProcessorAutoStart: false }); }
  catch (error) { secondDefaultRefused = error instanceof Error && /already owned/i.test(error.message); }
  if (!secondDefaultRefused) throw new Error('Expected a second default server to be refused.');

  const cutoverBytes = Buffer.from(JSON.stringify({ ...legacyDocument, version: 2, scans: [...legacyDocument.scans, ...agentDocument.scans] }));
  writeFileSync(backupPath, cutoverBytes);
  writeFileSync(path, cutoverBytes); // isolated synthetic cutover, not a production migration
  const injectedStore = currentStore.createJsonFileScanStore(path);
  const cutoverContainsThree = (await injectedStore.listByProject(projectId)).length === 3;
  let knownInjectedRefused = false;
  try { await currentServer.startServer({ config, logger, scanStore: injectedStore, scanEngines: [], scanProcessorAutoStart: false }); }
  catch (error) { knownInjectedRefused = error instanceof Error && /already owned/i.test(error.message); }
  if (!knownInjectedRefused) throw new Error('Expected a directly known injected file store to be leased.');
  // An opaque wrapper is indistinguishable from a third-party repository and
  // bypasses the known-store registry. It retains the same real file methods.
  const opaqueInjectedStore = { ...injectedStore };
  newServer = await currentServer.startServer({ config, logger, scanStore: opaqueInjectedStore, scanEngines: [], scanProcessorAutoStart: false });
  const bothHttpServersLive = (await fetch(`${ready.url}/livez`)).status === 200 && (await fetch(`${newServer.url}/livez`)).status === 200;
  mkdirSync(lockPath, { mode: 0o700 });
  lockHeld = true;
  const drained = waitMessage(oldServer, 'drained', () => stderr);
  oldServer.send('drain');
  await drained;
  const after = JSON.parse(readFileSync(path, 'utf8'));
  const ignoredLock = existsSync(lockPath);
  const oldOverwroteV2 = after.version === 1;
  const oldDroppedAgentJobs = agentIds.every((id) => after.scans.every((scan) => scan.id !== id));
  rmdirSync(lockPath); lockHeld = false;
  let newWriterFenced = false;
  try { await injectedStore.claimNextQueued(); }
  catch (error) { newWriterFenced = error instanceof Error && /changed|fenced/i.test(error.message); }
  const backupUnchanged = readFileSync(backupPath).equals(cutoverBytes);
  const result = { syntheticOnly: true, oldCommit, oldApiAndSharedSourcesFromPinnedCommit: true,
    localInstalledDependenciesUsed: true, oldWorkerEngines: 'none', secondDefaultServerRefused: secondDefaultRefused,
    knownInjectedStoreRefusedByLease: knownInjectedRefused,
    opaqueInjectedNewServerBypassedScanLease: bothHttpServersLive, cutoverContainedThreeJobs: cutoverContainsThree,
    oldFullServerIgnoredNewLock: ignoredLock, oldFullServerOverwroteV2AsV1: oldOverwroteV2,
    oldFullServerDroppedBothAgentJobs: oldDroppedAgentJobs, staleNewWriterFencedAfterLoss: newWriterFenced,
    separateSyntheticBackupUnchanged: backupUnchanged };
  if (!secondDefaultRefused || !knownInjectedRefused || !bothHttpServersLive || !cutoverContainsThree || !ignoredLock || !oldOverwroteV2 ||
      !oldDroppedAgentJobs || !newWriterFenced || !backupUnchanged) throw new Error(`Unexpected synthetic coexistence result: ${JSON.stringify(result)}`);
  console.log(JSON.stringify(result, null, 2));
} finally {
  if (newServer !== undefined) await newServer.stop();
  if (oldServer !== undefined && oldServer.exitCode === null && oldServer.signalCode === null) {
    const stopped = waitMessage(oldServer, 'stopped', () => '');
    oldServer.send('stop');
    try { await stopped; } catch { oldServer.kill('SIGKILL'); }
  }
  if (lockHeld) rmdirSync(join(temp, '.shared-scans.json.drobon-write-lock'));
  rmSync(temp, { recursive: true, force: true }); // only this script's synthetic fixtures and pinned source archive
}
