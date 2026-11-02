import { createServer, type Server } from 'node:http';
import { SOURCE_SNAPSHOT_BODY_MAX_BYTES } from '@drobon/shared';
import { createApp, type App, type AppDeps } from './app.js';
import { acquireJsonStoreLeases } from './lib/jsonStoreLease.js';
import { knownJsonFileStorePath } from './lib/jsonFileWriteFence.js';
import { attestAgentStorage, STORAGE_BLOCKED, StorageBlockedError, type StorageBoundaryIssue } from './lib/storageBoundary.js';

export type ServerDeps = AppDeps;

export interface StartedServer {
  app: App;
  url: string;
  port: number;
  resetRateLimit: () => void;
  stop: () => Promise<void>;
}

/** Start the HTTP server with conservative socket timeouts. */
export async function startServer(deps: ServerDeps): Promise<StartedServer> {
  const { config, logger } = deps;
  // Cover default stores and the actual paths of directly injected, known
  // JSON scan/assessment stores. Wrapped or third-party repositories remain
  // opaque and must provide their own coordination; this is not mandatory
  // fencing against an old process or another network namespace/host.
  const injectedScanPath = deps.scanStore === undefined ? undefined : knownJsonFileStorePath(deps.scanStore);
  const injectedAssessmentPath = deps.assessmentStore === undefined ? undefined : knownJsonFileStorePath(deps.assessmentStore);
  const paths = [
    ...(deps.users === undefined ? [config.authStorePath] : []),
    ...(deps.usageStore === undefined ? [config.usageStorePath] : []),
    ...(deps.projectStore === undefined ? [config.projectStorePath] : []),
    ...(deps.scanStore === undefined ? [config.scanStorePath] : injectedScanPath === undefined ? [] : [injectedScanPath]),
    ...(deps.assessmentStore === undefined ? [config.assessmentStorePath] : injectedAssessmentPath === undefined ? [] : [injectedAssessmentPath]),
    config.studentStorePath,
    ...(deps.sourceStore === undefined ? [config.sourceStorePath] : []),
    ...(deps.paymentStore === undefined ? [config.paymentStorePath] : []),
    ...(deps.entitlementStore === undefined ? [config.entitlementStorePath] : []),
    ...(deps.partnerStore === undefined ? [config.partnerStorePath] : []),
    ...(deps.paymentConfigStore === undefined ? [config.paymentConfigStorePath] : []),
  ];
  // Agent writes must land only behind an attested boundary: owner-only files,
  // an owner-only directory, ancestors that no other identity can replace, and
  // no other local process currently write-holding scan/assessment/quota
  // storage. Enforcement is limited to the durable store paths this server
  // actually writes; an injected opaque store is a test seam and cannot be
  // attested. A blocked verdict refuses startup instead of degrading silently.
  const durableAgentPaths: string[] = [];
  const addDurable = (path: string | undefined): void => {
    if (path !== undefined && path !== ':memory:') durableAgentPaths.push(path);
  };
  addDurable(deps.scanStore === undefined ? config.scanStorePath : injectedScanPath);
  addDurable(deps.assessmentStore === undefined ? config.assessmentStorePath : injectedAssessmentPath);
  addDurable(deps.usageStore === undefined ? config.usageStorePath : undefined);
  // An injected store whose real path is unknown cannot be attested: a wrapper
  // can point anywhere and silently bypass the lease. Such an adapter is refused
  // when a durable path is configured, and is never treated as protected.
  const opaqueInjected: StorageBoundaryIssue[] = [];
  if (deps.scanStore !== undefined && injectedScanPath === undefined && config.scanStorePath !== ':memory:') {
    opaqueInjected.push('opaque-injected-adapter');
  }
  if (deps.assessmentStore !== undefined && injectedAssessmentPath === undefined && config.assessmentStorePath !== ':memory:') {
    opaqueInjected.push('opaque-injected-adapter');
  }
  if (config.agentExperimentalEnabled === true && durableAgentPaths.length > 0) {
    const verdict = attestAgentStorage(durableAgentPaths);
    if (!verdict.ok) {
      logger.error('STORAGE BLOCKED', {
        code: verdict.code, issues: verdict.issues, foreignWriterCount: verdict.foreignWriterCount,
      });
      throw new StorageBlockedError(verdict.issues);
    }
    logger.info('Agent storage boundary attested', { code: verdict.code, stores: durableAgentPaths.length });
  }
  if (config.agentExperimentalEnabled === true && opaqueInjected.length > 0) {
    const issues = [...new Set(opaqueInjected)];
    logger.error('STORAGE BLOCKED', { code: STORAGE_BLOCKED, issues, foreignWriterCount: 0 });
    throw new StorageBlockedError(issues);
  }

  // Security-default attestation: both of these are safe by default, so a
  // weakened value is an explicit operator decision that must be visible.
  if (config.dastRequireEngagement === false) {
    logger.warn('DAST engagement authorization is DISABLED: unlinked DAST scans are accepted without an attested engagement. Set DAST_REQUIRE_ENGAGEMENT=true unless this is a deliberate legacy deployment.');
  }
  if (config.bodyMaxBytes < SOURCE_SNAPSHOT_BODY_MAX_BYTES) {
    logger.warn('BODY_MAX_BYTES is below the maximum JSON body of a legal source snapshot; a valid snapshot may be rejected at upload.', { bodyMaxBytes: config.bodyMaxBytes, snapshotBodyBound: SOURCE_SNAPSHOT_BODY_MAX_BYTES });
  }

  const leases = await acquireJsonStoreLeases(paths);
  if (!leases.guarded) logger.warn('Local JSON writer guard is unavailable on this platform; enforce one writer externally.');
  let app: App | undefined;
  let server: Server;
  try {
    // Acquire before constructing any cached document or starting recovery.
    app = createApp(deps);
    await app.ready;
    server = createServer(app.handle);
    server.headersTimeout = 10_000;
    server.requestTimeout = 30_000;
    server.keepAliveTimeout = 5_000;
    server.on('error', (error: unknown) => {
      logger.error('Server error', { err: error });
    });
    await new Promise<void>((resolve, reject) => {
      const onError = (error: unknown): void => {
        reject(error instanceof Error ? error : new Error(String(error)));
      };
      server.once('error', onError as (error: Error) => void);
      server.listen(config.port, config.host, () => {
        server.off('error', onError as (error: Error) => void);
        resolve();
      });
    });
  } catch (error) {
    if (app !== undefined) await app.scanProcessor.shutdown();
    await leases.release();
    throw error;
  }

  const address = server.address();
  const port = typeof address === 'object' && address !== null ? address.port : config.port;
  logger.info('API listening', { host: config.host, port });
  const startedApp = app;
  let stopped: Promise<void> | undefined;

  return {
    app: startedApp,
    url: `http://${config.host}:${port}`,
    port,
    resetRateLimit: startedApp.resetRateLimit,
    stop: () => {
      stopped ??= (async () => {
        // Do not release while existing HTTP requests or the scan processor
        // can still mutate an in-memory snapshot. Repeated stop is safe.
        await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
        await startedApp.scanProcessor.shutdown();
        await leases.release();
      })();
      return stopped;
    },
  };
}
