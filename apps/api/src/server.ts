import { createServer, type Server } from 'node:http';
import { createApp, type App, type AppDeps } from './app.js';
import { acquireJsonStoreLeases } from './lib/jsonStoreLease.js';

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
  // Only the stores constructed by createApp are covered: an injected
  // repository can point elsewhere and must provide its own coordination.
  const paths = [
    ...(deps.users === undefined ? [config.authStorePath] : []),
    ...(deps.usageStore === undefined ? [config.usageStorePath] : []),
    ...(deps.projectStore === undefined ? [config.projectStorePath] : []),
    ...(deps.scanStore === undefined ? [config.scanStorePath] : []),
    ...(deps.assessmentStore === undefined ? [config.assessmentStorePath] : []),
    config.studentStorePath,
    ...(deps.sourceStore === undefined ? [config.sourceStorePath] : []),
    ...(deps.paymentStore === undefined ? [config.paymentStorePath] : []),
    ...(deps.entitlementStore === undefined ? [config.entitlementStorePath] : []),
    ...(deps.partnerStore === undefined ? [config.partnerStorePath] : []),
    ...(deps.paymentConfigStore === undefined ? [config.paymentConfigStorePath] : []),
  ];
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
