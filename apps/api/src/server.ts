import { createServer, type Server } from 'node:http';
import { createApp, type App, type AppDeps } from './app.js';

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
  const app = createApp(deps);
  // Payment approval is a recoverable cross-file saga. Complete or fail
  // closed any interrupted approval before exposing an HTTP listener.
  await app.ready;
  const server: Server = createServer(app.handle);
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

  const address = server.address();
  const port =
    typeof address === 'object' && address !== null ? address.port : config.port;
  logger.info('API listening', { host: config.host, port });

  return {
    app,
    url: `http://${config.host}:${port}`,
    port,
    resetRateLimit: app.resetRateLimit,
    stop: () =>
      new Promise<void>((resolve, reject) => {
        app.scanProcessor.stop();
        server.close((error) => {
          if (error) {
            reject(error);
          } else {
            resolve();
          }
        });
      }),
  };
}
