import { createServer, type Server } from 'node:http';
import { createApp, type App } from './app.js';
import type { ApiConfig } from './config.js';
import type { Route } from './http.js';
import type { Logger } from './logger.js';

export interface ServerDeps {
  config: ApiConfig;
  logger: Logger;
  extraRoutes?: Route[];
}

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
