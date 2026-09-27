import type { ApiConfig } from '../src/config.js';
import type { Route } from '../src/http.js';
import { createLogger } from '../src/logger.js';
import { startServer, type StartedServer } from '../src/server.js';

export interface TestServer {
  baseUrl: string;
  config: ApiConfig;
  logs: string[];
  resetRateLimit: () => void;
  stop: () => Promise<void>;
}

export type TestServerOverrides = Partial<ApiConfig> & { extraRoutes?: Route[] };

/** Start an ephemeral API instance on 127.0.0.1 with an OS-assigned port. */
export async function startTestServer(overrides: TestServerOverrides = {}): Promise<TestServer> {
  const logs: string[] = [];
  const { extraRoutes, ...configOverrides } = overrides;
  const config: ApiConfig = {
    env: 'test',
    host: '127.0.0.1',
    port: 0,
    logLevel: 'error',
    corsAllowedOrigins: [],
    rateLimitMaxRequests: 1000,
    rateLimitWindowMs: 60_000,
    bodyMaxBytes: 1_048_576,
    version: '0.0.0-test',
    ...configOverrides,
  };
  const logger = createLogger({
    level: 'error',
    service: 'test',
    env: 'test',
    out: (line) => {
      logs.push(line);
    },
  });
  const started: StartedServer = await startServer(
    extraRoutes === undefined ? { config, logger } : { config, logger, extraRoutes },
  );
  return {
    baseUrl: started.url,
    config,
    logs,
    resetRateLimit: started.resetRateLimit,
    stop: started.stop,
  };
}

/** Read a fetch Response as unknown JSON. */
export async function readJson(res: Response): Promise<unknown> {
  return (await res.json()) as unknown;
}
