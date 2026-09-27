import { ConfigError, loadConfig } from './config.js';
import { createLogger } from './logger.js';
import { SERVICE_NAME } from './routes/health.js';
import { startServer } from './server.js';

/**
 * API entry point: validate config (fail fast), start the server, and handle
 * graceful shutdown on SIGTERM/SIGINT.
 */
async function main(): Promise<void> {
  const config = loadConfig();
  const logger = createLogger({ level: config.logLevel, service: SERVICE_NAME, env: config.env });
  const server = await startServer({ config, logger });

  let shuttingDown = false;
  const shutdown = (signal: string): void => {
    if (shuttingDown) {
      return;
    }
    shuttingDown = true;
    logger.info('Shutting down', { signal });
    const force = setTimeout(() => {
      process.exitCode = 1;
    }, 5000);
    force.unref();
    server
      .stop()
      .then(() => {
        clearTimeout(force);
        logger.info('Shutdown complete', { signal });
      })
      .catch((error: unknown) => {
        clearTimeout(force);
        logger.error('Shutdown failed', { signal, err: error });
        process.exitCode = 1;
      });
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  const prefix = error instanceof ConfigError ? 'Configuration error' : 'Fatal startup error';
  process.stderr.write(`${prefix}: ${message}\n`);
  process.exitCode = 1;
});
