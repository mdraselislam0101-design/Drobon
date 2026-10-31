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
  // ConfigError issues are constructed from fixed validation messages. Other
  // startup exceptions may contain paths, source text or credentials.
  const message = error instanceof ConfigError
    ? `Configuration error: ${error.message}`
    : 'Fatal startup error: details withheld.';
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
});
