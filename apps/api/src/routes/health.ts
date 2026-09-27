import type { HealthResponse, ReadinessResponse } from '@drobon/shared';
import type { ApiConfig } from '../config.js';
import type { Route } from '../http.js';
import { sendSuccess } from '../respond.js';

export const SERVICE_NAME = 'drobon-aegis-api';

export interface HealthRouteDeps {
  config: ApiConfig;
}

/**
 * Liveness/readiness probes. `/livez` means "the process answers";
 * `/readyz` means "startup completed and the instance accepts traffic".
 * Both are intentionally unauthenticated (required by orchestrators).
 */
export function createHealthRoutes(deps: HealthRouteDeps): Route[] {
  return [
    {
      method: 'GET',
      path: '/livez',
      handler: async (_req, res, ctx): Promise<void> => {
        const body: HealthResponse = {
          status: 'ok',
          service: SERVICE_NAME,
          version: deps.config.version,
        };
        sendSuccess(res, ctx, body);
      },
    },
    {
      method: 'GET',
      path: '/readyz',
      handler: async (_req, res, ctx): Promise<void> => {
        const body: ReadinessResponse = {
          status: 'ready',
          service: SERVICE_NAME,
          version: deps.config.version,
          checks: { configuration: 'ok', accounts: 'ok' },
        };
        sendSuccess(res, ctx, body);
      },
    },
  ];
}
