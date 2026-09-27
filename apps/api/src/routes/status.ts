import type { StatusResponse } from '@drobon/shared';
import type { ApiConfig } from '../config.js';
import type { Route } from '../http.js';
import { sendSuccess } from '../respond.js';
import { SERVICE_NAME } from './health.js';

export interface StatusRouteDeps {
  config: ApiConfig;
}

/** Service identity endpoint — the first versioned (`/api/v1`) route. */
export function createStatusRoutes(deps: StatusRouteDeps): Route[] {
  return [
    {
      method: 'GET',
      path: '/api/v1/status',
      handler: async (_req, res, ctx): Promise<void> => {
        const body: StatusResponse = {
          service: SERVICE_NAME,
          version: deps.config.version,
          environment: deps.config.env,
          time: new Date().toISOString(),
        };
        sendSuccess(res, ctx, body);
      },
    },
  ];
}
