import type { EnvironmentName } from './config.js';

/** `GET /livez` — the process is alive. */
export interface HealthResponse {
  status: 'ok';
  service: string;
  version: string;
}

/** `GET /readyz` — the process completed startup and can serve traffic. */
export interface ReadinessResponse {
  status: 'ready';
  service: string;
  version: string;
  checks: Record<string, 'ok'>;
}

/** `GET /api/v1/status` — service identity and build metadata. */
export interface StatusResponse {
  service: string;
  version: string;
  environment: EnvironmentName;
  time: string;
}

/** `POST /api/v1/echo` request. */
export interface EchoRequest {
  message: string;
}

/** `POST /api/v1/echo` response. `length` counts Unicode code points. */
export interface EchoResponse {
  message: string;
  length: number;
  receivedAt: string;
}
