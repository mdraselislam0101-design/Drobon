import type { ScanStatus, ScanType } from '@drobon/shared';
import type { ApiConfig } from '../config.js';
import type { Route } from '../http.js';
import { validationError } from '../errors.js';
import { sendSuccess } from '../respond.js';
import { assertPlatformAdmin } from './admin.js';
import type { ScanStore } from '../scans/store.js';
import type { ScanProcessor } from '../scans/processor.js';
import { SERVICE_NAME } from './health.js';

/**
 * Operational metrics (audit finding P2-15).
 *
 * Deliberately narrow and honest:
 * - ADMIN + platform-admin allowlist only, like every other admin surface;
 * - a snapshot of DURABLE state plus this process's uptime/memory — not a
 *   time series, no external metrics backend, no owner/project identifiers;
 * - no detection-quality number is derived here. Findings counts are already
 *   admin data; this endpoint exists so an operator can see queue depth and
 *   process health without reading the JSON stores by hand.
 */

export interface MetricsResponse {
  asOf: string;
  service: string;
  version: string;
  env: string;
  uptimeSeconds: number;
  process: {
    rssBytes: number;
    heapUsedBytes: number;
    heapTotalBytes: number;
    externalBytes: number;
  };
  scans: {
    total: number;
    queueDepth: number;
    byStatus: Record<ScanStatus, number>;
    byType: Record<ScanType, number>;
    recentlyCompleted: number;
  };
  processor: {
    started: boolean;
  };
  /**
   * Persisted scan-document shape (P1-6/P1-10). Every terminal transition
   * rewrites this whole document, so its size is the direct cost driver;
   * exposing it makes growth visible before it becomes a slow write.
   */
  store: {
    scans: number;
    reports: number;
    findingWorkflows: number;
    idempotencyEntries: number;
    documentBytes: number;
    estimatedFullRewriteBytes: number;
  };
  notes: string;
}

export interface MetricsRouteDeps {
  config: ApiConfig;
  scans: ScanStore;
  processor: ScanProcessor;
}

export function createMetricsRoutes(deps: MetricsRouteDeps): Route[] {
  const startedAt = Date.now();
  return [
    {
      method: 'GET',
      path: '/api/v1/metrics',
      requireAuth: true,
      handler: async (req, res, ctx): Promise<void> => {
        assertPlatformAdmin(ctx, deps.config);
        for (const key of new URL(req.url ?? '/', 'http://drobon.invalid').searchParams.keys()) {
          throw validationError([{ path: key, message: 'Metrics does not accept query parameters.' }]);
        }
        const [summary, stats] = await Promise.all([
          deps.scans.adminSummary(Date.now()),
          deps.scans.documentStats(),
        ]);
        const memory = process.memoryUsage();
        const body: MetricsResponse = {
          asOf: new Date().toISOString(),
          service: SERVICE_NAME,
          version: deps.config.version,
          env: deps.config.env,
          uptimeSeconds: Math.max(0, Math.floor((Date.now() - startedAt) / 1000)),
          process: {
            rssBytes: memory.rss,
            heapUsedBytes: memory.heapUsed,
            heapTotalBytes: memory.heapTotal,
            externalBytes: memory.external,
          },
          scans: {
            total: summary.total,
            queueDepth: summary.byStatus.QUEUED,
            byStatus: summary.byStatus,
            byType: summary.byType,
            recentlyCompleted: summary.recentlyCompleted,
          },
          processor: { started: deps.processor.started },
          store: {
            ...stats,
            // One full rewrite happens per terminal transition (and per report
            // write). Documented here so the cost is not a hidden constant.
            estimatedFullRewriteBytes: stats.documentBytes,
          },
          notes: 'Process-local snapshot of durable scan state. Not a time series, and not a detection-quality measurement: zero findings never means the target is safe.',
        };
        sendSuccess(res, ctx, body);
      },
    },
  ];
}
