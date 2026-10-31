/* eslint-disable @typescript-eslint/no-explicit-any -- external dataset JSON is untrusted and shape-checked before use. */
/**
 * Dataset status routes — honest visibility into what's loaded from Drobon-Dataset.
 * Read-only, no secrets, bounded.
 */

import type { ApiConfig } from '../config.js';
import type { Route } from '../http.js';
import { sendSuccess } from '../respond.js';
import { unauthorized } from '../errors.js';
import type { DatasetService } from './service.js';

export interface DatasetRouteDeps {
  config: ApiConfig;
  dataset: DatasetService;
}

export function createDatasetRoutes(deps: DatasetRouteDeps): Route[] {
  const { dataset } = deps;

  return [
    {
      method: 'GET',
      path: '/api/v1/dataset/status',
      requireAuth: true,
      handler: async (req, res, ctx) => {
        if (ctx.user === undefined) throw unauthorized();
        const url = new URL(req.url ?? '/', 'http://localhost');
        if ([...url.searchParams.keys()].length > 0) throw new Error('Unsupported query parameter.');
        const status = { ...await dataset.status() };
        // The configured filesystem path is operator-only and may itself
        // contain sensitive text. Keep the optional internal property for
        // existing server-side callers, but never return it over HTTP.
        delete status.datasetPath;
        sendSuccess(res, ctx, { dataset: status });
      },
    },
    {
      method: 'GET',
      path: '/api/v1/dataset/packs/:kind',
      requireAuth: true,
      handler: async (_req, res, ctx) => {
        if (ctx.user === undefined) throw unauthorized();
        const kind = ctx.params['kind'];
        if (kind !== 'sast' && kind !== 'secrets' && kind !== 'dast' && kind !== 'sca') throw new Error('Unsupported pack kind');
        let rules: unknown[] = [];
        if (kind === 'sast') rules = await dataset.sastPacks();
        else if (kind === 'secrets') rules = await dataset.secretsPacks();
        else if (kind === 'dast') rules = await dataset.dastPacks();
        else rules = await dataset.scaPacks();
        const pack = await dataset.packMetadata(kind);
        // Return bounded summary (no regex source truncation, but limited fields)
        const list = (rules as any[]).slice(0, 50).map(r => ({ id: r.id, title: r.title, severity: r.severity, category: r.category }));
        sendSuccess(res, ctx, { kind, count: (rules as any[]).length, ...(pack === undefined ? {} : { pack }), rules: list });
      },
    },
    {
      method: 'GET',
      path: '/api/v1/dataset/lessons',
      requireAuth: true,
      handler: async (_req, res, ctx) => {
        if (ctx.user === undefined) throw unauthorized();
        const lessons = await dataset.lessons();
        // Preserve the raw count while refusing malformed entries that would
        // otherwise throw and hide every subsequent lesson from the endpoint.
        const list = lessons.slice(0, 20).flatMap((lesson) => {
          if (typeof lesson !== 'object' || lesson === null || Array.isArray(lesson)) return [];
          const item = lesson as Record<string, unknown>;
          return [{ id: item['id'], title: item['title'] }];
        });
        sendSuccess(res, ctx, { count: lessons.length, lessons: list });
      },
    },
  ];
}
