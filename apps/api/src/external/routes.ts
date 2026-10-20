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
        const status = await dataset.status();
        sendSuccess(res, ctx, { dataset: status });
      },
    },
    {
      method: 'GET',
      path: '/api/v1/dataset/packs/:kind',
      requireAuth: true,
      handler: async (req, res, ctx) => {
        if (ctx.user === undefined) throw unauthorized();
        const kind = ctx.params['kind'];
        if (kind !== 'sast' && kind !== 'secrets' && kind !== 'dast') throw new Error('Unsupported pack kind');
        let rules: unknown[] = [];
        if (kind === 'sast') rules = await dataset.sastPacks();
        else if (kind === 'secrets') rules = await dataset.secretsPacks();
        else if (kind === 'dast') rules = await dataset.dastPacks();
        // Return bounded summary (no regex source truncation, but limited fields)
        const list = (rules as any[]).slice(0, 50).map(r => ({ id: r.id, title: r.title, severity: r.severity, category: r.category }));
        sendSuccess(res, ctx, { kind, count: (rules as any[]).length, rules: list });
      },
    },
    {
      method: 'GET',
      path: '/api/v1/dataset/lessons',
      requireAuth: true,
      handler: async (req, res, ctx) => {
        if (ctx.user === undefined) throw unauthorized();
        const lessons = await dataset.lessons();
        const list = (lessons as any[]).slice(0, 20).map((l: any) => ({ id: l.id, title: l.title }));
        sendSuccess(res, ctx, { count: (lessons as any[]).length, lessons: list });
      },
    },
  ];
}
