/**
 * Advisory status + analysis routes (Pump 15, MAIN-APP ONLY).
 *
 * Read-only and authenticated. `/analyze` evaluates an operator-supplied
 * observation (headers/body/manifests) WITHOUT creating a scan, so a new
 * advisory record can be verified immediately after it is added to the pack.
 * It never performs a network request and never mutates state.
 */

import type { Route } from '../http.js';
import { sendSuccess } from '../respond.js';
import { unauthorized, validationError } from '../errors.js';
import { readJsonBody } from '../lib/body.js';
import type { ApiConfig } from '../config.js';
import type { AdvisoryInputs, AdvisoryService } from '../external/advisory.js';

export interface AdvisoryRouteDeps {
  config: ApiConfig;
  advisory: AdvisoryService;
}

function parseInputs(raw: unknown): AdvisoryInputs | undefined {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return undefined;
  const record = raw as Record<string, unknown>;
  const out: AdvisoryInputs = {};
  if (record['headers'] !== undefined) {
    if (typeof record['headers'] !== 'object' || record['headers'] === null || Array.isArray(record['headers'])) return undefined;
    const headers: Record<string, string | string[] | undefined> = {};
    for (const [name, value] of Object.entries(record['headers'])) {
      if (!/^[a-z0-9-]{1,64}$/.test(name) || name.length === 0) return undefined;
      if (typeof value === 'string') headers[name] = value.slice(0, 2048);
      else if (Array.isArray(value) && value.length <= 5 && value.every((entry) => typeof entry === 'string')) {
        headers[name] = (value as string[]).map((entry) => entry.slice(0, 2048));
      } else return undefined;
    }
    out.headers = headers;
  }
  if (record['body'] !== undefined) {
    if (typeof record['body'] !== 'string') return undefined;
    out.body = record['body'].slice(0, 32_768);
  }
  if (record['files'] !== undefined) {
    if (!Array.isArray(record['files']) || record['files'].length > 50) return undefined;
    const files: Array<{ path: string; content: string }> = [];
    for (const entry of record['files']) {
      if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) return undefined;
      const file = entry as Record<string, unknown>;
      if (typeof file['path'] !== 'string' || typeof file['content'] !== 'string') return undefined;
      files.push({ path: file['path'].slice(0, 200), content: file['content'].slice(0, 262_144) });
    }
    out.files = files;
  }
  return out;
}

export function createAdvisoryRoutes(deps: AdvisoryRouteDeps): Route[] {
  const { advisory, config } = deps;
  return [
    {
      method: 'GET',
      path: '/api/v1/advisory/status',
      requireAuth: true,
      handler: async (_req, res, ctx): Promise<void> => {
        if (ctx.user === undefined) throw unauthorized();
        sendSuccess(res, ctx, { advisory: await advisory.status() });
      },
    },
    {
      method: 'POST',
      path: '/api/v1/advisory/analyze',
      requireAuth: true,
      handler: async (req, res, ctx): Promise<void> => {
        if (ctx.user === undefined) throw unauthorized();
        const body = await readJsonBody(req, { maxBytes: config.bodyMaxBytes });
        const inputs = parseInputs(body);
        if (inputs === undefined) {
          throw validationError([{ path: 'body', message: 'Provide bounded headers, body or files to analyze.' }]);
        }
        const result = await advisory.evaluate(inputs);
        sendSuccess(res, ctx, { analysis: result });
      },
    },
  ];
}
