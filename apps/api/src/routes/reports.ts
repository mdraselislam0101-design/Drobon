import type { IncomingMessage, ServerResponse } from 'node:http';
import {
  FINDING_ID_PATTERN,
  SCAN_ID_PATTERN,
  REPORT_MAX_BYTES,
  FINDINGS_PAGE_MAX,
  FINDINGS_PAGE_SIZE_MAX,
  FINDING_SEVERITIES,
  SCAN_TYPES,
  compareFindings,
  findingScanner,
  isFindingSeverity,
  isFindingScanner,
  type FindingDetailResponse,
  type FindingsPageResponse,
  type ScanType,
  type SecurityReport,
} from '@drobon/shared';
import type { ApiConfig } from '../config.js';
import { badRequest, conflict, internal, notFound, unauthorized, validationError } from '../errors.js';
import type { RequestContext, Route } from '../http.js';
import { readJsonBody } from '../lib/body.js';
import type { ProjectStore } from '../projects/store.js';
import { toProjectResponse } from '../projects/store.js';
import { createOwnProjectResolver, type OwnProjectResolver } from '../projects/access.js';
import type { ScanRecord, ScanStore } from '../scans/store.js';
import { toScanResponse } from '../scans/store.js';
import { sendSuccess } from '../respond.js';
import { buildSecurityReport, canonicalJson, renderSecurityReportMarkdown } from '../reports/build.js';
import * as v from '../lib/validate.js';

export interface ReportsRouteDeps {
  config: ApiConfig;
  projects: ProjectStore;
  scans: ScanStore;
  now?: () => number;
}

const emptyBodySchema = v.object({});

function parseSingleQuery(url: URL, name: string): string | undefined {
  const values = url.searchParams.getAll(name);
  if (values.length > 1) throw badRequest(`Query parameter '${name}' must appear only once.`);
  return values[0];
}

function parsePageInteger(value: string | undefined, fallback: number, max: number, field: string): number {
  if (value === undefined) return fallback;
  if (!/^[1-9][0-9]{0,5}$/.test(value)) {
    throw validationError([{ path: field, message: `Must be a positive integer no greater than ${max}.` }]);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed > max) {
    throw validationError([{ path: field, message: `Must be a positive integer no greater than ${max}.` }]);
  }
  return parsed;
}

function queryUrl(req: IncomingMessage): URL {
  try {
    return new URL(req.url ?? '/', 'http://localhost');
  } catch {
    throw badRequest('Malformed query string.');
  }
}

function rejectUnknownQueryParameters(req: IncomingMessage, allowed: ReadonlySet<string> = new Set()): void {
  const url = queryUrl(req);
  if ([...url.searchParams.keys()].some((key) => !allowed.has(key))) {
    throw badRequest('Unsupported query parameter.');
  }
}

function sendAttachment(
  res: ServerResponse,
  body: string,
  contentType: string,
  filename: string,
): void {
  const bytes = Buffer.from(body, 'utf8');
  if (bytes.length > REPORT_MAX_BYTES * 2) throw conflict('The report export exceeds the configured size limit.');
  res.writeHead(200, {
    'content-type': contentType,
    'content-length': String(bytes.length),
    'content-disposition': `attachment; filename="${filename}"`,
    'cache-control': 'private, no-store',
    'x-content-type-options': 'nosniff',
  });
  res.end(bytes);
}

export function createReportsRoutes(deps: ReportsRouteDeps): Route[] {
  const { config, projects, scans } = deps;
  const access: OwnProjectResolver = createOwnProjectResolver(projects);
  const clock = deps.now ?? Date.now;

  const resolveCompletedScan = async (rawProjectId: unknown, rawScanId: unknown, actorId: string): Promise<{
    project: Awaited<ReturnType<OwnProjectResolver['ownProjectOr403']>>;
    scan: ScanRecord;
  }> => {
    const project = await access.ownProjectOr403(rawProjectId, actorId);
    if (typeof rawScanId !== 'string' || !SCAN_ID_PATTERN.test(rawScanId)) throw notFound('Scan not found.');
    const scan = await scans.findByProjectAndId(project.id, rawScanId);
    if (scan === undefined) throw notFound('Scan not found.');
    if (scan.status !== 'COMPLETED') throw conflict('Reports and findings are available only after a scan completes.');
    return { project, scan };
  };

  const projectIdFromActor = async (ctx: RequestContext): Promise<string> => {
    if (ctx.user === undefined) throw unauthorized();
    const project = await access.ownProjectOr403(ctx.params['projectId'], ctx.user.id);
    return project.id;
  };

  const reportForScan = async (ctx: RequestContext): Promise<SecurityReport> => {
    const projectId = await projectIdFromActor(ctx);
    const scanId = ctx.params['scanId'];
    if (typeof scanId !== 'string' || !SCAN_ID_PATTERN.test(scanId)) throw notFound('Scan not found.');
    const report = await scans.findReportByProjectAndScan(projectId, scanId);
    if (report === undefined) throw notFound('Report not found.');
    return report;
  };

  return [
    {
      method: 'GET',
      path: '/api/v1/projects/:projectId/scans/:scanId/findings',
      requireAuth: true,
      handler: async (req, res, ctx): Promise<void> => {
        const actor = ctx.user;
        if (actor === undefined) throw unauthorized();
        const { scan } = await resolveCompletedScan(ctx.params['projectId'], ctx.params['scanId'], actor.id);
        const url = queryUrl(req);
        const allowed = new Set(['severity', 'scanner', 'page', 'pageSize']);
        if ([...url.searchParams.keys()].some((key) => !allowed.has(key))) {
          throw badRequest('Unsupported findings filter.');
        }
        const severityValue = parseSingleQuery(url, 'severity');
        const scannerValue = parseSingleQuery(url, 'scanner');
        const page = parsePageInteger(parseSingleQuery(url, 'page'), 1, FINDINGS_PAGE_MAX, 'page');
        const pageSize = parsePageInteger(parseSingleQuery(url, 'pageSize'), 20, FINDINGS_PAGE_SIZE_MAX, 'pageSize');
        if (severityValue !== undefined && !isFindingSeverity(severityValue)) {
          throw validationError([{ path: 'severity', message: `Must be one of: ${FINDING_SEVERITIES.join(', ')}.` }]);
        }
        if (scannerValue !== undefined && !isFindingScanner(scannerValue)) {
          throw validationError([{ path: 'scanner', message: `Must be one of: ${SCAN_TYPES.join(', ')}.` }]);
        }
        const ordered = [...(scan.findings ?? [])].sort(compareFindings);
        const filtered = ordered.filter((finding) =>
          (severityValue === undefined || finding.severity === severityValue) &&
          (scannerValue === undefined || findingScanner(finding) === scannerValue));
        const start = (page - 1) * pageSize;
        const result: FindingsPageResponse = {
          findings: filtered.slice(start, start + pageSize),
          page,
          pageSize,
          total: filtered.length,
          totalPages: Math.ceil(filtered.length / pageSize),
          ...(severityValue === undefined ? {} : { severity: severityValue }),
          ...(scannerValue === undefined ? {} : { scanner: scannerValue as ScanType }),
        };
        sendSuccess(res, ctx, result);
      },
    },
    {
      method: 'GET',
      path: '/api/v1/projects/:projectId/scans/:scanId/findings/:findingId',
      requireAuth: true,
      handler: async (req, res, ctx): Promise<void> => {
        const actor = ctx.user;
        if (actor === undefined) throw unauthorized();
        const { project, scan } = await resolveCompletedScan(ctx.params['projectId'], ctx.params['scanId'], actor.id);
        rejectUnknownQueryParameters(req);
        const findingId = ctx.params['findingId'];
        if (typeof findingId !== 'string' || findingId.length > 64 || !FINDING_ID_PATTERN.test(findingId)) {
          throw notFound('Finding not found.');
        }
        const finding = scan.findings?.find((candidate) => candidate.id === findingId);
        if (finding === undefined) throw notFound('Finding not found.');
        const result: FindingDetailResponse = {
          project: toProjectResponse(project),
          scan: toScanResponse(scan),
          finding,
        };
        sendSuccess(res, ctx, result);
      },
    },
    {
      method: 'POST',
      path: '/api/v1/projects/:projectId/scans/:scanId/report',
      requireAuth: true,
      handler: async (req, res, ctx): Promise<void> => {
        const actor = ctx.user;
        if (actor === undefined) throw unauthorized();
        const { project, scan } = await resolveCompletedScan(ctx.params['projectId'], ctx.params['scanId'], actor.id);
        rejectUnknownQueryParameters(req);
        const raw = await readJsonBody(req, { maxBytes: Math.min(config.bodyMaxBytes, 1024) });
        const parsed = emptyBodySchema.parse(raw);
        if (!parsed.ok) throw validationError(parsed.issues);
        let report: SecurityReport;
        try {
          report = buildSecurityReport(project, scan, new Date(clock()).toISOString());
        } catch (error) {
          if (error instanceof RangeError) throw conflict('The generated report exceeds the configured size limit.');
          throw internal('The report could not be generated safely.');
        }
        const outcome = await scans.createReport(report);
        if (outcome.outcome === 'scan-unavailable') throw conflict('The scan changed before report persistence.');
        if (outcome.outcome === 'capacity-exceeded') throw conflict('Report storage capacity has been reached.');
        if (outcome.outcome === 'invalid-report') throw internal('Generated report failed store validation.');
        sendSuccess(res, ctx, { report: outcome.report }, outcome.outcome === 'created' ? 201 : 200);
      },
    },
    {
      method: 'GET',
      path: '/api/v1/projects/:projectId/scans/:scanId/report',
      requireAuth: true,
      handler: async (req, res, ctx): Promise<void> => {
        rejectUnknownQueryParameters(req);
        const report = await reportForScan(ctx);
        sendSuccess(res, ctx, { report });
      },
    },
    {
      method: 'GET',
      path: '/api/v1/projects/:projectId/scans/:scanId/report/download',
      requireAuth: true,
      handler: async (req, res, ctx): Promise<void> => {
        const report = await reportForScan(ctx);
        const url = queryUrl(req);
        if ([...url.searchParams.keys()].some((key) => key !== 'format')) throw badRequest('Unsupported report export option.');
        const formatValues = url.searchParams.getAll('format');
        if (formatValues.length > 1) throw badRequest('Query parameter \'format\' must appear only once.');
        const format = formatValues[0] ?? 'json';
        const stem = `drobon-${report.reportId}`;
        if (format === 'json') {
          sendAttachment(res, `${canonicalJson(report)}\n`, 'application/json; charset=utf-8', `${stem}.json`);
          return;
        }
        if (format === 'markdown') {
          sendAttachment(res, renderSecurityReportMarkdown(report), 'text/markdown; charset=utf-8', `${stem}.md`);
          return;
        }
        throw validationError([{ path: 'format', message: 'Must be json or markdown.' }]);
      },
    },
  ];
}
