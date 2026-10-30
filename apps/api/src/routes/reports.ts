import type { IncomingMessage, ServerResponse } from 'node:http';
import {
  FINDING_ID_PATTERN,
  FINDING_LIFECYCLE_STATES,
  FINDING_HISTORY_PAGE_MAX,
  FINDING_HISTORY_PAGE_SIZE_MAX,
  FINDING_NOTE_MAX_LENGTH,
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
  type FindingHistoryResponse,
  type FindingLifecycleState,
  type FindingsPageResponse,
  type ScanType,
  type SecurityReport,
} from '@drobon/shared';
import type { ApiConfig } from '../config.js';
import { badRequest, conflict, internal, notFound, projectArchived, unauthorized, validationError } from '../errors.js';
import type { RequestContext, Route } from '../http.js';
import { readJsonBody } from '../lib/body.js';
import type { ProjectStore } from '../projects/store.js';
import { toProjectResponse } from '../projects/store.js';
import { createOwnProjectResolver, type OwnProjectResolver } from '../projects/access.js';
import type { ScanRecord, ScanStore } from '../scans/store.js';
import { toScanResponse } from '../scans/store.js';
import { sendSuccess } from '../respond.js';
import { buildSecurityReport, canonicalJson, renderSbomExport, renderSecurityReportMarkdown, renderSecurityReportSarif } from '../reports/build.js';
import { renderPortfolioPdf, renderSecurityReportPdf, type PortfolioPdfEntry } from '../reports/pdf.js';
import { selectLatestAttempt } from '../reports/portfolio.js';
import { prepareFindingNote } from '../scans/findingWorkflow.js';
import { remediationGuidanceForFinding } from '../scans/remediationGuidance.js';
import * as v from '../lib/validate.js';
import type { GuidanceLookup } from '../external/guidance.js';

export interface ReportsRouteDeps {
  config: ApiConfig;
  projects: ProjectStore;
  scans: ScanStore;
  now?: () => number;
  guidance?: GuidanceLookup;
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
  body: string | Buffer,
  contentType: string,
  filename: string,
): void {
  const bytes = typeof body === 'string' ? Buffer.from(body, 'utf8') : body;
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

  const lifecycleSchema = v.object({ state: v.string({ minLength: 1, maxLength: 24, trim: true }) });
  const remediationNoteSchema = v.object({ note: v.string({ minLength: 1, maxLength: FINDING_NOTE_MAX_LENGTH }) });

  const resolveFinding = async (
    rawProjectId: unknown, rawScanId: unknown, rawFindingId: unknown, actorId: string,
  ): Promise<{ project: Awaited<ReturnType<OwnProjectResolver['ownProjectOr403']>>; scan: ScanRecord; finding: NonNullable<ScanRecord['findings']>[number] }> => {
    const { project, scan } = await resolveCompletedScan(rawProjectId, rawScanId, actorId);
    if (typeof rawFindingId !== 'string' || rawFindingId.length > 64 || !FINDING_ID_PATTERN.test(rawFindingId)) throw notFound('Finding not found.');
    const finding = scan.findings?.find((candidate) => candidate.id === rawFindingId);
    if (finding === undefined) throw notFound('Finding not found.');
    return { project, scan, finding };
  };

  const assertProjectActive = async (projectId: string): Promise<void> => {
    const current = await projects.findById(projectId);
    if (current?.status === 'ARCHIVED') throw projectArchived();
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
        const { project, scan, finding } = await resolveFinding(ctx.params['projectId'], ctx.params['scanId'], ctx.params['findingId'], actor.id);
        rejectUnknownQueryParameters(req);
        const workflow = await scans.getFindingWorkflow(project.id, finding.fingerprint);
        if (workflow === undefined) throw conflict('Finding lifecycle data is unavailable for this record.');
        const result: FindingDetailResponse = {
          project: toProjectResponse(project),
          scan: toScanResponse(scan),
          finding,
          workflow,
          guidance: remediationGuidanceForFinding(finding, deps.guidance === undefined ? undefined : await deps.guidance(finding.ruleId)),
        };
        sendSuccess(res, ctx, result);
      },
    },
    {
      method: 'GET',
      path: '/api/v1/projects/:projectId/scans/:scanId/findings/:findingId/history',
      requireAuth: true,
      handler: async (req, res, ctx): Promise<void> => {
        const actor = ctx.user;
        if (actor === undefined) throw unauthorized();
        const { project, finding } = await resolveFinding(ctx.params['projectId'], ctx.params['scanId'], ctx.params['findingId'], actor.id);
        const url = queryUrl(req);
        rejectUnknownQueryParameters(req, new Set(['page', 'pageSize']));
        const page = parsePageInteger(parseSingleQuery(url, 'page'), 1, FINDING_HISTORY_PAGE_MAX, 'page');
        const pageSize = parsePageInteger(parseSingleQuery(url, 'pageSize'), 20, FINDING_HISTORY_PAGE_SIZE_MAX, 'pageSize');
        const result: FindingHistoryResponse | undefined = await scans.getFindingHistory(project.id, finding.fingerprint, page, pageSize);
        if (result === undefined) throw notFound('Finding history not found.');
        sendSuccess(res, ctx, result);
      },
    },
    {
      method: 'PATCH',
      path: '/api/v1/projects/:projectId/scans/:scanId/findings/:findingId/lifecycle',
      requireAuth: true,
      handler: async (req, res, ctx): Promise<void> => {
        const actor = ctx.user;
        if (actor === undefined) throw unauthorized();
        const { project, finding } = await resolveFinding(ctx.params['projectId'], ctx.params['scanId'], ctx.params['findingId'], actor.id);
        if (project.status === 'ARCHIVED') throw projectArchived();
        rejectUnknownQueryParameters(req);
        const raw = await readJsonBody(req, { maxBytes: Math.min(config.bodyMaxBytes, 1024) });
        const parsed = lifecycleSchema.parse(raw);
        if (!parsed.ok) throw validationError(parsed.issues);
        if (!(FINDING_LIFECYCLE_STATES as readonly string[]).includes(parsed.value.state)) {
          throw validationError([{ path: 'state', message: `Must be one of: ${FINDING_LIFECYCLE_STATES.join(', ')}.` }]);
        }
        await assertProjectActive(project.id);
        const result = await scans.transitionFindingLifecycle(project.id, finding.fingerprint, parsed.value.state as FindingLifecycleState, actor.id, new Date(clock()).toISOString());
        if (result.outcome !== 'updated') {
          if (result.outcome === 'not-found') throw notFound('Finding lifecycle not found.');
          if (result.outcome === 'invalid-transition') throw conflict('That finding lifecycle transition is not allowed.');
          throw conflict('Finding lifecycle history reached its limit; no state was changed.');
        }
        sendSuccess(res, ctx, { workflow: result.workflow });
      },
    },
    {
      method: 'POST',
      path: '/api/v1/projects/:projectId/scans/:scanId/findings/:findingId/notes',
      requireAuth: true,
      handler: async (req, res, ctx): Promise<void> => {
        const actor = ctx.user;
        if (actor === undefined) throw unauthorized();
        const { project, finding } = await resolveFinding(ctx.params['projectId'], ctx.params['scanId'], ctx.params['findingId'], actor.id);
        if (project.status === 'ARCHIVED') throw projectArchived();
        rejectUnknownQueryParameters(req);
        const raw = await readJsonBody(req, { maxBytes: Math.min(config.bodyMaxBytes, 8192) });
        const parsed = remediationNoteSchema.parse(raw);
        if (!parsed.ok) throw validationError(parsed.issues);
        const prepared = prepareFindingNote(parsed.value.note);
        if (!prepared.ok) {
          const messages = {
            EMPTY: 'Note must contain text.',
            TOO_LONG: `Note must be at most ${FINDING_NOTE_MAX_LENGTH} characters.`,
            CONTROL_CHARACTER: 'Note contains unsupported control characters.',
            HTML_NOT_ALLOWED: 'Notes are plain text; HTML markup is not allowed.',
          } as const;
          throw validationError([{ path: 'note', message: messages[prepared.reason] }]);
        }
        await assertProjectActive(project.id);
        const result = await scans.addFindingRemediationNote(project.id, finding.fingerprint, prepared, actor.id, new Date(clock()).toISOString());
        if (result.outcome !== 'updated') {
          if (result.outcome === 'not-found') throw notFound('Finding lifecycle not found.');
          if (result.outcome === 'notes-limit') throw conflict('The remediation note limit has been reached.');
          if (result.outcome === 'invalid-note') throw validationError([{ path: 'note', message: 'Note could not be stored safely.' }]);
          throw conflict('Finding lifecycle history reached its limit; no note was saved.');
        }
        sendSuccess(res, ctx, { workflow: result.workflow });
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
        const findings = scan.findings ?? [];
        if (scan.resultSummary?.findingsTotal !== findings.length) throw conflict('Persisted finding details are incomplete; this scan cannot produce a complete report.');
        let outcome: Awaited<ReturnType<ScanStore['createReport']>> | undefined;
        try {
          for (let attempt = 0; attempt < 3; attempt += 1) {
            const workflows = await scans.getFindingWorkflowsForFindings(project.id, findings);
            if (workflows.length !== findings.length) throw new TypeError('Finding workflow snapshots are unavailable.');
            const report = buildSecurityReport(project, scan, new Date(clock()).toISOString(), workflows);
            outcome = await scans.createReport(report);
            if (outcome.outcome !== 'workflow-changed') break;
          }
        } catch (error) {
          if (error instanceof RangeError) throw conflict('The generated report exceeds the configured size limit.');
          throw internal('The report could not be generated safely.');
        }
        if (outcome === undefined || outcome.outcome === 'workflow-changed') throw conflict('Finding lifecycle changed while the report was generated; retry the request.');
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
        if (format === 'sarif') {
          sendAttachment(res, renderSecurityReportSarif(report), 'application/sarif+json; charset=utf-8', `${stem}.sarif`);
          return;
        }
        if (format === 'pdf') {
          try {
            sendAttachment(res, await renderSecurityReportPdf(report), 'application/pdf', `${stem}.pdf`);
          } catch (error) {
            if (error instanceof RangeError) throw conflict('The generated PDF exceeds the size limit.');
            throw internal('The report could not be rendered safely.');
          }
          return;
        }
        throw validationError([{ path: 'format', message: 'Must be json, markdown, sarif, or pdf.' }]);
      },
    },
    {
      method: 'GET',
      path: '/api/v1/projects/:projectId/reports/portfolio/download',
      requireAuth: true,
      handler: async (req, res, ctx): Promise<void> => {
        rejectUnknownQueryParameters(req);
        if (ctx.user === undefined) throw unauthorized();
        const project = await access.ownProjectOr403(ctx.params['projectId'], ctx.user.id);
        // Select the latest ATTEMPT, never an older completion after a failure.
        // Equal latest timestamps do not imply an order; mark them uncertain.
        const projectScans = await scans.listByProject(project.id);
        if (projectScans.some((scan) => scan.ownerId !== ctx.user?.id || scan.projectId !== project.id)) throw internal('Scan scope is inconsistent.');
        const generatedAt = new Date(clock()).toISOString();
        const entries: PortfolioPdfEntry[] = [];
        for (const scanner of SCAN_TYPES) {
          const latest = selectLatestAttempt(projectScans, scanner);
          if (latest.kind === 'NONE') {
            entries.push({ scanner, status: 'NOT_RUN' });
            continue;
          }
          if (latest.kind === 'ORDER_UNCERTAIN') {
            entries.push({ scanner, status: 'ORDER_UNCERTAIN', requestedAt: latest.requestedAt });
            continue;
          }
          const scan = latest.scan;
          if (scan.status !== 'COMPLETED') {
            entries.push({ scanner, status: scan.status, requestedAt: scan.createdAt });
            continue;
          }
          const findings = scan.findings ?? [];
          if (scan.resultSummary?.findingsTotal !== findings.length) throw conflict('A completed scan has incomplete finding details.');
          const workflows = await scans.getFindingWorkflowsForFindings(project.id, findings);
          if (workflows.length !== findings.length) throw conflict('Finding workflow snapshots are unavailable.');
          try {
            entries.push({ scanner, status: 'COMPLETED', requestedAt: scan.createdAt,
              report: buildSecurityReport(project, scan, generatedAt, workflows) });
          } catch (error) {
            if (error instanceof RangeError) throw conflict('A scan report exceeds the configured size limit.');
            throw internal('The project report could not be generated safely.');
          }
        }
        try {
          const pdf = await renderPortfolioPdf({ project: { id: project.id, name: project.name }, generatedAt, entries });
          sendAttachment(res, pdf, 'application/pdf', `drobon-project-${project.id}.pdf`);
        } catch (error) {
          if (error instanceof RangeError) throw conflict('The generated PDF exceeds the size limit.');
          throw internal('The project report could not be rendered safely.');
        }
      },
    },
    {
      method: 'GET',
      path: '/api/v1/projects/:projectId/scans/:scanId/report/sbom',
      requireAuth: true,
      handler: async (req, res, ctx): Promise<void> => {
        rejectUnknownQueryParameters(req);
        const report = await reportForScan(ctx);
        const sbom = renderSbomExport(report);
        if (sbom === undefined) throw validationError([{ path: 'sbom', message: 'This scan has no dependency inventory; a standalone SBOM export is unavailable.' }]);
        sendAttachment(res, sbom, 'application/json; charset=utf-8', `drobon-${report.reportId}.cdx.json`);
      },
    },
  ];
}
