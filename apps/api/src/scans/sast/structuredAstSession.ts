import { Worker } from 'node:worker_threads';
import type { AstCandidate, AstReporterMap } from './astAnalyzer.js';
import type { AstLanguageProfile } from './astProfiles.js';

/** The structured parser is intentionally narrower than the legacy profiles. */
const STRUCTURED_AST_FAMILIES: readonly string[] = ['javascript', 'typescript', 'jsx', 'tsx', 'python', 'php', 'java'];
export const STRUCTURED_AST_MAX_BYTES = 131_072;
export const STRUCTURED_AST_TIMEOUT_MS = 3_000;
export const STRUCTURED_AST_MAX_WORKERS = 4;
export const STRUCTURED_AST_MAX_WAITERS = 8;
export const STRUCTURED_AST_QUEUE_WAIT_MS = 1_500;
let activeWorkers = 0;
const waiters: Array<{ grant(): void }> = [];

type WorkerPermit = 'GRANTED' | 'ABORTED' | 'UNAVAILABLE';
function acquireWorker(signal: AbortSignal, closed: AbortSignal, remainingMs: number): Promise<WorkerPermit> {
  if (signal.aborted) return Promise.resolve('ABORTED');
  if (closed.aborted) return Promise.resolve('UNAVAILABLE');
  if (activeWorkers < STRUCTURED_AST_MAX_WORKERS && waiters.length === 0) {
    activeWorkers += 1;
    return Promise.resolve('GRANTED');
  }
  if (waiters.length >= STRUCTURED_AST_MAX_WAITERS || remainingMs <= 0) return Promise.resolve('UNAVAILABLE');
  return new Promise<WorkerPermit>((resolve) => {
    let finished = false;
    const waiter = { grant: (): void => finish('GRANTED') };
    const finish = (result: WorkerPermit): void => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      signal.removeEventListener('abort', onAbort);
      closed.removeEventListener('abort', onClose);
      const index = waiters.indexOf(waiter);
      if (index >= 0) waiters.splice(index, 1);
      if (result === 'GRANTED') activeWorkers += 1;
      resolve(result);
    };
    const onAbort = (): void => finish('ABORTED');
    const onClose = (): void => finish('UNAVAILABLE');
    const timer = setTimeout(() => finish('UNAVAILABLE'), Math.max(1, Math.min(STRUCTURED_AST_QUEUE_WAIT_MS, remainingMs)));
    waiters.push(waiter);
    signal.addEventListener('abort', onAbort, { once: true });
    closed.addEventListener('abort', onClose, { once: true });
    if (signal.aborted) onAbort();
    else if (closed.aborted) onClose();
  });
}
function releaseWorker(): void {
  activeWorkers -= 1;
  const next = waiters.shift();
  if (next !== undefined) next.grant();
}

export function supportsStructuredAst(family: string): boolean {
  return STRUCTURED_AST_FAMILIES.includes(family);
}

export type StructuredAstStatus = 'OK' | 'SYNTAX_ERROR' | 'LIMIT' | 'ERROR' | 'TIMEOUT' | 'UNAVAILABLE' | 'ABORTED';
export interface StructuredAstResult {
  status: StructuredAstStatus;
  candidates: AstCandidate[];
}

export interface AstTraceLocation { file: string; line: number; column: number }
export interface ProjectAstCandidate extends AstCandidate {
  path: string;
  source: AstTraceLocation;
  via: AstTraceLocation[];
}
export interface ProjectAstResult {
  status: StructuredAstStatus;
  examinedFiles: number;
  unresolvedImports: number;
  candidates: ProjectAstCandidate[];
}
export interface ProjectAstFile {
  path: string;
  family: string;
  content: string;
  profile: AstLanguageProfile;
  reporters: AstReporterMap;
}

/**
 * One isolated, reusable parser worker per SAST scan. The worker has a heap
 * bound and per-file timeout; a hung or failed worker is terminated and never
 * retried during that scan. This protects the API's event loop from hostile
 * parser inputs. The existing SAST passes continue if this pass is incomplete.
 */
export class StructuredAstSession {
  private worker: Worker | undefined;
  private unavailable = false;
  private busy = false;
  private readonly closed = new AbortController();

  async analyze(input: {
    family: string;
    content: string;
    profile: AstLanguageProfile;
    reporters: AstReporterMap;
  }, signal: AbortSignal, remainingMs: number): Promise<StructuredAstResult> {
    if (signal.aborted) return { status: 'ABORTED', candidates: [] };
    if (Buffer.byteLength(input.content, 'utf8') > STRUCTURED_AST_MAX_BYTES) return { status: 'LIMIT', candidates: [] };
    return await this.request(input, signal, remainingMs);
  }

  /** Scanner-specific modes share the same bounded worker queue. Results are
   * untrusted until each caller validates its own record shape. */
  async analyzeSupplement(input: {
    kind: 'DAST' | 'SECRETS' | 'SCA';
    content: string;
    family?: string;
    contentType?: string;
    profile?: AstLanguageProfile;
  }, signal: AbortSignal, remainingMs: number): Promise<{ status: StructuredAstStatus; records: unknown[] }> {
    if (signal.aborted) return { status: 'ABORTED', records: [] };
    if (Buffer.byteLength(input.content, 'utf8') > STRUCTURED_AST_MAX_BYTES) return { status: 'LIMIT', records: [] };
    const result = await this.request({ mode: 'supplement', ...input }, signal, remainingMs);
    return { status: result.status, records: result.candidates as unknown[] };
  }

  async analyzeProject(files: readonly ProjectAstFile[], signal: AbortSignal, remainingMs: number): Promise<ProjectAstResult> {
    const result = await this.request({ mode: 'project', files }, signal, remainingMs);
    return {
      status: result.status,
      examinedFiles: result.examinedFiles ?? 0,
      unresolvedImports: result.unresolvedImports ?? 0,
      candidates: result.candidates as ProjectAstCandidate[],
    };
  }

  private async request(input: unknown, signal: AbortSignal, remainingMs: number): Promise<StructuredAstResult & { examinedFiles?: number; unresolvedImports?: number }> {
    const empty = (status: StructuredAstStatus): StructuredAstResult => ({ status, candidates: [] });
    if (signal.aborted) return empty('ABORTED');
    if (this.unavailable || this.busy) return empty('UNAVAILABLE');
    const startedAt = Date.now();
    if (this.worker === undefined) {
      // A small FIFO queue avoids immediately dropping ordinary concurrent
      // scans, while bounding both queued work and how long a scan may wait.
      this.busy = true;
      const permit = await acquireWorker(signal, this.closed.signal, remainingMs);
      this.busy = false;
      if (permit !== 'GRANTED') { this.unavailable = true; return empty(permit); }
      if (this.unavailable || signal.aborted) {
        releaseWorker();
        this.unavailable = true;
        return empty(signal.aborted ? 'ABORTED' : 'UNAVAILABLE');
      }
      try {
        this.worker = new Worker(new URL('./structuredAstWorker.mjs', import.meta.url), {
          // The worker is plain application-owned JavaScript; it does not need
          // inherited loaders, inspector flags or stdin-only Node options.
          execArgv: [],
          resourceLimits: { maxOldGenerationSizeMb: 96, maxYoungGenerationSizeMb: 16, stackSizeMb: 4 },
        });
        // Permanent error listener prevents an asynchronous worker error from
        // becoming an unhandled process-level error between requests.
        this.worker.on('error', () => { this.unavailable = true; });
        this.worker.once('exit', () => {
          this.unavailable = true;
          releaseWorker();
        });
      } catch {
        releaseWorker();
        this.unavailable = true;
        return empty('UNAVAILABLE');
      }
    }
    const worker = this.worker;
    const timeoutMs = Math.max(1, Math.min(STRUCTURED_AST_TIMEOUT_MS, Math.floor(remainingMs - (Date.now() - startedAt))));
    this.busy = true;
    return await new Promise<StructuredAstResult & { examinedFiles?: number; unresolvedImports?: number }>((resolve) => {
      let finished = false;
      const cleanup = (): void => {
        clearTimeout(timer);
        worker.off('message', onMessage);
        worker.off('error', onError);
        worker.off('exit', onExit);
        signal.removeEventListener('abort', onAbort);
      };
      const finish = (result: StructuredAstResult & { examinedFiles?: number; unresolvedImports?: number }, terminate = false): void => {
        if (finished) return;
        finished = true;
        cleanup();
        if (terminate) {
          this.unavailable = true;
          void worker.terminate().catch(() => undefined);
        }
        resolve(result);
      };
      const onMessage = (value: unknown): void => {
        // The worker is application-owned; still reject unexpected responses.
        if (typeof value !== 'object' || value === null) { finish(empty('ERROR'), true); return; }
        const result = value as Partial<StructuredAstResult & { examinedFiles: number; unresolvedImports: number }>;
        if (!['OK', 'SYNTAX_ERROR', 'LIMIT', 'ERROR'].includes(result.status ?? '') || !Array.isArray(result.candidates) || result.candidates.length > 1_001 ||
            (result.examinedFiles !== undefined && (!Number.isInteger(result.examinedFiles) || result.examinedFiles < 0 || result.examinedFiles > 64)) ||
            (result.unresolvedImports !== undefined && (!Number.isInteger(result.unresolvedImports) || result.unresolvedImports < 0 || result.unresolvedImports > 30_000))) {
          finish(empty('ERROR'), true);
          return;
        }
        finish({ status: result.status as StructuredAstStatus, candidates: result.candidates,
          ...(result.examinedFiles === undefined ? {} : { examinedFiles: result.examinedFiles }),
          ...(result.unresolvedImports === undefined ? {} : { unresolvedImports: result.unresolvedImports }) });
      };
      const onError = (): void => { finish(empty('ERROR'), true); };
      const onExit = (): void => { finish(empty('UNAVAILABLE')); };
      const onAbort = (): void => { finish(empty('ABORTED'), true); };
      const timer = setTimeout(() => finish(empty('TIMEOUT'), true), timeoutMs);
      worker.once('message', onMessage);
      worker.once('error', onError);
      worker.once('exit', onExit);
      signal.addEventListener('abort', onAbort, { once: true });
      if (signal.aborted) { onAbort(); return; }
      try { worker.postMessage(input); } catch { finish(empty('ERROR'), true); }
    }).finally(() => { this.busy = false; });
  }

  async close(): Promise<void> {
    this.unavailable = true;
    this.closed.abort();
    if (this.worker !== undefined) {
      try { await this.worker.terminate(); } catch { /* already stopped */ }
      this.worker = undefined;
    }
  }
}
