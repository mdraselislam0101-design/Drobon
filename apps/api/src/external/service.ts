/**
 * Unified Dataset Service — filesystem-backed loader for ALL Drobon-Dataset categories.
 * Isolation preserved: reads from external DATASET_PATH only at runtime, never committed.
 * Server-side only, read-only, cached per process, honest DATASET_* statuses.
 */

import { readdir, readFile, stat } from 'node:fs/promises';
import { join } from 'node:path';
import type { DatasetOverallStatus, DatasetCategoryStatus, DatasetAvailability } from './types.js';

interface LoaderOptions {
  datasetPath: string;
  logger?: Pick<Console, 'info' | 'warn' | 'error'>;
}

async function collectJsonFiles(dir: string, out: string[] = []): Promise<string[]> {
  let entries: string[];
  try {
    entries = await readdir(dir);
  } catch {
    return out;
  }
  for (const entry of entries) {
    const full = join(dir, entry);
    let s;
    try {
      s = await stat(full);
    } catch {
      continue;
    }
    if (s.isDirectory()) await collectJsonFiles(full, out);
    else if (entry.endsWith('.json')) out.push(full);
  }
  return out;
}

function avail(count: number, providerId: string, configured: boolean): DatasetCategoryStatus {
  if (!configured) return { status: 'NOT_CONFIGURED', count: 0, providerId: 'none' };
  if (count === 0) return { status: 'UNAVAILABLE', count: 0, providerId };
  return { status: 'AVAILABLE', count, providerId };
}

export function createDatasetService(options: { datasetPath?: string; providerId: string; logger?: Pick<Console, 'info' | 'warn' | 'error'> }) {
  const { datasetPath, providerId, logger } = options;
  const configured = providerId === 'filesystem' && typeof datasetPath === 'string' && datasetPath.length > 0;

  let loaded = false;
  let loadError: string | null = null;
  let overall: DatasetOverallStatus | null = null;

  // Cached payloads
  let sastPackRules: unknown[] = [];
  let secretsPackRules: unknown[] = [];
  let dastPackRules: unknown[] = [];
  let remediationRecords: unknown[] = [];
  let cweRecords: unknown[] = [];
  let lessonRecords: unknown[] = [];
  let assessmentTemplates: unknown[] = [];
  let engagementTemplates: unknown[] = [];
  let vulnIntelCount = 0;

  async function ensureLoaded(): Promise<void> {
    if (loaded) return;
    loaded = true;
    if (!configured || !datasetPath) {
      overall = buildOverall(0);
      return;
    }
    const now = new Date().toISOString();
    try {
      // vuln-intel
      const npmFiles = await collectJsonFiles(join(datasetPath, 'vuln-intel', 'npm'));
      const pypiFiles = await collectJsonFiles(join(datasetPath, 'vuln-intel', 'pypi'));
      const allVuln = [...npmFiles, ...pypiFiles].filter(f => !f.includes('/samples/') && !f.includes('\\samples\\'));
      vulnIntelCount = allVuln.length;

      // packs
      sastPackRules = await loadPackDir(join(datasetPath, 'packs', 'sast', 'v1', 'rules'));
      secretsPackRules = await loadPackDir(join(datasetPath, 'packs', 'secrets', 'v1', 'rules'));
      dastPackRules = await loadPackDir(join(datasetPath, 'packs', 'dast', 'v1', 'rules'));

      // knowledge
      remediationRecords = await loadDir(join(datasetPath, 'knowledge', 'remediation'));
      cweRecords = await loadDir(join(datasetPath, 'knowledge', 'cwe'));

      // audiences
      lessonRecords = await loadDir(join(datasetPath, 'learning', 'lessons'));
      assessmentTemplates = await loadDir(join(datasetPath, 'assessments', 'templates'));
      engagementTemplates = await loadDir(join(datasetPath, 'engagements'));

      overall = buildOverall(now);
      logger?.info?.(`[dataset] Loaded overall: vuln=${vulnIntelCount} sast=${sastPackRules.length} sec=${secretsPackRules.length} dast=${dastPackRules.length} remediation=${remediationRecords.length} cwe=${cweRecords.length} lessons=${lessonRecords.length} tmpl=${assessmentTemplates.length} eng=${engagementTemplates.length} from ${datasetPath}`);
    } catch (err) {
      loadError = (err as Error).message;
      logger?.warn?.(`[dataset] load failed: ${loadError}`);
      overall = buildOverall(now);
    }
  }

  async function loadPackDir(dir: string): Promise<unknown[]> {
    const files = await collectJsonFiles(dir);
    const out: unknown[] = [];
    for (const f of files) {
      try {
        const raw = await readFile(f, 'utf8');
        const parsed = JSON.parse(raw);
        // basic shape guard: must have schemaVersion and id
        if (typeof parsed?.schemaVersion === 'string' && typeof parsed?.id === 'string' && !parsed.id.includes('SAMPLE')) {
          out.push(parsed);
        }
      } catch {
        continue;
      }
    }
    return out;
  }
  async function loadDir(dir: string): Promise<unknown[]> {
    const files = await collectJsonFiles(dir);
    const out: unknown[] = [];
    for (const f of files) {
      try {
        const raw = await readFile(f, 'utf8');
        out.push(JSON.parse(raw));
      } catch {
        continue;
      }
    }
    return out;
  }

  function buildOverall(loadedAt: string | number): DatasetOverallStatus {
    const ts = typeof loadedAt === 'string' ? loadedAt : new Date(loadedAt).toISOString();
    const mk = (count: number): DatasetCategoryStatus => avail(count, providerId, configured);
    // byUserType for lessons: count dev lessons (lsn_dev_*) vs student
    let byUserType: Record<string, number> | undefined;
    if (lessonRecords.length > 0) {
      const dev = lessonRecords.filter((r: any) => typeof r.id === 'string' && r.id.startsWith('lsn_dev_')).length;
      const all = lessonRecords.length;
      byUserType = { DEVELOPER: dev, STUDENT: all, SECURITY_PROFESSIONAL: 0, PENTESTER: 0 };
    }
    return {
      configured,
      ...(datasetPath ? { datasetPath } : {}),
      providerId,
      vulnIntel: configured ? (vulnIntelCount > 0 ? { status: 'AVAILABLE' as DatasetAvailability, count: vulnIntelCount, providerId } : { status: 'UNAVAILABLE', count: 0, providerId }) : { status: 'NOT_CONFIGURED', count: 0, providerId: 'none' },
      sastPacks: mk(sastPackRules.length),
      secretsPacks: mk(secretsPackRules.length),
      dastPacks: mk(dastPackRules.length),
      remediation: mk(remediationRecords.length),
      cwe: mk(cweRecords.length),
      lessons: { ...mk(lessonRecords.length), ...(byUserType ? { byUserType } : {}) },
      assessmentTemplates: mk(assessmentTemplates.length),
      engagementTemplates: mk(engagementTemplates.length),
      ...(configured ? { loadedAt: ts } : {}),
    };
  }

  return {
    get configured() { return configured; },
    get datasetPath() { return datasetPath; },
    get providerId() { return providerId; },

    status: async (): Promise<DatasetOverallStatus> => {
      await ensureLoaded();
      return overall ?? buildOverall(new Date().toISOString());
    },

    // Raw accessors for engines/providers
    sastPacks: async (): Promise<unknown[]> => { await ensureLoaded(); return sastPackRules; },
    secretsPacks: async (): Promise<unknown[]> => { await ensureLoaded(); return secretsPackRules; },
    dastPacks: async (): Promise<unknown[]> => { await ensureLoaded(); return dastPackRules; },
    remediation: async (): Promise<unknown[]> => { await ensureLoaded(); return remediationRecords; },
    cwe: async (): Promise<unknown[]> => { await ensureLoaded(); return cweRecords; },
    lessons: async (): Promise<unknown[]> => { await ensureLoaded(); return lessonRecords; },
    assessmentTemplates: async (): Promise<unknown[]> => { await ensureLoaded(); return assessmentTemplates; },
    engagementTemplates: async (): Promise<unknown[]> => { await ensureLoaded(); return engagementTemplates; },
    vulnIntelCount: async (): Promise<number> => { await ensureLoaded(); return vulnIntelCount; },
  };
}

export type DatasetService = ReturnType<typeof createDatasetService>;
