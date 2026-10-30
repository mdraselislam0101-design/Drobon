/**
 * Unified Dataset Service — filesystem-backed loader for ALL Drobon-Dataset categories.
 * Isolation preserved: reads from external DATASET_PATH only at runtime, never committed.
 * Server-side only, read-only, cached per process, honest DATASET_* statuses.
 *
 * Loader conformance (GAP-042): every pack file is closed-field/schema validated,
 * ReDoS-linted and its declared tests executed before it can reach an engine.
 * Refused rules are dropped and counted on the status surface, never hidden.
 */

import { readdir, readFile, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { isValidSourcePath } from '@drobon/shared';
import type {
  DatasetOverallStatus, DatasetCategoryStatus, DatasetAvailability,
  DatasetPackIdentity, VulnIntelCounts,
} from './types.js';
import { emptyPackReport, parsePackManifest, validatePackRules, type PackFamily, type PackReport } from './conformance.js';
import { SCA_READABLE_PARSERS } from './scaDeclaration.js';

const PACK_FAMILIES: readonly PackFamily[] = ['sast', 'secrets', 'dast', 'sca'];

/** Potentially eligible rules: parser exists and the exact artifact can be uploaded.
 * This is NOT a guarantee that a bounded reader understands every shape. */
function reachableScaRuleCount(rules: readonly unknown[]): number {
  let count = 0;
  for (const raw of rules) {
    if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) continue;
    const parser = (raw as Record<string, unknown>)['parser'];
    const artifact = (raw as Record<string, unknown>)['artifact'];
    if (typeof parser === 'string' && (SCA_READABLE_PARSERS as readonly string[]).includes(parser) &&
        isValidSourcePath(artifact) && !artifact.includes('/')) count += 1;
  }
  return count;
}

async function collectJsonFiles(dir: string, out: string[] = []): Promise<string[]> {
  let entries: string[];
  try { entries = await readdir(dir); } catch { return out; }
  for (const entry of entries) {
    const full = join(dir, entry);
    let s;
    try { s = await stat(full); } catch { continue; }
    if (s.isDirectory()) await collectJsonFiles(full, out);
    else if (entry.endsWith('.json')) out.push(full);
  }
  return out;
}

function avail(count: number, providerId: string, configured: boolean, pack?: DatasetPackIdentity): DatasetCategoryStatus {
  if (!configured) return { status: 'NOT_CONFIGURED', count: 0, providerId: 'none' };
  if (count === 0) return { status: 'UNAVAILABLE', count: 0, providerId };
  return {
    status: 'AVAILABLE', count, providerId,
    ...(pack === undefined ? {} : { packId: pack.packId, version: pack.version }),
  };
}

async function loadRawPackDir(path: string): Promise<unknown[]> {
  const files = (await collectJsonFiles(join(path, 'rules'))).sort();
  const out: unknown[] = [];
  for (const file of files) {
    try { out.push(JSON.parse(await readFile(file, 'utf8'))); } catch { /* skip malformed JSON honestly */ }
  }
  return out;
}

async function loadDir(path: string): Promise<unknown[]> {
  const files = (await collectJsonFiles(path)).sort();
  const out: unknown[] = [];
  for (const file of files) {
    try { out.push(JSON.parse(await readFile(file, 'utf8'))); } catch { /* skip malformed JSON honestly */ }
  }
  return out;
}

export function createDatasetService(options: { datasetPath?: string | undefined; providerId: string; logger?: Pick<Console, 'info' | 'warn' | 'error'> }) {
  const { datasetPath, providerId, logger } = options;
  const configured = providerId === 'filesystem' && typeof datasetPath === 'string' && datasetPath.length > 0;
  // GAP-046: an unconfigured start must be LOUD, not silent. The app still
  // starts (honest degradation), but operators are told exactly what is off.
  if (!configured) {
    logger?.warn?.('[dataset] STARTUP: VULN_INTEL_PROVIDER=none — no external Drobon-Dataset. SAST/Secrets/DAST have 0 rules, remediation is UNAVAILABLE, SCA stays NOT_ASSESSED. Set VULN_INTEL_PROVIDER=filesystem + DATASET_PATH to unlock.');
  }

  // Share the in-flight load across concurrent scans. Marking a cache loaded
  // before the awaits finished exposed transient empty rule sets to callers.
  let loading: Promise<void> | undefined;
  let overall: DatasetOverallStatus | null = null;

  let sastPackRules: unknown[] = [];
  let secretsPackRules: unknown[] = [];
  let dastPackRules: unknown[] = [];
  let scaPackRules: unknown[] = [];
  let remediationRecords: unknown[] = [];
  let cweRecords: unknown[] = [];
  let lessonRecords: unknown[] = [];
  let assessmentTemplates: unknown[] = [];
  let engagementTemplates: unknown[] = [];
  let vulnIntelCount = 0;
  let vulnIntelCounts: VulnIntelCounts = { files: 0, identityItems: 0, advisoryIds: 0 };
  const packs: Partial<Record<PackFamily, DatasetPackIdentity>> = {};
  const reports: Record<PackFamily, PackReport> = {
    sast: emptyPackReport(), secrets: emptyPackReport(), dast: emptyPackReport(), sca: emptyPackReport(),
  };

  function ensureLoaded(): Promise<void> {
    if (loading === undefined) loading = loadOnce();
    return loading;
  }

  async function loadOnce(): Promise<void> {
    if (!configured || !datasetPath) {
      overall = buildOverall(new Date().toISOString());
      logger?.info?.('[dataset] No external dataset configured: scanners run with honest NOT_CONFIGURED / NO_DATA_LOADED states.');
      return;
    }
    try {
      // --- vuln-intel: raw file count plus canonical identity counters ---
      const npmFiles = await collectJsonFiles(join(datasetPath, 'vuln-intel', 'npm'));
      const pypiFiles = await collectJsonFiles(join(datasetPath, 'vuln-intel', 'pypi'));
      const allVuln = [...npmFiles, ...pypiFiles].filter((f) => !f.includes('/samples/') && !f.includes('\\samples\\'));
      vulnIntelCount = allVuln.length;
      const identities = new Set<string>();
      const advisoryIds = new Set<string>();
      for (const file of allVuln) {
        try {
          const record = JSON.parse(await readFile(file, 'utf8')) as Record<string, unknown>;
          if (record['fixture'] === true) continue;
          const id = typeof record['id'] === 'string' ? record['id'] : '';
          const provenance = record['provenance'];
          const source = typeof provenance === 'object' && provenance !== null && typeof (provenance as Record<string, unknown>)['source'] === 'string'
            ? String((provenance as Record<string, unknown>)['source']) : '';
          const ecosystem = typeof record['ecosystem'] === 'string' ? record['ecosystem'] : '';
          const pkg = typeof record['package'] === 'string' ? record['package'] : '';
          if (id.length === 0) continue;
          identities.add(`${source}\u0000${id}\u0000${ecosystem}\u0000${pkg}`);
          advisoryIds.add(id);
        } catch { /* unreadable record is skipped, never counted */ }
      }
      vulnIntelCounts = { files: allVuln.length, identityItems: identities.size, advisoryIds: advisoryIds.size };

      // --- packs: validate, execute declared tests, read manifest identity ---
      for (const family of PACK_FAMILIES) {
        const path = join(datasetPath, 'packs', family, 'v1');
        const raw = await loadRawPackDir(path);
        const outcome = validatePackRules(raw, family);
        reports[family] = outcome.report;
        if (family === 'sast') sastPackRules = outcome.rules;
        else if (family === 'secrets') secretsPackRules = outcome.rules;
        else if (family === 'dast') dastPackRules = outcome.rules;
        else scaPackRules = outcome.rules;
        try {
          const manifest = parsePackManifest(JSON.parse(await readFile(join(path, 'pack.json'), 'utf8')));
          if (manifest !== undefined) packs[family] = manifest;
        } catch { /* missing manifest: status says so */ }
        if (outcome.report.accepted < outcome.report.filesSeen) {
          logger?.warn?.(`[dataset] ${family}: accepted ${outcome.report.accepted}/${outcome.report.filesSeen} rules; ${outcome.report.failedTests} declared-test failures`);
        }
      }

      // --- knowledge + audiences ---
      remediationRecords = await loadDir(join(datasetPath, 'knowledge', 'remediation'));
      cweRecords = await loadDir(join(datasetPath, 'knowledge', 'cwe'));
      lessonRecords = await loadDir(join(datasetPath, 'learning', 'lessons'));
      assessmentTemplates = await loadDir(join(datasetPath, 'assessments', 'templates'));
      engagementTemplates = await loadDir(join(datasetPath, 'engagements'));

      overall = buildOverall(new Date().toISOString());
      logger?.info?.(`[dataset] Loaded vuln=${vulnIntelCount} sast=${sastPackRules.length} sec=${secretsPackRules.length} dast=${dastPackRules.length} sca=${scaPackRules.length} remediation=${remediationRecords.length} cwe=${cweRecords.length} lessons=${lessonRecords.length} tmpl=${assessmentTemplates.length} eng=${engagementTemplates.length} from ${datasetPath}`);
    } catch (err) {
      logger?.warn?.(`[dataset] load failed: ${(err as Error).message}`);
      overall = buildOverall(new Date().toISOString());
    }
  }

  function buildOverall(loadedAt: string): DatasetOverallStatus {
    const mk = (count: number, pack?: DatasetPackIdentity): DatasetCategoryStatus => avail(count, providerId, configured, pack);
    let byUserType: Record<string, number> | undefined;
    if (lessonRecords.length > 0) {
      const dev = lessonRecords.filter((r) => {
        if (typeof r !== 'object' || r === null) return false;
        const id = (r as Record<string, unknown>)['id'];
        return typeof id === 'string' && id.startsWith('lsn_dev_');
      }).length;
      byUserType = { DEVELOPER: dev, STUDENT: lessonRecords.length, SECURITY_PROFESSIONAL: 0, PENTESTER: 0 };
    }
    return {
      configured,
      ...(datasetPath ? { datasetPath } : {}),
      providerId,
      vulnIntel: configured
        ? (vulnIntelCount > 0
          ? { status: 'AVAILABLE' as DatasetAvailability, count: vulnIntelCount, providerId }
          : { status: 'UNAVAILABLE', count: 0, providerId })
        : { status: 'NOT_CONFIGURED', count: 0, providerId: 'none' },
      vulnIntelCounts,
      sastPacks: mk(sastPackRules.length, packs.sast),
      secretsPacks: mk(secretsPackRules.length, packs.secrets),
      dastPacks: mk(dastPackRules.length, packs.dast),
      scaPacks: mk(scaPackRules.length, packs.sca),
      packs: { ...packs },
      conformance: {
        sast: reports.sast, secrets: reports.secrets, dast: reports.dast, sca: reports.sca,
        scaDeclarationEvaluator: 'AVAILABLE',
        scaDeclarationScanParsers: SCA_READABLE_PARSERS,
        scaDeclarationScanReachableRules: reachableScaRuleCount(scaPackRules),
      },
      remediation: mk(remediationRecords.length),
      cwe: mk(cweRecords.length),
      lessons: { ...mk(lessonRecords.length), ...(byUserType ? { byUserType } : {}) },
      assessmentTemplates: mk(assessmentTemplates.length),
      engagementTemplates: mk(engagementTemplates.length),
      ...(configured ? { loadedAt } : {}),
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

    // Raw accessors (only conformance-validated rules are exposed).
    sastPacks: async (): Promise<unknown[]> => { await ensureLoaded(); return sastPackRules; },
    secretsPacks: async (): Promise<unknown[]> => { await ensureLoaded(); return secretsPackRules; },
    dastPacks: async (): Promise<unknown[]> => { await ensureLoaded(); return dastPackRules; },
    scaPacks: async (): Promise<unknown[]> => { await ensureLoaded(); return scaPackRules; },
    remediation: async (): Promise<unknown[]> => { await ensureLoaded(); return remediationRecords; },
    cwe: async (): Promise<unknown[]> => { await ensureLoaded(); return cweRecords; },
    lessons: async (): Promise<unknown[]> => { await ensureLoaded(); return lessonRecords; },
    assessmentTemplates: async (): Promise<unknown[]> => { await ensureLoaded(); return assessmentTemplates; },
    engagementTemplates: async (): Promise<unknown[]> => { await ensureLoaded(); return engagementTemplates; },
    vulnIntelCount: async (): Promise<number> => { await ensureLoaded(); return vulnIntelCount; },
    vulnIntelCounts: async (): Promise<VulnIntelCounts> => { await ensureLoaded(); return vulnIntelCounts; },
    packMetadata: async (family: PackFamily): Promise<DatasetPackIdentity | undefined> => { await ensureLoaded(); return packs[family]; },
    conformance: async () => {
      await ensureLoaded();
      return {
        ...reports,
        scaDeclarationEvaluator: 'AVAILABLE' as const,
        scaDeclarationScanParsers: SCA_READABLE_PARSERS,
        scaDeclarationScanReachableRules: reachableScaRuleCount(scaPackRules),
      };
    },
  };
}

export type DatasetService = ReturnType<typeof createDatasetService>;
