/**
 * Unified Dataset Service — filesystem-backed loader for ALL Drobon-Dataset categories.
 * Isolation preserved: reads from external DATASET_PATH only at runtime, never committed.
 * Server-side only, read-only, cached per process, honest DATASET_* statuses.
 *
 * Loader conformance (GAP-042): every pack file is closed-field/schema validated,
 * ReDoS-linted and its declared tests executed before it can reach an engine.
 * Refused rules are dropped and counted on the status surface, never hidden.
 */

import { lstat, opendir, realpath } from 'node:fs/promises';
import { basename, isAbsolute, join, relative, sep } from 'node:path';
import { isValidSourcePath } from '@drobon/shared';
import type {
  DatasetOverallStatus, DatasetCategoryStatus, DatasetAvailability, DatasetLoadIssues,
  DatasetPackIdentity, VulnIntelCounts,
} from './types.js';
import { emptyPackReport, parsePackManifest, validatePackRules, type PackFamily, type PackReport } from './conformance.js';
import { SCA_READABLE_PARSERS } from './scaDeclaration.js';
import { createJsonByteBudget, isResourceLimitError, readBoundedJsonFile, type JsonByteBudget } from './boundedJson.js';

/** Conservative process-local load ceilings; the pinned Dataset is much smaller.
 * Overrides are an internal test seam and can lower, but never raise, ceilings. */
export const DATASET_LOADER_LIMITS = {
  maxEntries: 50_000, maxFiles: 20_000, maxDepth: 16,
  maxFileBytes: 2 * 1024 * 1024, maxTotalBytes: 64 * 1024 * 1024,
  maxJsonDepth: 64, maxJsonTokens: 100_000,
} as const;
type DatasetLimits = { [K in keyof typeof DATASET_LOADER_LIMITS]: number };

function datasetLimits(overrides: Partial<DatasetLimits> | undefined): DatasetLimits {
  const limit = (key: keyof DatasetLimits): number => {
    const value = overrides?.[key];
    return typeof value === 'number' && Number.isSafeInteger(value) && value > 0
      ? Math.min(value, DATASET_LOADER_LIMITS[key]) : DATASET_LOADER_LIMITS[key];
  };
  return { maxEntries: limit('maxEntries'), maxFiles: limit('maxFiles'), maxDepth: limit('maxDepth'),
    maxFileBytes: limit('maxFileBytes'), maxTotalBytes: limit('maxTotalBytes'),
    maxJsonDepth: limit('maxJsonDepth'), maxJsonTokens: limit('maxJsonTokens') };
}

interface LoadBudget {
  root: string;
  limits: DatasetLimits;
  bytes: JsonByteBudget;
  entries: number;
  files: number;
  entryLimitReached: boolean;
  fileLimitReached: boolean;
}

const PACK_FAMILIES: readonly PackFamily[] = ['sast', 'secrets', 'dast', 'sca'];
const NON_PACK_CATEGORIES = ['vulnIntel', 'remediation', 'cwe', 'lessons', 'assessmentTemplates', 'engagementTemplates'] as const;
type NonPackCategory = typeof NON_PACK_CATEGORIES[number];

function emptyLoadIssues(): DatasetLoadIssues {
  return { filesSeen: 0, unreadableFiles: 0, invalidRecords: 0, enumerationFailures: 0 };
}

function withLoadIssues(status: DatasetCategoryStatus, issues: DatasetLoadIssues | undefined): DatasetCategoryStatus {
  if (issues === undefined || (issues.unreadableFiles === 0 && issues.invalidRecords === 0 && issues.enumerationFailures === 0 &&
      (issues.duplicateRecords ?? 0) === 0 && (issues.resourceLimitFailures ?? 0) === 0)) return status;
  // Counts only: paths, filenames, raw records, and exception messages stay private.
  return { ...status, incomplete: true, loadIssues: { ...issues } };
}

/** Potentially eligible rules: parser exists and the exact artifact can be uploaded.
 * This is NOT a guarantee that a bounded reader understands every shape. */
function reachableScaRuleCount(rules: readonly unknown[]): number {
  let count = 0;
  for (const raw of rules) {
    if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) continue;
    const parser = (raw as Record<string, unknown>)['parser'];
    const artifact = (raw as Record<string, unknown>)['artifact'];
    if (typeof parser === 'string' && (SCA_READABLE_PARSERS as readonly string[]).includes(parser) &&
        isValidSourcePath(artifact)) count += 1;
  }
  return count;
}

type EnumerationFailure = (path: string, reason: string, resourceLimit?: boolean) => void;

/** Expose only a validated pack-style filename, never arbitrary path text. */
function safeDiagnosticName(path: string, fallback: string): string {
  const name = basename(path);
  return /^DPK-(?:(?:SAST|SEC|DAST)-[0-9]{3,6}|SCA-[0-9]{4,6})(?:\.json)?$/.test(name)
    ? name : fallback;
}

/** Check every fixed path component below the operator-selected canonical root.
 * This prevents static parent symlink escapes; concurrent replacement is not
 * an OS-level sandbox and remains an operational limitation. */
async function assertSafeDirectory(root: string, dir: string): Promise<void> {
  const rel = relative(root, dir);
  if (rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel)) throw new Error('directory outside configured root');
  let current = root;
  for (const part of rel.split(sep).filter(Boolean)) {
    current = join(current, part);
    const info = await lstat(current);
    if (info.isSymbolicLink() || !info.isDirectory()) throw new Error('unsafe dataset directory');
  }
}

async function collectJsonFiles(dir: string, budget: LoadBudget, out: string[] = [], onFailure?: EnumerationFailure, depth = 0): Promise<string[]> {
  if (budget.entryLimitReached || budget.fileLimitReached) {
    onFailure?.(dir, 'resource limit exceeded during enumeration', true);
    return out;
  }
  try {
    if (depth === 0) await assertSafeDirectory(budget.root, dir);
    else {
      const info = await lstat(dir);
      if (info.isSymbolicLink() || !info.isDirectory()) throw new Error('unsafe dataset directory');
    }
    // opendir streams directory entries rather than allocating an unbounded list.
    const entries = await opendir(dir);
    for await (const entry of entries) {
      if (budget.entries >= budget.limits.maxEntries) {
        budget.entryLimitReached = true;
        onFailure?.(dir, 'resource limit exceeded during enumeration', true);
        break;
      }
      budget.entries += 1;
      const full = join(dir, entry.name);
      let info;
      try { info = await lstat(full); } catch {
        onFailure?.(full, 'dataset entry could not be inspected');
        continue;
      }
      if (info.isSymbolicLink()) onFailure?.(full, 'symbolic link was not followed');
      else if (info.isDirectory()) {
        if (depth >= budget.limits.maxDepth) onFailure?.(full, 'directory depth limit exceeded', true);
        else await collectJsonFiles(full, budget, out, onFailure, depth + 1);
      } else if (info.isFile() && entry.name.endsWith('.json')) {
        if (budget.files >= budget.limits.maxFiles) {
          budget.fileLimitReached = true;
          onFailure?.(full, 'file count limit exceeded', true);
          break;
        }
        budget.files += 1;
        out.push(full);
      } else if (!info.isFile()) onFailure?.(full, 'unsupported filesystem entry was not read');
      if (budget.entryLimitReached || budget.fileLimitReached) break;
    }
  } catch {
    onFailure?.(dir, 'dataset directory could not be enumerated');
  }
  return out;
}

async function readDatasetJson(file: string, budget: LoadBudget): Promise<unknown> {
  return readBoundedJsonFile(file, { maxFileBytes: budget.limits.maxFileBytes, budget: budget.bytes,
    parseLimits: { maxDepth: budget.limits.maxJsonDepth, maxTokens: budget.limits.maxJsonTokens } });
}

function noteResourceLimit(issues: DatasetLoadIssues): void {
  issues.resourceLimitFailures = (issues.resourceLimitFailures ?? 0) + 1;
}

function avail(count: number, providerId: string, configured: boolean, pack?: DatasetPackIdentity): DatasetCategoryStatus {
  if (!configured) return { status: 'NOT_CONFIGURED', count: 0, providerId: 'none' };
  if (count === 0) return { status: 'UNAVAILABLE', count: 0, providerId };
  return {
    status: 'AVAILABLE', count, providerId,
    ...(pack === undefined ? {} : { packId: pack.packId, version: pack.version }),
  };
}

async function loadRawPackDir(path: string, budget: LoadBudget): Promise<{
  rules: unknown[];
  unreadable: Array<{ id: string; reason: string }>;
  enumerationFailures: number;
  enumerationIssues: Array<{ id: string; reason: string }>;
  resourceLimitFailures: number;
}> {
  let enumerationFailures = 0;
  let resourceLimitFailures = 0;
  const enumerationIssues: Array<{ id: string; reason: string }> = [];
  const files = (await collectJsonFiles(join(path, 'rules'), budget, [], (entry, reason, limited) => {
    enumerationFailures += 1;
    if (limited) resourceLimitFailures += 1;
    if (enumerationIssues.length < 25) {
      const name = safeDiagnosticName(entry, '(unreadable entry)');
      enumerationIssues.push({ id: name, reason });
    }
  })).sort();
  const rules: unknown[] = [];
  const unreadable: Array<{ id: string; reason: string }> = [];
  for (const file of files) {
    try { rules.push(await readDatasetJson(file, budget)); }
    catch (error) {
      if (isResourceLimitError(error)) resourceLimitFailures += 1;
      // Count every discovered file, including malformed JSON and read errors.
      const name = safeDiagnosticName(file, '(unreadable file)');
      unreadable.push({ id: name, reason: isResourceLimitError(error) ? 'JSON resource limit exceeded' : 'unreadable or malformed JSON rule file' });
    }
  }
  return { rules, unreadable, enumerationFailures, enumerationIssues, resourceLimitFailures };
}

async function loadDir(path: string, budget: LoadBudget, identityKey?: 'id' | 'ruleId'): Promise<{ records: unknown[]; issues: DatasetLoadIssues }> {
  const issues = emptyLoadIssues();
  const files = (await collectJsonFiles(path, budget, [], (_entry, _reason, limited) => {
    issues.enumerationFailures += 1;
    if (limited) noteResourceLimit(issues);
  })).sort();
  issues.filesSeen = files.length;
  const records: unknown[] = [];
  const identities = new Set<string>();
  for (const file of files) {
    try {
      const record = await readDatasetJson(file, budget);
      records.push(record); // Preserve legacy raw-record acceptance and order.
      if (typeof record !== 'object' || record === null || Array.isArray(record)) {
        issues.invalidRecords += 1;
      } else if (identityKey !== undefined) {
        const identity = (record as Record<string, unknown>)[identityKey];
        if (typeof identity !== 'string' || identity.length === 0) issues.invalidRecords += 1;
        else if (identities.has(identity)) issues.duplicateRecords = (issues.duplicateRecords ?? 0) + 1;
        else identities.add(identity);
      }
    } catch (error) {
      issues.unreadableFiles += 1;
      if (isResourceLimitError(error)) noteResourceLimit(issues);
    }
  }
  // These checks are not full semantic validation of knowledge or lessons.
  return { records, issues };
}

export function createDatasetService(options: { datasetPath?: string | undefined; providerId: string; logger?: Pick<Console, 'info' | 'warn' | 'error'>; limits?: Partial<DatasetLimits> }) {
  const { datasetPath, providerId, logger } = options;
  const limits = datasetLimits(options.limits);
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
  const categoryIssues: Partial<Record<NonPackCategory, DatasetLoadIssues>> = {};
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
    const loadedFamilies = new Set<PackFamily>();
    const loadedCategories = new Set<NonPackCategory>();
    try {
      const budget: LoadBudget = { root: await realpath(datasetPath), limits, bytes: createJsonByteBudget(limits.maxTotalBytes),
        entries: 0, files: 0, entryLimitReached: false, fileLimitReached: false };
      // --- vuln-intel: preserve raw file count plus canonical identity counters ---
      const vulnIssues = emptyLoadIssues();
      categoryIssues.vulnIntel = vulnIssues;
      const onVulnEnumerationFailure: EnumerationFailure = (_entry, _reason, limited) => {
        vulnIssues.enumerationFailures += 1;
        if (limited) noteResourceLimit(vulnIssues);
      };
      const npmFiles = await collectJsonFiles(join(budget.root, 'vuln-intel', 'npm'), budget, [], onVulnEnumerationFailure);
      const pypiFiles = await collectJsonFiles(join(budget.root, 'vuln-intel', 'pypi'), budget, [], onVulnEnumerationFailure);
      const intelRoot = join(budget.root, 'vuln-intel');
      const allVuln = [...npmFiles, ...pypiFiles].filter((file) => !relative(intelRoot, file).split(sep).includes('samples'));
      vulnIntelCount = allVuln.length;
      vulnIssues.filesSeen = allVuln.length;
      const identities = new Set<string>();
      const advisoryIds = new Set<string>();
      for (const file of allVuln) {
        let parsed: unknown;
        try { parsed = await readDatasetJson(file, budget); }
        catch (error) {
          vulnIssues.unreadableFiles += 1;
          if (isResourceLimitError(error)) noteResourceLimit(vulnIssues);
          continue;
        }
        if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
          vulnIssues.invalidRecords += 1;
          continue;
        }
        const record = parsed as Record<string, unknown>;
        if (record['fixture'] === true) continue;
        const id = typeof record['id'] === 'string' ? record['id'] : '';
        const provenance = record['provenance'];
        const source = typeof provenance === 'object' && provenance !== null && typeof (provenance as Record<string, unknown>)['source'] === 'string'
          ? String((provenance as Record<string, unknown>)['source']) : '';
        const ecosystem = typeof record['ecosystem'] === 'string' ? record['ecosystem'] : '';
        const pkg = typeof record['package'] === 'string' ? record['package'] : '';
        if (id.length === 0) { vulnIssues.invalidRecords += 1; continue; }
        identities.add(`${source}\u0000${id}\u0000${ecosystem}\u0000${pkg}`);
        advisoryIds.add(id);
      }
      vulnIntelCounts = { files: allVuln.length, identityItems: identities.size, advisoryIds: advisoryIds.size };
      loadedCategories.add('vulnIntel');

      // --- packs: validate, execute declared tests, read manifest identity ---
      for (const family of PACK_FAMILIES) {
        const path = join(budget.root, 'packs', family, 'v1');
        const raw = await loadRawPackDir(path, budget);
        const outcome = validatePackRules(raw.rules, family);
        outcome.report.filesSeen += raw.unreadable.length;
        outcome.report.enumerationFailures = raw.enumerationFailures;
        if (raw.resourceLimitFailures > 0) outcome.report.resourceLimitFailures = (outcome.report.resourceLimitFailures ?? 0) + raw.resourceLimitFailures;
        // File rejections are counted; an unreadable directory is recorded
        // separately because the number of hidden files cannot be known.
        outcome.report.rejected = [...raw.enumerationIssues, ...raw.unreadable, ...outcome.report.rejected].slice(0, 25);
        reports[family] = outcome.report;
        loadedFamilies.add(family);
        if (family === 'sast') sastPackRules = outcome.rules;
        else if (family === 'secrets') secretsPackRules = outcome.rules;
        else if (family === 'dast') dastPackRules = outcome.rules;
        else scaPackRules = outcome.rules;
        try {
          await assertSafeDirectory(budget.root, path);
          const manifestPath = join(path, 'pack.json');
          const metadata = await lstat(manifestPath);
          if (metadata.isSymbolicLink() || !metadata.isFile()) throw new Error('unsafe manifest');
          if (budget.entries >= limits.maxEntries || budget.files >= limits.maxFiles) {
            if (budget.entries >= limits.maxEntries) budget.entryLimitReached = true;
            if (budget.files >= limits.maxFiles) budget.fileLimitReached = true;
            outcome.report.manifestIssue = 'manifest could not be checked due to a resource limit';
            outcome.report.resourceLimitFailures = (outcome.report.resourceLimitFailures ?? 0) + 1;
          } else {
            budget.entries += 1; budget.files += 1;
            // A present manifest must identify this pack family's supported
            // schema; individual rules are still validated independently.
            const manifest = parsePackManifest(await readDatasetJson(manifestPath, budget), family);
            if (manifest !== undefined) packs[family] = manifest;
            else outcome.report.manifestIssue = 'manifest failed validation';
          }
        } catch (error) {
          // The manifest remains optional; an absent one is not a failed rule.
          if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
            outcome.report.manifestIssue = 'manifest could not be safely read or validated';
            if (isResourceLimitError(error)) outcome.report.resourceLimitFailures = (outcome.report.resourceLimitFailures ?? 0) + 1;
          }
        }
        if (outcome.report.accepted < outcome.report.filesSeen || outcome.report.enumerationFailures > 0 || outcome.report.manifestIssue !== undefined) {
          logger?.warn?.(`[dataset] ${family}: accepted ${outcome.report.accepted}/${outcome.report.filesSeen} discovered rules; ${outcome.report.enumerationFailures} enumeration failures; ${outcome.report.failedTests} declared-test failures; manifest issue: ${outcome.report.manifestIssue === undefined ? 'no' : 'yes'}`);
        }
      }

      // --- knowledge + audiences: keep loaded data/counts unchanged, report omissions ---
      const remediation = await loadDir(join(budget.root, 'knowledge', 'remediation'), budget, 'ruleId');
      remediationRecords = remediation.records; categoryIssues.remediation = remediation.issues; loadedCategories.add('remediation');
      const cwe = await loadDir(join(budget.root, 'knowledge', 'cwe'), budget, 'id');
      cweRecords = cwe.records; categoryIssues.cwe = cwe.issues; loadedCategories.add('cwe');
      const lessons = await loadDir(join(budget.root, 'learning', 'lessons'), budget, 'id');
      lessonRecords = lessons.records; categoryIssues.lessons = lessons.issues; loadedCategories.add('lessons');
      const assessments = await loadDir(join(budget.root, 'assessments', 'templates'), budget);
      assessmentTemplates = assessments.records; categoryIssues.assessmentTemplates = assessments.issues; loadedCategories.add('assessmentTemplates');
      const engagements = await loadDir(join(budget.root, 'engagements'), budget);
      engagementTemplates = engagements.records; categoryIssues.engagementTemplates = engagements.issues; loadedCategories.add('engagementTemplates');

      overall = buildOverall(new Date().toISOString());
      const incomplete = NON_PACK_CATEGORIES.filter((category) => overall?.[category].incomplete === true);
      if (incomplete.length > 0) logger?.warn?.(`[dataset] Incomplete categories: ${incomplete.join(', ')} (aggregate counts only; see dataset status)`);
      logger?.info?.(`[dataset] Loaded vuln=${vulnIntelCount} sast=${sastPackRules.length} sec=${secretsPackRules.length} dast=${dastPackRules.length} sca=${scaPackRules.length} remediation=${remediationRecords.length} cwe=${cweRecords.length} lessons=${lessonRecords.length} tmpl=${assessmentTemplates.length} eng=${engagementTemplates.length}`);
    } catch {
      // Error strings and configured paths may contain arbitrary sensitive text.
      logger?.warn?.('[dataset] load failed (details withheld)');
      for (const family of PACK_FAMILIES) {
        if (!loadedFamilies.has(family)) {
          reports[family].enumerationFailures += 1;
          reports[family].rejected.push({ id: '(pack)', reason: 'dataset load was interrupted before this pack was enumerated' });
        }
      }
      for (const category of NON_PACK_CATEGORIES) {
        if (!loadedCategories.has(category)) {
          const issues = categoryIssues[category] ?? emptyLoadIssues();
          issues.enumerationFailures += 1;
          categoryIssues[category] = issues;
        }
      }
      overall = buildOverall(new Date().toISOString());
    }
  }

  function buildOverall(loadedAt: string): DatasetOverallStatus {
    const mk = (count: number, pack?: DatasetPackIdentity): DatasetCategoryStatus => avail(count, providerId, configured, pack);
    // AVAILABLE means some valid rules loaded, not that the pack is complete.
    // Surface the existing completeness flag for pack-level problems too.
    const packStatus = (family: PackFamily, count: number): DatasetCategoryStatus => {
      const category = mk(count, packs[family]);
      const report = reports[family];
      return configured && (report.accepted < report.filesSeen || report.enumerationFailures > 0 || report.manifestIssue !== undefined)
        ? { ...category, incomplete: true }
        : category;
    };
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
      vulnIntel: withLoadIssues(configured
        ? (vulnIntelCount > 0
          ? { status: 'AVAILABLE' as DatasetAvailability, count: vulnIntelCount, providerId }
          : { status: 'UNAVAILABLE', count: 0, providerId })
        : { status: 'NOT_CONFIGURED', count: 0, providerId: 'none' }, categoryIssues.vulnIntel),
      vulnIntelCounts,
      sastPacks: packStatus('sast', sastPackRules.length),
      secretsPacks: packStatus('secrets', secretsPackRules.length),
      dastPacks: packStatus('dast', dastPackRules.length),
      scaPacks: packStatus('sca', scaPackRules.length),
      packs: { ...packs },
      conformance: {
        sast: reports.sast, secrets: reports.secrets, dast: reports.dast, sca: reports.sca,
        scaDeclarationEvaluator: 'AVAILABLE',
        scaDeclarationScanParsers: SCA_READABLE_PARSERS,
        scaDeclarationScanReachableRules: reachableScaRuleCount(scaPackRules),
      },
      remediation: withLoadIssues(mk(remediationRecords.length), categoryIssues.remediation),
      cwe: withLoadIssues(mk(cweRecords.length), categoryIssues.cwe),
      lessons: { ...withLoadIssues(mk(lessonRecords.length), categoryIssues.lessons), ...(byUserType ? { byUserType } : {}) },
      assessmentTemplates: withLoadIssues(mk(assessmentTemplates.length), categoryIssues.assessmentTemplates),
      engagementTemplates: withLoadIssues(mk(engagementTemplates.length), categoryIssues.engagementTemplates),
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
