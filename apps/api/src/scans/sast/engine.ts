import {
  AST_FLOW_KINDS,
  FINDING_EVIDENCE_MAX_LENGTH,
  MAX_FINDINGS_PER_SCAN,
  isValidSourcePath,
  type AstAnalysisCoverage,
  type AstParserFamily,
  type Finding,
  type FindingSeverity,
  type ScanResultSummary,
  type StructuredAstSummary,
} from '@drobon/shared';
import type { EngineOutcome, ScanEngine, ScanEngineContext } from '../engines.js';
import type { ScanRecord } from '../store.js';
import type { SourceSnapshotRecord } from '../sources.js';
import { matchRuleLine, SAST_RULES, type SastRule } from './rules.js';
import type { DatasetService } from '../../external/service.js';
import { detectLanguageFamily, isAnalyzedMaturity, supportsBoundedAst } from './languages.js';
import { analyzeFileFlows, flowRulesForFamily, maskLiterals } from './semantic.js';
import { findingFingerprint } from '../findingIdentity.js';
import { analyzeAstFile, astReporterRules, type AstReporterMap } from './astAnalyzer.js';
import { astProfileFor } from './astProfiles.js';
import { StructuredAstSession, supportsStructuredAst, type ProjectAstFile } from './structuredAstSession.js';
import { effectiveSastRuleDigest, parserVersions } from './astCoverage.js';

/**
 * THE REAL SAST ENGINE (Pump 8).
 *
 * Static, deterministic, read-only analysis of a project's source
 * snapshot (the virtual content tree uploaded by the project owner —
 * see `sources.ts` and docs/SAST.md):
 *
 *   snapshot → discovery (bounded) → per-line rule matching →
 *   findings (evidence + fingerprint) → summary
 *
 * SECURITY BOUNDARIES (all tested):
 * - PATH CONTAINMENT: the engine never touches the filesystem. Every
 *   file path is re-validated against the shared single path policy
 *   (relative ASCII, no traversal, no dotfiles, no credential
 *   extensions) before it is resolved inside the snapshot — a
 *   traversal-shaped path fails the scan closed (SAST_INPUT_INVALID),
 *   and symlinks cannot exist in a content-addressed snapshot at all.
 * - NO EXECUTION OF TARGET CODE: the engine reads text, matches rules
 *   and parses bounded syntax trees. It NEVER runs npm/scripts/shell/project code,
 *   never installs anything, never follows build instructions — a malicious
 *   project cannot turn SAST into RCE.
 * - NO MODIFICATION: SAST is read-only. The engine never rewrites,
 *   patches or "auto-fixes" source, and never writes to the snapshot.
 * - RESOURCE LIMITS: file count, per-file bytes, total bytes, findings
 *   per scan and evidence size are hard-capped; a processing deadline
 *   (well inside the processor's 30s engine timeout) makes the engine
 *   fail closed with SAST_SCAN_TIMEOUT instead of hanging the worker.
 * - EVIDENCE DISCIPLINE: evidence is a bounded, match-centered window
 *   of the matched line; credential-like values are REDACTED by the
 *   matching rule. Evidence renders as text everywhere downstream.
 * - FINGERPRINT STABILITY: sha256(ruleId | file | line | evidence) —
 *   repeated scans of unchanged source reproduce identical finding
 *   ids/fingerprints; unrelated findings never collapse.
 *
 * This is application logic, NOT a vulnerability-database import: no
 * CVE/NVD/GHSA/OSV/KEV/EPSS data exists anywhere in the engine (the
 * dataset lock holds).
 */

/** The engine's hard resource limits (defaults; injectable for tests). */
export interface SastLimits {
  /** Maximum number of scannable files per scan. */
  maxFiles: number;
  /** Maximum UTF-8 bytes of one scannable file. */
  maxFileBytes: number;
  /** Maximum total scannable bytes per scan. */
  maxTotalBytes: number;
  /** Maximum findings persisted per scan. */
  maxFindings: number;
  /** Engine processing deadline in milliseconds. */
  deadlineMs: number;
}

export const DEFAULT_SAST_LIMITS: SastLimits = {
  maxFiles: 200,
  maxFileBytes: 262_144, // 256 KiB per file
  maxTotalBytes: 1_048_576, // 1 MiB per scan
  maxFindings: MAX_FINDINGS_PER_SCAN,
  deadlineMs: 10_000, // Well inside the processor's 30s engine timeout.
};

/**
 * Supported source languages (v2 — universal catalog): detection and
 * maturity live in `languages.ts` (53 language/configuration families
 * with honest PARTIAL / CONFIG_ANALYSIS / SYNTAX_ONLY / UNSUPPORTED
 * statuses). Files of PARTIAL and CONFIG_ANALYSIS families are
 * analyzed; everything else — unknown files included — is skipped and
 * counted, never claimed as scanned, never guessed at.
 */

/**
 * Directory segments never analyzed: dependency trees, build output and
 * caches are not the user's source and would only burn the scan budget
 * (and dependency code is SCA's domain, a later pump). No dotfile
 * segments can exist (path policy); test files ARE scanned (a leaked
 * credential in a test is still a leaked credential).
 */
export const SAST_IGNORED_DIR_SEGMENTS = [
  'node_modules',
  'dist',
  'build',
  'out',
  'coverage',
  'vendor',
  'target',
  'cache',
] as const;

/** The minimal surface the engine needs from the source store. */
export interface SourceSnapshotProvider {
  findByProject(projectId: string): Promise<SourceSnapshotRecord | undefined>;
}

export interface SastEngineOptions {
  sources: SourceSnapshotProvider;
  /** Override the default limits (tests). */
  limits?: Partial<SastLimits>;
  /** Clock for the deadline (tests). */
  now?: () => number;
  /** Optional dataset pack rules merged with built-in rules (server-side dataset integration). */
  rules?: readonly SastRule[];
  /** Optional dataset service for dynamic pack loading (merged per scan). */
  dataset?: DatasetService;
}

/** Deterministic file ordering: path byte-order ASC. */
function comparePaths(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function isIgnoredDir(path: string): boolean {
  const segments = path.split('/');
  segments.pop(); // The file name is not a directory segment.
  return segments.some((segment) =>
    (SAST_IGNORED_DIR_SEGMENTS as readonly string[]).includes(segment.toLowerCase()),
  );
}

/**
 * Bounded, match-centered evidence window (the match is always
 * visible), normalized for the API: tabs and control characters become
 * spaces, so the evidence satisfies the strict finding guard.
 */
function evidenceFromLine(rule: SastRule, rawLine: string, column: number): string {
  // eslint-disable-next-line no-control-regex -- source evidence must not persist control characters.
  const line = rawLine.replace(/\t/g, '  ').replace(/[\x00-\x1f\x7f]/g, ' ');
  // eslint-disable-next-line no-control-regex -- redaction callbacks cannot reintroduce control characters.
  const safeEvidence = (value: string): string => value.replace(/[\x00-\x1f\x7f]/g, ' ').slice(0, FINDING_EVIDENCE_MAX_LENGTH) || '(empty line)';
  const windowRadius = 60;
  // Room for the two ellipsis markers, so the result never exceeds the
  // evidence bound (the finding guard enforces it).
  const windowLength = FINDING_EVIDENCE_MAX_LENGTH - 2;
  let start = Math.max(0, column - 1 - windowRadius);
  const end = Math.min(line.length, start + windowLength);
  if (line.length <= FINDING_EVIDENCE_MAX_LENGTH) {
    // Short lines: no windowing needed.
    return safeEvidence(rule.redactEvidence === undefined ? line : rule.redactEvidence(line, { column }));
  }
  if (end - start < windowLength) {
    start = Math.max(0, end - windowLength);
  }
  let window = line.slice(start, end);
  // Redact INSIDE the window (redaction regexes work on any substring
  // containing the literal — the window is match-centered).
  if (rule.redactEvidence !== undefined) {
    window = rule.redactEvidence(window, { column: column - start });
  }
  const prefix = start > 0 ? '…' : '';
  const suffix = end < line.length ? '…' : '';
  return safeEvidence(`${prefix}${window}${suffix}`);
}

/** Deterministic finding identity — never a random UUID. */

interface DiscoveryResult {
  kind: 'ok';
  files: Array<{ path: string; content: string; family: string }>;
  skipped: number;
}

type DiscoveryFailure = { kind: 'input-invalid' } | { kind: 'file-limit' } | { kind: 'too-large' };

function discover(snapshot: SourceSnapshotRecord, limits: SastLimits, ruleFamilies: ReadonlySet<string>): DiscoveryResult | DiscoveryFailure {
  const scannable: Array<{ path: string; content: string; family: string }> = [];
  let skipped = 0;
  let totalBytes = 0;
  // Deterministic order: path ASC (stable scan output for stable input).
  const files = [...snapshot.files].sort((a, b) => comparePaths(a.path, b.path));
  for (const file of files) {
    // PATH CONTAINMENT (defense in depth): re-validate every path
    // inside the engine. The store loader already guarantees this — a
    // failure here means corrupt state, and the scan fails CLOSED.
    if (!isValidSourcePath(file.path)) {
      return { kind: 'input-invalid' };
    }
    // UNIVERSAL DETECTION: a file is analyzed when the catalog says the
    // family has real analysis (PARTIAL / CONFIG_ANALYSIS), OR when a
    // LOADED rule explicitly targets that family. The dataset ships
    // pattern rules for families the bare app marks SYNTAX_ONLY /
    // UNSUPPORTED (clojure, haskell, fortran, html, …); with those rules
    // loaded the same bounded lexical engine runs on those files instead
    // of silently dropping them (GAP-040). With no rule for a family the
    // file is still skipped and counted — never guessed at.
    const detection = detectLanguageFamily(file.path, file.content.slice(0, 8192));
    if (detection === undefined || (!isAnalyzedMaturity(detection.maturity) && !ruleFamilies.has(detection.family)) || isIgnoredDir(file.path)) {
      skipped += 1;
      continue;
    }
    if (Buffer.byteLength(file.content, 'utf8') > limits.maxFileBytes) {
      skipped += 1;
      continue;
    }
    if (scannable.length + 1 > limits.maxFiles) {
      return { kind: 'file-limit' };
    }
    totalBytes += Buffer.byteLength(file.content, 'utf8');
    if (totalBytes > limits.maxTotalBytes) {
      return { kind: 'too-large' };
    }
    scannable.push({ path: file.path, content: file.content, family: detection.family });
  }
  return { kind: 'ok', files: scannable, skipped };
}

const AST_HEURISTIC_DESCRIPTION = 'A bounded AST pass found a possible untrusted data flow. The rule was selected by category, not by its exact pattern; severity is inherited from that rule. Review the source and sink manually.';
const AST_HEURISTIC_REMEDIATION = 'Review the flow in context and use appropriate safe APIs, parameterization, validation or output encoding. Verify the result manually.';

const emptySeverityCounts = (): Record<FindingSeverity, number> => ({
  CRITICAL: 0,
  HIGH: 0,
  MEDIUM: 0,
  LOW: 0,
  INFO: 0,
});

/**
 * Build the real SAST engine and register it for the SAST scan type.
 * Side-effect bounded: it reads the snapshot, matches rules, and
 * returns findings — it never mutates job state (the processor owns
 * transitions) and never writes anywhere.
 */
export function createSastEngine(options: SastEngineOptions): ScanEngine {
  const sources = options.sources;
  const limits: SastLimits = { ...DEFAULT_SAST_LIMITS, ...options.limits };
  const now = options.now ?? Date.now;

  return {
    scanType: 'SAST',
    execute: async (record: ScanRecord, ctx: ScanEngineContext): Promise<EngineOutcome> => {
      // Dataset-aware rule merging (honest: if dataset unavailable, fallback to embedded)
      let effectiveRules: readonly SastRule[] = options.rules ?? SAST_RULES;
      let ruleSource: AstAnalysisCoverage['rules']['source'] = options.rules === undefined ? 'NONE' : 'EXPLICIT';
      let pack: { packId: string; version: string } | undefined;
      if (options.dataset?.configured) {
        try {
          const { getMergedSastRules } = await import('../../external/packIntegration.js');
          effectiveRules = await getMergedSastRules(options.dataset);
          ruleSource = 'DATASET';
          pack = await options.dataset.packMetadata('sast');
        } catch { /* fail closed: optional path */ }
      }
      // The deterministic scan target: the project's source snapshot.
      const snapshot = await sources.findByProject(record.projectId);
      if (snapshot === undefined) {
        return {
          kind: 'failed',
          failureCode: 'SAST_TARGET_NOT_FOUND',
          failureMessage:
            'No source snapshot is attached to this project. Upload source files before requesting a SAST scan.',
        };
      }
      // Ownership consistency (defense in depth): the snapshot must
      // belong to the same account as the scan. A mismatch means
      // inconsistent state — fail closed, no details leaked.
      if (snapshot.ownerId !== record.ownerId) {
        return {
          kind: 'failed',
          failureCode: 'SAST_INPUT_INVALID',
          failureMessage: 'The scan target is inconsistent with the scan owner.',
        };
      }
      const ruleFamilies = new Set<string>();
      for (const rule of effectiveRules) for (const family of rule.languages ?? []) ruleFamilies.add(family);
      const discovery = discover(snapshot, limits, ruleFamilies);
      if (discovery.kind === 'input-invalid') {
        return {
          kind: 'failed',
          failureCode: 'SAST_INPUT_INVALID',
          failureMessage: 'The scan target failed validation.',
        };
      }
      if (discovery.kind === 'file-limit') {
        return {
          kind: 'failed',
          failureCode: 'SAST_FILE_LIMIT_EXCEEDED',
          failureMessage: `The source snapshot has more scannable files than the SAST limit (${limits.maxFiles}).`,
        };
      }
      if (discovery.kind === 'too-large') {
        return {
          kind: 'failed',
          failureCode: 'SAST_TARGET_TOO_LARGE',
          failureMessage: `The source snapshot exceeds the SAST scan size limit (${limits.maxTotalBytes} bytes).`,
        };
      }

      const deadline = now() + limits.deadlineMs;
      const findings: Finding[] = [];
      const findingsBySeverity = emptySeverityCounts();
      let truncated = false;
      // Flow-rule lookup is family-keyed and computed once per scan
      // (the registry is a compile-time constant; this is a cache, not
      // state that can change).
      const flowRulesByFamily = new Map<string, ReturnType<typeof flowRulesForFamily>>();
      // Select applicable lexical rules once per language family rather than
      // rechecking all loaded rules on every line. Preserve original ordering.
      const lexicalRulesByFamily = new Map<string, readonly SastRule[]>();
      // The production registry is intentionally empty (data lives in the
      // external dataset). Flow findings must therefore resolve their rule
      // metadata from the SAME effective rule set that produced the flow
      // refs — otherwise every flow finding is silently dropped.
      const rulesById = new Map<string, SastRule>(effectiveRules.map((rule) => [rule.id, rule]));
      // Pump 16: bounded AST/dataflow reporters are chosen ONCE per family
      // from the same effective (dataset-backed) rule set. No rule → no AST
      // finding: the engine never invents a vulnerability rule.
      const astReportersByFamily = new Map<string, AstReporterMap>();
      let astFilesAnalyzed = 0;
      let astFlowsFound = 0;
      let filesScanned = 0;
      const astParser: StructuredAstSummary = { parsedFiles: 0, incompleteFiles: 0, filesWithoutRules: 0, findings: 0 };
      const astCoverage: AstAnalysisCoverage = {
        rules: { source: ruleSource, count: effectiveRules.length, sha256: effectiveSastRuleDigest(effectiveRules),
          ...(pack === undefined ? {} : { packId: pack.packId, packVersion: pack.version }) },
        parsers: parserVersions(), families: [], files: [], unstructuredFiles: 0,
        projectFlow: { status: 'NOT_RUN', examinedFiles: 0, unresolvedImports: 0, findings: 0 },
      };
      const structuredAst = new StructuredAstSession();

      try {
        outer: for (const file of discovery.files) {
          // Deadline checkpoints: between files…
          if (now() > deadline || ctx.signal.aborted) {
            return {
              kind: 'failed',
              failureCode: 'SAST_SCAN_TIMEOUT',
              failureMessage: 'The SAST engine exceeded its processing deadline.',
            };
          }
          // Count a file only after processing actually reaches it; the
          // findings cap may leave later discovered files untouched.
          filesScanned += 1;
          // CRLF-safe: strip the trailing CR so evidence and matching
          // never see control characters.
          const lines = file.content.split('\n').map((line) => line.replace(/\r$/, ''));
          let lexicalRules = lexicalRulesByFamily.get(file.family);
          if (lexicalRules === undefined) {
            lexicalRules = effectiveRules.filter((rule) => rule.languages === undefined || rule.languages.includes(file.family));
            lexicalRulesByFamily.set(file.family, lexicalRules);
          }
          const seenRuleLine = new Set<string>();
          for (let index = 0; index < lines.length; index += 1) {
            // …and every 512 lines (bounded per-file latency).
            if (index % 512 === 511 && now() > deadline) {
              return {
                kind: 'failed',
                failureCode: 'SAST_SCAN_TIMEOUT',
                failureMessage: 'The SAST engine exceeded its processing deadline.',
              };
            }
            const line = lines[index] ?? '';
            for (const rule of lexicalRules) {
              const match = matchRuleLine(rule, line);
              if (match === undefined) continue;
              const key = `${rule.id}\n${index + 1}`;
              if (seenRuleLine.has(key)) continue;
              seenRuleLine.add(key);
              const evidence = evidenceFromLine(rule, line, match.column);
              const fingerprint = findingFingerprint({
                scanner: 'SAST', projectId: record.projectId, ruleId: rule.id,
                location: file.path, line: index + 1, evidence,
              });
              findings.push({
                id: `fnd_${fingerprint.slice(0, 24)}`,
                scanId: record.id,
                ruleId: rule.id,
                scanner: 'SAST',
                projectId: record.projectId,
                severity: rule.severity,
                title: rule.title,
                description: rule.description,
                ...(rule.cwe === undefined ? {} : { cwe: rule.cwe }),
                file: file.path,
                line: index + 1,
                column: match.column,
                evidence,
                remediation: rule.remediation,
                fingerprint,
              });
              findingsBySeverity[rule.severity] += 1;
              if (findings.length >= limits.maxFindings) {
                truncated = true;
                break outer;
              }
              // One finding per rule per line (first pattern wins).
            }
          }

          // BOUNDED SEMANTIC PASS (deep-semantic pump): literal masking
          // + single-forward-pass source→sink flow analysis for the
          // flow-tagged rules of this family. Same finding model, same
          // identity, same caps; the deadline is honored here too.
          let flowRules = flowRulesByFamily.get(file.family);
          if (flowRules === undefined) {
            flowRules = flowRulesForFamily(file.family, effectiveRules);
            flowRulesByFamily.set(file.family, flowRules);
          }
          if (flowRules.length > 0) {
            if (now() > deadline || ctx.signal.aborted) {
              return {
                kind: 'failed',
                failureCode: 'SAST_SCAN_TIMEOUT',
                failureMessage: 'The SAST engine exceeded its processing deadline.',
              };
            }
            const maskedLines = maskLiterals(file.content, file.family).split('\n');
            const flowCandidates = analyzeFileFlows(file.family, maskedLines, flowRules, lines);
            for (const candidate of flowCandidates) {
              const rule = rulesById.get(candidate.ruleId);
              const originalLine = lines[candidate.lineIndex] ?? '';
              if (rule === undefined) continue;
              const key = `${rule.id}\n${candidate.lineIndex + 1}`;
              if (seenRuleLine.has(key)) continue;
              seenRuleLine.add(key);
              const evidence = evidenceFromLine(rule, originalLine, candidate.column);
              const fingerprint = findingFingerprint({
                scanner: 'SAST', projectId: record.projectId, ruleId: rule.id,
                location: file.path, line: candidate.lineIndex + 1, evidence,
              });
              findings.push({
                id: `fnd_${fingerprint.slice(0, 24)}`,
                scanId: record.id,
                ruleId: rule.id,
                scanner: 'SAST',
                projectId: record.projectId,
                severity: rule.severity,
                title: rule.title,
                description: rule.description,
                ...(rule.cwe === undefined ? {} : { cwe: rule.cwe }),
                file: file.path,
                line: candidate.lineIndex + 1,
                column: candidate.column,
                evidence,
                remediation: rule.remediation,
                fingerprint,
              });
              findingsBySeverity[rule.severity] += 1;
              if (findings.length >= limits.maxFindings) {
                truncated = true;
                break outer;
              }
            }
          }

          // ---- BOUNDED AST / DATAFLOW PASS (Pump 16, ADDITIVE) ----
          // Same finding model, same identity, same caps. Rules stay in the
          // dataset; this pass only decides WHERE a loaded rule's class is
          // actually reachable from untrusted input.
          if (supportsBoundedAst(file.family)) {
            if (now() > deadline || ctx.signal.aborted) {
              return {
                kind: 'failed',
                failureCode: 'SAST_SCAN_TIMEOUT',
                failureMessage: 'The SAST engine exceeded its processing deadline.',
              };
            }
            let reporters = astReportersByFamily.get(file.family);
            if (reporters === undefined) {
              reporters = astReporterRules(effectiveRules, file.family);
              astReportersByFamily.set(file.family, reporters);
            }
            const astResult = analyzeAstFile({
              family: file.family,
              content: file.content,
              reporters,
              shouldStop: () => now() > deadline || ctx.signal.aborted,
            });
            astFilesAnalyzed += 1;
            if (astResult.truncated) truncated = true;
            // One finding per (rule, line): lexical + flow + AST share this set.
            const already = new Set<string>();
            for (const existing of findings) {
              if ('file' in existing && existing.file === file.path) {
                already.add(`${existing.ruleId}\n${existing.line}`);
              }
            }
            for (const candidate of astResult.candidates) {
              const rule = rulesById.get(candidate.ruleId);
              if (rule === undefined) continue;
              const key = `${rule.id}\n${candidate.lineIndex + 1}`;
              if (already.has(key)) continue;
              already.add(key);
              const originalLine = lines[candidate.lineIndex] ?? '';
              const evidence = evidenceFromLine(rule, originalLine, candidate.column);
              const fingerprint = findingFingerprint({
                scanner: 'SAST', projectId: record.projectId, ruleId: rule.id,
                location: file.path, line: candidate.lineIndex + 1, evidence,
              });
              findings.push({
                id: `fnd_${fingerprint.slice(0, 24)}`,
                scanId: record.id,
                ruleId: rule.id,
                scanner: 'SAST',
                projectId: record.projectId,
                severity: rule.severity,
                title: `Possible ${candidate.kind} data flow (AST heuristic)`,
                description: AST_HEURISTIC_DESCRIPTION,
                file: file.path,
                line: candidate.lineIndex + 1,
                column: candidate.column,
                evidence,
                remediation: AST_HEURISTIC_REMEDIATION,
                astFlow: { mode: 'SHALLOW', category: candidate.kind, attribution: 'CATEGORY_REPORTER' },
                fingerprint,
              });
              findingsBySeverity[rule.severity] += 1;
              astFlowsFound += 1;
              if (findings.length >= limits.maxFindings) {
                truncated = true;
                break outer;
              }
            }
          }

          // A real, isolated syntax-tree pass supplements the older passes.
          if (supportsStructuredAst(file.family)) {
            const family = file.family as AstParserFamily;
            const profile = astProfileFor(file.family);
            const reporters = astReportersByFamily.get(file.family) ?? astReporterRules(effectiveRules, file.family);
            astReportersByFamily.set(file.family, reporters);
            if (!astCoverage.families.some((item) => item.family === family)) {
              astCoverage.families.push({ family, reporters: { ...reporters } });
            }
            if (profile === undefined) {
              astParser.incompleteFiles += 1;
              astCoverage.files.push({ path: file.path, family, status: 'ERROR' });
              continue;
            }
            const parsed = await structuredAst.analyze({ family: file.family, content: file.content, profile, reporters }, ctx.signal, deadline - now());
            if (now() > deadline || ctx.signal.aborted) {
              return {
                kind: 'failed',
                failureCode: 'SAST_SCAN_TIMEOUT',
                failureMessage: 'The SAST engine exceeded its processing deadline.',
              };
            }
            astCoverage.files.push({ path: file.path, family, status: parsed.status });
            if (parsed.status === 'OK') {
              astParser.parsedFiles += 1;
              if (Object.keys(reporters).length === 0) astParser.filesWithoutRules += 1;
            } else {
              astParser.incompleteFiles += 1;
            }
            const already = new Set<string>();
            for (const existing of findings) {
              if ('file' in existing && existing.file === file.path) {
                already.add(`${existing.ruleId}\n${existing.line}`);
              }
            }
            for (const candidate of parsed.candidates) {
              const rule = rulesById.get(candidate.ruleId);
              if (rule === undefined || reporters[candidate.kind] !== candidate.ruleId ||
                  !Number.isInteger(candidate.lineIndex) || candidate.lineIndex < 0 || candidate.lineIndex >= lines.length ||
                  !Number.isInteger(candidate.column) || candidate.column < 1) continue;
              const line = candidate.lineIndex + 1;
              const key = `${rule.id}\n${line}`;
              if (already.has(key)) continue;
              already.add(key);
              // Do not copy arbitrary source or literals across this new pass's
              // evidence boundary. The file/line/column points to the sink.
              const evidence = `AST ${candidate.kind} flow candidate; review the source and sink at this location.`;
              const fingerprint = findingFingerprint({
                scanner: 'SAST', projectId: record.projectId, ruleId: rule.id,
                location: file.path, line, evidence,
              });
              findings.push({
                id: `fnd_${fingerprint.slice(0, 24)}`,
                scanId: record.id,
                ruleId: rule.id,
                scanner: 'SAST',
                projectId: record.projectId,
                severity: rule.severity,
                title: `Possible ${candidate.kind} data flow (AST heuristic)`,
                description: AST_HEURISTIC_DESCRIPTION,
                file: file.path,
                line,
                column: candidate.column,
                evidence,
                remediation: AST_HEURISTIC_REMEDIATION,
                astFlow: { mode: 'STRUCTURED', category: candidate.kind, attribution: 'CATEGORY_REPORTER' },
                fingerprint,
              });
              findingsBySeverity[rule.severity] += 1;
              astFlowsFound += 1;
              astParser.findings += 1;
              if (findings.length >= limits.maxFindings) {
                truncated = true;
                break outer;
              }
            }
          } else {
            astCoverage.unstructuredFiles += 1;
          }
        }

        // A separately bounded project pass resolves only named local functions
        // and relative named imports in this virtual snapshot. It cannot read the
        // host filesystem or execute/resolve a target's dependencies.
        const projectFiles: ProjectAstFile[] = [];
        if (!truncated) {
          for (const file of discovery.files) {
            if (!['javascript', 'typescript', 'jsx', 'tsx'].includes(file.family)) continue;
            const profile = astProfileFor(file.family);
            if (profile === undefined) continue;
            projectFiles.push({ ...file, profile, reporters: astReportersByFamily.get(file.family) ?? astReporterRules(effectiveRules, file.family) });
          }
        }
        if (projectFiles.length > 0 && projectFiles.some((file) => Object.keys(file.reporters).length > 0)) {
          const projectResult = await structuredAst.analyzeProject(projectFiles, ctx.signal, deadline - now());
          if (now() > deadline || ctx.signal.aborted) {
            return { kind: 'failed', failureCode: 'SAST_SCAN_TIMEOUT', failureMessage: 'The SAST engine exceeded its processing deadline.' };
          }
          astCoverage.projectFlow.status = projectResult.status === 'OK' ? 'RAN' : 'INCOMPLETE';
          astCoverage.projectFlow.examinedFiles = projectResult.examinedFiles;
          astCoverage.projectFlow.unresolvedImports = projectResult.unresolvedImports;
          const projectByPath = new Map(projectFiles.map((file) => [file.path, file]));
          const linesByPath = new Map(projectFiles.map((file) => [file.path, file.content.split('\n')]));
          const validLocation = (location: unknown): location is { file: string; line: number; column: number } => {
            if (typeof location !== 'object' || location === null || Array.isArray(location)) return false;
            const item = location as Record<string, unknown>;
            if (!isValidSourcePath(item['file']) || typeof item['line'] !== 'number' || !Number.isInteger(item['line']) || item['line'] < 1 ||
                typeof item['column'] !== 'number' || !Number.isInteger(item['column']) || item['column'] < 1) return false;
            const sourceLines = linesByPath.get(item['file']);
            return sourceLines !== undefined && item['line'] <= sourceLines.length && item['column'] <= (sourceLines[item['line'] - 1]?.length ?? 0) + 1;
          };
          for (const candidate of projectResult.candidates) {
            const sinkFile = projectByPath.get(candidate.path);
            const rule = rulesById.get(candidate.ruleId);
            const sink = { file: candidate.path, line: candidate.lineIndex + 1, column: candidate.column };
            if (sinkFile === undefined || rule === undefined || !(AST_FLOW_KINDS as readonly string[]).includes(candidate.kind) ||
                sinkFile.reporters[candidate.kind] !== candidate.ruleId || !validLocation(sink) || !validLocation(candidate.source) ||
                !Array.isArray(candidate.via) || candidate.via.length > 4 || !candidate.via.every(validLocation)) {
              astCoverage.projectFlow.status = 'INCOMPLETE';
              continue;
            }
            const flow = { mode: 'PROJECT' as const, category: candidate.kind, attribution: 'CATEGORY_REPORTER' as const,
              source: candidate.source, via: candidate.via };
            const existing = findings.find((finding) => finding.scanner !== 'DAST' && finding.file === candidate.path &&
              finding.ruleId === candidate.ruleId && finding.line === sink.line);
            if (existing !== undefined) {
              // Do not relabel a lexical rule match as a category-only match.
              if (existing.scanner === 'SAST' && existing.astFlow?.category === candidate.kind) existing.astFlow = flow;
              continue;
            }
            const evidence = `AST ${candidate.kind} flow candidate across a bounded call path; category reporter, not proof of an exact rule-pattern match.`;
            const fingerprint = findingFingerprint({ scanner: 'SAST', projectId: record.projectId, ruleId: rule.id,
              location: candidate.path, line: sink.line, evidence });
            findings.push({ id: `fnd_${fingerprint.slice(0, 24)}`, scanId: record.id, ruleId: rule.id, scanner: 'SAST',
              projectId: record.projectId, severity: rule.severity, title: `Possible ${candidate.kind} data flow (AST heuristic)`,
              description: AST_HEURISTIC_DESCRIPTION, file: candidate.path, line: sink.line, column: sink.column,
              evidence, remediation: AST_HEURISTIC_REMEDIATION, astFlow: flow, fingerprint });
            findingsBySeverity[rule.severity] += 1;
            astFlowsFound += 1;
            astParser.findings += 1;
            astCoverage.projectFlow.findings += 1;
            if (findings.length >= limits.maxFindings) { truncated = true; break; }
          }
        }
      } finally {
        await structuredAst.close();
      }

      const partialReasons: string[] = [];
      if (effectiveRules.length === 0) partialReasons.push('No SAST rules were available.');
      else if (astParser.filesWithoutRules > 0) partialReasons.push('Some parsed files had no applicable AST flow rules.');
      else if (astCoverage.families.some((family) => Object.keys(family.reporters).length < AST_FLOW_KINDS.length)) partialReasons.push('Some AST categories lack rules.');
      if (astParser.incompleteFiles > 0) partialReasons.push('Some structured AST files were incomplete.');
      if (astCoverage.unstructuredFiles > 0) partialReasons.push('Some files lack a structured parser.');
      if (astCoverage.projectFlow.status === 'INCOMPLETE') partialReasons.push('Project flow analysis was incomplete.');
      const resultSummary: ScanResultSummary = {
        findingsTotal: findings.length,
        findingsBySeverity,
        filesScanned,
        filesSkipped: discovery.skipped + (discovery.files.length - filesScanned),
        truncated,
        astFilesAnalyzed,
        astFlowsFound,
        astParser,
        astCoverage,
        ...(partialReasons.length === 0 ? {} : { partial: true, partialReason: partialReasons.join(' ') }),
      };
      return {
        kind: 'completed',
        resultSummary,
        ...(findings.length === 0 ? {} : { findings }),
      };
    },
  };
}
