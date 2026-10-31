import {
  MAX_FINDINGS_PER_SCAN,
  FINDING_TEXT_MAX_LENGTH,
  isValidSourcePath,
  type Finding,
  type FindingSeverity,
  type ScanResultSummary,
} from '@drobon/shared';
import type { EngineOutcome, ScanEngine, ScanEngineContext } from '../engines.js';
import type { ScanRecord } from '../store.js';
import type { SourceSnapshotRecord } from '../sources.js';
import { matchSecretsRuleLine, SECRETS_RULES, type SecretsRule } from './rules.js';
import type { DatasetService } from '../../external/service.js';
import { findingFingerprint, WITHHELD_SOURCE_EVIDENCE } from '../findingIdentity.js';
import { addSecretAstContext } from '../supplementAst.js';

/**
 * THE REAL SECRETS ENGINE (Pump 10).
 *
 * Static, deterministic, read-only secrets detection over a project's
 * source snapshot (the Pump 8 content tree — same store, same caps,
 * same path policy; there is deliberately NO second source storage):
 *
 *   snapshot → discovery (bounded) → per-line rule matching →
 *   REDACTED evidence → findings (fingerprint) → honest summary
 *
 * SECURITY BOUNDARIES (all tested):
 * - PATH CONTAINMENT: identical to SAST — every path re-validated
 *   against the shared single path policy; traversal fails closed
 *   (SECRETS_INPUT_INVALID).
 * - NO EXECUTION OF TARGET CODE, NO NETWORK: the engine reads text
 *   and matches regexes. It NEVER runs project code, never installs,
 *   never opens sockets, and NEVER validates a credential against any
 *   service — DETECTED_SECRET is never reported as a live credential.
 * - REDACTION FIRST: no source snippet enters finding evidence. The
 *   detection rules and their denylists do not decide what is safe to
 *   display; rule and location metadata remain available for review.
 * - RESOURCE LIMITS: file count / per-file bytes / total bytes /
 *   findings cap / processing deadline — every breach is explicit.
 * - PARTIAL HONESTY: files skipped for SIZE (or a findings-cap
 *   truncation) mark the summary `partial: true` with a bounded
 *   reason. A partial scan with 0 findings is "nothing found in what
 *   was inspected", NEVER "no secrets". A FAILED scan never reports
 *   findings at all.
 * - FINGERPRINT STABILITY: sha256(ruleId | file | line | digest of
 *   the REDACTED evidence) — deterministic, and the raw secret is
 *   never an input to the fingerprint.
 */

/** The engine's hard resource limits (defaults; injectable for tests). */
export interface SecretsLimits {
  /** Maximum number of scannable files per scan. */
  maxFiles: number;
  /** Maximum UTF-8 bytes of one scannable file (oversize → skipped, PARTIAL). */
  maxFileBytes: number;
  /** Maximum total scannable bytes per scan. */
  maxTotalBytes: number;
  /** Maximum findings persisted per scan (cap → truncated + PARTIAL). */
  maxFindings: number;
  /** Engine processing deadline in milliseconds. */
  deadlineMs: number;
}

export const DEFAULT_SECRETS_LIMITS: SecretsLimits = {
  maxFiles: 200,
  maxFileBytes: 262_144, // 256 KiB per file (the Pump 8 snapshot cap)
  maxTotalBytes: 1_048_576, // 1 MiB per scan
  maxFindings: MAX_FINDINGS_PER_SCAN,
  deadlineMs: 10_000, // Well inside the processor's 30s engine timeout.
};

/**
 * Supported source/config formats (§ the secrets contract): the
 * common code and configuration file types where hardcoded secrets
 * actually appear. Everything else is skipped AND COUNTED (never
 * claimed as scanned, never guessed at). Binary files cannot enter
 * the store at all (upload rejects them).
 */
export const SECRETS_SUPPORTED_EXTENSIONS = [
  '.js',
  '.ts',
  '.jsx',
  '.tsx',
  '.mjs',
  '.cjs',
  '.py',
  '.java',
  '.go',
  '.rs',
  '.php',
  '.rb',
  '.cs',
  '.json',
  '.yaml',
  '.yml',
  '.toml',
  '.ini',
  '.cfg',
  '.conf',
  '.properties',
  '.env',
  '.sh',
  '.bash',
  '.zsh',
] as const;

/**
 * Directory segments never analyzed (same set as SAST): dependency
 * trees, build output and caches. A `.git` directory cannot exist in
 * a snapshot (dotfile path policy) — the engine scans the SUPPLIED
 * SNAPSHOT ONLY, never git history or remotes.
 */
export const SECRETS_IGNORED_DIR_SEGMENTS = [
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

export interface SecretsEngineOptions {
  sources: SourceSnapshotProvider;
  /** Override the default limits (tests). */
  limits?: Partial<SecretsLimits>;
  /** Clock for the deadline (tests). */
  now?: () => number;
  /** Optional dataset pack rules merged with built-in rules. */
  rules?: readonly SecretsRule[];
  dataset?: DatasetService;
}

/** Deterministic file ordering: path byte-order ASC. */
function comparePaths(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function isSupportedFile(path: string): boolean {
  const lower = path.toLowerCase();
  return SECRETS_SUPPORTED_EXTENSIONS.some((extension) => lower.endsWith(extension));
}

function isIgnoredDir(path: string): boolean {
  const segments = path.split('/');
  segments.pop(); // The file name is not a directory segment.
  return segments.some((segment) =>
    (SECRETS_IGNORED_DIR_SEGMENTS as readonly string[]).includes(segment.toLowerCase()),
  );
}

/** Detection and sanitization are independent: arbitrary surrounding
 * source text is not demonstrably safe, including denylisted neighbors. */
function evidenceFromLine(): string {
  return WITHHELD_SOURCE_EVIDENCE;
}

/**
 * Deterministic finding identity — never a random UUID, and NEVER a
 * function of the raw secret: the input is the REDACTED evidence
 * (the value is already replaced by a marker at this point).
 */

interface DiscoveryResult {
  kind: 'ok';
  files: Array<{ path: string; content: string }>;
  /** Files skipped as unsupported/ignored (out of scope, not partial). */
  skipped: number;
  /** Files skipped because they exceeded the per-file size cap. */
  oversize: number;
}

type DiscoveryFailure = { kind: 'input-invalid' } | { kind: 'file-limit' } | { kind: 'too-large' };

function discover(
  snapshot: SourceSnapshotRecord,
  limits: SecretsLimits,
): DiscoveryResult | DiscoveryFailure {
  const scannable: Array<{ path: string; content: string }> = [];
  let skipped = 0;
  let oversize = 0;
  let totalBytes = 0;
  // Deterministic order: path ASC (stable scan output for stable input).
  const files = [...snapshot.files].sort((a, b) => comparePaths(a.path, b.path));
  for (const file of files) {
    // PATH CONTAINMENT (defense in depth): re-validate every path
    // inside the engine. A failure here means corrupt state — the
    // scan fails CLOSED.
    if (!isValidSourcePath(file.path)) {
      return { kind: 'input-invalid' };
    }
    if (!isSupportedFile(file.path) || isIgnoredDir(file.path)) {
      skipped += 1;
      continue;
    }
    if (Buffer.byteLength(file.content, 'utf8') > limits.maxFileBytes) {
      // A size-limited skip is a PARTIAL scan: this file was NOT
      // inspected and the summary must say so (never "0 secrets").
      oversize += 1;
      continue;
    }
    if (scannable.length + 1 > limits.maxFiles) {
      return { kind: 'file-limit' };
    }
    totalBytes += Buffer.byteLength(file.content, 'utf8');
    if (totalBytes > limits.maxTotalBytes) {
      return { kind: 'too-large' };
    }
    scannable.push({ path: file.path, content: file.content });
  }
  return { kind: 'ok', files: scannable, skipped, oversize };
}

const emptySeverityCounts = (): Record<FindingSeverity, number> => ({
  CRITICAL: 0,
  HIGH: 0,
  MEDIUM: 0,
  LOW: 0,
  INFO: 0,
});

/**
 * Build the real secrets engine and register it for the SECRETS scan
 * type. Side-effect bounded like SAST: read, match, return — never a
 * job-state mutation, never a write, never a socket.
 */
export function createSecretsEngine(options: SecretsEngineOptions): ScanEngine {
  const sources = options.sources;
  const limits: SecretsLimits = { ...DEFAULT_SECRETS_LIMITS, ...options.limits };
  const now = options.now ?? Date.now;

  return {
    scanType: 'SECRETS',
    execute: async (record: ScanRecord, ctx: ScanEngineContext): Promise<EngineOutcome> => {
      let effectiveRules: readonly SecretsRule[] = options.rules ?? SECRETS_RULES;
      let datasetRulesIncomplete = false;
      if (options.dataset?.configured) {
        try {
          const { getMergedSecretsRules, hasRejectedPackRules } = await import('../../external/packIntegration.js');
          effectiveRules = await getMergedSecretsRules(options.dataset);
          datasetRulesIncomplete = await hasRejectedPackRules(options.dataset, 'secrets');
        } catch {
          datasetRulesIncomplete = true;
        }
      }
      // The deterministic scan target: the project's source snapshot.
      const snapshot = await sources.findByProject(record.projectId);
      if (snapshot === undefined) {
        return {
          kind: 'failed',
          failureCode: 'SECRETS_TARGET_NOT_FOUND',
          failureMessage:
            'No source snapshot is attached to this project. Upload source files before requesting a secrets scan.',
        };
      }
      // Ownership consistency (defense in depth): fail closed.
      if (snapshot.ownerId !== record.ownerId) {
        return {
          kind: 'failed',
          failureCode: 'SECRETS_INPUT_INVALID',
          failureMessage: 'The scan target is inconsistent with the scan owner.',
        };
      }
      const discovery = discover(snapshot, limits);
      if (discovery.kind === 'input-invalid') {
        return {
          kind: 'failed',
          failureCode: 'SECRETS_INPUT_INVALID',
          failureMessage: 'The scan target failed validation.',
        };
      }
      if (discovery.kind === 'file-limit') {
        return {
          kind: 'failed',
          failureCode: 'SECRETS_FILE_LIMIT_EXCEEDED',
          failureMessage: `The source snapshot has more scannable files than the secrets limit (${limits.maxFiles}).`,
        };
      }
      if (discovery.kind === 'too-large') {
        return {
          kind: 'failed',
          failureCode: 'SECRETS_TARGET_TOO_LARGE',
          failureMessage: `The source snapshot exceeds the secrets scan size limit (${limits.maxTotalBytes} bytes).`,
        };
      }

      const deadline = now() + limits.deadlineMs;
      const findings: Finding[] = [];
      const findingsBySeverity = emptySeverityCounts();
      let truncated = false;
      let filesScanned = 0;
      // Duplicate control: one finding per (rule, file, line) — the
      // same material matched twice on a line collapses; DIFFERENT
      // rules on the same line stay distinct (their ids differ).
      const seenRuleLine = new Set<string>();

      outer: for (const file of discovery.files) {
        // Deadline checkpoints: between files…
        if (now() >= deadline || ctx.signal.aborted) {
          return {
            kind: 'failed',
            failureCode: 'SECRETS_SCAN_TIMEOUT',
            failureMessage: 'The secrets engine exceeded its processing deadline.',
          };
        }
        // A file with no rules is not a successfully inspected file.
        if (effectiveRules.length > 0) filesScanned += 1;
        // CRLF/TAB-safe: strip CRs and expand tabs BEFORE matching, so
        // match columns and the evidence's normalized line share one
        // coordinate system (a tab shift would mis-place the redaction
        // span — columns must never drift between the two).
        const lines = file.content
          .split('\n')
          .map((line) => line.replace(/\r$/, '').replace(/\t/g, '  '));
        for (let index = 0; index < lines.length; index += 1) {
          // …and every 512 lines (bounded per-file latency).
          if (index % 512 === 511 && now() >= deadline) {
            return {
              kind: 'failed',
              failureCode: 'SECRETS_SCAN_TIMEOUT',
              failureMessage: 'The secrets engine exceeded its processing deadline.',
            };
          }
          const line = lines[index] ?? '';
          for (const rule of effectiveRules) {
            const match = matchSecretsRuleLine(rule, line);
            if (match === undefined) {
              continue;
            }
            const dedupeKey = `${rule.id}\n${file.path}\n${index + 1}`;
            if (seenRuleLine.has(dedupeKey)) {
              continue;
            }
            seenRuleLine.add(dedupeKey);
            const evidence = evidenceFromLine();
            const fingerprint = findingFingerprint({
              scanner: 'SECRETS', projectId: record.projectId, ruleId: rule.id,
              location: file.path, line: index + 1, evidence,
            });
            findings.push({
              id: `fnd_${fingerprint.slice(0, 24)}`,
              scanId: record.id,
              ruleId: rule.id,
              scanner: 'SECRETS',
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
              confidence: rule.confidence,
              fingerprint,
            });
            findingsBySeverity[rule.severity] += 1;
            if (findings.length >= limits.maxFindings) {
              truncated = true;
              break outer;
            }
          }
        }
      }

      // Reuse the bounded literal-context worker for additive static folding.
      // Reapply the configured rules/denylists; the worker returns coordinates
      // only. No source text, reconstructed value or credential is persisted.
      let foldedFindings = 0;
      const astSupplement = await addSecretAstContext(discovery.files.slice(0, filesScanned), findings, effectiveRules,
        ctx.signal, () => deadline - now(), truncated ? undefined : ({ file, line, column, rule }) => {
          const dedupeKey = `${rule.id}\n${file}\n${line}`;
          if (seenRuleLine.has(dedupeKey)) return 'IGNORED';
          if (findings.length >= limits.maxFindings) { truncated = true; return 'STOP'; }
          seenRuleLine.add(dedupeKey);
          const evidence = evidenceFromLine();
          const fingerprint = findingFingerprint({ scanner: 'SECRETS', projectId: record.projectId, ruleId: rule.id,
            location: file, line, evidence });
          findings.push({ id: `fnd_${fingerprint.slice(0, 24)}`, scanId: record.id, ruleId: rule.id,
            scanner: 'SECRETS', projectId: record.projectId, severity: rule.severity, title: rule.title,
            description: `A static literal concatenation matched this rule; credential validity was not checked. ${rule.description}`.slice(0, FINDING_TEXT_MAX_LENGTH),
            ...(rule.cwe === undefined ? {} : { cwe: rule.cwe }), file, line, column, evidence,
            remediation: rule.remediation, confidence: rule.confidence, fingerprint, astContext: { kind: 'SECRETS_STRING_LITERAL' } });
          findingsBySeverity[rule.severity] += 1;
          foldedFindings += 1;
          if (findings.length >= limits.maxFindings) { truncated = true; return 'ADDED_AND_STOP'; }
          return 'ADDED';
        });
      if (ctx.signal.aborted || now() >= deadline) {
        return { kind: 'failed', failureCode: 'SECRETS_SCAN_TIMEOUT', failureMessage: 'The secrets engine exceeded its processing deadline.' };
      }
      if (foldedFindings > 0) {
        const order = new Map(effectiveRules.map((rule, index) => [rule.id, index]));
        findings.sort((a, b) => comparePaths(a.file ?? '', b.file ?? '') || (a.line ?? 0) - (b.line ?? 0) ||
          (order.get(a.ruleId) ?? 0) - (order.get(b.ruleId) ?? 0));
      }

      // Base lexical coverage keeps its existing contract; optional folding
      // coverage is reported separately by astSupplement, including parser
      // errors, unsupported files and limits. A findings cap is scan-partial.
      const partialReasons: string[] = [];
      if (datasetRulesIncomplete) partialReasons.push('Some configured secrets rules were rejected or could not be loaded');
      if (effectiveRules.length === 0) partialReasons.push('No secrets rules were available');
      if (discovery.oversize > 0) {
        partialReasons.push(`${discovery.oversize} file(s) exceeded the per-file size limit and were not inspected`);
      }
      if (truncated) partialReasons.push('the findings cap was reached; later matches are not listed');
      const partial = partialReasons.length > 0;
      const resultSummary: ScanResultSummary = {
        astSupplement,
        findingsTotal: findings.length,
        findingsBySeverity,
        filesScanned,
        filesSkipped: discovery.skipped + discovery.oversize + (discovery.files.length - filesScanned),
        truncated,
        ...(partial ? { partial: true, partialReason: `${partialReasons.join('; ')}.`.slice(0, 200) } : {}),
      };
      return {
        kind: 'completed',
        resultSummary,
        ...(findings.length === 0 ? {} : { findings }),
      };
    },
  };
}
