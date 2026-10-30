import {
  FINDING_EVIDENCE_MAX_LENGTH,
  MAX_FINDINGS_PER_SCAN,
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
import { findingFingerprint } from '../findingIdentity.js';
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
 * - REDACTION FIRST: every credential-bearing rule redacts the secret
 *   value out of the evidence BEFORE the finding exists. The raw
 *   secret never enters a finding object, so it cannot reach the API,
 *   UI, logs, stores or exports through it.
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

/**
 * Length-neutral marker (the SAST-005 precedent): the fixed marker
 * for values of at least 10 characters, same-length asterisks for
 * shorter ones — redaction can never push evidence past its bound.
 */
function markerFor(length: number): string {
  return length >= 10 ? '<redacted>' : '*'.repeat(length);
}

/**
 * THE REDACTION STEP (critical, adversarially tested).
 *
 * The rule declares WHERE the secret sits inside the match
 * (`valueSpan`); the engine blanks that span POSITIONALLY — the
 * value's characters are removed by position, not by string search,
 * so a value cut by the evidence window can never leak partially.
 * Rules whose match is already safe text (`matchOnlyEvidence`, the
 * PEM header) return the match alone; nothing else from the line can
 * leak. If a span cannot be resolved, the engine FAILS CLOSED: a
 * bare rule marker instead of the line.
 */
function evidenceFromLine(
  rule: SecretsRule,
  rawLine: string,
  match: { column: number; text: string },
  activeRules: readonly SecretsRule[],
): string {
  if (rule.matchOnlyEvidence === true) {
    // Safe by contract: the match text carries no secret material.
    return match.text;
  }
  const span = rule.valueSpan?.(match);
  if (span === undefined || span.start < 0 || span.end <= span.start) {
    // Fail closed — never ship an unredacted line on a rule bug.
    return `[${rule.id}] <redacted>`;
  }
  const value = match.text.slice(span.start, span.end);
  if (value.length === 0) {
    return `[${rule.id}] <redacted>`;
  }
  // Defense in depth (a no-op for lines pre-normalized by execute):
  // evidence text must never carry control characters.
  const line = rawLine.replace(/\t/g, '  ').replace(/\r$/, '');
  // Absolute secret span within the line (match.column is 1-based).
  const absStart = match.column - 1 + span.start;
  const absEnd = match.column - 1 + span.end;

  // NEIGHBOUR REDACTION: a line can carry MORE than one secret — other
  // rules' material, or the same rule's later match. Blank every value
  // span ANY rule resolved on this line, so the evidence cannot leak
  // the neighbours either.
  const spans: Array<{ start: number; end: number }> = [{ start: absStart, end: absEnd }];
  for (const other of activeRules) {
    if (other.matchOnlyEvidence === true) {
      continue; // Header-only rules match safe text, never material.
    }
    const otherMatch = matchSecretsRuleLine(other, line);
    if (otherMatch === undefined) {
      continue;
    }
    const otherSpan = other.valueSpan?.(otherMatch);
    if (otherSpan === undefined || otherSpan.start < 0 || otherSpan.end <= otherSpan.start) {
      continue;
    }
    spans.push({
      start: otherMatch.column - 1 + otherSpan.start,
      end: otherMatch.column - 1 + otherSpan.end,
    });
  }

  // The evidence window: the whole line, or (long lines) a window
  // centered so the fired value's start is visible with context.
  const windowLength = FINDING_EVIDENCE_MAX_LENGTH - 2;
  let winStart = 0;
  let winEnd = line.length;
  if (line.length > FINDING_EVIDENCE_MAX_LENGTH) {
    winStart = Math.max(0, absStart - 40);
    winEnd = Math.min(line.length, winStart + windowLength);
    if (winEnd - winStart < windowLength) {
      winStart = Math.max(0, winEnd - windowLength);
    }
  }
  // Blank every span POSITIONALLY inside the window (spans cut by the
  // window edge shrink to their visible part — never leak a fragment).
  const window = line.slice(winStart, winEnd);
  let redacted = '';
  let pos = 0;
  const clipped = spans
    .map((sp) => ({ start: sp.start - winStart, end: sp.end - winStart }))
    .filter((sp) => sp.end > 0 && sp.start < window.length)
    .map((sp) => ({ start: Math.max(0, sp.start), end: Math.min(window.length, sp.end) }))
    .sort((a, b) => a.start - b.start);
  for (const sp of clipped) {
    const start = Math.max(sp.start, pos);
    if (sp.end <= start) {
      continue;
    }
    redacted += window.slice(pos, start) + markerFor(sp.end - start);
    pos = sp.end;
  }
  redacted += window.slice(pos);
  const prefix = winStart > 0 ? '…' : '';
  const suffix = winEnd < line.length ? '…' : '';
  const evidence = `${prefix}${redacted}${suffix}`;

  // DEFENSIVE RE-SCAN (the invariant, checked not assumed): the FINAL
  // evidence must contain no secret-shaped match of any rule. This
  // catches a second, DIFFERENT value of the same rule on one line
  // (its matcher returns the first match only, so the neighbour was
  // not blanked above) — the whole evidence fails closed.
  for (const other of activeRules) {
    if (other.matchOnlyEvidence === true) {
      continue;
    }
    if (matchSecretsRuleLine(other, evidence) !== undefined) {
      return `[${rule.id}] <redacted>`;
    }
  }
  return defensiveGuard(rule, evidence, value);
}

/**
 * Last line of defense: if the exact value still appears in the
 * evidence (a rule/engine bug), replace the ENTIRE evidence with a
 * bare marker. A finding must never ship the secret.
 */
function defensiveGuard(rule: SecretsRule, evidence: string, value: string): string {
  if (value.length >= 4 && evidence.includes(value)) {
    return `[${rule.id}] <redacted>`;
  }
  return evidence;
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
      if (options.dataset?.configured) {
        try { const { getMergedSecretsRules } = await import('../../external/packIntegration.js'); effectiveRules = await getMergedSecretsRules(options.dataset); } catch { /* fail closed: optional path */ }
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
            const evidence = evidenceFromLine(rule, line, match, effectiveRules);
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

      // PARTIAL honesty (§ report integrity): the summary must never
      // read as "0 secrets" when content went uninspected.
      const partialReasons: string[] = [];
      if (effectiveRules.length === 0) partialReasons.push('No secrets rules were available');
      if (discovery.oversize > 0) {
        partialReasons.push(
          `${discovery.oversize} file(s) exceeded the per-file size limit and were not inspected`,
        );
      }
      if (truncated) {
        partialReasons.push('the findings cap was reached; later matches are not listed');
      }
      const partial = partialReasons.length > 0;

      // Context enrichment only applies to files actually reached by the
      // secrets matcher; do not parse later files after a finding cap.
      const astSupplement = await addSecretAstContext(discovery.files.slice(0, filesScanned), findings, effectiveRules, ctx.signal, () => deadline - now());
      if (ctx.signal.aborted || now() >= deadline) {
        return { kind: 'failed', failureCode: 'SECRETS_SCAN_TIMEOUT', failureMessage: 'The secrets engine exceeded its processing deadline.' };
      }
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
