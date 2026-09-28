import { createHash } from 'node:crypto';
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
import { matchRuleLine, SAST_RULES, type SastRule } from './rules.js';

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
 * - NO EXECUTION OF TARGET CODE: the engine reads text and matches
 *   regexes. It NEVER runs npm/scripts/shell/project code, never
 *   installs anything, never follows build instructions — a malicious
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
 * Supported source languages (v1): TypeScript and JavaScript — this
 * repository's own application stack. Every other language is
 * UNSUPPORTED and documented as such (files are skipped and counted,
 * never claimed as scanned, never guessed at).
 */
export const SAST_SUPPORTED_EXTENSIONS = ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs'] as const;

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
}

/** Deterministic file ordering: path byte-order ASC. */
function comparePaths(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function isSupportedFile(path: string): boolean {
  const lower = path.toLowerCase();
  return SAST_SUPPORTED_EXTENSIONS.some((extension) => lower.endsWith(extension));
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
 * visible), normalized for the API: tabs become spaces and a trailing
 * CR is dropped, so the evidence always satisfies the strict finding
 * guard (no control characters).
 */
function evidenceFromLine(rule: SastRule, rawLine: string, column: number): string {
  const line = rawLine.replace(/\t/g, '  ');
  const windowRadius = 60;
  // Room for the two ellipsis markers, so the result never exceeds the
  // evidence bound (the finding guard enforces it).
  const windowLength = FINDING_EVIDENCE_MAX_LENGTH - 2;
  let start = Math.max(0, column - 1 - windowRadius);
  const end = Math.min(line.length, start + windowLength);
  if (line.length <= FINDING_EVIDENCE_MAX_LENGTH) {
    // Short lines: no windowing needed.
    return rule.redactEvidence === undefined ? line : rule.redactEvidence(line, { column });
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
  return `${prefix}${window}${suffix}`;
}

/** Deterministic finding identity — never a random UUID. */
function fingerprintOf(ruleId: string, file: string, line: number, evidence: string): string {
  const evidenceDigest = createHash('sha256').update(evidence, 'utf8').digest('hex');
  return createHash('sha256')
    .update(`${ruleId}\n${file}\n${line}\n${evidenceDigest}`, 'utf8')
    .digest('hex');
}

interface DiscoveryResult {
  kind: 'ok';
  files: Array<{ path: string; content: string }>;
  skipped: number;
}

type DiscoveryFailure = { kind: 'input-invalid' } | { kind: 'file-limit' } | { kind: 'too-large' };

function discover(snapshot: SourceSnapshotRecord, limits: SastLimits): DiscoveryResult | DiscoveryFailure {
  const scannable: Array<{ path: string; content: string }> = [];
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
    if (!isSupportedFile(file.path) || isIgnoredDir(file.path)) {
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
    scannable.push({ path: file.path, content: file.content });
  }
  return { kind: 'ok', files: scannable, skipped };
}

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
      const discovery = discover(snapshot, limits);
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

      outer: for (const file of discovery.files) {
        // Deadline checkpoints: between files…
        if (now() > deadline || ctx.signal.aborted) {
          return {
            kind: 'failed',
            failureCode: 'SAST_SCAN_TIMEOUT',
            failureMessage: 'The SAST engine exceeded its processing deadline.',
          };
        }
        // CRLF-safe: strip the trailing CR so evidence and matching
        // never see control characters.
        const lines = file.content.split('\n').map((line) => line.replace(/\r$/, ''));
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
          for (const rule of SAST_RULES) {
            const match = matchRuleLine(rule, line);
            if (match === undefined) {
              continue;
            }
            const evidence = evidenceFromLine(rule, line, match.column);
            const fingerprint = fingerprintOf(rule.id, file.path, index + 1, evidence);
            findings.push({
              id: `fnd_${fingerprint.slice(0, 24)}`,
              scanId: record.id,
              ruleId: rule.id,
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
      }

      const resultSummary: ScanResultSummary = {
        findingsTotal: findings.length,
        findingsBySeverity,
        filesScanned: discovery.files.length,
        filesSkipped: discovery.skipped,
        truncated,
      };
      return {
        kind: 'completed',
        resultSummary,
        ...(findings.length === 0 ? {} : { findings }),
      };
    },
  };
}
