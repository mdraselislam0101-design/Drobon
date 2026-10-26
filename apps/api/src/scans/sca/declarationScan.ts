/**
 * SCA declaration SCAN layer (Pump 14, MAIN-APP ONLY).
 *
 * Connects the pure declaration evaluator (`external/scaDeclaration.ts`) to a
 * real project source snapshot. This is an ADDITIVE layer on top of the old
 * SCA engine: inventory, SBOM and advisory assessment are untouched.
 *
 * WHAT IT DOES TODAY (stated honestly):
 *  - reads the project's stored virtual content tree (never the filesystem);
 *  - for artifacts whose declared `parser` is JSON, parses the text into a
 *    document and evaluates every matching declaration rule against it;
 *  - emits real, persisted `scanner: 'SCA'` findings with stable fingerprints;
 *  - counts the rules it could NOT evaluate (artifact absent, or a parser kind
 *    the app does not read yet) instead of pretending they ran.
 *
 * WHAT IT DOES NOT DO: no downloads, no package install, no execution, no
 * advisory lookup, no auto-remediation, no TOML/YAML/XML/INI/text parsing yet.
 * A declared VALUE (which can be a registry token) is NEVER copied into a
 * finding — evidence carries only the rule id, artifact, check and matched key.
 *
 * BOUNDS: documents, evaluations and findings are hard-capped; the caller's
 * `shouldStop` (deadline/abort) is checked inside the evaluation loop.
 */

import {
  FINDING_EVIDENCE_MAX_LENGTH,
  FINDING_TEXT_MAX_LENGTH,
  FINDING_TITLE_MAX_LENGTH,
  MAX_FINDINGS_PER_SCAN,
  SCA_MAX_MANIFESTS_PER_SCAN,
  isValidSourcePath,
  type Finding,
  type FindingSeverity,
} from '@drobon/shared';
import { findingFingerprint } from '../findingIdentity.js';
import type { ScanRecord } from '../store.js';
import {
  SCA_READABLE_PARSERS,
  compileScaDeclarationRules,
  findScaMatch,
  type CompiledScaDeclarationRule,
} from '../../external/scaDeclaration.js';

/** Directory segments that are vendored/build noise, never project declarations. */
const IGNORED_DIR_SEGMENTS = [
  'node_modules', 'dist', 'build', 'out', 'coverage', 'vendor', 'target', 'cache',
] as const;

/** Upper bound on (rule × document) evaluations per scan — bounded work, always. */
export const MAX_DECLARATION_EVALUATIONS = 10_000;

export interface DeclarationFile {
  path: string;
  content: string;
}

export interface DeclarationScanOutcome {
  findings: Finding[];
  severityCounts: Record<FindingSeverity, number>;
  rulesEvaluated: number;
  rulesNotEvaluated: number;
  truncated: boolean;
}

export interface DeclarationScanOptions {
  /** Raw, already conformance-validated SCA pack rules. */
  rawRules: readonly unknown[];
  files: readonly DeclarationFile[];
  record: ScanRecord;
  maxFindings?: number;
  /** Deadline / abort signal from the engine (checked inside the loop). */
  shouldStop?: () => boolean;
}

function emptySeverityCounts(): Record<FindingSeverity, number> {
  return { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
}

/** Finding text must be non-empty, control-character-free and within its cap. */
function safeText(value: string, maxLength: number): string {
  let out = '';
  for (const char of value) {
    const code = char.codePointAt(0) ?? 0;
    out += code < 0x20 || code === 0x7f ? ' ' : char;
    if (out.length >= maxLength) break;
  }
  return out.length > 0 ? out : 'unavailable';
}

/**
 * Locate the first path segment in the raw artifact text. This is a bounded
 * approximation for the finding's line/column: declaration documents are
 * structured data, not line-oriented source, so we point at the key's first
 * occurrence (or 1:1 when the shape has no such key, e.g. `field-absent`).
 */
function locatePath(content: string, path: string): { line: number; column: number } {
  const first = path.split('.')[0]?.replace(/\[\]$/, '') ?? '';
  if (first === '' || first === '*') return { line: 1, column: 1 };
  const needle = `"${first}"`;
  const index = content.slice(0, 262_144).indexOf(needle);
  if (index < 0) return { line: 1, column: 1 };
  let line = 1;
  let column = 1;
  for (let i = 0; i < index; i += 1) {
    if (content[i] === '\n') { line += 1; column = 1; } else { column += 1; }
  }
  return { line, column };
}

function isIgnoredPath(path: string): boolean {
  const segments = path.split('/');
  segments.pop();
  return segments.some((segment) => (IGNORED_DIR_SEGMENTS as readonly string[]).includes(segment));
}

function parseJsonDocument(content: string): unknown | undefined {
  try { return JSON.parse(content) as unknown; } catch { return undefined; }
}

function buildFinding(
  compiled: CompiledScaDeclarationRule,
  file: DeclarationFile,
  record: ScanRecord,
  match: { path: string; key?: string },
  content: string,
): Finding {
  const { rule } = compiled;
  const { line, column } = locatePath(content, rule.check.path);
  const keyPart = match.key === undefined ? '' : ` key=${safeText(match.key, 60)}`;
  const evidence = safeText(
    `${rule.id} ${file.path.split('/').pop() ?? rule.artifact} ${rule.check.type} ${safeText(match.path, 80)}${keyPart} (values withheld)`,
    FINDING_EVIDENCE_MAX_LENGTH,
  );
  const fingerprint = findingFingerprint({
    scanner: 'SCA',
    projectId: record.projectId,
    ruleId: rule.id,
    location: file.path,
    line,
    evidence,
  });
  return {
    id: `fnd_${fingerprint.slice(0, 24)}`,
    scanId: record.id,
    ruleId: rule.id,
    scanner: 'SCA',
    projectId: record.projectId,
    severity: rule.severity,
    title: safeText(rule.title, FINDING_TITLE_MAX_LENGTH),
    description: safeText(`${rule.description} ${rule.limitation}`, FINDING_TEXT_MAX_LENGTH),
    ...(rule.cwe === undefined ? {} : { cwe: rule.cwe }),
    file: file.path,
    line,
    column,
    evidence,
    remediation: safeText(rule.remediation, FINDING_TEXT_MAX_LENGTH),
    fingerprint,
  };
}

/**
 * Evaluate loaded declaration rules against the snapshot and return real
 * findings plus honest coverage counters. Never throws for bad input.
 */
export function evaluateScaDeclarations(options: DeclarationScanOptions): DeclarationScanOutcome {
  const outcome: DeclarationScanOutcome = {
    findings: [],
    severityCounts: emptySeverityCounts(),
    rulesEvaluated: 0,
    rulesNotEvaluated: 0,
    truncated: false,
  };
  const compiled = compileScaDeclarationRules(options.rawRules);
  if (compiled.length === 0) return outcome;

  const maxFindings = Math.min(options.maxFindings ?? MAX_FINDINGS_PER_SCAN, MAX_FINDINGS_PER_SCAN);
  const readable = SCA_READABLE_PARSERS as readonly string[];

  // Rules whose parser the scan layer cannot read are honestly not evaluated.
  const unreadable = compiled.filter((entry) => !readable.includes(entry.rule.parser));
  outcome.rulesNotEvaluated = unreadable.length;

  const byArtifact = new Map<string, CompiledScaDeclarationRule[]>();
  for (const entry of compiled) {
    if (!readable.includes(entry.rule.parser)) continue;
    const list = byArtifact.get(entry.rule.artifact) ?? [];
    list.push(entry);
    byArtifact.set(entry.rule.artifact, list);
  }

  const candidates = options.files
    .filter((file) => isValidSourcePath(file.path) && !isIgnoredPath(file.path))
    .filter((file) => byArtifact.has(file.path.split('/').pop() ?? ''))
    .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0))
    .slice(0, SCA_MAX_MANIFESTS_PER_SCAN);

  const evaluatedRules = new Set<string>();
  const seenFindings = new Set<string>();
  let evaluations = 0;
  let stopped = false;

  outer: for (const file of candidates) {
    const basename = file.path.split('/').pop() ?? '';
    const rules = byArtifact.get(basename) ?? [];
    const document = parseJsonDocument(file.content);
    for (const entry of rules) {
      if (evaluations >= MAX_DECLARATION_EVALUATIONS || (options.shouldStop?.() ?? false)) {
        stopped = true;
        break outer;
      }
      evaluations += 1;
      // A malformed/unreadable artifact is NOT a "no match": it is not
      // evaluated, and the caller reports the coverage honestly.
      if (document === undefined) continue;
      evaluatedRules.add(entry.rule.id);
      const match = findScaMatch(entry, document);
      if (match === undefined) continue;
      const dedupe = `${entry.rule.id}\n${file.path}`;
      if (seenFindings.has(dedupe)) continue;
      seenFindings.add(dedupe);
      outcome.findings.push(buildFinding(entry, file, options.record, match, file.content));
      outcome.severityCounts[entry.rule.severity] += 1;
      if (outcome.findings.length >= maxFindings) {
        stopped = true;
        break outer;
      }
    }
  }

  outcome.rulesEvaluated = evaluatedRules.size;
  outcome.rulesNotEvaluated += (compiled.length - unreadable.length) - evaluatedRules.size;
  outcome.truncated = stopped;
  return outcome;
}
