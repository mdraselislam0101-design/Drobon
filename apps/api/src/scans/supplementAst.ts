import type { AstSupplementSummary, Finding } from '@drobon/shared';
import { parserVersions } from './sast/astCoverage.js';
import { detectLanguageFamily } from './sast/languages.js';
import { StructuredAstSession } from './sast/structuredAstSession.js';
import { matchSecretsRuleLine, type SecretsRule } from './secrets/rules.js';

const MAX_FILES = 32;
const MAX_CONCAT_RULE_CHECKS = 32_000;
const MAX_CONCAT_LINE_CHARS = 4_096;
type File = { path: string; content: string };
type Literal = { type: 'literal'; line: number; start: number; end: number };
type Concat = { type: 'concat'; line: number; start: number; end: number; pieces: Array<{ start: number; end: number }> };
export interface SecretConcatCandidate { file: string; line: number; column: number; rule: SecretsRule }
export type SecretConcatResult = 'ADDED' | 'IGNORED' | 'STOP' | 'ADDED_AND_STOP';

function isLiteral(value: unknown): value is Literal {
  if (typeof value !== 'object' || value === null) return false;
  const v = value as Record<string, unknown>;
  return Object.keys(v).length === 4 && v['type'] === 'literal' &&
    Number.isInteger(v['line']) && Number.isInteger(v['start']) && Number.isInteger(v['end']) &&
    (v['line'] as number) > 0 && (v['line'] as number) <= 131_072 &&
    (v['start'] as number) > 0 && (v['end'] as number) > (v['start'] as number) && (v['end'] as number) <= 131_073;
}

function isConcat(value: unknown): value is Concat {
  if (typeof value !== 'object' || value === null) return false;
  const v = value as Record<string, unknown>;
  if (Object.keys(v).length !== 5 || v['type'] !== 'concat' || !Number.isInteger(v['line']) ||
      !Number.isInteger(v['start']) || !Number.isInteger(v['end']) ||
      (v['line'] as number) < 1 || (v['line'] as number) > 131_072 ||
      (v['start'] as number) < 1 || (v['end'] as number) <= (v['start'] as number) ||
      (v['end'] as number) > 131_073 || !Array.isArray(v['pieces']) || v['pieces'].length < 2 || v['pieces'].length > 16) return false;
  let previous = (v['start'] as number);
  for (const item of v['pieces']) {
    if (typeof item !== 'object' || item === null || Object.keys(item).length !== 2) return false;
    const piece = item as Record<string, unknown>;
    if (!Number.isInteger(piece['start']) || !Number.isInteger(piece['end']) ||
        (piece['start'] as number) < previous || (piece['end'] as number) <= (piece['start'] as number) + 1 ||
        (piece['end'] as number) > (v['end'] as number)) return false;
    previous = piece['end'] as number;
  }
  return true;
}

function isConcatLimit(value: unknown): value is { type: 'concat-limit' } {
  return typeof value === 'object' && value !== null && Object.keys(value).length === 1 &&
    (value as { type?: unknown }).type === 'concat-limit';
}

function status(parsed: number, incomplete: number, skipped: number): AstSupplementSummary['status'] {
  if (parsed === 0 && incomplete === 0 && skipped === 0) return 'NOT_APPLICABLE';
  return incomplete > 0 || skipped > 0 ? 'PARTIAL' : 'RAN';
}

/**
 * Classify existing matches and optionally evaluate static literal-only
 * concatenations with the SAME configured rules and validators. The worker
 * returns coordinates only; reconstructed text never enters findings/logs and
 * no project code is executed or credential verified. Coverage is bounded to
 * the reported parser status, eligible JS/TS files and simple ASCII literals.
 */
export async function addSecretAstContext(
  files: readonly File[], findings: Finding[], rules: readonly SecretsRule[], signal: AbortSignal, remainingMs: () => number,
  onConcat?: (candidate: SecretConcatCandidate) => SecretConcatResult,
): Promise<AstSupplementSummary> {
  const eligible = files.map((file) => ({ file, family: detectLanguageFamily(file.path)?.family }))
    .filter((item) => ['javascript', 'typescript', 'jsx', 'tsx'].includes(item.family ?? ''));
  let skipped = Math.min(200, files.length - eligible.length + Math.max(0, eligible.length - MAX_FILES));
  let parsed = 0; let incomplete = 0; let signals = 0;
  let checks = 0; let stopConcats = false;
  const session = new StructuredAstSession();
  try {
    for (const { file, family } of eligible.slice(0, MAX_FILES)) {
      if (signal.aborted || remainingMs() <= 0) { skipped = Math.min(200, skipped + 1); continue; }
      // The Secrets engine normalizes tabs and trailing CR before matching;
      // use exactly the same coordinate system for literal spans.
      const lines = file.content.split('\n').map((line) => line.replace(/\r$/, '').replace(/\t/g, '  '));
      const result = await session.analyzeSupplement({ kind: 'SECRETS', ...(family === undefined ? {} : { family }), content: lines.join('\n') }, signal, remainingMs());
      if (result.status !== 'OK' || !result.records.every((entry) => isLiteral(entry) || isConcat(entry) || isConcatLimit(entry))) { incomplete += 1; continue; }
      parsed += 1;
      const spans = result.records.filter(isLiteral);
      for (const finding of findings) {
        if (finding.scanner !== 'SECRETS' || finding.file !== file.path) continue;
        const rule = rules.find((item) => item.id === finding.ruleId);
        const line = lines[finding.line - 1];
        if (!rule || line === undefined || rule.matchOnlyEvidence === true) continue;
        const match = matchSecretsRuleLine(rule, line);
        const value = match && rule.valueSpan?.(match);
        if (!match || !value || value.start < 0 || value.end <= value.start) continue;
        const start = match.column + value.start;
        const end = match.column + value.end;
        if (spans.some((span) => span.line === finding.line && start < span.end && end > span.start)) {
          finding.astContext = { kind: 'SECRETS_STRING_LITERAL' };
          signals += 1;
        }
      }
      if (onConcat === undefined || stopConcats) continue;
      const concats = result.records.filter(isConcat)
        .sort((a, b) => a.line - b.line || a.start - b.start || b.end - a.end);
      let limited = result.records.some(isConcatLimit);
      concatLoop: for (const concat of concats) {
        const line = lines[concat.line - 1];
        if (line === undefined || concat.end > line.length + 1) { limited = true; break; }
        if (line.length > MAX_CONCAT_LINE_CHARS) { limited = true; continue; }
        const parts: string[] = [];
        for (const piece of concat.pieces) {
          const raw = line.slice(piece.start - 1, piece.end - 1);
          const value = raw.slice(1, -1);
          if ((raw[0] !== '"' && raw[0] !== "'") || raw.at(-1) !== raw[0] || !/^[A-Za-z0-9_+/.=:-]*$/.test(value)) {
            limited = true; break concatLoop;
          }
          parts.push(value);
        }
        const joined = parts.join('');
        if (joined.length > 1_024) { limited = true; continue; }
        const base = concat.start - 1;
        const valueStart = base + 1;
        const folded = `${line.slice(0, base)}"${joined}"${line.slice(concat.end - 1)}`;
        let cumulative = 0;
        const seams = parts.slice(0, -1).map((part) => { cumulative += part.length; return valueStart + cumulative; });
        for (const rule of rules) {
          if (++checks > MAX_CONCAT_RULE_CHECKS || signal.aborted || remainingMs() <= 0) {
            limited = true; stopConcats = true; break concatLoop;
          }
          const match = matchSecretsRuleLine(rule, folded);
          if (match === undefined) continue;
          const matchStart = match.column - 1;
          const matchEnd = matchStart + match.text.length;
          // A newly-created match must actually cross a concatenation seam;
          // unrelated text elsewhere on the line is never re-attributed.
          if (!seams.some((seam) => matchStart < seam && matchEnd > seam)) continue;
          let column = match.column;
          if (matchStart >= valueStart) {
            let offset = matchStart - valueStart;
            for (let index = 0; index < parts.length; index += 1) {
              const part = parts[index] ?? '';
              const piece = concat.pieces[index];
              if (piece !== undefined && offset < part.length) { column = piece.start + 1 + offset; break; }
              offset -= part.length;
            }
          }
          const decision = onConcat({ file: file.path, line: concat.line, column, rule });
          if (decision === 'ADDED' || decision === 'ADDED_AND_STOP') signals += 1;
          if (decision === 'STOP' || decision === 'ADDED_AND_STOP') { limited = true; stopConcats = true; break concatLoop; }
        }
      }
      if (limited) { parsed -= 1; incomplete += 1; }
    }
  } finally { await session.close(); }
  return {
    mode: 'SECRETS_LITERAL_CONTEXT',
    status: rules.length === 0 && parsed > 0 ? 'PARTIAL' : status(parsed, incomplete, skipped),
    parsed, incomplete, skipped, signals, parserVersion: parserVersions().typescript,
  };
}

/** package.json AST supplement: counts syntactic declaration entries only;
 * the existing SCA parser and intelligence provider remain authoritative. */
export async function analyzeScaManifestAst(
  files: readonly File[], signal: AbortSignal, remainingMs: () => number,
): Promise<AstSupplementSummary> {
  const eligible = files.filter((file) => file.path.split('/').pop() === 'package.json');
  let skipped = Math.min(200, files.length - eligible.length + Math.max(0, eligible.length - MAX_FILES));
  let parsed = 0; let incomplete = 0; let signals = 0;
  const session = new StructuredAstSession();
  try {
    for (const file of eligible.slice(0, MAX_FILES)) {
      if (signal.aborted || remainingMs() <= 0) { skipped = Math.min(200, skipped + 1); continue; }
      const result = await session.analyzeSupplement({ kind: 'SCA', content: file.content }, signal, remainingMs());
      const first = result.records[0];
      if (result.status !== 'OK' || result.records.length !== 1 || typeof first !== 'object' || first === null ||
          Object.keys(first).length !== 2 || (first as { type?: unknown }).type !== 'declarations' ||
          !Number.isInteger((first as { count?: unknown }).count) || (first as { count: number }).count < 0 || (first as { count: number }).count > 16_000) {
        incomplete += 1; continue;
      }
      parsed += 1;
      signals = Math.min(100_000, signals + (first as { count: number }).count);
    }
  } finally { await session.close(); }
  return { mode: 'SCA_JSON_MANIFEST', status: status(parsed, incomplete, skipped), parsed, incomplete, skipped, signals, parserVersion: parserVersions().typescript };
}
