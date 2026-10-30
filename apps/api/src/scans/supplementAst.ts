import type { AstSupplementSummary, Finding } from '@drobon/shared';
import { parserVersions } from './sast/astCoverage.js';
import { detectLanguageFamily } from './sast/languages.js';
import { StructuredAstSession } from './sast/structuredAstSession.js';
import { matchSecretsRuleLine, type SecretsRule } from './secrets/rules.js';

const MAX_FILES = 32;
type File = { path: string; content: string };
type Literal = { type: 'literal'; line: number; start: number; end: number };

function isLiteral(value: unknown): value is Literal {
  if (typeof value !== 'object' || value === null) return false;
  const v = value as Record<string, unknown>;
  return Object.keys(v).length === 4 && v['type'] === 'literal' &&
    Number.isInteger(v['line']) && Number.isInteger(v['start']) && Number.isInteger(v['end']) &&
    (v['line'] as number) > 0 && (v['line'] as number) <= 131_072 &&
    (v['start'] as number) > 0 && (v['end'] as number) > (v['start'] as number) && (v['end'] as number) <= 131_073;
}

function status(parsed: number, incomplete: number, skipped: number): AstSupplementSummary['status'] {
  if (parsed === 0 && incomplete === 0 && skipped === 0) return 'NOT_APPLICABLE';
  return incomplete > 0 || skipped > 0 ? 'PARTIAL' : 'RAN';
}

/**
 * Classify existing Secrets matches only. This never creates/suppresses a
 * match or copies source into a result, and never verifies a credential.
 */
export async function addSecretAstContext(
  files: readonly File[], findings: Finding[], rules: readonly SecretsRule[], signal: AbortSignal, remainingMs: () => number,
): Promise<AstSupplementSummary> {
  const eligible = files.map((file) => ({ file, family: detectLanguageFamily(file.path)?.family }))
    .filter((item) => ['javascript', 'typescript', 'jsx', 'tsx'].includes(item.family ?? ''));
  let skipped = Math.min(200, files.length - eligible.length + Math.max(0, eligible.length - MAX_FILES));
  let parsed = 0; let incomplete = 0; let signals = 0;
  const session = new StructuredAstSession();
  try {
    for (const { file, family } of eligible.slice(0, MAX_FILES)) {
      if (signal.aborted || remainingMs() <= 0) { skipped = Math.min(200, skipped + 1); continue; }
      // The Secrets engine normalizes tabs and trailing CR before matching;
      // use exactly the same coordinate system for literal spans.
      const lines = file.content.split('\n').map((line) => line.replace(/\r$/, '').replace(/\t/g, '  '));
      const result = await session.analyzeSupplement({ kind: 'SECRETS', ...(family === undefined ? {} : { family }), content: lines.join('\n') }, signal, remainingMs());
      if (result.status !== 'OK' || !result.records.every(isLiteral)) { incomplete += 1; continue; }
      parsed += 1;
      const spans = result.records as Literal[];
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
