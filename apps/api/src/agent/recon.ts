import ts from 'typescript';
import { SCA_MANIFEST_FILE_NAMES } from '../scans/sca/engine.js';
import type { SourceSnapshotRecord } from '../scans/sources.js';
import type { AgentAssessment } from '@drobon/shared';

const MAX_NODES = 50_000;
const METHODS = new Set(['get', 'post', 'put', 'patch', 'delete']);

/**
 * Bounded, read-only local inventory. Route candidates are syntax shapes,
 * not discovered live endpoints or proof that a router is reachable. No
 * source, route text, credentials, repository instructions or network access
 * leave this component. Other languages and dynamic routes are not analyzed.
 */
export function inventory(snapshot: SourceSnapshotRecord | undefined, targetConfigured: boolean): AgentAssessment['inventory'] {
  const files = snapshot?.files ?? [];
  const manifests = files.filter((file) => (SCA_MANIFEST_FILE_NAMES as readonly string[]).includes(file.path.split('/').at(-1) ?? '')).length;
  let routeCandidates = 0;
  let nodes = 0;
  let applicable = false;
  let partial = false;
  for (const file of files) {
    if (!/\.(?:js|cjs|mjs|ts|jsx|tsx)$/i.test(file.path)) continue;
    applicable = true;
    if (nodes >= MAX_NODES) { partial = true; break; }
    try {
      const lower = file.path.toLowerCase();
      const kind = lower.endsWith('.tsx') ? ts.ScriptKind.TSX : lower.endsWith('.jsx') ? ts.ScriptKind.JSX
        : lower.endsWith('.ts') ? ts.ScriptKind.TS : ts.ScriptKind.JS;
      const root = ts.createSourceFile(file.path, file.content, ts.ScriptTarget.Latest, true, kind);
      // TypeScript exposes parser diagnostics at runtime but not in its public
      // SourceFile type. If unavailable or nonempty, never report a complete
      // syntax pass; retain bounded candidates as tentative observations.
      const diagnostics: unknown = Reflect.get(root, 'parseDiagnostics');
      if (!Array.isArray(diagnostics) || diagnostics.length > 0) partial = true;
      const stack: ts.Node[] = [root];
      while (stack.length > 0) {
        if (nodes >= MAX_NODES) { partial = true; break; }
        const node = stack.pop();
        if (node === undefined) break;
        nodes += 1;
        if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) &&
            METHODS.has(node.expression.name.text.toLowerCase()) && node.arguments.length > 0) {
          const first = node.arguments[0];
          if (first !== undefined && ts.isStringLiteral(first) && first.text.startsWith('/')) routeCandidates += 1;
        }
        ts.forEachChild(node, (child) => { stack.push(child); });
      }
    } catch { partial = true; }
  }
  return {
    sourceFiles: files.length,
    targetConfigured,
    manifestFiles: manifests,
    routeCandidates: Math.min(routeCandidates, 10_000),
    routeAnalysis: !applicable ? 'NOT_APPLICABLE' : partial || routeCandidates > 10_000 ? 'PARTIAL' : 'COMPLETE',
  };
}
