/**
 * Scanner-specific, read-only AST supplements. Runs only inside the bounded
 * AST worker. It never executes code, resolves imports, opens the network or
 * returns source text, manifest values, credentials or parser diagnostics.
 */
import ts from 'typescript';
import { parse } from 'parse5';
import { analyzeStructuredAst } from './structuredAst.mjs';

const MAX_BYTES = 131_072;
const MAX_NODES = 16_000;
const MAX_DEPTH = 80;
const MAX_LITERAL_SPANS = 1_000;
const MAX_CONCAT_SPANS = 64;
const MAX_CONCAT_PARTS = 16;
const MAX_CONCAT_CHARS = 1_024;
const MAX_SCRIPTS = 8;
const MAX_HTML_NODES = 4_000;
const JS_KINDS = { javascript: ts.ScriptKind.JS, typescript: ts.ScriptKind.TS, jsx: ts.ScriptKind.JSX, tsx: ts.ScriptKind.TSX };
const empty = (status) => ({ status, candidates: [] });

function parseJs(content, family) {
  if (typeof content !== 'string' || Buffer.byteLength(content, 'utf8') > MAX_BYTES || JS_KINDS[family] === undefined) return undefined;
  const source = ts.createSourceFile('input', content, ts.ScriptTarget.Latest, false, JS_KINDS[family]);
  const diagnostics = Reflect.get(source, 'parseDiagnostics');
  return Array.isArray(diagnostics) && diagnostics.length === 0 ? source : undefined;
}

/** Return coordinates for a same-line, literal-only `+` expression. No text
 * escapes the worker; dynamic values, escaped literals and templates are not
 * evaluated. Bounds also prevent nested expressions from multiplying work. */
function concatCoordinates(node, source) {
  if (!ts.isBinaryExpression(node) || node.operatorToken.kind !== ts.SyntaxKind.PlusToken) return undefined;
  const start = source.getLineAndCharacterOfPosition(node.getStart(source));
  const end = source.getLineAndCharacterOfPosition(node.end);
  if (start.line !== end.line) return undefined;
  const pending = [node];
  const pieces = [];
  let size = 0;
  let steps = 0;
  while (pending.length) {
    if (++steps > MAX_CONCAT_PARTS * 4) return undefined;
    const current = pending.pop();
    if (ts.isParenthesizedExpression(current)) { pending.push(current.expression); continue; }
    if (ts.isBinaryExpression(current) && current.operatorToken.kind === ts.SyntaxKind.PlusToken) {
      pending.push(current.right, current.left); continue;
    }
    if (!ts.isStringLiteral(current) || pieces.length >= MAX_CONCAT_PARTS) return undefined;
    const at = current.getStart(source);
    const raw = source.text.slice(at, current.end);
    const value = raw.slice(1, -1);
    // Restrict to simple, unescaped ASCII credential-shaped characters.
    if ((raw[0] !== '"' && raw[0] !== "'") || raw.at(-1) !== raw[0] || !/^[A-Za-z0-9_+/.=:-]*$/.test(value)) return undefined;
    const from = source.getLineAndCharacterOfPosition(at);
    const to = source.getLineAndCharacterOfPosition(current.end);
    if (from.line !== start.line || to.line !== start.line || (size += value.length) > MAX_CONCAT_CHARS) return undefined;
    pieces.push({ start: from.character + 1, end: to.character + 1 });
  }
  if (pieces.length < 2) return undefined;
  return { type: 'concat', line: start.line + 1, start: start.character + 1, end: end.character + 1, pieces };
}

/** Return only string-literal and static-concatenation coordinates, never text. */
function secretLiterals({ content, family }) {
  const source = parseJs(content, family);
  if (!source) return empty('SYNTAX_ERROR');
  const pending = [{ node: source, depth: 0 }];
  const records = [];
  let visited = 0;
  let concats = 0;
  let literals = 0;
  let concatLimited = false;
  while (pending.length) {
    const { node, depth } = pending.pop();
    if (++visited > MAX_NODES || depth > MAX_DEPTH) return empty('LIMIT');
    const concat = concatCoordinates(node, source);
    if (concat) {
      if (concats < MAX_CONCAT_SPANS) { records.push(concat); concats += 1; }
      else concatLimited = true;
    }
    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node) ||
        ts.isTemplateHead(node) || ts.isTemplateMiddle(node) || ts.isTemplateTail(node)) {
      const start = source.getLineAndCharacterOfPosition(node.getStart(source));
      const end = source.getLineAndCharacterOfPosition(node.end);
      const lineStarts = source.getLineStarts();
      // The existing secret matcher works one line at a time. Emit only
      // coordinates for each literal segment, including multiline templates;
      // never copy literal characters out of the worker.
      for (let line = start.line; line <= end.line; line += 1) {
        const first = line === start.line ? start.character + 1 : 1;
        const last = line === end.line ? end.character + 1 : (lineStarts[line + 1] ?? node.end) - (lineStarts[line] ?? 0) + 1;
        if (last <= first) continue;
        if (++literals > MAX_LITERAL_SPANS) return empty('LIMIT');
        records.push({ type: 'literal', line: line + 1, start: first, end: last });
      }
    }
    ts.forEachChild(node, (child) => { pending.push({ node: child, depth: depth + 1 }); });
  }
  if (concatLimited) records.push({ type: 'concat-limit' });
  return { status: 'OK', candidates: records };
}

/** package.json-only syntactic declaration count; no keys/values are returned. */
function manifestAst({ content }) {
  if (typeof content !== 'string' || Buffer.byteLength(content, 'utf8') > MAX_BYTES) return empty('LIMIT');
  try { JSON.parse(content); } catch { return empty('SYNTAX_ERROR'); }
  const source = ts.parseJsonText('manifest.json', content);
  const diagnostics = Reflect.get(source, 'parseDiagnostics');
  if (!Array.isArray(diagnostics) || diagnostics.length > 0) return empty('SYNTAX_ERROR');
  const pending = [{ node: source, depth: 0 }];
  let visited = 0;
  while (pending.length) {
    const { node, depth } = pending.pop();
    if (++visited > MAX_NODES || depth > MAX_DEPTH) return empty('LIMIT');
    ts.forEachChild(node, (child) => { pending.push({ node: child, depth: depth + 1 }); });
  }
  const stmt = source.statements[0];
  const root = stmt && ts.isExpressionStatement(stmt) ? stmt.expression : undefined;
  let count = 0;
  if (root && ts.isObjectLiteralExpression(root)) {
    for (const property of root.properties) {
      if (!ts.isPropertyAssignment(property) || !ts.isStringLiteral(property.name) || !ts.isObjectLiteralExpression(property.initializer)) continue;
      if (!['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'].includes(property.name.text)) continue;
      count += property.initializer.properties.filter(ts.isPropertyAssignment).length;
    }
  }
  return { status: 'OK', candidates: [{ type: 'declarations', count: Math.min(count, MAX_NODES) }] };
}

/** Only the already-received baseline response: no extra requests or execution. */
function dastResponse({ content, contentType, profile }) {
  if (typeof content !== 'string' || Buffer.byteLength(content, 'utf8') > 32_768 || !profile) return empty('LIMIT');
  const scripts = [];
  let skipped = 0;
  const type = typeof contentType === 'string' ? contentType.toLowerCase() : '';
  if (['text/javascript', 'application/javascript', 'text/ecmascript', 'application/ecmascript'].includes(type)) {
    scripts.push(content);
  } else if (type === 'text/html' || type === 'application/xhtml+xml') {
    const root = parse(content);
    const pending = [root];
    let visited = 0;
    while (pending.length) {
      const node = pending.pop();
      if (++visited > MAX_HTML_NODES) { skipped += 1; break; }
      if (node.tagName === 'script') {
        const attrs = Array.isArray(node.attrs) ? node.attrs : [];
        const src = attrs.some((attribute) => attribute.name.toLowerCase() === 'src');
        const scriptType = attrs.find((attribute) => attribute.name.toLowerCase() === 'type')?.value?.trim().toLowerCase() ?? '';
        const executable = scriptType === '' || scriptType === 'module' || ['text/javascript', 'application/javascript', 'text/ecmascript', 'application/ecmascript'].includes(scriptType);
        if (src && executable) skipped += 1; // External scripts are NEVER fetched by this pass.
        else if (executable) {
          const text = (node.childNodes ?? []).filter((child) => child.nodeName === '#text').map((child) => child.value ?? '').join('');
          if (text.trim() !== '') {
            if (scripts.length < MAX_SCRIPTS) scripts.push(text);
            else skipped += 1;
          }
        }
        continue;
      }
      // Do not enter inert <template> contents or parse event-handler attributes.
      for (let index = (node.childNodes?.length ?? 0) - 1; index >= 0; index -= 1) pending.push(node.childNodes[index]);
    }
  }
  let parsed = 0;
  let incomplete = 0;
  const records = [];
  const reporters = { html: 'AST-HTML', code: 'AST-CODE' };
  for (let index = 0; index < scripts.length; index += 1) {
    const result = analyzeStructuredAst({ family: 'javascript', content: scripts[index], profile, reporters });
    if (result.status === 'OK') parsed += 1;
    else incomplete += 1;
    for (const candidate of result.status === 'OK' ? result.candidates : []) {
      if ((candidate.kind === 'html' || candidate.kind === 'code') && records.length < 100) {
        records.push({ type: 'flow', script: index + 1, line: candidate.lineIndex + 1, column: candidate.column, category: candidate.kind });
      }
    }
  }
  return { status: 'OK', candidates: [{ type: 'summary', parsed, incomplete, skipped: Math.min(skipped, 200) }, ...records] };
}

export function analyzeSupplementAst(input) {
  try {
    if (input.kind === 'SECRETS') return secretLiterals(input);
    if (input.kind === 'SCA') return manifestAst(input);
    if (input.kind === 'DAST') return dastResponse(input);
    return empty('ERROR');
  } catch {
    return empty('ERROR');
  }
}
