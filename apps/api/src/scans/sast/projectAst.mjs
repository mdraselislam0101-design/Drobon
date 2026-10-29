/**
 * Bounded JS/TS interprocedural analysis over the uploaded virtual tree.
 * No project code, imports or packages are executed or loaded from disk.
 * Only local named functions and relative named imports are resolved; this is
 * intentionally not a whole-program/type/control-flow proof.
 */
import path from 'node:path';
import ts from 'typescript';

const MAX_FILES = 64;
const MAX_BYTES = 393_216;
const MAX_FILE_BYTES = 131_072;
const MAX_FUNCTIONS = 96;
const MAX_NODES = 30_000;
const MAX_WORK = 150_000;
const MAX_DEPTH = 64;
const MAX_TOKENS = 16;
const MAX_SINKS = 200;
const ITERATIONS = 4;
const KINDS = ['command', 'sql', 'html', 'code'];
const SCRIPT_KINDS = { javascript: ts.ScriptKind.JS, typescript: ts.ScriptKind.TS, jsx: ts.ScriptKind.JSX, tsx: ts.ScriptKind.TSX };

function sourceMatches(chain, names) {
  return chain !== '' && names.some((name) => chain === name || chain.endsWith(`.${name}`) || chain.startsWith(`${name}.`) || chain.startsWith(`${name}[`));
}
function sinkKind(profile, chain) {
  return KINDS.find((kind) => profile.sinks[kind].some((name) => chain === name || chain.endsWith(`.${name}`)));
}
function staticChain(expression) {
  const parts = [];
  let node = expression;
  for (let depth = 0; node && depth < 32; depth += 1) {
    if (ts.isParenthesizedExpression(node) || ts.isAsExpression(node) || ts.isNonNullExpression(node) ||
        ts.isTypeAssertionExpression(node) || ts.isSatisfiesExpression(node)) node = node.expression;
    else if (ts.isIdentifier(node)) { parts.unshift(node.text); return parts.join('.'); }
    else if (ts.isPropertyAccessExpression(node)) { parts.unshift(node.name.text); node = node.expression; }
    else if (ts.isElementAccessExpression(node) && node.argumentExpression && (ts.isStringLiteral(node.argumentExpression) || ts.isNumericLiteral(node.argumentExpression))) {
      parts.unshift(node.argumentExpression.text); node = node.expression;
    } else return '';
  }
  return '';
}
function location(module, node) {
  const pos = module.source.getLineAndCharacterOfPosition(node.getStart(module.source));
  return { file: module.path, line: pos.line + 1, column: pos.character + 1 };
}
function locKey(loc) { return `${loc.file}:${loc.line}:${loc.column}`; }
function empty() { return new Map(); }
function combine(target, value, state) {
  for (const [key, origin] of value) {
    if (!target.has(key)) {
      if (target.size >= MAX_TOKENS) { state.limited = true; break; }
      target.set(key, origin);
    }
  }
  return target;
}
function tick(state) { if (++state.work > MAX_WORK) { state.limited = true; return false; } return true; }
function concrete(module, node) {
  const source = location(module, node);
  return new Map([[`s:${locKey(source)}`, { source, via: [] }]]);
}
function addVia(value, at) {
  const out = empty();
  for (const [key, origin] of value) {
    const via = origin.via.some((step) => locKey(step) === locKey(at)) ? origin.via : [...origin.via, at].slice(-4);
    out.set(key, { ...origin, via });
  }
  return out;
}
function substitute(value, args, callsite, state) {
  const out = empty();
  for (const [key, origin] of value) {
    if (key.startsWith('p:')) {
      const index = Number(key.slice(2));
      let actual = addVia(args[index] ?? empty(), callsite);
      for (const step of origin.via) actual = addVia(actual, step);
      combine(out, actual, state);
    } else {
      combine(out, new Map([[key, { ...origin, via: [...origin.via, callsite].slice(-4) }]]), state);
    }
  }
  return out;
}
function bindNames(name, value, env, state) {
  if (ts.isIdentifier(name)) { env.set(name.text, combine(env.get(name.text) ?? empty(), value, state)); return; }
  if (ts.isObjectBindingPattern(name) || ts.isArrayBindingPattern(name)) {
    for (const element of name.elements) if (ts.isBindingElement(element)) bindNames(element.name, value, env, state);
  }
}
function resolveRelative(from, spec, modules) {
  if (!(spec.startsWith('./') || spec.startsWith('../')) || spec.includes('\\')) return undefined;
  const target = path.posix.normalize(path.posix.join(path.posix.dirname(from), spec));
  if (target.startsWith('../') || target.startsWith('/') || target === '..') return undefined;
  const withoutJs = target.replace(/\.(?:js|jsx|mjs|cjs)$/, '');
  const possibilities = [target, ...['.js', '.ts', '.jsx', '.tsx'].map((ext) => target + ext),
    ...['.ts', '.tsx', '.js', '.jsx'].map((ext) => withoutJs + ext),
    ...['.js', '.ts', '.jsx', '.tsx'].map((ext) => `${target}/index${ext}`)];
  return possibilities.find((candidate) => modules.has(candidate));
}
function isExported(node) { return node.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword) === true; }

function prepare(input, state) {
  const modules = new Map();
  let bytes = 0;
  const files = input.files.slice(0, MAX_FILES);
  if (input.files.length > MAX_FILES) state.limited = true;
  for (const file of files) {
    const kind = SCRIPT_KINDS[file.family];
    const size = Buffer.byteLength(file.content, 'utf8');
    if (kind === undefined || size > MAX_FILE_BYTES || bytes + size > MAX_BYTES) { state.limited = true; continue; }
    bytes += size;
    let source;
    try { source = ts.createSourceFile('input', file.content, ts.ScriptTarget.Latest, false, kind); }
    catch { state.limited = true; continue; }
    const diagnostics = Reflect.get(source, 'parseDiagnostics');
    if (!Array.isArray(diagnostics) || diagnostics.length) { state.limited = true; continue; }
    const cursor = [source];
    while (cursor.length && tick(state)) {
      const node = cursor.pop();
      if (++state.nodes > MAX_NODES) { state.limited = true; break; }
      ts.forEachChild(node, (child) => { cursor.push(child); });
    }
    modules.set(file.path, { ...file, source, functions: new Map(), exports: new Map(), imports: new Map() });
    if (state.work > MAX_WORK || state.nodes > MAX_NODES) break;
  }
  let functionCount = 0;
  for (const module of modules.values()) {
    for (const statement of module.source.statements) {
      if (ts.isFunctionDeclaration(statement) && statement.name && statement.body) {
        if (++functionCount > MAX_FUNCTIONS) { state.limited = true; break; }
        module.functions.set(statement.name.text, { node: statement, module, summary: { returns: empty(), sinks: [] } });
        if (isExported(statement)) module.exports.set(statement.name.text, statement.name.text);
      } else if (ts.isVariableStatement(statement)) {
        for (const declaration of statement.declarationList.declarations) {
          if (!ts.isIdentifier(declaration.name) || !declaration.initializer || !(ts.isArrowFunction(declaration.initializer) || ts.isFunctionExpression(declaration.initializer))) continue;
          if (++functionCount > MAX_FUNCTIONS) { state.limited = true; break; }
          module.functions.set(declaration.name.text, { node: declaration.initializer, module, summary: { returns: empty(), sinks: [] } });
          if (isExported(statement)) module.exports.set(declaration.name.text, declaration.name.text);
        }
      } else if (ts.isExportDeclaration(statement) && !statement.moduleSpecifier && statement.exportClause && ts.isNamedExports(statement.exportClause)) {
        for (const item of statement.exportClause.elements) module.exports.set(item.name.text, (item.propertyName ?? item.name).text);
      }
    }
    module.top = { node: module.source, module, summary: { returns: empty(), sinks: [] } };
  }
  for (const module of modules.values()) {
    for (const statement of module.source.statements) {
      if (!ts.isImportDeclaration(statement) || !ts.isStringLiteral(statement.moduleSpecifier) || !statement.importClause?.namedBindings ||
          !ts.isNamedImports(statement.importClause.namedBindings) || statement.importClause.isTypeOnly) continue;
      const specifier = statement.moduleSpecifier.text;
      const resolved = resolveRelative(module.path, specifier, modules);
      if (!resolved) {
        if (specifier.startsWith('./') || specifier.startsWith('../')) { state.unresolvedImports += 1; state.limited = true; }
        continue;
      }
      for (const item of statement.importClause.namedBindings.elements) {
        if (!item.isTypeOnly) module.imports.set(item.name.text, { file: resolved, exported: (item.propertyName ?? item.name).text });
      }
    }
  }
  return modules;
}
function resolveFunction(module, name, modules) {
  if (module.functions.has(name)) return module.functions.get(name);
  const reference = module.imports.get(name);
  if (!reference) return undefined;
  const target = modules.get(reference.file);
  if (!target) return undefined;
  const local = target.exports.get(reference.exported);
  return local ? target.functions.get(local) : undefined;
}
function recordSink(ctx, kind, sink, value) {
  if (!value.size) return;
  if (ctx.sinks.length >= MAX_SINKS) { ctx.state.limited = true; return; }
  ctx.sinks.push({ kind, sink, value });
}
function evaluate(node, ctx, depth = 0) {
  if (!node || depth > MAX_DEPTH || !tick(ctx.state)) {
    if (depth > MAX_DEPTH) ctx.state.limited = true;
    return empty();
  }
  if (ts.isTypeNode(node) || ts.isStringLiteralLike(node) || ts.isNumericLiteral(node) ||
      node.kind === ts.SyntaxKind.RegularExpressionLiteral || ts.isFunctionLike(node) || ts.isClassLike(node)) return empty();
  if (ts.isIdentifier(node)) {
    const known = ctx.env.get(node.text);
    if (known) return new Map(known);
    return sourceMatches(node.text, ctx.module.profile.sources) ? concrete(ctx.module, node) : empty();
  }
  const chain = staticChain(node);
  if (sourceMatches(chain, ctx.module.profile.sources)) return concrete(ctx.module, node);
  if (ts.isBinaryExpression(node) && node.operatorToken.kind >= ts.SyntaxKind.FirstAssignment && node.operatorToken.kind <= ts.SyntaxKind.LastAssignment) {
    const value = evaluate(node.right, ctx, depth + 1);
    if (ts.isIdentifier(node.left)) bindNames(node.left, value, ctx.env, ctx.state);
    return value;
  }
  if (ts.isCallExpression(node) || ts.isNewExpression(node)) {
    const callee = staticChain(node.expression);
    const args = (node.arguments ?? []).map((argument) => evaluate(argument, ctx, depth + 1));
    const kind = sinkKind(ctx.module.profile, callee);
    const first = node.arguments?.[0];
    const second = node.arguments?.[1];
    const looksBound = kind === 'sql' && first && ts.isStringLiteral(first) && second &&
      (ts.isArrayLiteralExpression(second) || ts.isObjectLiteralExpression(second)) &&
      ctx.module.profile.parameterizedSql.some((marker) => first.text.includes(marker));
    if (kind && !looksBound) {
      const value = empty();
      for (const arg of args) combine(value, arg, ctx.state);
      recordSink(ctx, kind, location(ctx.module, node.expression), value);
    }
    if (sourceMatches(callee, ctx.module.profile.sourceCalls)) return concrete(ctx.module, node.expression);
    const target = ts.isIdentifier(node.expression) && !ctx.env.has(node.expression.text)
      ? resolveFunction(ctx.module, node.expression.text, ctx.modules) : undefined;
    if (target) {
      const at = location(ctx.module, node.expression);
      for (const item of target.summary.sinks) recordSink(ctx, item.kind, item.sink, substitute(item.value, args, at, ctx.state));
      return substitute(target.summary.returns, args, at, ctx.state);
    }
    // Unknown functions are not assumed to sanitize; over-approximate returns.
    const value = empty();
    for (const arg of args) combine(value, arg, ctx.state);
    return value;
  }
  const out = empty();
  if (ts.isPropertyAccessExpression(node)) return evaluate(node.expression, ctx, depth + 1);
  if (ts.isPropertyAssignment(node)) return evaluate(node.initializer, ctx, depth + 1);
  if (ts.isShorthandPropertyAssignment(node)) return evaluate(node.name, ctx, depth + 1);
  ts.forEachChild(node, (child) => { combine(out, evaluate(child, ctx, depth + 1), ctx.state); });
  return out;
}
function summarize(fn, modules, state) {
  const { module, node } = fn;
  const ctx = { module, modules, state, env: new Map(), sinks: [] };
  const returns = empty();
  if (ts.isFunctionLike(node)) {
    node.parameters.forEach((parameter, index) => bindNames(parameter.name, new Map([[`p:${index}`, { via: [] }]]), ctx.env, state));
  }
  const body = ts.isSourceFile(node) ? node : node.body;
  if (!body) return { returns, sinks: [] };
  if (!ts.isBlock(body) && !ts.isSourceFile(body)) combine(returns, evaluate(body, ctx), state);
  else {
    const pending = [{ node: body, depth: 0 }];
    while (pending.length && tick(state)) {
      const frame = pending.pop();
      if (frame.depth > MAX_DEPTH) { state.limited = true; break; }
      const current = frame.node;
      if (current !== body && (ts.isFunctionLike(current) || ts.isClassLike(current) || ts.isTypeNode(current) ||
          ts.isImportDeclaration(current) || ts.isExportDeclaration(current))) continue;
      if (ts.isVariableDeclaration(current)) {
        if (current.initializer && !ts.isFunctionLike(current.initializer)) bindNames(current.name, evaluate(current.initializer, ctx), ctx.env, state);
        continue;
      }
      if (ts.isReturnStatement(current)) { combine(returns, evaluate(current.expression, ctx), state); continue; }
      if (ts.isExpressionStatement(current)) { evaluate(current.expression, ctx); continue; }
      const parts = [];
      ts.forEachChild(current, (child) => { parts.push(child); });
      for (let i = parts.length - 1; i >= 0; i -= 1) pending.push({ node: parts[i], depth: frame.depth + 1 });
    }
  }
  // Merge duplicate call paths deterministically, keeping distinct origins.
  const unique = new Map();
  for (const item of ctx.sinks) {
    const key = `${item.kind}:${locKey(item.sink)}`;
    if (!unique.has(key)) unique.set(key, { ...item, value: empty() });
    combine(unique.get(key).value, item.value, state);
  }
  return { returns, sinks: [...unique.values()] };
}

export function analyzeProjectAst(input) {
  const state = { work: 0, nodes: 0, limited: false, unresolvedImports: 0 };
  let modules;
  try {
    modules = prepare(input, state);
    // Fixed-point iterations bound call-chain depth; this is not recursion or
    // a promise of complete call graph resolution.
    for (let iteration = 0; iteration < ITERATIONS && state.work <= MAX_WORK; iteration += 1) {
      for (const module of modules.values()) {
        for (const fn of module.functions.values()) fn.summary = summarize(fn, modules, state);
        module.top.summary = summarize(module.top, modules, state);
      }
    }
    const candidates = [];
    const seen = new Set();
    for (const module of modules.values()) {
      for (const fn of [module.top, ...module.functions.values()]) {
        for (const item of fn.summary.sinks) {
          const sinkModule = modules.get(item.sink.file);
          const ruleId = sinkModule?.reporters[item.kind];
          if (!ruleId) continue;
          for (const origin of item.value.values()) {
            if (!origin.source) continue;
            const key = `${item.kind}:${locKey(item.sink)}`;
            if (seen.has(key)) continue;
            seen.add(key);
            candidates.push({ ruleId, kind: item.kind, path: item.sink.file, lineIndex: item.sink.line - 1,
              column: item.sink.column, source: origin.source, via: origin.via });
            if (candidates.length >= MAX_SINKS) { state.limited = true; break; }
          }
        }
      }
    }
    return { status: state.limited ? 'LIMIT' : 'OK', examinedFiles: modules.size, unresolvedImports: state.unresolvedImports, candidates };
  } catch {
    return { status: 'ERROR', examinedFiles: 0, unresolvedImports: 0, candidates: [] };
  }
}
