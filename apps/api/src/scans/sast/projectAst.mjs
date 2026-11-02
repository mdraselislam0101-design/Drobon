/**
 * Bounded JS/TS interprocedural analysis over the uploaded virtual tree.
 * No project code, imports or packages are executed or loaded from disk.
 * Only local named functions and relative named imports are resolved; this is
 * intentionally not a whole-program/type/control-flow proof.
 */
import path from 'node:path';
import ts from 'typescript';

// Bounds are aligned with the snapshot upload caps (200 files / 768 KiB total),
// so a project is no longer silently cut at 64 files.
const MAX_FILES = 200;
const MAX_BYTES = 786_432;
const MAX_FILE_BYTES = 131_072;
const MAX_FUNCTIONS = 400;
const MAX_NODES = 60_000;
const MAX_WORK = 300_000;
const MAX_DEPTH = 64;
const MAX_TOKENS = 16;
const MAX_SINKS = 200;
/** Propagation continues to a FIXED POINT (summary equality), never past this. */
const MAX_ROUNDS = 12;
/** Steps recorded in a finding's cross-file trace. */
const MAX_TRACE = 6;
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
    const via = origin.via.some((step) => locKey(step) === locKey(at)) ? origin.via : [...origin.via, at].slice(-MAX_TRACE);
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
      combine(out, new Map([[key, { ...origin, via: [...origin.via, callsite].slice(-MAX_TRACE) }]]), state);
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
function isDefaultExported(node) { return node.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.DefaultKeyword) === true; }

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
    modules.set(file.path, { ...file, source, functions: new Map(), exports: new Map(), imports: new Map(),
      namespaces: new Map(), exportStars: [] });
    if (state.work > MAX_WORK || state.nodes > MAX_NODES) break;
  }
  let functionCount = 0;
  for (const module of modules.values()) {
    for (const statement of module.source.statements) {
      if (ts.isFunctionDeclaration(statement) && statement.name && statement.body) {
        if (++functionCount > MAX_FUNCTIONS) { state.limited = true; break; }
        module.functions.set(statement.name.text, { node: statement, module, summary: { returns: empty(), sinks: [] } });
        if (isExported(statement)) module.exports.set(statement.name.text, statement.name.text);
        if (isDefaultExported(statement)) module.exports.set('default', statement.name.text);
      } else if (ts.isVariableStatement(statement)) {
        for (const declaration of statement.declarationList.declarations) {
          if (!ts.isIdentifier(declaration.name) || !declaration.initializer || !(ts.isArrowFunction(declaration.initializer) || ts.isFunctionExpression(declaration.initializer))) continue;
          if (++functionCount > MAX_FUNCTIONS) { state.limited = true; break; }
          module.functions.set(declaration.name.text, { node: declaration.initializer, module, summary: { returns: empty(), sinks: [] } });
          if (isExported(statement)) module.exports.set(declaration.name.text, declaration.name.text);
        }
      } else if (ts.isExportDeclaration(statement) && !statement.moduleSpecifier && statement.exportClause && ts.isNamedExports(statement.exportClause)) {
        for (const item of statement.exportClause.elements) module.exports.set(item.name.text, (item.propertyName ?? item.name).text);
      } else if (ts.isExportAssignment(statement) && ts.isIdentifier(statement.expression)) {
        // `export default fn` — an explicit, local, named re-export.
        module.exports.set('default', statement.expression.text);
      }
    }
    module.top = { node: module.source, module, summary: { returns: empty(), sinks: [] } };
  }
  const resolveSpecifier = (module, specifier) => {
    const resolved = resolveRelative(module.path, specifier, modules);
    if (!resolved && (specifier.startsWith('./') || specifier.startsWith('../'))) {
      state.unresolvedImports += 1;
      state.limited = true;
    }
    return resolved;
  };
  for (const module of modules.values()) {
    for (const statement of module.source.statements) {
      // `export * from './x'` re-exports every named export of the target.
      if (ts.isExportDeclaration(statement) && statement.moduleSpecifier && ts.isStringLiteral(statement.moduleSpecifier) &&
          statement.exportClause === undefined && !statement.isTypeOnly) {
        const resolved = resolveSpecifier(module, statement.moduleSpecifier.text);
        if (resolved !== undefined && resolved !== module.path) module.exportStars.push(resolved);
        continue;
      }
      if (!ts.isImportDeclaration(statement) || !ts.isStringLiteral(statement.moduleSpecifier) ||
          statement.importClause === undefined || statement.importClause.isTypeOnly) continue;
      const resolved = resolveSpecifier(module, statement.moduleSpecifier.text);
      if (resolved === undefined) continue;
      const bindings = statement.importClause.namedBindings;
      if (statement.importClause.name !== undefined) {
        // `import fn from './m'` — resolves only to that module's default export.
        module.imports.set(statement.importClause.name.text, { file: resolved, exported: 'default' });
      }
      if (bindings !== undefined && ts.isNamedImports(bindings)) {
        for (const item of bindings.elements) {
          if (!item.isTypeOnly) module.imports.set(item.name.text, { file: resolved, exported: (item.propertyName ?? item.name).text });
        }
      } else if (bindings !== undefined && ts.isNamespaceImport(bindings)) {
        // `import * as ns from './m'` — recorded so `ns.fn()` can resolve.
        module.namespaces.set(bindings.name.text, resolved);
      }
    }
  }
  return modules;
}
/** Named export lookup that follows `export * from './x'` chains (cycle-safe). */
function lookupExport(module, exported, modules, seen = new Set()) {
  if (seen.has(module.path)) return undefined;
  seen.add(module.path);
  const local = module.exports.get(exported);
  if (local !== undefined) return { module, local };
  for (const starPath of module.exportStars) {
    const target = modules.get(starPath);
    if (target === undefined) continue;
    const found = lookupExport(target, exported, modules, seen);
    if (found !== undefined) return found;
  }
  return undefined;
}
function resolveFunction(module, name, modules) {
  if (module.functions.has(name)) return module.functions.get(name);
  const reference = module.imports.get(name);
  if (!reference) return undefined;
  const target = modules.get(reference.file);
  if (!target) return undefined;
  const found = lookupExport(target, reference.exported, modules);
  return found === undefined ? undefined : found.module.functions.get(found.local);
}
/** `ns.fn()` where `ns` is a namespace import of a relative module. */
function resolveNamespacedCall(module, chain, modules) {
  const parts = chain.split('.');
  if (parts.length !== 2) return undefined;
  const file = module.namespaces.get(parts[0]);
  if (file === undefined) return undefined;
  const target = modules.get(file);
  if (target === undefined) return undefined;
  const found = lookupExport(target, parts[1], modules);
  return found === undefined ? undefined : found.module.functions.get(found.local);
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
      ? resolveFunction(ctx.module, node.expression.text, ctx.modules)
      : (callee !== '' ? resolveNamespacedCall(ctx.module, callee, ctx.modules) : undefined);
    if (target) {
      ctx.state.callEdges += 1;
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

/** Canonical form of a summary, used only for fixed-point comparison. */
function summaryKey(summary) {
  const sinks = summary.sinks.map((item) => `${item.kind}|${locKey(item.sink)}|${item.value.size}`).join(';');
  const origins = [];
  for (const value of [summary.returns, ...summary.sinks.map((item) => item.value)]) {
    for (const [key, origin] of value) origins.push(`${key}=${origin.source === undefined ? '' : locKey(origin.source)}/${origin.via.map(locKey).join('>')}`);
  }
  origins.sort();
  return `${sinks}#${origins.join(';')}`;
}

export function analyzeProjectAst(input) {
  const state = { work: 0, nodes: 0, limited: false, unresolvedImports: 0, callEdges: 0, rounds: 0, converged: false };
  let modules;
  try {
    modules = prepare(input, state);
    // Propagation continues until the summaries stop changing (a real fixed
    // point for the bounded call graph), capped by MAX_ROUNDS and the shared
    // work budget. Not converging is reported, never assumed away.
    let previous = undefined;
    for (let round = 0; round < MAX_ROUNDS && state.work <= MAX_WORK; round += 1) {
      state.rounds = round + 1;
      state.callEdges = 0;
      for (const module of modules.values()) {
        for (const fn of module.functions.values()) fn.summary = summarize(fn, modules, state);
        module.top.summary = summarize(module.top, modules, state);
      }
      const current = [...modules.values()].map((module) =>
        `${module.path}::top=${summaryKey(module.top.summary)}|${[...module.functions].map(([name, fn]) => `${name}=${summaryKey(fn.summary)}`).join(',')}`).join('\n');
      if (current === previous) { state.converged = true; break; }
      previous = current;
      if (state.work > MAX_WORK) break;
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
    return {
      status: state.limited || !state.converged ? 'LIMIT' : 'OK',
      examinedFiles: modules.size,
      unresolvedImports: state.unresolvedImports,
      callEdges: state.callEdges,
      rounds: state.rounds,
      converged: state.converged,
      candidates,
    };
  } catch {
    return { status: 'ERROR', examinedFiles: 0, unresolvedImports: 0, callEdges: 0, rounds: 0, converged: false, candidates: [] };
  }
}
