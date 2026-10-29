/**
 * Read-only, bounded syntax-tree analysis for JavaScript, TypeScript, JSX and
 * TSX. The caller runs this module in an isolated worker; the source is only
 * passed to TypeScript's createSourceFile, never loaded, executed or resolved.
 *
 * This is a deliberately small intra-file heuristic, not a type checker,
 * complete taint engine, exploit proof or replacement for the older passes.
 * Findings are emitted only for flow classes with an existing reporter rule.
 */
import ts from 'typescript';

export const STRUCTURED_AST_MAX_BYTES = 131_072;
export const STRUCTURED_AST_MAX_NODES = 16_000;
export const STRUCTURED_AST_MAX_DEPTH = 80;
export const STRUCTURED_AST_MAX_WORK = 100_000;
const MAX_BINDINGS = 512;
const MAX_PER_RULE = 3;
const MAX_CANDIDATES = 200;
const KINDS = ['command', 'sql', 'html', 'code'];

const SCRIPT_KINDS = Object.freeze({
  javascript: ts.ScriptKind.JS,
  typescript: ts.ScriptKind.TS,
  jsx: ts.ScriptKind.JSX,
  tsx: ts.ScriptKind.TSX,
});

function chainMatches(chain, names) {
  return names.some((name) => chain === name || chain.endsWith(`.${name}`) ||
    chain.startsWith(`${name}.`) || chain.startsWith(`${name}[`));
}

/** Static member names only. Dynamic computed names are not guessed. */
function expressionChain(expression) {
  const parts = [];
  let node = expression;
  for (let depth = 0; node && depth < 32; depth += 1) {
    if (ts.isParenthesizedExpression(node) || ts.isAsExpression(node) ||
        ts.isTypeAssertionExpression(node) || ts.isNonNullExpression(node) ||
        ts.isSatisfiesExpression(node)) {
      node = node.expression;
    } else if (ts.isIdentifier(node)) {
      parts.unshift(node.text);
      return parts.join('.');
    } else if (ts.isPropertyAccessExpression(node)) {
      parts.unshift(node.name.text);
      node = node.expression;
    } else if (ts.isElementAccessExpression(node)) {
      const name = node.argumentExpression;
      if (!name || !(ts.isStringLiteral(name) || ts.isNumericLiteral(name))) return '';
      parts.unshift(name.text);
      node = node.expression;
    } else {
      return '';
    }
  }
  return '';
}

function isSource(profile, chain) {
  return chain !== '' && chainMatches(chain, profile.sources);
}

function sinkKind(profile, chain) {
  if (chain === '') return undefined;
  return KINDS.find((kind) => profile.sinks[kind].some((name) => chain === name || chain.endsWith(`.${name}`)));
}

function scope(parent) {
  return { parent, values: new Map() };
}

function lookup(bindingScope, name) {
  for (let current = bindingScope; current; current = current.parent) {
    if (current.values.has(name)) return current.values.get(name);
  }
  return undefined;
}

function declare(bindingScope, name, tainted, state) {
  if (!bindingScope.values.has(name)) {
    state.bindings += 1;
    if (state.bindings > MAX_BINDINGS) { state.limited = true; return; }
  }
  bindingScope.values.set(name, tainted);
}

function assign(bindingScope, name, tainted, state) {
  // We never prove that a later clean assignment sanitizes all branches.
  // Keeping earlier taint can over-report but avoids a false clean verdict.
  for (let current = bindingScope; current; current = current.parent) {
    if (current.values.has(name)) {
      current.values.set(name, current.values.get(name) === true || tainted);
      return;
    }
  }
  declare(bindingScope, name, tainted, state);
}

function spend(state) {
  state.work += 1;
  if (state.work > STRUCTURED_AST_MAX_WORK) state.limited = true;
  return !state.limited;
}

/** Conservative expression walk; literals, comments, types and nested functions are not code flows. */
function expressionTainted(expression, bindingScope, profile, state) {
  if (!expression) return false;
  const pending = [expression];
  while (pending.length && spend(state)) {
    const node = pending.pop();
    if (!node) continue;
    if (ts.isIdentifier(node)) {
      const binding = lookup(bindingScope, node.text);
      if (binding === true || (binding === undefined && isSource(profile, node.text))) return true;
      continue;
    }
    if (ts.isTypeNode(node) || ts.isFunctionLike(node) || ts.isClassLike(node) ||
        ts.isStringLiteralLike(node) || ts.isNumericLiteral(node) ||
        node.kind === ts.SyntaxKind.RegularExpressionLiteral) continue;
    const chain = expressionChain(node);
    if (isSource(profile, chain)) return true;
    if ((ts.isCallExpression(node) || ts.isNewExpression(node)) &&
        chainMatches(expressionChain(node.expression), profile.sourceCalls)) return true;
    // Property names are not variable references. Computed indices are.
    if (ts.isPropertyAccessExpression(node)) {
      pending.push(node.expression);
    } else if (ts.isElementAccessExpression(node)) {
      pending.push(node.expression);
      if (node.argumentExpression) pending.push(node.argumentExpression);
    } else if (ts.isPropertyAssignment(node)) {
      pending.push(node.initializer);
      if (ts.isComputedPropertyName(node.name)) pending.push(node.name.expression);
    } else if (ts.isShorthandPropertyAssignment(node)) {
      pending.push(node.name);
      if (node.objectAssignmentInitializer) pending.push(node.objectAssignmentInitializer);
    } else {
      ts.forEachChild(node, (child) => { pending.push(child); });
    }
  }
  return false;
}

/** Propagate into all identifiers of a bounded destructuring declaration. */
function bindPattern(name, inherited, base, bindingScope, profile, state) {
  const pending = [{ name, inherited, base }];
  while (pending.length && spend(state)) {
    const item = pending.pop();
    if (!item) continue;
    if (ts.isIdentifier(item.name)) {
      declare(bindingScope, item.name.text, item.inherited, state);
      continue;
    }
    if (!ts.isObjectBindingPattern(item.name) && !ts.isArrayBindingPattern(item.name)) continue;
    for (const element of item.name.elements) {
      if (!ts.isBindingElement(element)) continue;
      const property = element.propertyName ?? (ts.isIdentifier(element.name) ? element.name : undefined);
      const propertyName = property && (ts.isIdentifier(property) || ts.isStringLiteral(property) || ts.isNumericLiteral(property))
        ? property.text : '';
      const childChain = item.base && propertyName ? `${item.base}.${propertyName}` : '';
      const tainted = item.inherited || isSource(profile, childChain) ||
        expressionTainted(element.initializer, bindingScope, profile, state);
      pending.push({ name: element.name, inherited: tainted, base: childChain });
    }
  }
}

function queryLooksParameterized(node, profile) {
  const args = node.arguments;
  if (!args || args.length < 2) return false;
  const first = args[0];
  const second = args[1];
  return first !== undefined && ts.isStringLiteral(first) && second !== undefined &&
    (ts.isArrayLiteralExpression(second) || ts.isObjectLiteralExpression(second)) &&
    profile.parameterizedSql.some((marker) => first.text.includes(marker));
}

function jsxHtmlValue(attribute) {
  if (!ts.isIdentifier(attribute.name) || attribute.name.text !== 'dangerouslySetInnerHTML' || !attribute.initializer ||
      !ts.isJsxExpression(attribute.initializer) || !attribute.initializer.expression ||
      !ts.isObjectLiteralExpression(attribute.initializer.expression)) return undefined;
  for (const property of attribute.initializer.expression.properties) {
    if (ts.isPropertyAssignment(property) &&
        (ts.isIdentifier(property.name) || ts.isStringLiteral(property.name)) && property.name.text === '__html') {
      return property.initializer;
    }
  }
  return undefined;
}

/**
 * Returns only rule ids and locations. No raw diagnostics or source snippets
 * cross the worker boundary. Any parse/analysis limit is explicitly incomplete.
 */
export function analyzeStructuredAst({ family, content, profile, reporters }) {
  const scriptKind = SCRIPT_KINDS[family];
  if (scriptKind === undefined) return { status: 'UNSUPPORTED', candidates: [] };
  if (Buffer.byteLength(content, 'utf8') > STRUCTURED_AST_MAX_BYTES) return { status: 'LIMIT', candidates: [] };
  let source;
  try {
    // A fixed virtual filename prevents module resolution or filesystem access.
    source = ts.createSourceFile('input', content, ts.ScriptTarget.Latest, false, scriptKind);
  } catch {
    return { status: 'ERROR', candidates: [] };
  }
  const diagnostics = Reflect.get(source, 'parseDiagnostics');
  if (!Array.isArray(diagnostics) || diagnostics.length > 0) return { status: 'SYNTAX_ERROR', candidates: [] };
  if (!KINDS.some((kind) => reporters[kind] !== undefined)) return { status: 'OK', candidates: [] };

  const state = { work: 0, bindings: 0, limited: false };
  const candidates = [];
  const seen = new Set();
  const perRule = new Map();
  const add = (kind, node) => {
    const ruleId = reporters[kind];
    if (!ruleId) return;
    const position = source.getLineAndCharacterOfPosition(node.getStart(source));
    const key = `${ruleId}\n${position.line}`;
    if (seen.has(key)) return;
    if ((perRule.get(ruleId) ?? 0) >= MAX_PER_RULE || candidates.length >= MAX_CANDIDATES) {
      state.limited = true;
      return;
    }
    seen.add(key);
    perRule.set(ruleId, (perRule.get(ruleId) ?? 0) + 1);
    candidates.push({ ruleId, kind, lineIndex: position.line, column: position.character + 1 });
  };

  const pending = [{ node: source, bindingScope: scope(undefined), depth: 0 }];
  let nodes = 0;
  try {
    while (pending.length && spend(state)) {
      const frame = pending.pop();
      if (!frame) continue;
      const { node, depth } = frame;
      if (++nodes > STRUCTURED_AST_MAX_NODES || depth > STRUCTURED_AST_MAX_DEPTH) { state.limited = true; break; }
      if (ts.isTypeNode(node)) continue;
      let bindingScope = frame.bindingScope;
      if (ts.isFunctionLike(node)) {
        bindingScope = scope(bindingScope);
        for (const parameter of node.parameters ?? []) {
          bindPattern(parameter.name, expressionTainted(parameter.initializer, bindingScope, profile, state), '', bindingScope, profile, state);
        }
      } else if (ts.isBlock(node) || ts.isCatchClause(node)) {
        bindingScope = scope(bindingScope);
        if (ts.isCatchClause(node) && node.variableDeclaration) {
          bindPattern(node.variableDeclaration.name, false, '', bindingScope, profile, state);
        }
      }

      if (ts.isVariableDeclaration(node)) {
        const tainted = expressionTainted(node.initializer, bindingScope, profile, state);
        bindPattern(node.name, tainted, node.initializer ? expressionChain(node.initializer) : '', bindingScope, profile, state);
      } else if (ts.isBinaryExpression(node) &&
                 node.operatorToken.kind >= ts.SyntaxKind.FirstAssignment && node.operatorToken.kind <= ts.SyntaxKind.LastAssignment) {
        const tainted = expressionTainted(node.right, bindingScope, profile, state);
        const chain = expressionChain(node.left);
        if (tainted && sinkKind(profile, chain) === 'html') add('html', node.left);
        const root = chain.split('.')[0];
        if (root) assign(bindingScope, root, tainted, state);
      } else if (ts.isCallExpression(node) || ts.isNewExpression(node)) {
        const kind = sinkKind(profile, expressionChain(node.expression));
        if (kind && reporters[kind] && !(kind === 'sql' && queryLooksParameterized(node, profile)) &&
            (node.arguments ?? []).some((argument) => expressionTainted(argument, bindingScope, profile, state))) {
          add(kind, node.expression);
        }
      } else if (ts.isJsxAttribute(node)) {
        const html = jsxHtmlValue(node);
        if (html && expressionTainted(html, bindingScope, profile, state)) add('html', node.name);
      }
      if (state.limited) break;
      const children = [];
      ts.forEachChild(node, (child) => { children.push(child); });
      for (let index = children.length - 1; index >= 0; index -= 1) {
        pending.push({ node: children[index], bindingScope, depth: depth + 1 });
      }
    }
  } catch {
    return { status: 'ERROR', candidates: [] };
  }
  return { status: state.limited ? 'LIMIT' : 'OK', candidates };
}
