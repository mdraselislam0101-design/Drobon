/**
 * Bounded, read-only syntax-tree passes for Python, Java and PHP. These are
 * intentionally narrow intra-file heuristics, not language runtimes, type
 * checkers, framework emulators or complete security analyses. No imports or
 * source code are executed or resolved. The worker owns the resource/time cap.
 */
import { parser as pythonParser } from '@lezer/python';
import { parser as javaParser } from '@lezer/java';
import PhpParser from 'php-parser';

const MAX_BYTES = 131_072;
const MAX_NODES = 16_000;
const MAX_DEPTH = 80;
const MAX_WORK = 100_000;
const MAX_BINDINGS = 512;
const MAX_PER_RULE = 3;
const MAX_CANDIDATES = 200;
const FLOW_KINDS = ['command', 'sql', 'html', 'code'];

function matches(chain, names) {
  return chain !== '' && names.some((name) => chain === name || chain.endsWith(`.${name}`) ||
    chain.startsWith(`${name}.`) || chain.startsWith(`${name}[`));
}

function sinkKind(profile, chain) {
  // A sink name must be the called operation, not merely a prefix of it.
  return FLOW_KINDS.find((kind) => profile.sinks[kind].some((name) => chain === name || chain.endsWith(`.${name}`)));
}

function newScope(parent) { return { parent, values: new Map() }; }
function lookup(scope, name) {
  for (let current = scope; current; current = current.parent) {
    if (current.values.has(name)) return current.values.get(name);
  }
  return undefined;
}
function assign(scope, name, tainted, state, declared = false) {
  if (!name) return;
  let target = scope;
  if (!declared) {
    for (let current = scope; current; current = current.parent) {
      if (current.values.has(name)) { target = current; break; }
    }
  }
  if (!target.values.has(name)) {
    state.bindings += 1;
    if (state.bindings > MAX_BINDINGS) { state.limited = true; return; }
  }
  // Conservative across branches: do not treat later assignments as proof of
  // sanitization. Local declarations can still shadow an outer name.
  target.values.set(name, target.values.get(name) === true || tainted);
}
function spend(state) {
  state.work += 1;
  if (state.work > MAX_WORK) state.limited = true;
  return !state.limited;
}
function lineStarts(content) {
  const out = [0];
  for (let i = 0; i < content.length; i += 1) if (content[i] === '\n') out.push(i + 1);
  return out;
}
function position(starts, offset) {
  let lo = 0;
  let hi = starts.length;
  while (lo + 1 < hi) {
    const mid = (lo + hi) >>> 1;
    if (starts[mid] <= offset) lo = mid; else hi = mid;
  }
  return { lineIndex: lo, column: offset - starts[lo] + 1 };
}
function analysisState(content, reporters) {
  const state = { work: 0, bindings: 0, limited: false, candidates: [], seen: new Set(), perRule: new Map() };
  const starts = lineStarts(content);
  state.add = (kind, offset) => {
    const ruleId = reporters[kind];
    if (!ruleId) return;
    const where = position(starts, offset);
    const key = `${ruleId}\n${where.lineIndex}`;
    if (state.seen.has(key)) return;
    if ((state.perRule.get(ruleId) ?? 0) >= MAX_PER_RULE || state.candidates.length >= MAX_CANDIDATES) {
      state.limited = true;
      return;
    }
    state.seen.add(key);
    state.perRule.set(ruleId, (state.perRule.get(ruleId) ?? 0) + 1);
    state.candidates.push({ ruleId, kind, ...where });
  };
  return state;
}

function children(node) {
  const out = [];
  for (let child = node.firstChild; child; child = child.nextSibling) out.push(child);
  return out;
}
function text(content, node) { return content.slice(node.from, node.to); }

/** Resolve only syntactically static identifiers/properties; never evaluate. */
function lezerChain(node, content, depth = 0) {
  if (!node || depth > 32) return '';
  if (['VariableName', 'Identifier', 'PropertyName', 'Definition'].includes(node.name)) return text(content, node);
  if (node.name === 'MethodName') {
    const child = node.firstChild;
    return child ? lezerChain(child, content, depth + 1) : text(content, node);
  }
  if (node.name === 'MemberExpression' || node.name === 'FieldAccess') {
    const parts = children(node).filter((child) => child.name !== '.');
    if (parts.length !== 2) return '';
    const base = lezerChain(parts[0], content, depth + 1);
    const property = lezerChain(parts[1], content, depth + 1);
    return base && property ? `${base}.${property}` : '';
  }
  if (node.name === 'CallExpression') return lezerChain(node.firstChild, content, depth + 1);
  if (node.name === 'MethodInvocation') {
    const parts = children(node).filter((child) => child.name !== '.' && child.name !== 'ArgumentList');
    const chains = parts.map((child) => lezerChain(child, content, depth + 1)).filter(Boolean);
    return chains.join('.');
  }
  if (['SubscriptExpression', 'IndexExpression'].includes(node.name)) {
    const base = lezerChain(node.firstChild, content, depth + 1);
    return base ? `${base}[]` : '';
  }
  if (node.name === 'ParenthesizedExpression') {
    const inner = children(node).find((child) => child.name !== '(' && child.name !== ')');
    return lezerChain(inner, content, depth + 1);
  }
  return '';
}

const LEZER_LITERAL = new Set(['String', 'StringLiteral', 'CharacterLiteral', 'Number', 'NumberLiteral',
  'LineComment', 'BlockComment', 'Comment', 'TypeName', 'PropertyName', 'MethodName']);
const LEZER_FUNCTION = new Set(['FunctionDefinition', 'LambdaExpression', 'MethodDeclaration', 'ConstructorDeclaration', 'ClassDefinition', 'ClassDeclaration']);

function lezerTainted(nodes, scope, profile, state, content) {
  const pending = [...nodes];
  while (pending.length && spend(state)) {
    const node = pending.pop();
    if (!node || LEZER_LITERAL.has(node.name) || LEZER_FUNCTION.has(node.name)) continue;
    if (node.name === 'VariableName' || node.name === 'Identifier') {
      const name = text(content, node);
      const bound = lookup(scope, name);
      if (bound === true || (bound === undefined && matches(name, profile.sources))) return true;
      continue;
    }
    const chain = lezerChain(node, content);
    if (matches(chain, profile.sources)) return true;
    if ((node.name === 'CallExpression' || node.name === 'MethodInvocation') && matches(chain, profile.sourceCalls)) return true;
    if (node.name === 'MemberExpression' || node.name === 'FieldAccess') {
      if (node.firstChild) pending.push(node.firstChild);
    } else {
      for (const child of children(node)) pending.push(child);
    }
  }
  return false;
}

function isLezerSyntaxValid(tree) {
  const cursor = tree.cursor();
  let count = 0;
  do {
    if (cursor.type.isError) return 'SYNTAX_ERROR';
    if (++count > MAX_NODES) return 'LIMIT';
  } while (cursor.next());
  return 'OK';
}

function analyzeLezer({ family, content, profile, reporters }) {
  let tree;
  try { tree = (family === 'python' ? pythonParser : javaParser).parse(content); }
  catch { return { status: 'ERROR', candidates: [] }; }
  const valid = isLezerSyntaxValid(tree);
  if (valid !== 'OK') return { status: valid, candidates: [] };
  if (!FLOW_KINDS.some((kind) => reporters[kind] !== undefined)) return { status: 'OK', candidates: [] };
  const state = analysisState(content, reporters);
  const pending = [{ node: tree.topNode, scope: newScope(undefined), depth: 0 }];
  try {
    while (pending.length && spend(state)) {
      const frame = pending.pop();
      if (!frame) continue;
      const { node, depth } = frame;
      if (depth > MAX_DEPTH) { state.limited = true; break; }
      if (LEZER_LITERAL.has(node.name)) continue;
      let scope = frame.scope;
      if (LEZER_FUNCTION.has(node.name) || (family === 'java' && node.name === 'Block')) scope = newScope(scope);
      const parts = children(node);
      if (family === 'python' && node.name === 'AssignStatement') {
        const operator = parts.findIndex((child) => child.name === 'AssignOp');
        const left = parts[0];
        if (operator > 0 && left?.name === 'VariableName') {
          assign(scope, text(content, left), lezerTainted(parts.slice(operator + 1), scope, profile, state, content), state);
        }
      } else if (family === 'java' && node.name === 'VariableDeclarator') {
        const left = parts.find((child) => child.name === 'Definition');
        const operator = parts.findIndex((child) => child.name === 'AssignOp');
        if (left) assign(scope, text(content, left), operator >= 0 && lezerTainted(parts.slice(operator + 1), scope, profile, state, content), state, true);
      } else if (family === 'java' && node.name === 'AssignmentExpression') {
        const operator = parts.findIndex((child) => child.name === 'AssignOp');
        const left = parts[0];
        if (operator > 0 && left?.name === 'Identifier') assign(scope, text(content, left), lezerTainted(parts.slice(operator + 1), scope, profile, state, content), state);
      }
      if ((family === 'python' && node.name === 'CallExpression') || (family === 'java' && node.name === 'MethodInvocation')) {
        const kind = sinkKind(profile, lezerChain(node, content));
        const args = parts.find((child) => child.name === 'ArgList' || child.name === 'ArgumentList');
        const values = args ? children(args).filter((child) => !['(', ')', ','].includes(child.name)) : [];
        const first = values[0];
        const second = values[1];
        const looksBound = family === 'python' && kind === 'sql' && first?.name === 'String' && second &&
          ['ArrayExpression', 'TupleExpression', 'DictionaryExpression'].includes(second.name) &&
          profile.parameterizedSql.some((marker) => text(content, first).includes(marker));
        if (kind && reporters[kind] && args && !looksBound && lezerTainted(values, scope, profile, state, content)) state.add(kind, node.from);
      }
      if (state.limited) break;
      for (let i = parts.length - 1; i >= 0; i -= 1) pending.push({ node: parts[i], scope, depth: depth + 1 });
    }
  } catch { return { status: 'ERROR', candidates: [] }; }
  return { status: state.limited ? 'LIMIT' : 'OK', candidates: state.candidates };
}

/** All traversal is over parser-created objects, never user-selected keys. */
function phpChildren(node) {
  const out = [];
  for (const [key, value] of Object.entries(node)) {
    if (key === 'loc' || key === 'leadingComments' || key === 'trailingComments' || key === 'errors') continue;
    if (Array.isArray(value)) {
      for (const item of value) if (item && typeof item === 'object' && typeof item.kind === 'string') out.push(item);
    } else if (value && typeof value === 'object' && typeof value.kind === 'string') out.push(value);
  }
  return out;
}
function phpChain(node, depth = 0) {
  if (!node || depth > 32) return '';
  if (node.kind === 'variable') return typeof node.name === 'string' ? `$${node.name}` : '';
  if (node.kind === 'name' || node.kind === 'identifier') return typeof node.name === 'string' ? node.name : '';
  if (node.kind === 'propertylookup' || node.kind === 'staticlookup') {
    const base = phpChain(node.what, depth + 1);
    const property = phpChain(node.offset, depth + 1);
    return base && property ? `${base}.${property}` : '';
  }
  if (node.kind === 'offsetlookup') {
    const base = phpChain(node.what, depth + 1);
    return base ? `${base}[]` : '';
  }
  if (node.kind === 'call') return phpChain(node.what, depth + 1);
  return '';
}
const PHP_LITERAL = new Set(['string', 'number', 'boolean', 'nullkeyword', 'commentline', 'commentblock', 'identifier', 'name']);
const PHP_FUNCTION = new Set(['function', 'method', 'closure', 'arrowfunc', 'class', 'trait', 'interface']);
function phpTainted(nodes, scope, profile, state) {
  const pending = [...nodes];
  while (pending.length && spend(state)) {
    const node = pending.pop();
    if (!node || PHP_LITERAL.has(node.kind) || PHP_FUNCTION.has(node.kind)) continue;
    if (node.kind === 'variable') {
      const name = phpChain(node);
      const bound = lookup(scope, name);
      if (bound === true || (bound === undefined && matches(name, profile.sources))) return true;
      continue;
    }
    const chain = phpChain(node);
    if (matches(chain, profile.sources)) return true;
    if (node.kind === 'call' && matches(chain, profile.sourceCalls)) return true;
    if (node.kind === 'propertylookup' || node.kind === 'staticlookup') {
      if (node.what) pending.push(node.what);
    } else {
      pending.push(...phpChildren(node));
    }
  }
  return false;
}

function analyzePhp({ content, profile, reporters }) {
  let tree;
  try {
    const parser = new PhpParser.Engine({ parser: { suppressErrors: false }, ast: { withPositions: true } });
    tree = parser.parseCode(content, 'input.php');
  } catch { return { status: 'SYNTAX_ERROR', candidates: [] }; }
  if (Array.isArray(tree.errors) && tree.errors.length) return { status: 'SYNTAX_ERROR', candidates: [] };
  if (!FLOW_KINDS.some((kind) => reporters[kind] !== undefined)) return { status: 'OK', candidates: [] };
  const state = analysisState(content, reporters);
  const pending = [{ node: tree, scope: newScope(undefined), depth: 0 }];
  let nodes = 0;
  try {
    while (pending.length && spend(state)) {
      const frame = pending.pop();
      if (!frame) continue;
      const { node, depth } = frame;
      if (++nodes > MAX_NODES || depth > MAX_DEPTH) { state.limited = true; break; }
      if (PHP_LITERAL.has(node.kind)) continue;
      let scope = frame.scope;
      if (PHP_FUNCTION.has(node.kind)) scope = newScope(scope);
      if (node.kind === 'assign' && node.left?.kind === 'variable') {
        assign(scope, phpChain(node.left), phpTainted([node.right], scope, profile, state), state);
      }
      if (node.kind === 'call') {
        const kind = sinkKind(profile, phpChain(node.what));
        if (kind && reporters[kind] && phpTainted(node.arguments ?? [], scope, profile, state)) {
          state.add(kind, node.what?.loc?.start?.offset ?? node.loc?.start?.offset ?? 0);
        }
      } else if ((node.kind === 'echo' || node.kind === 'print') && reporters.html) {
        const values = node.expressions ?? (node.expression ? [node.expression] : []);
        if (phpTainted(values, scope, profile, state)) state.add('html', node.loc?.start?.offset ?? 0);
      }
      if (state.limited) break;
      const parts = phpChildren(node);
      for (let i = parts.length - 1; i >= 0; i -= 1) pending.push({ node: parts[i], scope, depth: depth + 1 });
    }
  } catch { return { status: 'ERROR', candidates: [] }; }
  return { status: state.limited ? 'LIMIT' : 'OK', candidates: state.candidates };
}

export function analyzePolyglotAst(input) {
  if (Buffer.byteLength(input.content, 'utf8') > MAX_BYTES) return { status: 'LIMIT', candidates: [] };
  if (input.family === 'python' || input.family === 'java') return analyzeLezer(input);
  if (input.family === 'php') return analyzePhp(input);
  return { status: 'UNSUPPORTED', candidates: [] };
}
