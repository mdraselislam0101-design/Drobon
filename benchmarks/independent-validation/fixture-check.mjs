#!/usr/bin/env node
/** Scanner-free cross-check of ONLY the pinned, locally authored corpus.
 * This is NOT an independent human review, a scanner, a general JavaScript
 * interpreter, exploit proof, or a sandbox. Acorn parses data; no fixture code
 * executes. Python standard libraries parse JSON/XML/Python source as data.
 * The only network traffic is GET to an ephemeral loopback synthetic lab.
 * Neither the scanner, its results nor the existing mechanical oracle is read.
 */
import { parse } from 'acorn';
import { request } from 'node:http';
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { cases, manifestDigest } from '../accuracy-v2/fixtures.mjs';
import { createLabServer } from '../local/target.mjs';

const PIN = '8ae13962b8889b7f92018216868c2b1483556ae08c1dfc12d5e730890d6911e6';
const MARKER = 'DROBON_REVIEW_MARKER';
const HTML_MARKER = `<b>${MARKER}</b>`;
const ids = (prefix, numbers) => numbers.map((n) => `${prefix}-${String(n).padStart(2, '0')}`);
const modes = new Map([
  ...ids('SAST', [1, 2, 3, 4, 8]).map((id) => [id, 'shell']),
  ...ids('SAST', [5, 6]).map((id) => [id, 'sql']),
  ['SAST-07', 'html'],
  ...ids('AX-SAST', [1, 2, 3, 4, 5, 6, 7, 12, 13]).map((id) => [id, 'shell']),
  ...ids('AX-SAST', [8, 9]).map((id) => [id, 'sql']),
  ...ids('AX-SAST', [10, 11]).map((id) => [id, 'html']),
  ...ids('SECRET', [1, 2]).map((id) => [id, 'key']),
  ['SECRET-03', 'placeholder'], ['SECRET-04', 'env-lookup'],
  ...ids('AX-SEC', [1, 2, 3, 4, 5, 6, 8, 10, 11]).map((id) => [id, 'key']),
  ['AX-SEC-07', 'placeholder'], ['AX-SEC-09', 'python-key'],
  ...ids('SCA', [1, 2, 3, 4]).map((id) => [id, 'json-both']),
  ...ids('AX-SCA', [1, 2]).map((id) => [id, 'json-dev']),
  ...ids('AX-SCA', [3, 4, 5]).map((id) => [id, 'json-runtime']),
  ['AX-SCA-06', 'requirement'],
  ...ids('AX-SCA', [7, 8, 9, 10, 11]).map((id) => [id, 'xml-http']),
  ...ids('DAST', [1, 2, 3]).map((id) => [id, 'header']),
  ...ids('DAST', [4, 5]).map((id) => [id, 'reflection']),
  ...ids('AX-DAST', [1, 2, 3]).map((id) => [id, 'invalid-only']),
  ...ids('AX-DAST', [4, 5, 6]).map((id) => [id, 'header']),
]);

function isMarked(value) { return typeof value === 'string' && value.includes(MARKER); }

/** Narrow fake-call analysis: marker in executable, shell command or enabled
 * shell argv is a positive. Positional data may later be interpreted by the
 * script (e.g. eval "$1"), so it is unknown, not proof of a safe negative. */
export function shellMarkerReached(calls) {
  let uncertain = false;
  for (const call of calls) {
    if (call.kind === 'exec') {
      if (typeof call.command !== 'string') uncertain = true;
      else if (isMarked(call.command)) return true;
      continue;
    }
    if (call.kind !== 'execFile') continue;
    if (isMarked(call.program)) return true;
    if (typeof call.program !== 'string' || !Array.isArray(call.args)) { uncertain = true; continue; }
    if (call.options?.shell === true && call.args.some(isMarked)) return true;
    const program = call.program.toLowerCase();
    const flag = program === 'cmd' || program === 'cmd.exe' ? '/c' : '-c';
    if (!['sh', 'bash', 'cmd', 'cmd.exe'].includes(program)) continue;
    const flagIndex = call.args.findIndex((arg) => typeof arg === 'string' && arg.toLowerCase() === flag);
    if (flagIndex >= 0 && isMarked(call.args[flagIndex + 1])) return true;
    if (call.args.some(isMarked)) uncertain = true;
  }
  return uncertain ? null : false;
}

function propertyName(node) {
  if (node?.type === 'Identifier') return node.name;
  if (node?.type === 'Literal' && typeof node.value === 'string') return node.value;
  return undefined;
}

function scalar(node, env) {
  if (!node) return undefined;
  switch (node.type) {
    case 'Literal': return node.value;
    case 'Identifier': return Object.hasOwn(env, node.name) ? env[node.name] : undefined;
    case 'MemberExpression': {
      const object = scalar(node.object, env);
      const name = node.computed ? scalar(node.property, env) : propertyName(node.property);
      return typeof object === 'object' && object !== null && typeof name === 'string' && Object.hasOwn(object, name)
        ? object[name] : undefined;
    }
    case 'BinaryExpression': {
      const left = scalar(node.left, env); const right = scalar(node.right, env);
      return node.operator === '+' && typeof left === 'string' && typeof right === 'string' ? left + right : undefined;
    }
    case 'TemplateLiteral': {
      let result = node.quasis[0]?.value.cooked;
      if (typeof result !== 'string') return undefined;
      for (let i = 0; i < node.expressions.length; i += 1) {
        const part = scalar(node.expressions[i], env); const after = node.quasis[i + 1]?.value.cooked;
        if (typeof part !== 'string' || typeof after !== 'string') return undefined;
        result += part + after;
      }
      return result;
    }
    case 'ArrayExpression': return node.elements.map((item) => scalar(item, env));
    case 'ObjectExpression': {
      const result = Object.create(null);
      for (const property of node.properties) {
        if (property.type !== 'Property' || property.computed) return undefined;
        const name = propertyName(property.key);
        if (name === undefined) return undefined;
        result[name] = scalar(property.value, env);
      }
      return result;
    }
    default: return undefined;
  }
}

function declarations(body, env) {
  for (const statement of body) {
    const node = statement.type === 'ExportNamedDeclaration' ? statement.declaration : statement;
    if (node?.type !== 'VariableDeclaration') continue;
    for (const entry of node.declarations) {
      if (entry.id.type === 'Identifier') env[entry.id.name] = scalar(entry.init, env);
    }
  }
}

/** Parse and interpret only the tiny AST subset present in our pinned fixtures.
 * Unknown expressions stay unknown; this never loads or executes the source. */
export function checkJs(content, mode, remainder = '') {
  let ast;
  try { ast = parse(content, { ecmaVersion: 'latest', sourceType: 'module' }); }
  catch { return null; }
  const env = Object.assign(Object.create(null), {
    req: { query: { name: HTML_MARKER, id: MARKER } },
    process: { env: { REMAINDER: remainder } },
  });
  declarations(ast.body, env);
  if (mode === 'env-lookup') {
    const declaration = ast.body.flatMap((statement) => {
      const node = statement.type === 'ExportNamedDeclaration' ? statement.declaration : statement;
      return node?.type === 'VariableDeclaration' ? node.declarations : [];
    }).find((entry) => entry.id.type === 'Identifier' && entry.id.name === 'credential');
    const init = declaration?.init;
    return init?.type === 'MemberExpression' && !init.computed && propertyName(init.property) === 'SERVICE_KEY' &&
      init.object?.type === 'MemberExpression' && !init.object.computed && propertyName(init.object.property) === 'env' &&
      init.object.object?.type === 'Identifier' && init.object.object.name === 'process' ? false : null;
  }
  if (mode === 'key') return typeof env.credential === 'string' ? /^AKIA[0-9A-Z]{16}$/.test(env.credential) : null;
  if (mode === 'placeholder') return typeof env.api_key === 'string' ? !env.api_key.toLowerCase().includes('example') : null;

  const calls = []; const writes = [];
  for (const statement of ast.body) {
    const node = statement.type === 'ExportNamedDeclaration' ? statement.declaration : statement;
    if (node?.type !== 'FunctionDeclaration' || !node.body || node.body.type !== 'BlockStatement') continue;
    const local = Object.assign(Object.create(null), env);
    for (const action of node.body.body) {
      if (action.type === 'VariableDeclaration') { declarations([action], local); continue; }
      if (action.type === 'ReturnStatement' || action.type === 'EmptyStatement') continue;
      if (action.type !== 'ExpressionStatement') return null;
      const exp = action.expression;
      if (exp.type === 'AssignmentExpression' && exp.left.type === 'MemberExpression') {
        const target = exp.left.object.type === 'Identifier' ? exp.left.object.name : '';
        const value = scalar(exp.right, local);
        if (target !== 'element' || typeof value !== 'string') return null;
        writes.push({ target, property: propertyName(exp.left.property), value });
      }
      if (exp.type === 'AssignmentExpression') continue;
      if (exp.type !== 'CallExpression') return null;
      const args = exp.arguments.map((item) => scalar(item, local));
      const before = calls.length;
      if (exp.callee.type === 'Identifier' && exp.callee.name === 'exec') {
        if (typeof args[0] !== 'string') return null;
        calls.push({ kind: 'exec', command: args[0] });
      }
      if (exp.callee.type === 'Identifier' && exp.callee.name === 'execFile') {
        if (typeof args[0] !== 'string' || !Array.isArray(args[1]) || args[1].some((value) => typeof value !== 'string') ||
            (args.length >= 3 && (typeof args[2] !== 'object' || args[2] === null)) ||
            (args[2] && Object.hasOwn(args[2], 'shell') && typeof args[2].shell !== 'boolean')) return null;
        calls.push({ kind: 'execFile', program: args[0], args: args[1], options: args[2] });
      }
      if (exp.callee.type === 'MemberExpression' && exp.callee.object.type === 'Identifier' &&
          exp.callee.object.name === 'db' && propertyName(exp.callee.property) === 'query') {
        if (typeof args[0] !== 'string') return null;
        calls.push({ kind: 'query', args });
      }
      if (calls.length === before) return null;
    }
  }
  if (mode === 'shell') return shellMarkerReached(calls);
  if (mode === 'sql') return calls.some((call) => call.kind === 'query' && isMarked(call.args[0]));
  if (mode === 'html') return writes.some((write) => write.target === 'element' && write.property === 'innerHTML' && isMarked(write.value));
  throw new Error('Unexpected fixture mode');
}

const PYTHON_CHECK = `import ast,json,re,sys,xml.dom.minidom,xml.parsers.expat\nmode=sys.argv[1]\ns=sys.stdin.read()\nresult=None\ntry:\n if mode.startswith('json-'):\n  d=json.loads(s); fields={'json-both':['dependencies','devDependencies'],'json-dev':['devDependencies'],'json-runtime':['dependencies']}[mode]\n  result=any(v=='*' for field in fields for v in d.get(field,{}).values())\n elif mode=='xml-http':\n  if '<!' in s: raise ValueError('unsupported declaration')\n  d=xml.dom.minidom.parseString(s); nodes=d.getElementsByTagName('add'); result=bool(nodes and nodes[0].getAttribute('value').startswith('http:'))\n elif mode=='python-key':\n  def value(n):\n   if isinstance(n,ast.Constant) and isinstance(n.value,str): return n.value\n   if isinstance(n,ast.BinOp) and isinstance(n.op,ast.Add): return value(n.left)+value(n.right)\n   raise ValueError('unsupported')\n  t=ast.parse(s); result=bool(re.fullmatch(r'AKIA[0-9A-Z]{16}',value(t.body[0].value)))\n elif mode=='requirement':\n  from pip._vendor.packaging.requirements import Requirement\n  r=Requirement(s.strip()); result=bool(r.name and not str(r.specifier) and not r.url)\nexcept (ValueError,SyntaxError,KeyError,TypeError,IndexError,xml.parsers.expat.ExpatError): result=None\nprint(json.dumps(result))`;

function pythonCheck(mode, input) {
  const result = spawnSync('python3', ['-c', PYTHON_CHECK, mode], { input, encoding: 'utf8', timeout: 5_000, maxBuffer: 1024 });
  if (result.status !== 0 || result.error) throw new Error(`Python ${mode} check unavailable`);
  return JSON.parse(result.stdout);
}

function requestLab(port, path) {
  return new Promise((done, fail) => {
    const req = request({ hostname: '127.0.0.1', port, path, method: 'GET', agent: false, timeout: 2_000 }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => done({ status: res.statusCode, header: res.headers['x-content-type-options'], body: Buffer.concat(chunks).toString('utf8') }));
      res.on('error', fail);
    });
    req.on('error', fail); req.on('timeout', () => req.destroy(new Error('Local lab timed out'))); req.end();
  });
}

/** Inputs are copied WITHOUT expected labels before any observation is made. */
export async function checkCorpus() {
  if (manifestDigest() !== PIN) throw new Error('Corpus digest changed; review before checking the pin.');
  const inputs = cases.map(({ id, family, content, path, route }) => ({ id, family, content, path, route }));
  if (inputs.length !== 62 || modes.size !== 62 || inputs.some((item) => !modes.has(item.id))) throw new Error('Case coverage mismatch');
  const server = createLabServer();
  await new Promise((done, fail) => { server.once('error', fail); server.listen(0, '127.0.0.1', done); });
  let independent;
  try {
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('Loopback lab unavailable');
    independent = [];
    for (const item of inputs) {
      const mode = modes.get(item.id); let observed; let method;
      if (['shell', 'sql', 'html', 'key', 'placeholder', 'env-lookup'].includes(mode)) {
        observed = checkJs(item.content, mode); method = 'ACORN_STATIC_SUBSET';
      } else if (['json-both', 'json-dev', 'json-runtime', 'xml-http', 'python-key', 'requirement'].includes(mode)) {
        observed = pythonCheck(mode, item.content); method = mode === 'xml-http' ? 'PYTHON_MINIDOM' : mode === 'requirement'
          ? 'PIP_PACKAGING_OFFLINE' : mode === 'python-key' ? 'PYTHON_AST' : 'PYTHON_JSON';
      } else {
        const route = mode === 'reflection' ? `${item.route}?input=${encodeURIComponent(HTML_MARKER)}` : item.route;
        const res = await requestLab(address.port, route);
        if (res.status !== 200) throw new Error(`Local lab response failed for ${item.id}`);
        observed = mode === 'reflection' ? res.body.includes(HTML_MARKER) : mode === 'invalid-only'
          ? typeof res.header === 'string' && res.header !== '' && res.header.toLowerCase() !== 'nosniff'
          : typeof res.header !== 'string' || res.header.toLowerCase() !== 'nosniff';
        method = 'LOOPBACK_HTTP';
      }
      independent.push({ id: item.id, family: item.family, method, observed,
        ...(item.id === 'AX-SEC-05' ? { controlledEmptyEnvironment: true,
          nonEmptyEnvironmentChangesResult: checkJs(item.content, mode, 'EXTRA') === false } : {}) });
    }
  } finally { await new Promise((done, fail) => server.close((error) => error ? fail(error) : done())); }
  const labels = new Map(cases.map((item) => [item.id, item.expected]));
  const rows = independent.map((item) => ({ ...item, authoredExpected: labels.get(item.id), agrees: item.observed === labels.get(item.id) }));
  return { schemaVersion: 'drobon.scanner-free-fixture-check/v1', fixtureManifestSha256: PIN,
    independentHumanReview: false, blindedHumanReview: false, scannerOutputUsed: false,
    note: 'Scanner-free mechanical cross-check created by the same agent; not independently adjudicated or exploit proof.', rows };
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const result = await checkCorpus();
  console.log(JSON.stringify(result, null, 2));
  if (result.rows.some((item) => !item.agrees)) process.exitCode = 1;
}
