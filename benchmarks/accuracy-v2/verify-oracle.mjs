#!/usr/bin/env node
/** Mechanical cross-check, not independent human adjudication. The digest pin
 * prevents executing any changed code until deliberately reviewed. Node vm is
 * NOT a security boundary: never run customer/downloaded/untrusted code here. */
import vm from 'node:vm';
import { spawnSync } from 'node:child_process';
import { request } from 'node:http';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { addedCases, cases, manifestDigest } from './fixtures.mjs';
import { createLabServer } from '../local/target.mjs';
import { verifyOracle as verifyFrozenOracle } from '../local/verify-oracle.mjs';
import { classifyShellFlow } from '../local/shell-oracle.mjs';

const REVIEWED_DIGEST = '8ae13962b8889b7f92018216868c2b1483556ae08c1dfc12d5e730890d6911e6';
const MARKER = 'DROBON_INPUT_MARKER';
const HTML = '<b>DROBON_INPUT_MARKER</b>';

// Exposed for adversarial tests; this remains fixture-only oracle logic.
export function isExpandedShellFlow(calls, marker = MARKER) {
  return classifyShellFlow(calls, marker);
}

function localJs(item) {
  const calls = [];
  const sandbox = { exec: (command) => calls.push({ kind: 'shell', command }),
    execFile: (program, args, options) => calls.push({ kind: 'execFile', program, args, options }),
    db: { query: (...args) => calls.push({ kind: 'sql', args }) },
    req: { query: { name: item.oracle === 'html' ? HTML : MARKER, id: MARKER } },
    element: { innerHTML: '', textContent: '' }, process: { env: { REMAINDER: '' } } };
  const source = item.content.replace(/^import \{ (?:exec|execFile) \} from "node:child_process";\n/, '').replace(/^export /gm, '');
  if (item.oracle === 'syntax') {
    try { new vm.Script(source); return 'NOT_MALFORMED'; } catch { return null; }
  }
  const invocation = item.oracle === 'shell' ? 'run(req);' : item.oracle === 'sql' ? 'find(db, req);' :
    item.oracle === 'html' ? 'show(element, req);' : item.oracle === 'placeholder'
      ? 'globalThis.__fixtureValue = api_key;' : 'globalThis.__fixtureValue = credential;';
  const context = vm.createContext(sandbox, { codeGeneration: { strings: false, wasm: false } });
  new vm.Script(`${source}\n${invocation}`, { filename: 'trusted-synthetic.js' }).runInContext(context, { timeout: 250 });
  if (item.oracle === 'shell') return isExpandedShellFlow(calls);
  if (item.oracle === 'sql') return calls.some((call) => call.kind === 'sql' && String(call.args[0]).includes(MARKER));
  if (item.oracle === 'html') return sandbox.element.innerHTML.includes(HTML);
  if (item.oracle === 'placeholder') return typeof sandbox.__fixtureValue === 'string' && !sandbox.__fixtureValue.includes('example');
  return typeof sandbox.__fixtureValue === 'string' && /^(?:AKIA)[0-9A-Z]{16}$/.test(sandbox.__fixtureValue);
}

function pythonOracle(kind, input) {
  // The snippets are constants authored in this repository. Python receives
  // the fixture as DATA, never executes it, and emits only true/false/null.
  const code = kind === 'xml' ? `import json,sys,xml.etree.ElementTree as E\ntry:\n r=E.fromstring(sys.stdin.read()); n=r.find('./packageSources/add'); v=n.get('value','') if n is not None else ''; print(json.dumps(v.startswith('http:')))\nexcept E.ParseError: print('null')` :
    `import ast,json,re,sys\ndef value(n):\n if isinstance(n,ast.Constant) and isinstance(n.value,str): return n.value\n if isinstance(n,ast.BinOp) and isinstance(n.op,ast.Add): return value(n.left)+value(n.right)\n raise ValueError()\ntry:\n t=ast.parse(sys.stdin.read()); v=value(t.body[0].value); print(json.dumps(bool(re.fullmatch(r'AKIA[0-9A-Z]{16}',v))))\nexcept (SyntaxError,ValueError,IndexError): print('null')`;
  const result = spawnSync('python3', ['-c', code], { input, encoding: 'utf8', timeout: 3_000, maxBuffer: 1024 });
  if (result.status !== 0) throw new Error('Independent standard-library oracle failed');
  return JSON.parse(result.stdout);
}
function getLocal(port, path) {
  return new Promise((resolvePromise, reject) => {
    const req = request({ hostname: '127.0.0.1', port, path, method: 'GET', agent: false, timeout: 2_000 }, (response) => {
      response.resume();
      response.on('end', () => resolvePromise({ status: response.statusCode, headers: response.headers }));
      response.on('error', reject);
    });
    req.on('error', reject); req.on('timeout', () => req.destroy(new Error('Loopback timeout'))); req.end();
  });
}
function documentOracle(item) {
  if (item.oracle === 'xml-http') return pythonOracle('xml', item.content);
  // A bare requirement name has no version bound; no installation occurs.
  if (item.oracle === 'unsupported-declaration') return /^[A-Za-z][A-Za-z0-9_.-]*$/.test(item.content.trim());
  try {
    const doc = JSON.parse(item.content);
    const field = item.oracle === 'dev-wildcard' ? 'devDependencies' : 'dependencies';
    return Object.values(doc[field] ?? {}).some((value) => value === '*');
  } catch { return null; }
}

export async function verifyExpandedOracle() {
  if (manifestDigest() !== REVIEWED_DIGEST) throw new Error('Corpus or test rules changed: review before updating the oracle pin.');
  const original = await verifyFrozenOracle();
  const server = createLabServer();
  await new Promise((done, fail) => { server.once('error', fail); server.listen(0, '127.0.0.1', done); });
  try {
    const address = server.address();
    if (address === null || typeof address === 'string') throw new Error('Loopback listener unavailable');
    const observations = [...original.observations];
    for (const item of addedCases) {
      let actual;
      if (item.family === 'SAST' || item.family === 'SECRETS') actual = item.oracle === 'python-secret'
        ? pythonOracle('python', item.content) : localJs(item);
      else if (item.family === 'SCA') actual = documentOracle(item);
      else {
        const response = await getLocal(address.port, item.route);
        if (response.status !== 200) throw new Error(`Unexpected loopback response for ${item.id}`);
        const value = response.headers['x-content-type-options'];
        actual = item.oracle === 'invalid-value' ? value !== undefined && value !== 'nosniff' : value !== 'nosniff';
      }
      observations.push({ id: item.id, expected: item.expected, observed: actual, matches: actual === item.expected });
    }
    if (observations.length !== cases.length) throw new Error('Oracle case accounting failed');
    return { schemaVersion: 'drobon.synthetic-oracle/v2', fixtureManifestSha256: manifestDigest(),
      independentHumanReview: false, independentMechanicalChecks: 'Node fake sinks and loopback HTTP; Python standard-library XML/Python AST; authored alongside fixtures',
      observations };
  } finally { await new Promise((done, fail) => server.close((error) => error ? fail(error) : done())); }
}
if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const result = await verifyExpandedOracle();
  console.log(JSON.stringify(result, null, 2));
  if (result.observations.some((item) => !item.matches)) process.exitCode = 1;
}
