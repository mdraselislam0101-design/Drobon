/** Mechanical cross-check of this exact trusted synthetic corpus, not an independent review.
 * Uses fake sink callbacks, JSON.parse and a loopback HTTP client; no real shell,
 * database, credential service, browser, or scanner is invoked. Never feed this
 * VM customer/untrusted code: Node's vm is not a security boundary.
 */
import { request } from 'node:http';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import { cases, fixtureManifestDigest } from './fixtures.mjs';
import { createLabServer } from './target.mjs';
import { classifyShellFlow } from './shell-oracle.mjs';

// Review any changed source before updating this pin: the VM executes only
// the exact locally authored fixtures identified by this digest.
const REVIEWED_FIXTURE_DIGEST = '26c75d9c3376c560ab1ec7c349dc99a083b8f8a5f00cfaa7ffe91eb485923220';
const MARKER = 'DROBON_BENCH_MARKER';
const HTML = '<b>DROBON_BENCH_MARKER</b>';

function runSyntheticSource(item, invocation) {
  const calls = [];
  const sandbox = {
    exec: (command) => { calls.push({ type: 'shell', command }); },
    execFile: (program, args, options) => { calls.push({ type: 'execFile', program, args, options }); },
    db: { query: (...args) => { calls.push({ type: 'query', args }); } },
    req: { query: { name: MARKER, id: MARKER } },
    element: { innerHTML: '' },
    process: { env: {} },
  };
  const source = item.content.replace(/^import \{ (?:exec|execFile) \} from "node:child_process";\n/, '')
    .replace(/^export /gm, '');
  const context = vm.createContext(sandbox, { codeGeneration: { strings: false, wasm: false } });
  new vm.Script(`${source}\n${invocation}`, { filename: 'synthetic-fixture.js' }).runInContext(context, { timeout: 250 });
  return { calls, sandbox };
}

// Exposed for adversarial tests; this remains fixture-only oracle logic.
export function isFrozenShellFlow(calls, marker = MARKER) {
  return classifyShellFlow(calls, marker);
}

function inspectSource(item) {
  switch (item.id) {
    case 'SAST-01': case 'SAST-02': case 'SAST-03': case 'SAST-04': case 'SAST-08': {
      const { calls } = runSyntheticSource(item, 'run(req);');
      // This narrow oracle concerns input reaching a shell command, not all
      // possible executable/path or argument-injection risks.
      return isFrozenShellFlow(calls);
    }
    case 'SAST-05': case 'SAST-06': {
      const { calls } = runSyntheticSource(item, 'find(db, req);');
      return calls.some((call) => call.type === 'query' && typeof call.args[0] === 'string' && call.args[0].includes(MARKER));
    }
    case 'SAST-07': {
      const { sandbox } = runSyntheticSource(item, `req.query.name = ${JSON.stringify(HTML)}; show(element, req);`);
      return sandbox.element.innerHTML.includes(HTML);
    }
    case 'SECRET-01': case 'SECRET-02': case 'SECRET-04': {
      const { sandbox } = runSyntheticSource(item, 'globalThis.__fixtureValue = credential;');
      return typeof sandbox.__fixtureValue === 'string' && /^(?:AKIA)[0-9A-Z]{16}$/.test(sandbox.__fixtureValue);
    }
    case 'SECRET-03': {
      const { sandbox } = runSyntheticSource(item, 'globalThis.__fixtureValue = api_key;');
      return typeof sandbox.__fixtureValue === 'string' && !sandbox.__fixtureValue.includes('example');
    }
    default: throw new Error('Unexpected synthetic source case');
  }
}

function inspectManifest(item) {
  try {
    const doc = JSON.parse(item.content);
    return ['dependencies', 'devDependencies'].some((field) =>
      Object.values(doc[field] ?? {}).some((version) => version === '*'));
  } catch { return null; }
}

function getLocal(port, path) {
  return new Promise((resolvePromise, reject) => {
    const req = request({ hostname: '127.0.0.1', port, path, method: 'GET', agent: false, timeout: 2000 }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => { chunks.push(chunk); });
      res.on('end', () => resolvePromise({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }));
      res.on('error', reject);
    });
    req.on('timeout', () => req.destroy(new Error('Local fixture request timed out')));
    req.on('error', reject);
    req.end();
  });
}

export async function verifyOracle() {
  if (fixtureManifestDigest() !== REVIEWED_FIXTURE_DIGEST) throw new Error('Fixture changed; review the corpus and update the oracle pin before executing it.');
  const server = createLabServer();
  await new Promise((resolvePromise, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolvePromise); });
  try {
    const address = server.address();
    if (address === null || typeof address === 'string') throw new Error('Local fixture server unavailable');
    const observations = [];
    for (const item of cases) {
      let actual;
      if (item.family === 'SAST' || item.family === 'SECRETS') actual = inspectSource(item);
      else if (item.family === 'SCA') actual = inspectManifest(item);
      else {
        const path = item.rule === null ? `${item.route}?input=${encodeURIComponent(HTML)}` : item.route;
        const response = await getLocal(address.port, path);
        if (response.status !== 200) throw new Error('Unexpected local fixture status');
        actual = item.rule === null ? response.body.includes(HTML) : response.headers['x-content-type-options'] !== 'nosniff';
      }
      observations.push({ id: item.id, expected: item.expected, observed: actual, matches: actual === item.expected });
    }
    return { fixtureManifestSha256: fixtureManifestDigest(), independentHumanReview: false,
      description: 'Mechanical behavior cross-check authored alongside the fixtures; not independent vulnerability adjudication.', observations };
  } finally {
    await new Promise((resolvePromise, reject) => server.close((error) => error ? reject(error) : resolvePromise()));
  }
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const result = await verifyOracle();
  console.log(JSON.stringify(result, null, 2));
  if (result.observations.some((item) => !item.matches)) process.exitCode = 1;
}
