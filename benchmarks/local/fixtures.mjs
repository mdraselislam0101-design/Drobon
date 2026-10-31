/** Small synthetic cases for local-only, provisional scanner measurement.
 * These are NOT Dataset rules, real credentials or an independently reviewed
 * benchmark. Cases are deliberately separated so one finding cannot satisfy a
 * different case merely because it was emitted somewhere in a large scan.
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

const syntheticKey = ['AK', 'IA', 'X9V8U7T6S5R4Q3P2'].join('');
const digest = (value) => createHash('sha256').update(value).digest('hex');

export const cases = Object.freeze([
  { id: 'SAST-01', family: 'SAST', expected: true, rule: 'DG-SAST-001', cwe: 'CWE-78', path: 'src/case.js',
    rationale: 'Request input is concatenated into a shell command.',
    content: 'import { exec } from "node:child_process";\nexport function run(req) { exec("echo " + req.query.name); }\n' },
  { id: 'SAST-02', family: 'SAST', expected: false, rule: 'DG-SAST-001', cwe: 'CWE-78', path: 'src/case.js',
    rationale: 'The shell command is a fixed concatenation of two constants.',
    content: 'import { exec } from "node:child_process";\nexport function run() { exec("echo " + "hello"); }\n' },
  { id: 'SAST-03', family: 'SAST', expected: true, rule: 'DG-SAST-001', cwe: 'CWE-78', path: 'src/case.js',
    rationale: 'Request input is assigned on one line and then passed to a shell.',
    content: 'import { exec } from "node:child_process";\nexport function run(req) {\n  const command = "echo " + req.query.name;\n  exec(command);\n}\n' },
  { id: 'SAST-04', family: 'SAST', expected: false, rule: 'DG-SAST-001', cwe: 'CWE-78', path: 'src/case.js',
    rationale: 'An argument-vector API is used without a shell.',
    content: 'import { execFile } from "node:child_process";\nexport function run(req) { execFile("echo", [req.query.name]); }\n' },
  { id: 'SAST-05', family: 'SAST', expected: true, rule: 'DG-SAST-003', cwe: 'CWE-89', path: 'src/case.js',
    rationale: 'Request input is concatenated into a SQL query.',
    content: 'export function find(db, req) { db.query("SELECT * FROM users WHERE id = " + req.query.id); }\n' },
  { id: 'SAST-06', family: 'SAST', expected: false, rule: 'DG-SAST-003', cwe: 'CWE-89', path: 'src/case.js',
    rationale: 'The SQL value is supplied through a parameter placeholder.',
    content: 'export function find(db, req) { db.query("SELECT * FROM users WHERE id = ?", [req.query.id]); }\n' },
  { id: 'SAST-07', family: 'SAST', expected: true, rule: 'DG-SAST-004', cwe: 'CWE-79', path: 'src/case.js',
    rationale: 'Request input is assigned to an HTML sink.',
    content: 'export function show(element, req) { element.innerHTML = "<p>" + req.query.name; }\n' },
  { id: 'SAST-08', family: 'SAST', expected: false, rule: 'DG-SAST-001', cwe: 'CWE-78', path: 'src/case.js',
    rationale: 'The apparent shell sink is only inside a comment.',
    content: '// exec("echo " + req.query.name);\nexport function run() { return "ok"; }\n' },

  { id: 'SECRET-01', family: 'SECRETS', expected: true, rule: 'DG-SEC-002', path: 'src/case.js',
    rationale: 'An invented service-key-shaped value is present as one literal.',
    content: `export const credential = "${syntheticKey}";\n` },
  { id: 'SECRET-02', family: 'SECRETS', expected: true, rule: 'DG-SEC-002', path: 'src/case.js',
    rationale: 'The same invented key shape is reconstructed from separate literals at runtime.',
    content: `export const credential = "${syntheticKey.slice(0, 4)}" + "${syntheticKey.slice(4)}";\n` },
  { id: 'SECRET-03', family: 'SECRETS', expected: false, rule: 'DG-SEC-005', path: 'src/case.js',
    rationale: 'The literal is explicitly an example placeholder.',
    content: 'export const api_key = "example-placeholder-value-1234";\n' },
  { id: 'SECRET-04', family: 'SECRETS', expected: false, rule: 'DG-SEC-002', path: 'src/case.js',
    rationale: 'Only an environment-variable lookup is present, with no literal value.',
    content: 'export const credential = process.env.SERVICE_KEY;\n' },

  { id: 'SCA-01', family: 'SCA', expected: true, rule: 'DPK-SCA-9001', path: 'package.json',
    rationale: 'A runtime dependency uses an unrestricted wildcard declaration.',
    content: '{"name":"synthetic-project","dependencies":{"fixture-package":"*"}}\n' },
  { id: 'SCA-02', family: 'SCA', expected: false, rule: 'DPK-SCA-9001', path: 'package.json',
    rationale: 'The runtime dependency has a fixed version; no wildcard is declared.',
    content: '{"name":"synthetic-project","dependencies":{"fixture-package":"1.2.3"}}\n' },
  { id: 'SCA-03', family: 'SCA', expected: true, rule: 'DPK-SCA-9001', path: 'package.json',
    rationale: 'An unrestricted wildcard occurs in development dependencies, outside this fixture rule path.',
    content: '{"name":"synthetic-project","devDependencies":{"fixture-package":"*"}}\n' },
  { id: 'SCA-04', family: 'SCA', expected: null, rule: 'DPK-SCA-9001', path: 'package.json',
    rationale: 'Malformed JSON is not a valid ground-truth negative or a completed evaluation.',
    content: '{"dependencies":\n' },

  { id: 'DAST-01', family: 'DAST', expected: true, rule: 'DG-DAST-003', route: '/lab/header-missing',
    rationale: 'The response omits the nosniff header.' },
  { id: 'DAST-02', family: 'DAST', expected: true, rule: 'DG-DAST-003', route: '/lab/header-invalid',
    rationale: 'The response sends an unrelated value instead of nosniff.' },
  { id: 'DAST-03', family: 'DAST', expected: false, rule: 'DG-DAST-003', route: '/lab/header-safe',
    rationale: 'The response supplies nosniff.' },
  { id: 'DAST-04', family: 'DAST', expected: true, rule: null, route: '/lab/reflect-unsafe',
    rationale: 'The application reflects a marker into HTML without escaping; active query validation is required.' },
  { id: 'DAST-05', family: 'DAST', expected: false, rule: null, route: '/lab/reflect-safe',
    rationale: 'The application escapes the same marker before including it in HTML.' },
]);

export function fixtureManifest() {
  // The HTTP cases depend on the response implementation, not just route
  // names. Bind its complete source to the manifest so a changed lab cannot
  // silently be scored as the same corpus.
  const targetSha256 = digest(readFileSync(new URL('./target.mjs', import.meta.url), 'utf8'));
  return cases.map(({ id, family, expected, path, route, content }) => ({ id, family, expected,
    ...(path === undefined ? {} : { path }), ...(route === undefined ? {} : { route, targetSha256 }),
    ...(content === undefined ? {} : { inputSha256: digest(content) }) }));
}

export function fixtureManifestDigest() { return digest(JSON.stringify(fixtureManifest())); }
