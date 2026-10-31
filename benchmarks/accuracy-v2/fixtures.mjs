/** Expanded author-defined synthetic corpus. The original 21 cases remain
 * frozen in ../local; new cases are separate, not a replacement holdout.
 * No real credential, customer code, package install or Dataset data. */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { cases as frozen } from '../local/fixtures.mjs';

const part1 = ['AK', 'IA'].join('');
const part2 = 'X9V8U7T6S5R4Q3P2';
// Check both the whole invented value and its longer fragment in reports.
export const syntheticSecrets = [part1 + part2, part2];
const commandImport = 'import { exec } from "node:child_process";\n';
const fileImport = 'import { execFile } from "node:child_process";\n';
const sast = (id, expected, rule, cwe, content, oracle, extra = {}) =>
  ({ id, family: 'SAST', expected, rule, cwe, path: 'src/case.js', content, oracle, ...extra });
const secret = (id, expected, content, oracle = 'secret', extra = {}) =>
  ({ id, family: 'SECRETS', expected, rule: 'DG-SEC-002', path: 'src/case.js', content, oracle, ...extra });
const sca = (id, expected, rule, content, oracle, extra = {}) =>
  ({ id, family: 'SCA', expected, rule, path: 'package.json', content, oracle, ...extra });
const dast = (id, expected, rule, route, oracle = 'nosniff', extra = {}) =>
  ({ id, family: 'DAST', expected, rule, route, oracle, ...extra });

export const addedCases = Object.freeze([
  sast('AX-SAST-01', true, 'DG-SAST-001', 'CWE-78', `${commandImport}export function run(req) { exec(\`echo ${'${req.query.name}'}\`); }\n`, 'shell', { rationale: 'Request interpolation reaches exec.' }),
  sast('AX-SAST-02', true, 'DG-SAST-001', 'CWE-78', `${fileImport}export function run(req) { execFile(req.query.name, []); }\n`, 'shell', { rationale: 'The executable itself is request-controlled.' }),
  sast('AX-SAST-03', true, 'DG-SAST-001', 'CWE-78', `${fileImport}export function run(req) { execFile("echo", [req.query.name], { shell: true }); }\n`, 'shell', { rationale: 'Explicit shell option with user input.' }),
  sast('AX-SAST-04', true, 'DG-SAST-001', 'CWE-78', `${fileImport}export function run(req) { execFile("sh", ["-c", "echo " + req.query.name]); }\n`, 'shell', { rationale: 'A shell interpreter receives a constructed command.' }),
  sast('AX-SAST-05', false, 'DG-SAST-001', 'CWE-78', `${fileImport}export function run() { execFile("echo", ["hello"]); }\n`, 'shell', { rationale: 'Constant program and constant argument.' }),
  sast('AX-SAST-06', false, 'DG-SAST-001', 'CWE-78', `${commandImport}export function run() { exec("uptime"); }\n`, 'shell', { rationale: 'Constant shell text; no request input.' }),
  sast('AX-SAST-07', false, 'DG-SAST-001', 'CWE-78', `${commandImport}// exec("echo " + req.query.name);\nexport function run() { return "ok"; }\n`, 'shell', { rationale: 'Source-like text occurs only in a comment.' }),
  sast('AX-SAST-08', true, 'DG-SAST-003', 'CWE-89', 'export function find(db, req) { db.query(`SELECT id FROM t WHERE id=${req.query.id}`); }\n', 'sql', { rationale: 'SQL text contains interpolated input.' }),
  sast('AX-SAST-09', false, 'DG-SAST-003', 'CWE-89', 'export function find(db, req) {\n  db.query("SELECT id FROM t WHERE id=?", [req.query.id]);\n}\n', 'sql', { rationale: 'SQL input is passed as a separate parameter.' }),
  sast('AX-SAST-10', true, 'DG-SAST-004', 'CWE-79', 'export function show(element, req) { element.innerHTML = `<p>${req.query.name}</p>`; }\n', 'html', { rationale: 'Unescaped input reaches an HTML sink.' }),
  sast('AX-SAST-11', false, 'DG-SAST-004', 'CWE-79', 'export function show(element, req) { element.textContent = req.query.name; }\n', 'html', { rationale: 'Input is assigned to a text, not an HTML, sink.' }),
  sast('AX-SAST-12', true, 'DG-SAST-001', 'CWE-78', `${commandImport}export function run(req) { exec("echo " + req.query.name); }\n`, 'shell', { path: 'src/case.txt', unsupported: true, rationale: 'Command source in an unsupported text extension.' }),
  sast('AX-SAST-13', null, 'DG-SAST-001', 'CWE-78', 'export function run(req) { exec(\n', 'syntax', { rationale: 'Malformed JavaScript: no trustworthy shell-flow truth.' }),

  secret('AX-SEC-01', true, `export const credential = "${part1}${part2}";\n`, 'secret', { path: 'src/case.ts', rationale: 'Single synthetic key-shaped literal.' }),
  secret('AX-SEC-02', true, `export const credential = "${part1}" + "${part2}";\n`, 'secret', { requiresLiteralFold: true, rationale: 'Two unescaped literals reconstruct the synthetic shape.' }),
  secret('AX-SEC-03', true, `export const credential = ('${part1.slice(0, 2)}' + '${part1.slice(2)}') + '${part2}';\n`, 'secret', { requiresLiteralFold: true, rationale: 'Three literal pieces, including parentheses.' }),
  secret('AX-SEC-04', false, `// "${part1}" + "${part2}"\nexport const credential = "none";\n`, 'secret', { rationale: 'Literal fragments occur only in a comment.' }),
  secret('AX-SEC-05', true, `export const credential = "${part1}" + process.env.REMAINDER + "${part2}";\n`, 'secret', { unsupported: true, rationale: 'The controlled oracle uses an empty environment value; dynamic folding is unsupported.' }),
  secret('AX-SEC-06', true, `export const credential = "\\x41KIA" + "${part2}";\n`, 'secret', { unsupported: true, rationale: 'A JavaScript escape is required to reconstruct the synthetic shape.' }),
  secret('AX-SEC-07', false, 'export const api_key = "example-" + "placeholder-value-1234";\n', 'placeholder', { rule: 'DG-SEC-005', requiresLiteralFold: true, rationale: 'An explicitly example placeholder is not a credential.' }),
  secret('AX-SEC-08', true, `export const credential = "${part1}" + "" + "${part2}";\n`, 'secret', { requiresLiteralFold: true, rationale: 'Static fragments include an empty string.' }),
  secret('AX-SEC-09', true, `credential = "${part1}" + "${part2}"\n`, 'python-secret', { path: 'src/case.py', unsupported: true, rationale: 'Static folding is not implemented for Python.' }),
  secret('AX-SEC-10', null, `export const credential = "${part1}" + "${part2}\n`, 'syntax', { requiresLiteralFold: true, rationale: 'Malformed source has unknown runtime value and incomplete syntax analysis.' }),
  secret('AX-SEC-11', true, `export const credential = "${part1}${part2}";\n`, 'secret', { path: 'node_modules/case.js', unsupported: true, rationale: 'Ignored dependency directory; not assessed by source policy.' }),

  sca('AX-SCA-01', true, 'DPK-SCA-9002', '{"devDependencies":{"fixture":"*"}}\n', 'dev-wildcard', { rationale: 'Dev wildcard with a test-only dev-field rule.' }),
  sca('AX-SCA-02', false, 'DPK-SCA-9002', '{"devDependencies":{"fixture":"1.0.0"}}\n', 'dev-wildcard', { rationale: 'A fixed dev version does not match wildcard check.' }),
  sca('AX-SCA-03', true, 'DPK-SCA-9001', '{"dependencies":{"fixture":"*","other":"1.2.0"}}\n', 'runtime-wildcard', { rationale: 'A wildcard is present among runtime dependencies.' }),
  sca('AX-SCA-04', false, 'DPK-SCA-9001', '{"name":"fixture"}\n', 'runtime-wildcard', { rationale: 'No runtime wildcard field.' }),
  sca('AX-SCA-05', null, 'DPK-SCA-9001', '{"dependencies":\n', 'json-invalid', { rationale: 'Malformed JSON is unknown, not a negative.' }),
  sca('AX-SCA-06', true, 'DPK-SCA-9001', 'fixture\n', 'unsupported-declaration', { path: 'requirements.in', unsupported: true, rationale: 'An unrestricted bare requirement is outside this npm rule artifact.' }),
  sca('AX-SCA-07', true, 'DPK-SCA-9003', '<configuration><packageSources><add key="fixture" value="http&#58;//registry.invalid/v3"/></packageSources></configuration>\n', 'xml-http', { path: 'nuget.config', rationale: 'XML numeric reference decodes to a plain HTTP source.' }),
  sca('AX-SCA-08', false, 'DPK-SCA-9003', '<configuration><packageSources><add key="fixture" value="https://registry.invalid/v3"/></packageSources></configuration>\n', 'xml-http', { path: 'nuget.config', rationale: 'Source uses HTTPS, not this rule’s HTTP check.' }),
  sca('AX-SCA-09', false, 'DPK-SCA-9003', '<configuration><packageSources><add key="fixture" value="https&#x3a;//registry.invalid/v3"/></packageSources></configuration>\n', 'xml-http', { path: 'nuget.config', rationale: 'Hexadecimal reference decodes to HTTPS.' }),
  sca('AX-SCA-10', null, 'DPK-SCA-9003', '<configuration><packageSources><add key="fixture" value="&unknown;"/></packageSources></configuration>\n', 'xml-http', { path: 'nuget.config', rationale: 'Unknown XML entity: no valid declaration truth.' }),
  sca('AX-SCA-11', null, 'DPK-SCA-9003', '<configuration><packageSources/></configuration><broken', 'xml-http', { path: 'nuget.config', rationale: 'Trailing incomplete XML; parser must not claim completeness.' }),

  dast('AX-DAST-01', true, 'DG-DAST-900', '/lab/header-invalid', 'invalid-value', { rationale: 'The test-only value-aware rule sees a wrong nonempty header.' }),
  dast('AX-DAST-02', false, 'DG-DAST-900', '/lab/header-safe', 'invalid-value', { rationale: 'Correct nosniff value does not match the invalid-value rule.' }),
  dast('AX-DAST-03', false, 'DG-DAST-900', '/lab/header-missing', 'invalid-value', { rationale: 'A missing value is outside this specific value-only rule; absence is a separate concern.' }),
  dast('AX-DAST-04', true, 'DG-DAST-003', '/lab/header-missing', 'nosniff', { rationale: 'Presence-only test rule flags a missing header.' }),
  dast('AX-DAST-05', false, 'DG-DAST-003', '/lab/header-safe', 'nosniff', { rationale: 'Presence-only test rule accepts a present valid header.' }),
  dast('AX-DAST-06', false, 'DG-DAST-003', '/lab/header-safe?fixture=1', 'nosniff', { unsupported: true, rationale: 'The lab response is safe, but production query-bearing targets are blocked.' }),
]);

export const cases = Object.freeze([...frozen, ...addedCases]);
const sha = (value) => createHash('sha256').update(value).digest('hex');
export function manifest() {
  const targetSha256 = sha(readFileSync(new URL('../local/target.mjs', import.meta.url)));
  const testRulesSha256 = sha(readFileSync(new URL('../../apps/api/test/fixtures/testData.ts', import.meta.url)));
  const extraRulesSha256 = sha(readFileSync(new URL('./rules.mjs', import.meta.url)));
  return { schemaVersion: 'drobon.synthetic-corpus/v2', targetSha256, testRulesSha256, extraRulesSha256,
    cases: cases.map(({ id, family, expected, rule, cwe, path, route, content, oracle, unsupported, requiresLiteralFold, rationale }) => ({
      id, family, expected, rule, ...(cwe === undefined ? {} : { cwe }), ...(path === undefined ? {} : { path }),
      ...(route === undefined ? {} : { route }), ...(content === undefined ? {} : { inputSha256: sha(content) }),
      ...(oracle === undefined ? {} : { oracle }), ...(unsupported ? { unsupported: true } : {}),
      ...(requiresLiteralFold ? { requiresLiteralFold: true } : {}), ...(rationale === undefined ? {} : { rationale }),
    })) };
}
export function manifestDigest() { return sha(JSON.stringify(manifest())); }
