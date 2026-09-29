// Repository-level release safety checks. Keep this separate from application
// behavior and run it as an authoritative `npm run verify` gate.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { spawnSync } from 'node:child_process';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const WORKFLOW_PATH = '.github/workflows/ci.yml';
const WORKSPACES = [
  'apps/api',
  'apps/worker',
  'apps/web',
  'packages/shared',
];
const PACKAGE_FIELDS = [
  'name',
  'version',
  'dependencies',
  'devDependencies',
  'optionalDependencies',
  'peerDependencies',
];
const DENIED_PACKAGES = new Set([
  'pg', 'postgres', 'mysql', 'mysql2', 'sqlite3', 'better-sqlite3',
  'node-sqlite3', 'sql.js', 'prisma', '@prisma/client', 'typeorm',
  'sequelize', 'mongoose', 'mongodb', 'redis', 'ioredis', 'knex',
  'drizzle-orm', 'cve', 'nvd', 'ghsa', 'osv', 'kev', 'epss',
]);
const DATA_PACKAGE_PATTERN = /^(?:@(cve|nvd|ghsa|osv|kev|epss)(?:\/|$)|(?:cve|nvd|ghsa|osv|kev|epss)(?:-|$)|.*(?:vulnerability[-_ ]?(?:dataset|catalog|feed)|security[-_ ]?dataset).*)/i;
const CREDENTIAL_FILE_PATTERN = /(?:^|\/)(?:\.env(?:\..+)?|[^/]+\.env|\.netrc|\.pypirc|\.docker\/config\.json|application_default_credentials\.json|id_(?:rsa|dsa|ecdsa|ed25519)|credentials?(?:\.(?:json|ya?ml|ini|conf))?|service[-_]?account(?:\.(?:json|ya?ml))?|secrets?\.(?:json|ya?ml|ini|conf)|[^/]*\.(?:pem|p12|pfx|p8|key|jks|keystore|tfstate))$/i;
const DATASET_FILE_PATTERN = /(?:^|\/)(?:cve|nvd|ghsa|osv|kev|epss)(?:[-_.][^/]*)?(?:\/|$)|(?:^|\/)[^/]*(?:cve|nvd|ghsa|osv|kev|epss|vulnerability[-_ ]?(?:dataset|catalog|feed))[^/]*\.(?:json|jsonl|ndjson|csv|xml|sqlite|db|gz|zip)$/i;
const FORBIDDEN_GENERATED_PATH = /(?:^|\/)(?:node_modules|dist|coverage|\.data|artifacts)(?:\/|$)/;

function git(args) {
  const result = spawnSync('git', args, { cwd: ROOT, encoding: 'utf8' });
  if (result.status !== 0) {
    throw new Error(`git ${args.join(' ')} failed: ${result.stderr || result.error || 'unknown error'}`);
  }
  return result.stdout;
}

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
  }
  return value;
}

function comparablePackage(manifest) {
  return Object.fromEntries(PACKAGE_FIELDS.map((field) => [
    field,
    field.endsWith('Dependencies') ? (manifest[field] ?? {}) : (manifest[field] ?? null),
  ]));
}

function packageNameFromLockPath(lockPath) {
  const afterLastNodeModules = lockPath.slice(lockPath.lastIndexOf('node_modules/') + 'node_modules/'.length);
  const parts = afterLastNodeModules.split('/');
  return parts[0]?.startsWith('@') ? `${parts[0]}/${parts[1] ?? ''}` : parts[0];
}

function checkLockfile(findings) {
  const rootManifest = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
  const lock = JSON.parse(readFileSync(join(ROOT, 'package-lock.json'), 'utf8'));
  if (lock.lockfileVersion !== 3 || !lock.packages || !lock.packages['']) {
    findings.push('package-lock.json must be npm lockfileVersion 3 with root package metadata');
    return;
  }

  for (const path of ['', ...WORKSPACES]) {
    const manifestPath = path ? `${path}/package.json` : 'package.json';
    const lockEntry = lock.packages[path];
    if (!lockEntry) {
      findings.push(`${manifestPath}: missing matching package-lock.json workspace entry`);
      continue;
    }
    const manifest = JSON.parse(readFileSync(join(ROOT, manifestPath), 'utf8'));
    if (JSON.stringify(canonical(comparablePackage(manifest))) !== JSON.stringify(canonical(comparablePackage(lockEntry)))) {
      findings.push(`${manifestPath}: name/version/dependency declarations do not match package-lock.json`);
    }
  }

  const packageManager = rootManifest.packageManager;
  if (typeof packageManager !== 'string' || !/^npm@10\.\d+\.\d+$/.test(packageManager)) {
    findings.push('package.json must pin the supported npm 10 package manager version');
  }

  for (const path of Object.keys(lock.packages)) {
    if (!path.startsWith('node_modules/')) continue;
    const name = packageNameFromLockPath(path);
    if (DENIED_PACKAGES.has(name) || DATA_PACKAGE_PATTERN.test(name ?? '')) {
      findings.push(`package-lock.json: forbidden database/security-dataset package ${JSON.stringify(name)}`);
    }
  }

  const lockText = readFileSync(join(ROOT, 'package-lock.json'), 'utf8');
  const lockCredentialPatterns = [
    /https?:\/\/[^/\s:@]+:[^@\s/]+@/i,
    /(?:_authToken|_password|access_token|client_secret|private_key)\s*["']?\s*[:=]\s*["']?[^\s"']{8,}/i,
  ];
  if (lockCredentialPatterns.some((pattern) => pattern.test(lockText))) {
    findings.push('package-lock.json contains credential-shaped registry or token material');
  }
}

function isCredentialPath(path) {
  return CREDENTIAL_FILE_PATTERN.test(path) && !/(?:^|\/)\.env\.example$/i.test(path);
}

function checkPolicySelfTest(findings) {
  const cases = [
    { path: '.env', predicate: isCredentialPath, expected: true },
    { path: 'ops/.env.production', predicate: isCredentialPath, expected: true },
    { path: 'ops/service-account.json', predicate: isCredentialPath, expected: true },
    { path: 'ops/.netrc', predicate: isCredentialPath, expected: true },
    { path: 'ops/.docker/config.json', predicate: isCredentialPath, expected: true },
    { path: 'certs/deploy-key.pem', predicate: isCredentialPath, expected: true },
    { path: '.env.example', predicate: isCredentialPath, expected: false },
    { path: 'apps/api/test/secretsApi.test.ts', predicate: isCredentialPath, expected: false },
    { path: 'fixtures/kev-2026.jsonl', predicate: (path) => DATASET_FILE_PATTERN.test(path), expected: true },
    { path: 'docs/SECURITY.md', predicate: (path) => DATASET_FILE_PATTERN.test(path), expected: false },
    { path: 'apps/web/dist/assets/index.js', predicate: (path) => FORBIDDEN_GENERATED_PATH.test(path), expected: true },
    { path: 'apps/web/src/main.tsx', predicate: (path) => FORBIDDEN_GENERATED_PATH.test(path), expected: false },
  ];
  for (const test of cases) {
    if (test.predicate(test.path) !== test.expected) {
      findings.push(`repository-integrity policy self-test failed for ${test.path}`);
    }
  }
  if (!DENIED_PACKAGES.has('pg') || !DATA_PACKAGE_PATTERN.test('@cve/advisories') || DATA_PACKAGE_PATTERN.test('vitest')) {
    findings.push('repository-integrity dependency policy self-test failed');
  }
}

function checkFileInventory(findings) {
  const paths = git(['ls-files', '--cached', '--others', '--exclude-standard', '-z'])
    .split('\0')
    .filter(Boolean);

  for (const path of paths) {
    if (isCredentialPath(path)) {
      findings.push(`${path}: credential/environment file must not be committed`);
    }
    if (DATASET_FILE_PATTERN.test(path)) {
      findings.push(`${path}: external vulnerability dataset/catalog/feed is forbidden`);
    }
    if (FORBIDDEN_GENERATED_PATH.test(path)) {
      findings.push(`${path}: generated, runtime, or dependency output must not be committed`);
    }
  }

  const npmrcPath = '.npmrc';
  const npmrc = readFileSync(join(ROOT, npmrcPath), 'utf8');
  if (/(?:_authToken|_password|username\s*=|password\s*=)\s*[:=]/i.test(npmrc)) {
    findings.push('.npmrc contains registry credential configuration');
  }
}

function workflowPermissionBlocks(source) {
  const lines = source.split(/\r?\n/);
  const blocks = [];
  for (let index = 0; index < lines.length; index += 1) {
    const header = lines[index].match(/^(\s*)permissions\s*:\s*$/);
    if (!header) continue;
    const baseIndent = header[1].length;
    const entries = [];
    for (let cursor = index + 1; cursor < lines.length; cursor += 1) {
      const line = lines[cursor];
      if (line.trim() === '' || line.trimStart().startsWith('#')) continue;
      const indent = line.match(/^\s*/)[0].length;
      if (indent <= baseIndent) break;
      entries.push(line.trim());
    }
    blocks.push(entries);
  }
  return blocks;
}

function checkWorkflow(findings) {
  let workflow;
  try {
    workflow = readFileSync(join(ROOT, WORKFLOW_PATH), 'utf8');
  } catch {
    findings.push(`${WORKFLOW_PATH}: required least-privilege CI workflow is missing`);
    return;
  }

  if (!/^\s{2}pull_request:\s*$/m.test(workflow)) findings.push('CI must run for ordinary pull_request events');
  if (/pull_request_target/i.test(workflow)) findings.push('CI must not use pull_request_target');
  if (!/^\s{2}push:\s*$/m.test(workflow) || !/arena\/\*\*/.test(workflow)) {
    findings.push('CI must run on pushes to Arena session branches');
  }
  if (!/npm ci --ignore-scripts/.test(workflow) || !/npm run verify/.test(workflow)) {
    findings.push('CI must install from the lockfile without lifecycle scripts and run npm run verify');
  }
  if (!/npm run release:evidence/.test(workflow) || !/needs:\s*verify/.test(workflow)) {
    findings.push('main-branch release evidence must depend on the successful verify job');
  }
  if (!/persist-credentials:\s*false/.test(workflow)) {
    findings.push('checkout must not persist its token in the worktree');
  }
  if (/pull_request_target|\bsecrets\s*\.|environment\s*:|id-token\s*:\s*write|contents\s*:\s*write|packages\s*:\s*write|actions\s*:\s*write/i.test(workflow)) {
    findings.push('CI must not request privileged permissions, secrets, deployment environments, or OIDC');
  }
  const permissionBlocks = workflowPermissionBlocks(workflow);
  if (permissionBlocks.length === 0 || permissionBlocks.some((block) => block.length !== 1 || block[0] !== 'contents: read')) {
    findings.push('every explicit workflow/job permission must be read-only contents access');
  }
  const uses = [...workflow.matchAll(/^\s*uses:\s*([^\s#]+)\s*$/gm)].map((match) => match[1]);
  if (uses.length === 0 || uses.some((reference) => !/@[0-9a-f]{40}$/i.test(reference))) {
    findings.push('every external GitHub Action must be pinned to a full 40-character commit SHA');
  }
  if (/\$\{\{\s*(?:secrets\.|github\.event\.|inputs\.)/i.test(workflow)) {
    findings.push('CI must not interpolate secrets or untrusted event/input data');
  }
  if (/\b(?:deploy|deployment|production-release)\b/i.test(workflow)) {
    findings.push('CI must not deploy or publish production releases');
  }
}

function main() {
  const findings = [];
  checkPolicySelfTest(findings);
  checkLockfile(findings);
  checkFileInventory(findings);
  checkWorkflow(findings);

  if (findings.length > 0) {
    process.stdout.write(`check-repo-integrity: FAIL (${findings.length} finding(s))\n`);
    for (const finding of findings) process.stdout.write(`  ${finding}\n`);
    process.exitCode = 1;
    return;
  }
  process.stdout.write('check-repo-integrity: PASS (lock/workspaces, credential & dataset inventory, least-privilege CI)\n');
}

main();
