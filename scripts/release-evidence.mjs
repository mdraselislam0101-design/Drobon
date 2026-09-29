// CI-only release-evidence builder. This records observed verification/build
// facts; it does not sign, attest, publish a release, or deploy production.
import { createHash } from 'node:crypto';
import {
  cpSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join, relative, resolve, sep } from 'node:path';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const OUTPUT = join(ROOT, 'artifacts', 'release-evidence');
const BUILD_OUTPUTS = [
  { name: 'shared', path: 'packages/shared/dist' },
  { name: 'api', path: 'apps/api/dist' },
  { name: 'worker', path: 'apps/worker/dist' },
  { name: 'web', path: 'apps/web/dist' },
];
const VERIFY_GATES = [
  'scope boundaries',
  'repository integrity and lock/workspace consistency',
  'release evidence consistency/hash self-test',
  'secret matcher self-test',
  'secret scan (sources)',
  'typecheck',
  'lint',
  'complete workspace tests',
  'shared/API/worker/Web production builds',
  'secret scan (including builds)',
  'npm audit --audit-level=high',
];

function fail(message) {
  process.stderr.write(`release-evidence: FAIL: ${message}\n`);
  process.exit(1);
}

function command(executable, args) {
  const result = spawnSync(executable, args, {
    cwd: ROOT,
    encoding: 'utf8',
    stdio: 'inherit',
    shell: process.platform === 'win32',
  });
  if (result.status !== 0) fail(`${executable} ${args.join(' ')} exited with ${result.status ?? 'no status'}`);
}

function git(args) {
  const result = spawnSync('git', args, { cwd: ROOT, encoding: 'utf8' });
  if (result.status !== 0) fail(`git ${args.join(' ')} failed: ${result.stderr || 'unknown error'}`);
  return result.stdout.trim();
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function safeBuildDirectory(relativePath) {
  const absolutePath = resolve(ROOT, relativePath);
  if (!absolutePath.startsWith(`${ROOT}${sep}`) || !relativePath.endsWith('/dist')) {
    fail(`refusing to clean unexpected build output path ${relativePath}`);
  }
  try {
    if (lstatSync(absolutePath).isSymbolicLink()) fail(`refusing to follow build output symlink ${relativePath}`);
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
  return absolutePath;
}

function cleanBuildOutputs() {
  for (const output of BUILD_OUTPUTS) {
    rmSync(safeBuildDirectory(output.path), { recursive: true, force: true });
  }
}

function listFiles(directory) {
  const files = [];
  const walk = (current) => {
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const path = join(current, entry.name);
      if (entry.isSymbolicLink()) fail(`build output contains a symlink: ${relative(ROOT, path)}`);
      if (entry.isDirectory()) walk(path);
      else if (entry.isFile()) files.push(path);
      else fail(`build output contains a non-regular file: ${relative(ROOT, path)}`);
    }
  };
  walk(directory);
  return files.sort((a, b) => relative(directory, a).localeCompare(relative(directory, b)));
}

function inspectBuildOutputs() {
  const result = {};
  for (const output of BUILD_OUTPUTS) {
    const directory = safeBuildDirectory(output.path);
    if (!statSync(directory, { throwIfNoEntry: false })?.isDirectory()) {
      fail(`expected production output is missing: ${output.path}`);
    }
    const files = listFiles(directory).map((path) => {
      const bytes = readFileSync(path);
      return {
        relativePath: relative(directory, path).split(sep).join('/'),
        size: bytes.length,
        sha256: sha256(bytes),
      };
    });
    if (files.length === 0) fail(`production output is empty: ${output.path}`);
    const tree = createHash('sha256');
    for (const file of files) tree.update(`${file.relativePath}\0${file.size}\0${file.sha256}\n`);
    result[output.name] = {
      sourceDirectory: output.path,
      fileCount: files.length,
      totalBytes: files.reduce((total, file) => total + file.size, 0),
      treeSha256: tree.digest('hex'),
      files,
    };
  }
  return result;
}

function sameBuild(first, second) {
  for (const output of BUILD_OUTPUTS) {
    const left = first[output.name];
    const right = second[output.name];
    if (left.fileCount !== right.fileCount || left.totalBytes !== right.totalBytes || left.treeSha256 !== right.treeSha256) {
      return false;
    }
    if (JSON.stringify(left.files) !== JSON.stringify(right.files)) return false;
  }
  return true;
}

function copyPayload(builds) {
  rmSync(OUTPUT, { recursive: true, force: true });
  mkdirSync(join(OUTPUT, 'payload'), { recursive: true });
  for (const output of BUILD_OUTPUTS) {
    cpSync(join(ROOT, output.path), join(OUTPUT, 'payload', output.name), { recursive: true, errorOnExist: true });
  }

  const artifactEntries = {};
  for (const output of BUILD_OUTPUTS) {
    const directory = join(OUTPUT, 'payload', output.name);
    const files = listFiles(directory).map((path) => {
      const bytes = readFileSync(path);
      return {
        path: relative(OUTPUT, path).split(sep).join('/'),
        size: bytes.length,
        sha256: sha256(bytes),
      };
    });
    const expected = builds[output.name].files.map((file) => ({
      relativePath: file.relativePath,
      size: file.size,
      sha256: file.sha256,
    }));
    const actual = files.map((file) => ({
      relativePath: file.path.slice(`payload/${output.name}/`.length),
      size: file.size,
      sha256: file.sha256,
    }));
    if (JSON.stringify(expected) !== JSON.stringify(actual)) fail(`copied artifact does not match ${output.name} production output`);
    const tree = createHash('sha256');
    for (const file of files) tree.update(`${file.path}\0${file.size}\0${file.sha256}\n`);
    artifactEntries[output.name] = {
      directory: `payload/${output.name}`,
      fileCount: files.length,
      totalBytes: files.reduce((total, file) => total + file.size, 0),
      treeSha256: tree.digest('hex'),
      files,
    };
  }
  return artifactEntries;
}

function selfTest() {
  const fixture = Object.fromEntries(BUILD_OUTPUTS.map(({ name }) => [name, {
    fileCount: 1,
    totalBytes: 3,
    treeSha256: 'a'.repeat(64),
    files: [{ relativePath: 'index.js', size: 3, sha256: 'b'.repeat(64) }],
  }]));
  if (!sameBuild(fixture, structuredClone(fixture))) fail('build-equality self-test rejected identical file inventories');
  const changed = structuredClone(fixture);
  changed.web.files[0].sha256 = 'c'.repeat(64);
  if (sameBuild(fixture, changed)) fail('build-equality self-test accepted a changed artifact digest');
  if (sha256(Buffer.from('release-evidence-self-test')) !== sha256(Buffer.from('release-evidence-self-test'))) {
    fail('SHA-256 self-test is not deterministic');
  }
  process.stdout.write('release-evidence --self-test: PASS (deterministic hashes and artifact mismatch detection)\n');
}

function main() {
  if (process.argv.includes('--self-test')) {
    selfTest();
    return;
  }
  if (process.env.GITHUB_ACTIONS !== 'true') fail('this command may only run in GitHub Actions');
  if (process.env.DROBON_VERIFY_RESULT !== 'success') fail('the required verify job did not report success');

  const revision = git(['rev-parse', 'HEAD']);
  const expectedRevision = process.env.GITHUB_SHA;
  if (!/^[0-9a-f]{40}$/i.test(expectedRevision ?? '') || revision !== expectedRevision) {
    fail('checked-out HEAD does not exactly match the GitHub workflow source revision');
  }
  const dirty = git(['status', '--porcelain', '--untracked-files=all']);
  if (dirty) fail(`source checkout is not clean before building:\n${dirty}`);

  const manifest = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
  const packageLockSha256 = sha256(readFileSync(join(ROOT, 'package-lock.json')));
  const sourceTree = git(['rev-parse', 'HEAD^{tree}']);

  process.stdout.write('release-evidence: first clean production build\n');
  cleanBuildOutputs();
  command(process.platform === 'win32' ? 'npm.cmd' : 'npm', ['run', 'build']);
  const firstBuild = inspectBuildOutputs();

  process.stdout.write('release-evidence: second clean production build for consistency check\n');
  cleanBuildOutputs();
  command(process.platform === 'win32' ? 'npm.cmd' : 'npm', ['run', 'build']);
  const secondBuild = inspectBuildOutputs();
  if (!sameBuild(firstBuild, secondBuild)) fail('two clean production builds produced different output files or SHA-256 digests');

  const artifacts = copyPayload(secondBuild);
  const evidence = {
    format: 'drobon-release-evidence/v1',
    source: {
      revision,
      tree: sourceTree,
      ref: process.env.GITHUB_REF ?? null,
      event: process.env.GITHUB_EVENT_NAME ?? null,
      package: { name: manifest.name, version: manifest.version },
      packageLockSha256,
    },
    verification: {
      workflow: '.github/workflows/ci.yml',
      job: 'verify',
      command: 'npm run verify',
      result: process.env.DROBON_VERIFY_RESULT,
      gates: VERIFY_GATES,
    },
    build: {
      command: 'npm run build',
      cleanBuildsCompared: 2,
      outputsMatched: true,
      nodeVersion: process.version,
      npmVersion: process.env.npm_config_user_agent?.match(/npm\/(\S+)/)?.[1] ?? null,
      artifactPayload: artifacts,
    },
    claims: {
      signed: false,
      signedAttestation: false,
      deploymentPerformed: false,
      vulnerabilityCatalogIncluded: false,
      note: 'Hashes and CI job status are integrity evidence only; no signature, attestation, provenance certification, or production deployment is claimed.',
    },
  };

  mkdirSync(OUTPUT, { recursive: true });
  const manifestText = `${JSON.stringify(evidence, null, 2)}\n`;
  writeFileSync(join(OUTPUT, 'release-manifest.json'), manifestText, { mode: 0o644 });

  const sumEntries = [];
  for (const output of BUILD_OUTPUTS) {
    for (const file of artifacts[output.name].files) sumEntries.push(`${file.sha256}  ${file.path}`);
  }
  sumEntries.push(`${sha256(Buffer.from(manifestText))}  release-manifest.json`);
  sumEntries.sort((a, b) => a.localeCompare(b));
  writeFileSync(join(OUTPUT, 'SHA256SUMS'), `${sumEntries.join('\n')}\n`, { mode: 0o644 });

  process.stdout.write(`release-evidence: PASS revision=${revision}; ${sumEntries.length - 1} build files; two matching clean builds\n`);
  process.stdout.write(`release-evidence: bundle=${relative(ROOT, OUTPUT)} (unsigned; no deployment)\n`);
}

main();
