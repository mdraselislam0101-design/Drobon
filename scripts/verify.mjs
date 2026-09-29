// `npm run verify` — the authoritative, fail-closed repository pipeline.
// Every required step must pass; the summary names each step PASS/FAIL.
import { spawnSync } from 'node:child_process';

const ROOT = new URL('..', import.meta.url).pathname;

const STEPS = [
  { name: 'scope boundaries', command: ['node', ['scripts/check-boundaries.mjs']] },
  { name: 'repository integrity', command: ['node', ['scripts/check-repo-integrity.mjs']] },
  { name: 'release evidence self-test', command: ['node', ['scripts/release-evidence.mjs', '--self-test']] },
  { name: 'secret matcher self-test', command: ['node', ['scripts/check-no-secrets.mjs', '--self-test']] },
  { name: 'secret scan (sources)', command: ['node', ['scripts/check-no-secrets.mjs']] },
  { name: 'typecheck', command: ['npm', ['run', 'typecheck']] },
  { name: 'lint', command: ['npm', ['run', 'lint']] },
  { name: 'tests', command: ['npm', ['run', 'test']] },
  { name: 'production builds', command: ['npm', ['run', 'build']] },
  { name: 'secret scan (incl. builds)', command: ['node', ['scripts/check-no-secrets.mjs']] },
  { name: 'dependency audit', command: ['npm', ['run', 'audit']] },
];

function runStep(step) {
  const started = Date.now();
  process.stdout.write(`\n===== ${step.name} =====\n`);
  const result = spawnSync(step.command[0], step.command[1], {
    cwd: ROOT,
    stdio: 'inherit',
    shell: process.platform === 'win32',
  });
  const seconds = ((Date.now() - started) / 1000).toFixed(1);
  if (result.status === 0) {
    return { name: step.name, status: 'PASS', seconds };
  }
  // Includes npm audit registry/network errors: an unavailable security gate
  // is not a successful verification result.
  return { name: step.name, status: 'FAIL', seconds };
}

const results = STEPS.map(runStep);

process.stdout.write('\n===== verification summary =====\n');
for (const result of results) {
  process.stdout.write(`${result.status.padEnd(6)} ${result.name} (${result.seconds}s)\n`);
}

const failed = results.filter((result) => result.status === 'FAIL');
if (failed.length > 0) {
  process.stdout.write(`\nVERIFY: FAIL (${failed.length} step(s) failed)\n`);
  process.exitCode = 1;
} else {
  process.stdout.write('\nVERIFY: PASS\n');
}
