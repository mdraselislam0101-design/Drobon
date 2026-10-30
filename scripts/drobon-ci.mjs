#!/usr/bin/env node
// Local/CI adapter around the existing Drobon scanners. No network scans,
// GitHub API calls, target execution, automatic fixes, or dataset mutations.
import { constants } from 'node:fs';
import { open, realpath } from 'node:fs/promises';
import { basename, dirname, isAbsolute, join, relative, sep } from 'node:path';
import { runCiCheck } from './ci/runner.ts';

const usage = `Drobon CI (read-only source scan)

node --import tsx scripts/drobon-ci.mjs --root PATH --dataset PATH [options]
  --scanners SAST,SECRETS,SCA   Default: all three
  --severity INFO|LOW|MEDIUM|HIGH|CRITICAL   Default: HIGH
  --project-key KEY            Stable repository identity for finding fingerprints
  --sarif PATH                 Write a new SARIF file (never overwrite)
  --allow-incomplete           Explicitly accept coverage gaps (findings still fail)
  --help

Exit 0: no threshold hits and no unaccepted gaps; 1: threshold hit(s);
2: invalid input, error, or unaccepted incomplete coverage. See docs/CI_SECURITY_BN.md.
An exit of 0 never proves safety or complete coverage.`;

function parse(args) {
  const result = { scanners: ['SAST', 'SECRETS', 'SCA'], threshold: 'HIGH', allowIncomplete: false };
  const seen = new Set();
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === '--help') { console.log(usage); return null; }
    if (seen.has(arg)) throw new TypeError(`Duplicate option: ${arg}`);
    seen.add(arg);
    if (arg === '--allow-incomplete') { result.allowIncomplete = true; continue; }
    if (!['--root', '--dataset', '--scanners', '--severity', '--project-key', '--sarif'].includes(arg)) throw new TypeError(`Unknown option: ${arg}`);
    const value = args[++i];
    if (!value || value.startsWith('--')) throw new TypeError(`Missing value for ${arg}`);
    if (arg === '--root') result.root = value;
    if (arg === '--dataset') result.datasetPath = value;
    if (arg === '--sarif') result.sarifPath = value;
    if (arg === '--project-key') result.projectKey = value;
    if (arg === '--severity') result.threshold = value;
    if (arg === '--scanners') result.scanners = value.split(',');
  }
  if (!result.root || !result.datasetPath) throw new TypeError('Both --root and --dataset are required.');
  if (new Set(result.scanners).size !== result.scanners.length) throw new TypeError('Do not repeat a scanner.');
  return result;
}

async function writeNewSarif(path, datasetPath, content) {
  const dir = await realpath(dirname(path));
  const target = join(dir, basename(path));
  const dataset = await realpath(datasetPath);
  const rel = relative(dataset, target);
  if (rel === '' || (rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel))) {
    throw new TypeError('SARIF output must be outside the read-only dataset.');
  }
  const file = await open(target, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600);
  try { await file.writeFile(content, 'utf8'); } finally { await file.close(); }
}

try {
  const options = parse(process.argv.slice(2));
  if (options !== null) {
    const result = await runCiCheck(options);
    if (options.sarifPath) await writeNewSarif(options.sarifPath, options.datasetPath, result.sarif);
    console.log(JSON.stringify(result.summary, null, 2));
    process.exitCode = result.exitCode;
  }
} catch (error) {
  console.error(`Drobon CI could not complete: ${error instanceof Error ? error.message : 'unknown error'}`);
  process.exitCode = 2;
}
