#!/usr/bin/env node
/**
 * Sync the external Drobon-Dataset repo (clone or pull).
 *
 * This helper keeps the main app repo clean (no dataset files committed)
 * while allowing local dev to load the dataset via VULN_INTEL_PROVIDER=filesystem.
 *
 * Usage:
 *   node scripts/sync-dataset.mjs                        # clone to ../Drobon-Dataset if missing, else pull
 *   node scripts/sync-dataset.mjs --path /opt/drobon-dataset
 *   node scripts/sync-dataset.mjs --check                # verify path exists and has vuln-intel/
 */

import { spawnSync } from 'node:child_process';
import { existsSync, statSync } from 'node:fs';
import { resolve, join } from 'node:path';

const DATASET_REPO = 'https://github.com/mdraselislam0101-design/Drobon-Dataset.git';
const DEFAULT_PATH = '../Drobon-Dataset';

function parseArgs() {
  const args = process.argv.slice(2);
  let datasetPath = DEFAULT_PATH;
  let check = false;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--path' && args[i + 1]) {
      datasetPath = args[i + 1];
      i++;
    } else if (args[i] === '--check') {
      check = true;
    } else if (args[i] === '--help' || args[i] === '-h') {
      console.log(`Usage: node scripts/sync-dataset.mjs [--path <dir>] [--check]
  --path <dir>   Where to clone/pull (default: ${DEFAULT_PATH})
  --check        Verify the path contains vuln-intel/ and exit`);
      process.exit(0);
    }
  }
  return { datasetPath: resolve(datasetPath), check };
}

function run(cmd, args, opts = {}) {
  const result = spawnSync(cmd, args, { encoding: 'utf8', ...opts });
  if (result.status !== 0) {
    console.error(`[sync-dataset] ${cmd} ${args.join(' ')} failed:\n${result.stderr || result.stdout}`);
    process.exit(result.status ?? 1);
  }
  return result.stdout;
}

function main() {
  const { datasetPath, check } = parseArgs();
  console.log(`[sync-dataset] Dataset path: ${datasetPath}`);

  if (check) {
    if (!existsSync(datasetPath)) {
      console.error(`[sync-dataset] FAIL: path does not exist: ${datasetPath}`);
      process.exit(1);
    }
    const vulnIntel = join(datasetPath, 'vuln-intel');
    if (!existsSync(vulnIntel)) {
      console.error(`[sync-dataset] FAIL: vuln-intel/ not found under ${datasetPath}`);
      console.error(`  Expected: ${vulnIntel}`);
      process.exit(1);
    }
    const files = run('find', [vulnIntel, '-name', '*.json', '-type', 'f']);
    const count = files.trim().split('\n').filter(Boolean).length;
    console.log(`[sync-dataset] PASS: ${count} advisory files under vuln-intel/`);
    console.log(`[sync-dataset] Ready for VULN_INTEL_PROVIDER=filesystem DATASET_PATH=${datasetPath}`);
    return;
  }

  if (existsSync(datasetPath)) {
    const stat = statSync(datasetPath);
    if (!stat.isDirectory()) {
      console.error(`[sync-dataset] Path exists but is not a directory: ${datasetPath}`);
      process.exit(1);
    }
    // Check if it's a git repo
    const gitDir = join(datasetPath, '.git');
    if (existsSync(gitDir)) {
      console.log(`[sync-dataset] Pulling existing checkout...`);
      run('git', ['-C', datasetPath, 'pull', '--ff-only']);
    } else {
      console.error(`[sync-dataset] Path exists but is not a git checkout: ${datasetPath}`);
      console.error(`  Remove it or use --path <other>`);
      process.exit(1);
    }
  } else {
    console.log(`[sync-dataset] Cloning ${DATASET_REPO} ...`);
    run('git', ['clone', DATASET_REPO, datasetPath]);
  }

  // Verify
  const vulnIntel = join(datasetPath, 'vuln-intel');
  if (!existsSync(vulnIntel)) {
    console.error(`[sync-dataset] Clone succeeded but vuln-intel/ missing: ${vulnIntel}`);
    process.exit(1);
  }
  console.log(`[sync-dataset] Done. Set in .env:`);
  console.log(`  VULN_INTEL_PROVIDER=filesystem`);
  console.log(`  DATASET_PATH=${datasetPath}`);
  console.log(`[sync-dataset] Verify with: node scripts/sync-dataset.mjs --path ${datasetPath} --check`);
}

main();
