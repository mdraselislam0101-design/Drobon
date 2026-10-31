#!/usr/bin/env node
/** Create only a new, private local corpus outside any Git checkout. Never
 * overwrite existing files or write into the read-only Dataset repository. */
import { existsSync, mkdirSync, realpathSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { cases, manifest, manifestDigest } from './fixtures.mjs';

const argument = process.argv[2];
if (process.argv.length !== 3 || argument === undefined || !argument.startsWith('/')) {
  throw new Error('Usage: node benchmarks/accuracy-v2/materialize.mjs /absolute/path/to/new-lab-directory');
}
const root = resolve(argument);
if (root.split('/').some((part) => part.toLowerCase() === 'drobon-dataset')) throw new Error('Dataset destination refused');
let ancestor = realpathSync(dirname(root));
for (;;) {
  if (existsSync(join(ancestor, '.git'))) throw new Error('Choose a directory outside all Git checkouts');
  const parent = dirname(ancestor);
  if (parent === ancestor) break;
  ancestor = parent;
}
// Validate all corpus-derived paths before creating anything.
for (const item of cases) {
  if (item.content === undefined) continue;
  if (!/^[A-Z0-9-]+$/.test(item.id) || typeof item.path !== 'string' ||
      !/^[A-Za-z0-9][A-Za-z0-9._-]*(?:\/[A-Za-z0-9][A-Za-z0-9._-]*)*$/.test(item.path)) {
    throw new Error('Invalid synthetic fixture path');
  }
}
mkdirSync(root, { recursive: false, mode: 0o700 });
let count = 0;
for (const item of cases) {
  if (item.content === undefined) continue;
  const target = join(root, item.id, item.path);
  mkdirSync(dirname(target), { recursive: true, mode: 0o700 });
  writeFileSync(target, item.content, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
  count += 1;
}
writeFileSync(join(root, 'MANIFEST.json'), JSON.stringify({ fixtureManifestSha256: manifestDigest(), ...manifest() }, null, 2) + '\n',
  { encoding: 'utf8', flag: 'wx', mode: 0o600 });
console.log(`Created ${count} separate synthetic source/dependency cases in a new private directory.`);
console.log(`Corpus SHA-256: ${manifestDigest()}. HTTP cases use the separate loopback lab.`);
