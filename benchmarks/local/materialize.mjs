import { existsSync, mkdirSync, realpathSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { cases } from './fixtures.mjs';

// Only write into a new, explicitly named directory: never overwrite existing
// work or create files inside an existing Dataset checkout. A partial output
// after interruption must be inspected/removed by its owner before a retry.
const argument = process.argv[2];
if (process.argv.length !== 3 || argument === undefined) {
  throw new Error('Usage: node benchmarks/local/materialize.mjs /absolute/path/to/new-lab-directory');
}
const root = resolve(argument);
if (!argument.startsWith('/')) throw new Error('Specify an absolute, NEW directory outside the Dataset repository');
if (root.split('/').some((part) => part.toLowerCase() === 'drobon-dataset')) {
  throw new Error('Refusing to create benchmark inputs in a Dataset checkout');
}
// Resolve ancestor symlinks and refuse every Git checkout, including this
// repository and a Dataset checkout reached through an alias. This is not a
// substitute for the operator checking that the destination is disposable.
let ancestor = realpathSync(dirname(root));
for (;;) {
  if (existsSync(join(ancestor, '.git'))) throw new Error('Choose a destination outside all Git checkouts');
  const parent = dirname(ancestor);
  if (parent === ancestor) break;
  ancestor = parent;
}
mkdirSync(root, { recursive: false, mode: 0o700 });
let count = 0;
for (const item of cases) {
  if (item.content === undefined) continue;
  const destination = join(root, item.id, item.path);
  mkdirSync(dirname(destination), { recursive: true, mode: 0o700 });
  writeFileSync(destination, item.content, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
  count += 1;
}
console.log(`Created ${count} separate synthetic source/dependency cases in a new private directory.`);
console.log('This corpus contains invented credential-shaped data; it has no real credential.');
