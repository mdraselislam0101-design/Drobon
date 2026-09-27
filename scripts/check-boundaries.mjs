// `npm run check:boundaries` — enforce the Pump 1 scope gates:
// no database, no dataset, no child processes, no node: imports in browser code.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

const ROOT = new URL('..', import.meta.url).pathname;

const DENIED_DEPENDENCIES = [
  // Databases, ORMs, clients, embedded engines.
  'pg',
  'postgres',
  'mysql',
  'mysql2',
  'sqlite3',
  'better-sqlite3',
  'node-sqlite3',
  'sql.js',
  'prisma',
  '@prisma/client',
  'typeorm',
  'sequelize',
  'mongoose',
  'mongodb',
  'redis',
  'ioredis',
  'knex',
  'drizzle-orm',
  // Security datasets / feeds (maintained separately, never in the app).
  'cve',
  'nvd',
  'ghsa',
  'osv',
  'epss',
];

const DENIED_FILENAME = /(migration|seed|sqlite|\.db\b|cve|nvd|ghsa|\bosv\b|kev|epss|vuln|catalog|threat.?feed|dataset|ingest)/i;

const DENIED_SPECIFIERS = [
  'child_process',
  'node:child_process',
  ...DENIED_DEPENDENCIES,
];

const CODE_DIRS = ['apps/api/src', 'apps/worker/src', 'apps/web/src', 'packages/shared/src'];

function listFiles(dir) {
  const out = [];
  const walk = (current) => {
    for (const entry of readdirSync(current)) {
      const full = join(current, entry);
      if (statSync(full).isDirectory()) {
        walk(full);
      } else {
        out.push(full);
      }
    }
  };
  walk(join(ROOT, dir));
  return out;
}

function checkDependencies() {
  const findings = [];
  const manifests = [
    'package.json',
    'apps/api/package.json',
    'apps/worker/package.json',
    'apps/web/package.json',
    'packages/shared/package.json',
  ];
  for (const manifest of manifests) {
    const pkg = JSON.parse(readFileSync(join(ROOT, manifest), 'utf8'));
    for (const section of ['dependencies', 'devDependencies', 'peerDependencies']) {
      for (const name of Object.keys(pkg[section] ?? {})) {
        if (DENIED_DEPENDENCIES.some((denied) => name === denied || name.startsWith(`${denied}/`))) {
          findings.push(`${manifest}: denied dependency "${name}" in ${section}`);
        }
      }
    }
  }
  return findings;
}

function checkFilenames() {
  const findings = [];
  for (const dir of CODE_DIRS) {
    for (const full of listFiles(dir)) {
      const rel = relative(ROOT, full);
      if (DENIED_FILENAME.test(rel)) {
        findings.push(`${rel}: denied filename (database/dataset scope)`);
      }
    }
  }
  return findings;
}

function checkSpecifiers() {
  const findings = [];
  const pattern = /(?:from\s+['"]([^'"]+)['"]|require\(\s*['"]([^'"]+)['"]\s*\))/g;
  for (const dir of CODE_DIRS) {
    for (const full of listFiles(dir)) {
      if (!/\.(ts|tsx|mjs|cjs|js|jsx)$/.test(full)) continue;
      const rel = relative(ROOT, full);
      const content = readFileSync(full, 'utf8');
      for (const match of content.matchAll(pattern)) {
        const spec = match[1] ?? match[2] ?? '';
        if (DENIED_SPECIFIERS.some((denied) => spec === denied || spec.startsWith(`${denied}/`))) {
          findings.push(`${rel}: denied import "${spec}"`);
        }
      }
      if (dir === 'apps/web/src') {
        for (const match of content.matchAll(pattern)) {
          const spec = match[1] ?? match[2] ?? '';
          if (spec === 'fs' || spec === 'node:fs' || spec.startsWith('node:')) {
            findings.push(`${rel}: node import "${spec}" forbidden in browser code`);
          }
        }
      }
    }
  }
  return findings;
}

function main() {
  const findings = [...checkDependencies(), ...checkFilenames(), ...checkSpecifiers()];
  if (findings.length > 0) {
    process.stdout.write(`check-boundaries: FAIL (${findings.length} finding(s))\n`);
    for (const finding of findings) {
      process.stdout.write(`  ${finding}\n`);
    }
    process.exitCode = 1;
    return;
  }
  process.stdout.write('check-boundaries: PASS (no database, dataset, or shell scope)\n');
}

main();
