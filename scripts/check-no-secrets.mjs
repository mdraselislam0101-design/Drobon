// `npm run check:secrets` — fail if anything looking like a committed secret
// (or a private key block) exists in first-party code, templates or builds.
//
// Design:
// - Line-based scan for `keyword [=:] "value"` shapes (JS/TS/JSON/docs/.env).
// - A match is only excused when the same line carries an obviously-fake
//   marker (test, example, redacted, ...). Real values never contain those.
// - Private key blocks always fail. `.env.example` may not even *name* a
//   secret variable. Local `.env` files are gitignored and skipped.
// - `apps/web/dist` (contains third-party vendor code) gets the reduced scan:
//   key blocks + secret-named VITE_* references only. First-party browser code
//   is covered by the src scan + the web static tests instead.
// - Findings print file:line with the value redacted — the report itself
//   must never leak the secret it found.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

const ROOT = join(new URL('.', import.meta.url).pathname, '..');

const SKIP_DIRS = new Set(['.git', 'node_modules', 'coverage', '.vite']);
const SKIP_FILES = new Set(['package-lock.json']);
const SKIP_EXTENSIONS = new Set(['.map', '.tsbuildinfo', '.png', '.jpg', '.jpeg', '.gif', '.ico']);
const TEXT_EXTENSIONS = new Set([
  '.ts',
  '.tsx',
  '.mjs',
  '.cjs',
  '.js',
  '.jsx',
  '.json',
  '.md',
  '.html',
  '.css',
  '.svg',
  '.example',
  '.npmrc',
  '.nvmrc',
  '.gitignore',
  '.editorconfig',
  '',
]);

const SECRET_LITERAL =
  /\b(password|passwd|pwd|secret|api[_-]?key|auth[_-]?token|access[_-]?token|refresh[_-]?token|id[_-]?token|private[_-]?key|client[_-]?secret|connection[_-]?string)\b\s*['"]?\s*[:=]\s*['"`][^'"`]{3,}['"`]/i;
const PRIVATE_KEY_BLOCK = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/;
const SECRET_ENV_NAME = /(PASSWORD|PASSWD|SECRET|TOKEN|PRIVATE_KEY|API_KEY|CREDENTIALS)/;
const VITE_SECRET_REF = /\bVITE_[A-Z0-9_]*(SECRET|PASSWORD|TOKEN|PRIVATE|CREDENTIAL|API_KEY)[A-Z0-9_]*\b/;
const ENV_ASSIGNMENT = /^\s*(?:export\s+)?([A-Z][A-Z0-9_]*)\s*=\s*\S+/;

// Markers that prove a matched literal is an intentional, fake fixture.
const FAKE_MARKERS = [
  'test',
  'example',
  'fake',
  'redacted',
  'changeme',
  'placeholder',
  'dummy',
  'sample',
  'mock',
  'hunter2',
  'xxx',
  'your-',
  'todo',
];

function isTextFile(name) {
  if (SKIP_FILES.has(name)) return false;
  const dot = name.lastIndexOf('.');
  const ext = dot === -1 ? '' : name.slice(dot);
  if (SKIP_EXTENSIONS.has(ext)) return false;
  if (name === '.env.example' || name.startsWith('.env.')) return true;
  return TEXT_EXTENSIONS.has(ext);
}

function listFiles(dir, out = []) {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const rel = relative(ROOT, full);
    if (statSync(full).isDirectory()) {
      if (!SKIP_DIRS.has(entry) && !entry.startsWith('.')) {
        // Hidden dirs (except .git, skipped above) hold no sources.
        if (entry !== '.git') listFiles(full, out);
      } else if (entry === '.github' || entry === '.vscode') {
        listFiles(full, out);
      }
      continue;
    }
    if (entry === '.env' || (entry.startsWith('.env.') && entry !== '.env.example')) {
      continue; // Local, gitignored environment — not committed content.
    }
    if (isTextFile(entry)) {
      out.push({ full, rel });
    }
  }
  return out;
}

function hasFakeMarker(line) {
  const lower = line.toLowerCase();
  return FAKE_MARKERS.some((marker) => lower.includes(marker));
}

function redactFinding(line, match) {
  const index = line.indexOf(match);
  const keyword = (match.match(/^[A-Za-z0-9_$]+/) ?? ['<match>'])[0];
  const shown = `${line.slice(0, index)}${keyword} [REDACTED]`;
  return shown.length > 160 ? `${shown.slice(0, 157)}...` : shown;
}

function scanFile({ full, rel }) {
  const findings = [];
  const content = readFileSync(full, 'utf8');
  if (content.includes('\u0000')) return findings; // Binary after all.
  const isWebDist = rel.replace(/\\/g, '/').startsWith('apps/web/dist/');
  const lines = content.split('\n');
  lines.forEach((line, index) => {
    const location = `${rel}:${index + 1}`;
    if (PRIVATE_KEY_BLOCK.test(line)) {
      findings.push(`${location}: private key block must never be committed`);
      return;
    }
    if (isWebDist) {
      if (VITE_SECRET_REF.test(line)) {
        findings.push(`${location}: secret-named VITE_* reference in web bundle`);
      }
      return;
    }
    const literal = line.match(SECRET_LITERAL);
    if (literal && !hasFakeMarker(line)) {
      findings.push(`${location}: possible committed secret — ${redactFinding(line, literal[0])}`);
    }
    if (rel.endsWith('.env.example')) {
      const assignment = line.match(ENV_ASSIGNMENT);
      if (assignment && SECRET_ENV_NAME.test(assignment[1])) {
        findings.push(`${location}: .env.example must not define secret variable ${assignment[1]}`);
      }
    }
  });
  return findings;
}

function selfTest() {
  // NOTE: "should-flag" fixtures are assembled with string concatenation so
  // the scanner's own source never contains a flaggable literal (the scan
  // covers this file too — no carve-outs). Excused fixtures stay literal on
  // purpose: their fake markers must excuse them here as well.
  const cases = [
    // [line, shouldFlag]
    ['pass' + 'word: "s3cr3t-value-99"', true],
    ['api' + '_key = \'AKIA1234567890ABCD\'', true],
    ['"cl' + 'ientSecret": "abc123xyz789"', true],
    ['pass' + 'word = "unquoted-marker-absent-12345"', true],
    [`password: "hunter2-example"`, false],
    [`password: "[REDACTED]"`, false],
    [`apiKey: "test-key-123"`, false],
    [`const password = getPassword();`, false],
    [`['password', 'secret', 'token']`, false],
    [`if (password.length > 0) {}`, false],
    [`VITE_API_BASE_URL=https://x.test`, false],
    ['-----BEGIN ' + 'RSA PRIVATE KEY-----', 'key'],
  ];
  let failures = 0;
  for (const [line, expected] of cases) {
    const flagged =
      PRIVATE_KEY_BLOCK.test(line) && expected === 'key'
        ? 'key'
        : SECRET_LITERAL.test(line) && !hasFakeMarker(line);
    const normalized = expected === 'key' ? 'key' : expected;
    if (flagged !== normalized) {
      failures += 1;
      process.stderr.write(`self-test mismatch for: ${line}\n`);
    }
  }
  if (failures > 0) {
    process.stderr.write(`check-no-secrets --self-test: ${failures} FAILURES\n`);
    process.exitCode = 1;
  } else {
    process.stdout.write('check-no-secrets --self-test: PASS\n');
  }
}

function main() {
  if (process.argv.includes('--self-test')) {
    selfTest();
    return;
  }
  const files = listFiles(ROOT);
  const findings = files.flatMap(scanFile);
  if (findings.length > 0) {
    process.stdout.write(`check-no-secrets: FAIL (${findings.length} finding(s))\n`);
    for (const finding of findings) {
      process.stdout.write(`  ${finding}\n`);
    }
    process.exitCode = 1;
    return;
  }
  process.stdout.write(`check-no-secrets: PASS (${files.length} files scanned)\n`);
}

main();
