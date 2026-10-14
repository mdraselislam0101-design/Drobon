// `npm run dev` — run the API and Web dev servers side by side.
// No third-party process manager needed.
import { spawn } from 'node:child_process';

const TARGETS = [
  {
    label: 'api',
    args: ['run', 'dev', '--workspace', '@drobon/api'],
    env: {
      ...process.env,
      HOST: process.env.API_HOST ?? '127.0.0.1',
    },
  },
  {
    label: 'web',
    args: ['run', 'dev', '--workspace', '@drobon/web'],
    env: {
      ...process.env,
      HOST: process.env.HOST ?? '0.0.0.0',
      ALLOWED_HOSTS: process.env.ALLOWED_HOSTS ?? '*',
    },
  },
];

const children = [];

function pipe(child, label, stream, prefix) {
  child[stream].on('data', (chunk) => {
    for (const line of String(chunk).split('\n')) {
      if (line.length > 0) {
        process.stdout.write(`[${label}:${prefix}] ${line}\n`);
      }
    }
  });
}

function shutdown(signal) {
  for (const child of children) {
    child.kill(signal);
  }
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

for (const target of TARGETS) {
  const child = spawn('npm', target.args, {
    stdio: ['ignore', 'pipe', 'pipe'],
    shell: process.platform === 'win32',
    env: target.env,
  });
  children.push(child);
  pipe(child, target.label, 'stdout', 'out');
  pipe(child, target.label, 'stderr', 'err');
  child.on('exit', (code) => {
    process.stdout.write(`[${target.label}] exited with code ${code}\n`);
    shutdown('SIGTERM');
    process.exitCode = code ?? 1;
  });
}
