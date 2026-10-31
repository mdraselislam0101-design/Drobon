import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { describe, expect, test } from 'vitest';
import { createJsonFileSourceStore } from '../src/scans/sources.js';

describe.skipIf(process.platform === 'win32')('private JSON process crash boundary', () => {
  test('SIGKILL before rename retains the old source and can leave a private orphan that is not auto-deleted', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'drobon-json-crash-'));
    try {
      const path = join(dir, 'sources.json');
      const input = { ownerId: 'usr_fixture', projectId: 'prj_00000000-0000-4000-8000-000000000001',
        files: [{ path: 'src/app.js', content: 'const oldFixture = true;' }] };
      await createJsonFileSourceStore(path).replace(input);
      const original = readFileSync(path, 'utf8');
      const moduleUrl = pathToFileURL(resolve('src/lib/writePrivateJson.ts')).href;
      const script = `
        import fs from 'node:fs'; import { syncBuiltinESMExports } from 'node:module';
        const originalWrite = fs.writeFileSync;
        fs.writeFileSync = (target, data, options) => {
          if (typeof target === 'number') {
            fs.writeSync(target, 'partial synthetic content');
            fs.writeSync(1, 'PARTIAL_WRITTEN\\n');
            Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0);
          }
          return originalWrite(target, data, options);
        };
        syncBuiltinESMExports();
        const { writePrivateJson } = await import(${JSON.stringify(moduleUrl)});
        writePrivateJson(${JSON.stringify(path)}, 'new synthetic data');
      `;
      const child = spawn(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', script], { stdio: ['ignore', 'pipe', 'pipe'] });
      let stderr = '';
      try {
        await new Promise<void>((resolveReady, reject) => {
          const timer = setTimeout(() => reject(new Error(`fixture timed out: ${stderr}`)), 10_000);
          child.stderr.on('data', (chunk: Buffer) => { stderr += chunk.toString(); });
          child.stdout.on('data', (chunk: Buffer) => { if (chunk.toString().includes('PARTIAL_WRITTEN')) { clearTimeout(timer); resolveReady(); } });
          child.once('error', (error) => { clearTimeout(timer); reject(error); });
          child.once('exit', () => { clearTimeout(timer); reject(new Error(`fixture exited: ${stderr}`)); });
        });
        const exited = new Promise<void>((resolveExit) => child.once('exit', () => resolveExit()));
        child.kill('SIGKILL'); await exited;
      } finally { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); }
      expect(readFileSync(path, 'utf8')).toBe(original);
      const leftovers = readdirSync(dir).filter((name) => name.endsWith('.tmp'));
      expect(leftovers).toHaveLength(1);
      expect(statSync(join(dir, leftovers[0]!)).mode & 0o777).toBe(0o600);
      const reopened = createJsonFileSourceStore(path);
      expect((await reopened.findByProject(input.projectId))?.files[0]?.content).toBe(input.files[0]?.content);
      await reopened.replace({ ...input, files: [{ path: 'src/app.js', content: 'const newFixture = true;' }] });
      expect((await createJsonFileSourceStore(path).findByProject(input.projectId))?.files[0]?.content).toBe('const newFixture = true;');
      expect(readdirSync(dir).filter((name) => name.endsWith('.tmp'))).toEqual(leftovers);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
});
