import { readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, test } from 'vitest';

const SRC_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'src');

function listSourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      out.push(...listSourceFiles(full));
    } else if (entry.endsWith('.ts') || entry.endsWith('.tsx')) {
      out.push(full);
    }
  }
  return out;
}

const sources = (): Array<{ file: string; content: string }> =>
  listSourceFiles(SRC_DIR).map((file) => ({
    file: relative(SRC_DIR, file),
    content: readFileSync(file, 'utf8'),
  }));

describe('static web safety', () => {
  test('import.meta.env is touched only by the config boundary and boot', () => {
    const readers = sources()
      .filter(({ content }) => content.includes('import.meta.env'))
      .map(({ file }) => file)
      .sort();
    expect(readers).toEqual(['config.ts', 'main.tsx']);
  });

  test('only the allowlisted VITE_* keys are read', () => {
    const allowed = ['VITE_API_BASE_URL', 'VITE_APP_NAME', 'VITE_APP_ENV'];
    const violations: string[] = [];
    for (const { file, content } of sources()) {
      for (const match of content.matchAll(/\bVITE_[A-Z0-9_]+\b/g)) {
        if (!allowed.includes(match[0])) {
          violations.push(`${file}: reads ${match[0]}`);
        }
      }
    }
    expect(violations).toEqual([]);
  });

  test('no secret-shaped VITE_* variable is ever referenced', () => {
    const violations = sources().filter(({ content }) =>
      /\bVITE_[A-Z0-9_]*(SECRET|PASSWORD|TOKEN|PRIVATE|CREDENTIAL)[A-Z0-9_]*\b/.test(content),
    );
    expect(violations).toEqual([]);
  });

  test('no dangerous rendering or execution primitives', () => {
    const forbidden: Array<{ pattern: RegExp; reason: string }> = [
      { pattern: /dangerouslySetInnerHTML/, reason: 'raw HTML injection is forbidden' },
      { pattern: /\beval\s*\(/, reason: 'eval is forbidden' },
      { pattern: /new\s+Function\s*\(/, reason: 'Function constructor is forbidden' },
      { pattern: /child_process/, reason: 'node child processes are forbidden' },
      { pattern: /from\s+['"]node:/, reason: 'node: imports are forbidden in browser code' },
    ];
    const violations: string[] = [];
    for (const { file, content } of sources()) {
      // main.tsx builds the fatal-error box with textContent only (no HTML
      // parsing); innerHTML='' there just clears the mount node.
      const scanned = file === 'main.tsx' ? content.replace(/\.innerHTML = '';/g, '') : content;
      for (const { pattern, reason } of forbidden) {
        if (pattern.test(scanned)) {
          violations.push(`${file}: ${reason}`);
        }
      }
      if (file !== 'main.tsx' && /\.innerHTML/.test(content)) {
        violations.push(`${file}: innerHTML is forbidden`);
      }
    }
    expect(violations).toEqual([]);
  });
});
