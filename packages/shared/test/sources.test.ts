import { describe, expect, test } from 'vitest';
import {
  SOURCE_BLOCKED_EXTENSIONS,
  SOURCE_MAX_FILES,
  SOURCE_PATH_MAX_LENGTH,
  SOURCE_PATH_MAX_SEGMENT_LENGTH,
  SOURCE_PATH_MAX_SEGMENTS,
  isSourceSnapshotPublic,
  isSourceSnapshotResponse,
  isValidSourceContent,
  isValidSourcePath,
  type SourceSnapshotPublic,
} from '../src/sources.js';

/**
 * Source-snapshot contracts (Pump 8) — the SAST scan target.
 *
 * The path policy is the single security boundary for scan-target
 * paths: everything traversal-shaped, hidden, encoded or
 * credential-typed must be structurally rejected by ONE validator used
 * by the API boundary, the durable store and the engine.
 */
describe('source path policy', () => {
  test('accepts ordinary relative source paths', () => {
    for (const path of [
      'index.ts',
      'src/app.tsx',
      'src/components/Button.jsx',
      'lib/deep/nested/module.mjs',
      'scripts/run.cjs',
      'a-b_c.d1e2/zz-9.js',
      'UPPER.ts',
      'trailing.dots.ts',
    ]) {
      expect(isValidSourcePath(path)).toBe(true);
    }
  });

  test('rejects traversal-shaped paths', () => {
    for (const path of [
      '../etc/passwd',
      'src/../../secrets.txt',
      '..',
      '../',
      'a/../b',
      './app.ts',
      '.',
      '...',
      'a/..',
    ]) {
      expect(isValidSourcePath(path)).toBe(false);
    }
  });

  test('rejects absolute paths, drive letters and UNC shapes', () => {
    for (const path of [
      '/etc/passwd',
      '/abs/path.ts',
      'C:/windows/system32/config',
      'C:\\\\windows\\\\system32',
      '\\\\\\\\server\\\\share\\\\file.ts',
      '\\\\server\\share.ts',
      '//etc/passwd',
    ]) {
      expect(isValidSourcePath(path)).toBe(false);
    }
  });

  test('rejects backslashes, NUL, control characters and percent encoding', () => {
    for (const path of [
      'src\\\\app.ts',
      'src/app\u0000.ts',
      'src/app\x00.ts',
      'src/app%2F..%2F..ts',
      'src/%2e%2e/ts',
      'src/app%00.ts',
      'src/ap p.ts',
      'src/app\\tt.ts',
      'src/app\\n.ts',
    ]) {
      expect(isValidSourcePath(path)).toBe(false);
    }
  });

  test('rejects dotfile segments (hidden files: .env, .git, .npmrc)', () => {
    for (const path of [
      '.env',
      '.git/config',
      'config/.env',
      '.npmrc',
      'src/.hidden.ts',
      '.DS_Store',
    ]) {
      expect(isValidSourcePath(path)).toBe(false);
    }
  });

  test('rejects credential-material file extensions outright', () => {
    for (const extension of SOURCE_BLOCKED_EXTENSIONS) {
      expect(isValidSourcePath(`keys/prod${extension}`)).toBe(false);
      expect(isValidSourcePath(`keys/PROD${extension.toUpperCase()}`)).toBe(false);
    }
    // Regular source extensions stay fine.
    expect(isValidSourcePath('keys/prod.ts')).toBe(true);
  });

  test('rejects non-strings, empty and oversized paths', () => {
    expect(isValidSourcePath(undefined)).toBe(false);
    expect(isValidSourcePath(42)).toBe(false);
    expect(isValidSourcePath(null)).toBe(false);
    expect(isValidSourcePath('')).toBe(false);
    expect(isValidSourcePath(`${'a'.repeat(SOURCE_PATH_MAX_LENGTH + 1)}.ts`)).toBe(false);
    expect(isValidSourcePath(`${'a'.repeat(SOURCE_PATH_MAX_SEGMENT_LENGTH + 1)}.ts`)).toBe(false);
    expect(
      isValidSourcePath(Array.from({ length: SOURCE_PATH_MAX_SEGMENTS + 1 }, () => 'a').join('/')),
    ).toBe(false);
    // Exactly at the bounds: accepted.
    expect(isValidSourcePath('a'.repeat(SOURCE_PATH_MAX_SEGMENT_LENGTH))).toBe(true);
    expect(
      isValidSourcePath(Array.from({ length: SOURCE_PATH_MAX_SEGMENTS }, () => 'a').join('/')),
    ).toBe(true);
  });
});

describe('source content policy', () => {
  test('accepts ordinary text (letters, newlines, tabs, unicode)', () => {
    expect(isValidSourceContent('const x = 1;\\n')).toBe(true);
    expect(isValidSourceContent('\\tindented\\r\\nwindows')).toBe(true);
    expect(isValidSourceContent('héllo wörld ✓')).toBe(true);
    expect(isValidSourceContent('')).toBe(true);
  });

  test('rejects binary-shaped content (NUL and control characters)', () => {
    expect(isValidSourceContent('before\u0000after')).toBe(false);
    expect(isValidSourceContent('\u0001')).toBe(false);
    expect(isValidSourceContent('a\u0007b')).toBe(false);
    expect(isValidSourceContent('a\u007fb')).toBe(false);
    expect(isValidSourceContent('\u001f')).toBe(false);
    // Del (0x7f) is rejected; tab/CR/LF are the allowed exceptions.
    expect(isValidSourceContent('\\t')).toBe(true);
    expect(isValidSourceContent('\\n')).toBe(true);
    expect(isValidSourceContent('\\r')).toBe(true);
  });

  test('rejects non-strings and over-bound content', () => {
    expect(isValidSourceContent(undefined)).toBe(false);
    expect(isValidSourceContent(42)).toBe(false);
    expect(isValidSourceContent('x'.repeat(262_145))).toBe(false);
  });
});

describe('public snapshot metadata guard', () => {
  const snapshot: SourceSnapshotPublic = {
    projectId: 'prj_00000000-0000-4000-8000-000000000000',
    fileCount: 1,
    totalBytes: 20,
    updatedAt: '2026-09-28T10:00:00.000Z',
    files: [{ path: 'src/app.ts', bytes: 20 }],
  };

  test('accepts the exact public shape', () => {
    expect(isSourceSnapshotPublic(snapshot)).toBe(true);
    expect(isSourceSnapshotResponse({ snapshot })).toBe(true);
  });

  test('rejects injected/unknown fields and wrong shapes', () => {
    expect(isSourceSnapshotPublic({ ...snapshot, ownerId: 'usr_1' })).toBe(false);
    expect(isSourceSnapshotPublic({ ...snapshot, content: 'x' })).toBe(false);
    expect(isSourceSnapshotPublic({ ...snapshot, fileCount: 2 })).toBe(false);
    expect(isSourceSnapshotPublic({ ...snapshot, files: [...snapshot.files, { path: '../x.ts', bytes: 1 }] })).toBe(false);
    expect(isSourceSnapshotResponse({ snapshot, extra: 1 })).toBe(false);
    expect(isSourceSnapshotResponse({})).toBe(false);
    expect(isSourceSnapshotResponse(null)).toBe(false);
  });

  test('rejects file entries with wrong shapes', () => {
    const base = { ...snapshot, files: [{ path: 'a.ts', bytes: 1 }] as Array<{ path: string; bytes: number }> };
    expect(isSourceSnapshotPublic(base)).toBe(true);
    expect(
      isSourceSnapshotPublic({
        ...snapshot,
        files: [{ path: 'a.ts', bytes: 1, content: 'x' }] as never,
      }),
    ).toBe(false);
    expect(
      isSourceSnapshotPublic({
        ...snapshot,
        files: [{ path: 'a.ts', bytes: -1 }] as never,
      }),
    ).toBe(false);
  });

  test('documents the hard file-count bound', () => {
    expect(SOURCE_MAX_FILES).toBe(200);
  });
});
