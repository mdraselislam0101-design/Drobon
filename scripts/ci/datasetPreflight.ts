import { lstat, opendir, realpath } from 'node:fs/promises';
import { join, relative, sep } from 'node:path';

/** The production loader follows filesystem entries. CI accepts only a
 * reviewed, local dataset and first rejects symlinks in every subtree the
 * existing loader reads, including packs not selected for this run. This is
 * a defence-in-depth check, not an OS sandbox or a defense against a process
 * concurrently replacing directories. Never run untrusted code alongside it. */
export async function inspectDataset(path: string): Promise<Record<'sast' | 'secrets' | 'sca', number>> {
  const root = await realpath(path);
  if (!(await lstat(root)).isDirectory()) throw new TypeError('Dataset must be a directory.');
  const counts = { sast: 0, secrets: 0, sca: 0 };
  let visited = 0;
  let files = 0;
  const pending = ['packs', 'vuln-intel', 'knowledge', 'learning', 'assessments', 'engagements'].map((rel) => ({ rel, depth: 0 }));
  while (pending.length > 0) {
    const item = pending.pop();
    if (item === undefined) break;
    const { rel, depth } = item;
    const full = join(root, rel);
    let info;
    try { info = await lstat(full); } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') continue;
      throw new TypeError('Dataset directory cannot be inspected.');
    }
    if (info.isSymbolicLink()) throw new TypeError('Dataset symlinks are not allowed in CI.');
    if (!info.isDirectory()) throw new TypeError('Dataset subtree is not a directory.');
    const handle = await opendir(full);
    for await (const entry of handle) {
      visited += 1;
      if (visited > 50_000) throw new RangeError('Dataset exceeds the CI entry limit.');
      const child = join(full, entry.name);
      const childRel = relative(root, child);
      if (entry.isSymbolicLink()) throw new TypeError('Dataset symlinks are not allowed in CI.');
      if (entry.isDirectory()) {
        if (depth >= 16) throw new RangeError('Dataset exceeds the CI directory depth limit.');
        pending.push({ rel: childRel, depth: depth + 1 });
        continue;
      }
      if (!entry.isFile()) throw new TypeError('Dataset contains an unsupported filesystem entry.');
      if (++files > 20_000) throw new RangeError('Dataset exceeds the CI file limit.');
      const metadata = await lstat(child);
      if (metadata.isSymbolicLink() || !metadata.isFile()) throw new TypeError('Dataset entry changed during inspection.');
      if (metadata.size > 2 * 1024 * 1024) throw new RangeError('Dataset contains an oversized file.');
      if (!entry.name.endsWith('.json')) continue;
      for (const family of ['sast', 'secrets', 'sca'] as const) {
        if (childRel.startsWith(`packs${sep}${family}${sep}v1${sep}rules${sep}`)) counts[family] += 1;
      }
    }
  }
  return counts;
}
