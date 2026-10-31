import { inflateSync } from 'node:zlib';

/** Minimal test-only decoder for this renderer's subset-font TJ streams. */
export function pdfText(pdf: Buffer): string {
  const binary = pdf.toString('latin1');
  const streams: string[] = [];
  for (const match of binary.matchAll(/\bstream\r?\n/g)) {
    const start = (match.index ?? 0) + match[0].length;
    const end = binary.indexOf('endstream', start);
    if (end < 0) continue;
    try { streams.push(inflateSync(pdf.subarray(start, end)).toString('utf8')); } catch { /* other streams are not zlib */ }
  }
  const cmap = streams.find((stream) => stream.includes('beginbfrange'));
  if (cmap === undefined) throw new Error('Font mapping missing');
  const chars = new Map<number, string>();
  for (const block of cmap.matchAll(/<([0-9a-f]{4})>\s*<[0-9a-f]{4}>\s*\[([^\]]*)\]/gi)) {
    let id = parseInt(block[1] ?? '', 16);
    for (const entry of (block[2] ?? '').matchAll(/<([0-9a-f\s]*)>/gi)) {
      const hex = (entry[1] ?? '').replace(/\s/g, '');
      let decoded = '';
      for (let index = 0; index < hex.length; index += 4) decoded += String.fromCharCode(parseInt(hex.slice(index, index + 4), 16));
      chars.set(id++, decoded);
    }
  }
  let out = '';
  for (const stream of streams.filter((item) => item.includes(' TJ'))) {
    for (const operation of stream.matchAll(/\[([^\]]+)\]\s*TJ/g)) {
      for (const token of (operation[1] ?? '').matchAll(/<([0-9a-f]+)>/gi)) {
        const hex = token[1] ?? '';
        for (let index = 0; index < hex.length; index += 4) out += chars.get(parseInt(hex.slice(index, index + 4), 16)) ?? '?';
      }
    }
  }
  return out;
}

