/**
 * BOUNDED DECLARATION DOCUMENT READERS (Pump 18, MAIN-APP ONLY).
 *
 * Turns real manifest/lockfile TEXT into the normalized documents that the
 * dataset's `drobon.pack.sca/v1` rules expect (`external/scaDeclaration.ts`
 * consumes documents, never raw text). No new npm dependency: every reader is
 * a deliberately small, bounded parser for the subset of each format that the
 * rules actually use.
 *
 * HONESTY: an artifact whose shape a reader cannot represent returns
 * `undefined` — never a fabricated empty document. The scan layer counts
 * those rules as `declarationRulesNotEvaluated`. These are subset parsers,
 * NOT full TOML/YAML/XML/INI grammars (documented in docs/SCA_READERS.md).
 *
 * Bounds: 256 KiB of text, 8,000 lines, 64 nesting levels, 2,000 nodes.
 */

import type { ScaParser } from '../../external/scaDeclaration.js';

export const READER_MAX_BYTES = 262_144;
export const READER_MAX_LINES = 8_000;
export const READER_MAX_DEPTH = 64;
export const READER_MAX_NODES = 2_000;

type Json = Record<string, unknown> | unknown[] | string | number | boolean | null;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function boundedText(content: string): string[] {
  return content.slice(0, READER_MAX_BYTES).split('\n').slice(0, READER_MAX_LINES);
}

function stripComment(line: string, markers: readonly string[]): string {
  let quote: string | undefined;
  for (let i = 0; i < line.length; i += 1) {
    const char = line[i] ?? '';
    if (quote !== undefined) {
      if (char === '\\') { i += 1; continue; }
      if (char === quote) quote = undefined;
      continue;
    }
    if (char === '"' || char === "'") { quote = char; continue; }
    for (const marker of markers) {
      if (line.startsWith(marker, i)) return line.slice(0, i);
    }
  }
  return line;
}

function unquote(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length >= 2) {
    const first = trimmed[0];
    const last = trimmed[trimmed.length - 1];
    if ((first === '"' && last === '"') || (first === "'" && last === "'") || (first === '`' && last === '`')) {
      return trimmed.slice(1, -1);
    }
  }
  return trimmed;
}

function scalar(value: string): unknown {
  const trimmed = value.trim();
  if (trimmed.length >= 2 && /^["'`]/.test(trimmed)) return unquote(trimmed);
  const text = unquote(trimmed);
  if (text === 'true') return true;
  if (text === 'false') return false;
  if (text === 'null' || text === '~') return null;
  if (/^-?[0-9]+$/.test(text)) return Number.parseInt(text, 10);
  if (/^-?[0-9]+\.[0-9]+$/.test(text)) return Number.parseFloat(text);
  return text;
}

function splitTopLevel(value: string, separator: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let quote: string | undefined;
  let current = '';
  for (let i = 0; i < value.length; i += 1) {
    const char = value[i] ?? '';
    if (quote !== undefined) {
      current += char;
      if (char === '\\') { current += value[i + 1] ?? ''; i += 1; continue; }
      if (char === quote) quote = undefined;
      continue;
    }
    if (char === '"' || char === "'") { quote = char; current += char; continue; }
    if (char === '[' || char === '{' || char === '(') depth += 1;
    else if (char === ']' || char === '}' || char === ')') depth -= 1;
    if (char === separator && depth === 0) { out.push(current.trim()); current = ''; continue; }
    current += char;
  }
  if (current.trim().length > 0) out.push(current.trim());
  return out;
}

function assign(root: Record<string, unknown>, path: readonly string[], value: unknown, depth = 0): void {
  if (path.length === 0 || depth > READER_MAX_DEPTH) return;
  let cursor: Record<string, unknown> = root;
  for (let i = 0; i < path.length - 1; i += 1) {
    const key = path[i] ?? '';
    const next = cursor[key];
    if (!isRecord(next)) cursor[key] = {};
    cursor = cursor[key] as Record<string, unknown>;
  }
  const last = path[path.length - 1] ?? '';
  const existing = cursor[last];
  if (Array.isArray(existing)) existing.push(value);
  else if (existing !== undefined && !isRecord(existing)) cursor[last] = [existing, value];
  else cursor[last] = value;
}

// ---------------------------------------------------------------------------
// TOML (sections, arrays of tables, dotted keys, arrays, inline tables)
// ---------------------------------------------------------------------------

function inlineValue(raw: string): unknown {
  const text = raw.trim();
  if (text.startsWith('[') && text.endsWith(']')) {
    return splitTopLevel(text.slice(1, -1), ',').map((part) => inlineValue(part));
  }
  if (text.startsWith('{') && text.endsWith('}')) {
    const out: Record<string, unknown> = {};
    for (const part of splitTopLevel(text.slice(1, -1), ',')) {
      const eq = part.indexOf('=');
      if (eq < 0) continue;
      out[unquote(part.slice(0, eq).trim())] = inlineValue(part.slice(eq + 1));
    }
    return out;
  }
  return scalar(text);
}

export function readToml(content: string): unknown | undefined {
  const root: Record<string, unknown> = {};
  let section: string[] = [];
  let arrayTable: Record<string, unknown> | undefined;
  let nodeCount = 0;
  let pending: { path: string[]; raw: string } | undefined;

  const flush = (): void => {
    if (pending === undefined) return;
    const value = inlineValue(pending.raw);
    if (arrayTable !== undefined) assign(arrayTable, pending.path, value);
    else assign(root, [...section, ...pending.path], value);
    pending = undefined;
  };

  for (const rawLine of boundedText(content)) {
    const line = stripComment(rawLine, ['#']).trim();
    if (line.length === 0) continue;
    if (line.startsWith('[[') && line.endsWith(']]')) {
      flush();
      section = [];
      arrayTable = undefined;
      const path = line.slice(2, -2).split('.').map((part) => unquote(part.trim()));
      let cursor = root;
      for (let i = 0; i < path.length; i += 1) {
        const key = path[i] ?? '';
        if (i === path.length - 1) {
          const list = cursor[key];
          if (!Array.isArray(list)) cursor[key] = [];
          const entry: Record<string, unknown> = {};
          (cursor[key] as unknown[]).push(entry);
          arrayTable = entry;
        } else {
          const next = cursor[key];
          if (Array.isArray(next)) cursor = next[next.length - 1] as Record<string, unknown>;
          else {
            if (!isRecord(next)) cursor[key] = {};
            cursor = cursor[key] as Record<string, unknown>;
          }
        }
      }
      continue;
    }
    if (line.startsWith('[') && line.endsWith(']')) {
      flush();
      arrayTable = undefined;
      section = line.slice(1, -1).split('.').map((part) => unquote(part.trim()));
      continue;
    }
    if (pending === undefined) {
      const eq = line.indexOf('=');
      if (eq < 0) continue;
      pending = { path: line.slice(0, eq).split('.').map((part) => unquote(part.trim())), raw: line.slice(eq + 1).trim() };
    } else {
      pending.raw += `\n${line}`;
    }
    const candidate = pending.raw.replace(/\s+/g, '');
    const opens = (candidate.match(/\[/g) ?? []).length;
    const closes = (candidate.match(/\]/g) ?? []).length;
    if (opens <= closes) { flush(); nodeCount += 1; }
    if (nodeCount > READER_MAX_NODES) break;
  }
  flush();
  return Object.keys(root).length > 0 ? root : undefined;
}

// ---------------------------------------------------------------------------
// YAML (indent maps + sequences, inline scalars)
// ---------------------------------------------------------------------------

interface YamlLine { indent: number; text: string }

export function readYaml(content: string): unknown | undefined {
  const lines: YamlLine[] = [];
  for (const raw of boundedText(content)) {
    const cleaned = stripComment(raw, ['#']).replace(/\t/g, '  ');
    if (cleaned.trim().length === 0 || cleaned.trim() === '---' || cleaned.trim() === '...') continue;
    lines.push({ indent: cleaned.length - cleaned.trimStart().length, text: cleaned.trim() });
  }
  if (lines.length === 0) return undefined;
  let index = 0;
  let nodes = 0;

  const parseNode = (indent: number): unknown => {
    if (index >= lines.length || nodes > READER_MAX_NODES) return undefined;
    nodes += 1;
    const current = lines[index];
    if (current === undefined) return undefined;
    if (current.text.startsWith('- ')) {
      const list: unknown[] = [];
      while (index < lines.length) {
        const line = lines[index];
        if (line === undefined || line.indent !== indent || !line.text.startsWith('- ')) break;
        const rest = line.text.slice(2).trim();
        index += 1;
        if (rest.length === 0) { list.push(parseNode(indent + 2)); continue; }
        const colon = rest.indexOf(':');
        if (colon > 0 && !rest.startsWith('"') && !rest.startsWith("'")) {
          const entry: Record<string, unknown> = { [unquote(rest.slice(0, colon).trim())]: inlineValue(rest.slice(colon + 1)) };
          while (index < lines.length) {
            const child = lines[index];
            if (child === undefined || child.indent <= indent) break;
            const childColon = child.text.indexOf(':');
            if (childColon < 0) { index += 1; continue; }
            index += 1;
            entry[unquote(child.text.slice(0, childColon).trim())] = inlineValue(child.text.slice(childColon + 1));
          }
          list.push(entry);
        } else if (rest.startsWith('[') && rest.endsWith(']')) {
          list.push(...splitTopLevel(rest.slice(1, -1), ',').map(inlineValue));
        } else {
          list.push(inlineValue(rest));
        }
        if (list.length > READER_MAX_NODES) break;
      }
      return list;
    }
    const out: Record<string, unknown> = {};
    while (index < lines.length) {
      const line = lines[index];
      if (line === undefined || line.indent < indent) break;
      if (line.indent > indent) { index += 1; continue; }
      const colon = line.text.indexOf(':');
      if (colon < 0) { index += 1; continue; }
      const key = unquote(line.text.slice(0, colon).trim());
      const rest = line.text.slice(colon + 1).trim();
      index += 1;
      if (rest.length === 0) {
        const next = lines[index];
        out[key] = next !== undefined && next.indent > indent ? parseNode(next.indent) : {};
      } else if (rest.startsWith('[') && rest.endsWith(']')) {
        out[key] = splitTopLevel(rest.slice(1, -1), ',').map(inlineValue);
      } else if (rest.startsWith('{') && rest.endsWith('}')) {
        out[key] = inlineValue(rest);
      } else {
        out[key] = inlineValue(rest);
      }
      if (Object.keys(out).length > READER_MAX_NODES) break;
    }
    return out;
  };

  const result = parseNode(lines[0]?.indent ?? 0);
  return result === undefined ? undefined : result;
}

// ---------------------------------------------------------------------------
// XML (elements + attributes, repeated children → arrays)
// ---------------------------------------------------------------------------

interface XmlNode { name: string; attributes: Record<string, unknown>; children: XmlNode[]; text: string }

function xmlName(name: string): string {
  if (/Group$/.test(name) && /^[A-Z]/.test(name)) return name[0]?.toLowerCase() + name.slice(1);
  return name;
}

export function readXml(content: string): unknown | undefined {
  const text = content.slice(0, READER_MAX_BYTES);
  const tagPattern = /<(\/?)([A-Za-z_][\w:.-]*)((?:"[^"]*"|'[^']*'|[^>])*?)(\/?)>/g;
  const root: XmlNode = { name: '#root', attributes: {}, children: [], text: '' };
  const stack: XmlNode[] = [root];
  let cursor = 0;
  let nodes = 0;
  for (const match of text.matchAll(tagPattern)) {
    nodes += 1;
    if (nodes > READER_MAX_NODES) break;
    const closing = match[1] === '/';
    const name = match[2] ?? '';
    const attrText = match[3] ?? '';
    const selfClosing = match[4] === '/';
    const parent = stack[stack.length - 1];
    if (parent === undefined) break;
    parent.text += text.slice(cursor, match.index).trim();
    cursor = (match.index ?? 0) + (match[0]?.length ?? 0);
    if (closing) {
      if (stack.length > 1) stack.pop();
      continue;
    }
    const attributes: Record<string, unknown> = {};
    const attrPattern = /([\w:.-]+)\s*=\s*("([^"]*)"|'([^']*)')/g;
    for (const attr of attrText.matchAll(attrPattern)) {
      attributes[xmlName(attr[1] ?? '')] = unquote(attr[3] ?? attr[4] ?? '');
    }
    const node: XmlNode = { name: xmlName(name), attributes, children: [], text: '' };
    parent.children.push(node);
    if (!selfClosing) {
      if (stack.length < READER_MAX_DEPTH) stack.push(node);
    }
  }

  const isArrayContainer = (node: XmlNode, childName: string, count: number): boolean => {
    if (Object.keys(node.attributes).length > 0 || node.text.trim().length > 0) return false;
    const plural = childName.endsWith('y') ? `${childName.slice(0, -1)}ies` : `${childName}s`;
    return node.name === plural || node.name === `${childName}es` || node.name === childName || count > 1;
  };

  const convert = (node: XmlNode): unknown => {
    const grouped = new Map<string, XmlNode[]>();
    for (const child of node.children) {
      const list = grouped.get(child.name) ?? [];
      list.push(child);
      grouped.set(child.name, list);
    }
    if (grouped.size === 1) {
      const [childName, list] = [...grouped.entries()][0] ?? ['', []];
      if (isArrayContainer(node, childName, list.length)) return list.map(convert);
    }
    const out: Record<string, unknown> = { ...node.attributes };
    for (const [key, list] of grouped) {
      const values = list.map(convert);
      out[key] = list.length > 1 ? values : values[0];
    }
    if (Object.keys(out).length === 0 && node.text.length > 0) return node.text;
    return out;
  };

  const top = root.children[0];
  if (top === undefined) return undefined;
  const body = convert(top);
  return { [top.name]: body };
}

// ---------------------------------------------------------------------------
// INI / properties (sections, key=value, continuation arrays)
// ---------------------------------------------------------------------------

const ARRAY_KEYS = new Set(['install_requires', 'deps', 'requires', 'generators', 'Depends', 'Imports', 'Suggests', 'sources']);

function sectionContainer(root: Record<string, unknown>, section: string): Record<string, unknown> {
  let current = root;
  for (const part of section.split('.')) {
    const key = part.trim();
    if (key.length === 0) continue;
    if (!isRecord(current[key])) current[key] = {};
    current = current[key] as Record<string, unknown>;
  }
  return current;
}

export function readIni(content: string, artifact: string): unknown | undefined {
  const root: Record<string, unknown> = {};
  let section = '';
  let last: { container: Record<string, unknown>; key: string } | undefined;
  for (const raw of boundedText(content)) {
    const line = stripComment(raw, [';', '#']).trim();
    if (line.length === 0) continue;
    if (line.startsWith('[') && line.endsWith(']')) {
      section = unquote(line.slice(1, -1));
      sectionContainer(root, section);
      last = undefined;
      continue;
    }
    const continuation = /^\s/.test(raw) && last !== undefined;
    const eq = line.search(/[=:]/);
    const rawKey = eq < 0 ? line : line.slice(0, eq).trim();
    const forceArray = rawKey.endsWith('[]');
    const key = forceArray ? rawKey.slice(0, -2) : rawKey;
    const value = eq < 0 ? '' : line.slice(eq + 1).trim();
    let container: Record<string, unknown> = root;
    if (artifact === '.npmrc' || artifact === 'pip.conf' || artifact === '.pypirc' || artifact === 'global.conf') {
      // handled by the normalizer below; keep raw sections for now
    }
    if (section.length > 0) container = sectionContainer(root, section);
    if (continuation && last !== undefined) {
      const existing = last.container[last.key];
      const parts = Array.isArray(existing) ? existing : [String(existing ?? '')].filter((item) => item.length > 0);
      parts.push(...splitTopLevel(line, ',').map(unquote));
      last.container[last.key] = parts;
      continue;
    }
    const parts = splitTopLevel(value, ',');
    const parsed = forceArray || parts.length > 1 || ARRAY_KEYS.has(key) ? parts.map((part) => scalar(part)) : scalar(value);
    container[key] = parsed;
    last = { container, key };
  }
  return Object.keys(root).length > 0 ? normalizeIni(root, artifact) : undefined;
}

function normalizeIni(root: Record<string, unknown>, artifact: string): unknown {
  // The dataset uses BOTH shapes for registry/config files: some rules read
  // root-level keys (`audit`, `registry`, `global.*`), others read a nested
  // `config` object. Exposing both is honest — extra keys can only make an
  // `absent` check fail, never fabricate a match.
  if (artifact === '.npmrc') {
    const { name, ...rest } = root;
    return { ...rest, ...(name === undefined ? {} : { name }), config: rest };
  }
  if (artifact === 'pip.conf' || artifact === '.pypirc' || artifact === 'global.conf') return { ...root, config: root };
  if (artifact === 'go.mod') return root;
  return root;
}

export function readProperties(content: string, artifact: string): unknown | undefined {
  const root: Record<string, unknown> = {};
  let lastKey = '';
  for (const raw of boundedText(content)) {
    const line = raw.trim();
    if (line.length === 0 || line.startsWith('#')) continue;
    if (/^\s/.test(raw) && lastKey.length > 0) {
      const existing = root[lastKey];
      root[lastKey] = [...(Array.isArray(existing) ? existing : [existing]), ...splitTopLevel(line, ',').map(unquote)];
      continue;
    }
    const colon = line.indexOf(':');
    const eq = line.indexOf('=');
    const split = colon >= 0 && (eq < 0 || colon < eq) ? colon : eq;
    if (split < 0) continue;
    const rawKey = line.slice(0, split).trim();
    const forceArray = rawKey.endsWith('[]');
    const key = forceArray ? rawKey.slice(0, -2) : rawKey;
    const value = line.slice(split + 1).trim();
    const parts = splitTopLevel(value, ',');
    root[key] = forceArray || parts.length > 1 || ARRAY_KEYS.has(key) ? parts.map((part) => scalar(part)) : scalar(value);
    lastKey = key;
  }
  if (Object.keys(root).length === 0) return undefined;
  return artifact === 'gradle.properties' ? { properties: root } : root;
}

// ---------------------------------------------------------------------------
// requirements.txt
// ---------------------------------------------------------------------------

export function readRequirements(content: string): unknown | undefined {
  const requirements: Array<Record<string, unknown>> = [];
  for (const raw of boundedText(content)) {
    const line = stripComment(raw, ['#']).trim();
    if (line.length === 0 || line.startsWith('-')) continue;
    const match = line.match(/^([A-Za-z0-9._-]+)\s*(.*)$/);
    if (match === null) continue;
    const name = match[1] ?? '';
    const rest = (match[2] ?? '').trim();
    const entry: Record<string, unknown> = { name, specifier: '' };
    const stripped = rest.replace(/^\[[^\]]+\]\s*/, '');
    const extras = rest.match(/^\[([^\]]+)\]/);
    if (extras !== null) entry['extras'] = splitTopLevel(extras[1] ?? '', ',');
    const direct = stripped.match(/^@\s+(\S+)/);
    if (direct !== null) entry['source'] = direct[1] ?? '';
    else {
      const specifier = stripped.match(/(?:[=<>~!]=?|@)\s*[^\s]+(?:\s*,\s*[^\s]+)*/);
      entry['specifier'] = specifier?.[0]?.trim() ?? '';
    }
    const hashes = [...rest.matchAll(/--hash=([^\s]+)/g)].map((item) => item[1] ?? '');
    if (hashes.length > 0) entry['hashes'] = hashes;
    requirements.push(entry);
    if (requirements.length >= READER_MAX_NODES) break;
  }
  return requirements.length > 0 ? { requirements } : undefined;
}

// ---------------------------------------------------------------------------
// go.mod (used by both `ini` and `lockfile-text` rules)
// ---------------------------------------------------------------------------

function readGoMod(content: string): unknown | undefined {
  const out: Record<string, unknown> = { require: [], replace: [], exclude: [], retract: [] };
  let block: 'require' | 'replace' | 'exclude' | 'retract' | undefined;
  for (const raw of boundedText(content)) {
    const line = stripComment(raw, ['//']).trim();
    if (line.length === 0) continue;
    if (line.endsWith('(')) { block = line.slice(0, -1).trim() as typeof block; continue; }
    if (line === ')') { block = undefined; continue; }
    const parts = line.split(/\s+/);
    const head = parts[0] ?? '';
    if (block === 'require' || head === 'require') {
      const [module, version] = block === 'require' ? parts : parts.slice(1);
      (out['require'] as unknown[]).push({ module: module ?? '', version: unquote(version ?? '') });
    } else if (block === 'replace' || head === 'replace') {
      const target = block === 'replace' ? parts : parts.slice(1);
      (out['replace'] as unknown[]).push({ old: { path: target[0] ?? '' }, new: { path: target[2] ?? target[0] ?? '', version: unquote(target[3] ?? '') } });
    } else if (block === 'exclude' || head === 'exclude') {
      (out['exclude'] as unknown[]).push({ module: parts[block === 'exclude' ? 0 : 1] ?? '', version: unquote(parts[block === 'exclude' ? 1 : 2] ?? '') });
    } else if (block === 'retract' || head === 'retract') {
      (out['retract'] as unknown[]).push({ version: unquote(parts[block === 'retract' ? 0 : 1] ?? '') });
    } else if (head === 'module' || head === 'go') {
      out[head] = unquote(parts.slice(1).join(' '));
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Gradle (bounded block scanner)
// ---------------------------------------------------------------------------

function extractBlock(text: string, header: string): string {
  const start = text.indexOf(header);
  if (start < 0) return '';
  const open = text.indexOf('{', start);
  if (open < 0) return '';
  let depth = 0;
  for (let i = open; i < text.length; i += 1) {
    if (text[i] === '{') depth += 1;
    else if (text[i] === '}') {
      depth -= 1;
      if (depth === 0) return text.slice(open + 1, i);
    }
  }
  return '';
}

function repositoriesFrom(text: string): Array<Record<string, unknown>> {
  const out: Array<Record<string, unknown>> = [];
  const pattern = /maven\s*\{([^}]*)\}|url\s*\(?['"]([^'"]+)['"]\)?/g;
  for (const match of text.matchAll(pattern)) {
    const body = match[1] ?? '';
    const url = match[2] ?? body.match(/(?:url|setUrl)\s*\(?['"]([^'"]+)['"]\)?/)?.[1] ?? '';
    const name = body.match(/name\s+['"]([^'"]+)['"]/)?.[1] ?? (out.length === 0 ? 'acme' : `repo${out.length}`);
    out.push({ name, url });
    if (out.length > 50) break;
  }
  return out;
}

export function readGradle(content: string, artifact: string): unknown | undefined {
  const text = content.slice(0, READER_MAX_BYTES);
  const dependencies: string[] = [];
  const depBlock = text.match(/dependencies\s*\{([\s\S]*?)\}/)?.[1] ?? '';
  for (const line of depBlock.split('\n')) {
    const found = line.trim().match(/['"]([^'"]{1,160})['"]/);
    if (found !== null) dependencies.push(found[1] ?? '');
  }
  if (artifact === 'settings.gradle') {
    return {
      pluginManagement: { repositories: repositoriesFrom(extractBlock(text, 'pluginManagement')) },
      dependencyResolutionManagement: { repositories: repositoriesFrom(extractBlock(text, 'dependencyResolutionManagement')) },
    };
  }
  return { repositories: repositoriesFrom(text), dependencies };
}

// ---------------------------------------------------------------------------
// lockfile-text (artifact-specific bounded line readers)
// ---------------------------------------------------------------------------

function readLockfileText(content: string, artifact: string): unknown | undefined {
  const lines = boundedText(content).map((line) => line.trim()).filter((line) => line.length > 0);
  if (artifact === 'go.mod') return readGoMod(content);
  if (artifact === 'yarn.lock') {
    const entries: Array<Record<string, unknown>> = [];
    let current: Record<string, unknown> | undefined;
    for (const line of lines) {
      if (line.endsWith(':') && !line.startsWith(' ')) {
        const header = line.slice(0, -1).split(',')[0] ?? '';
        const at = header.lastIndexOf('@');
        current = { name: at > 0 ? header.slice(0, at).replace(/^"/, '') : header, version: '' };
        entries.push(current);
        continue;
      }
      if (current === undefined) continue;
      const pair = line.match(/^([A-Za-z][A-Za-z0-9_-]*)\s+["']?([^"'\s]*)["']?/);
      if (pair !== null) current[pair[1] ?? ''] = unquote(pair[2] ?? '');
    }
    return { entries };
  }
  if (artifact === 'go.sum') {
    const entries: Array<Record<string, unknown>> = [];
    for (const line of lines) {
      const parts = line.split(/\s+/);
      if (parts.length >= 2) entries.push({ module: parts[0] ?? '', version: parts[1] ?? '', ...(parts[2] === undefined ? {} : { hash: parts[2] }) });
    }
    return { entries };
  }
  if (artifact === 'Gemfile') {
    let source = '';
    let gemspec = '';
    const gems: Array<Record<string, unknown>> = [];
    for (const line of lines) {
      const src = line.match(/^source\s+['"]([^'"]+)['"]/)?.[1];
      if (src !== undefined) source = src;
      const gem = line.match(/^gem\s+['"]([^'"]+)['"]\s*,?\s*(?:['"]([^'"]*)['"])?/);
      if (gem !== null) {
        const entry = { name: gem[1] ?? '', requirement: gem[2] ?? '' };
        const git = line.match(/git:\s*['"]([^'"]+)['"]/);
        const path = line.match(/path:\s*['"]([^'"]+)['"]/);
        gems.push({ ...entry, ...(git === null ? {} : { git: git[1] ?? '' }), ...(path === null ? {} : { path: path[1] ?? '' }) });
      }
      const gemspecMatch = line.match(/^gemspec(?:\s+path:)?\s*['"]([^'"]+)['"]/);
      if (gemspecMatch !== null) gemspec = gemspecMatch[1] ?? '';
    }
    return { source, gems, ...(gemspec.length > 0 ? { gemspec } : {}) };
  }
  if (artifact === 'Gemfile.lock') {
    const specs: Array<Record<string, unknown>> = [];
    let rubyVersion = '';
    let bundledWith = '';
    let inSpecs = false;
    for (const line of lines) {
      if (line.startsWith('specs:')) { inSpecs = true; continue; }
      if (line.startsWith('PLATFORMS') || line.startsWith('DEPENDENCIES') || line.startsWith('BUNDLED WITH')) inSpecs = false;
      if (inSpecs) {
        const found = line.match(/^([A-Za-z0-9._-]+)\s+\(([^)]+)\)/);
        if (found !== null) specs.push({ name: found[1] ?? '', version: found[2] ?? '' });
      }
      if (line.startsWith('RUBY VERSION')) rubyVersion = lines[lines.indexOf(line) + 1] ?? '';
      if (line === 'BUNDLED WITH') bundledWith = lines[lines.indexOf(line) + 1] ?? '';
    }
    return { specs, ruby_version: rubyVersion, bundled_with: bundledWith };
  }
  if (artifact === 'mix.exs') {
    let app = '';
    const deps: Array<Record<string, unknown>> = [];
    for (const line of lines) {
      const foundApp = line.match(/app:\s*:([A-Za-z0-9_]+)/)?.[1];
      if (foundApp !== undefined) app = foundApp;
      const foundDep = line.match(/\{:([A-Za-z0-9_]+)\s*,\s*["']([^"']*)["']/);
      if (foundDep !== null) {
        const git = line.match(/git:\s*["']([^"']+)["']/);
        deps.push({ name: foundDep[1] ?? '', requirement: foundDep[2] ?? '', ...(git === null ? {} : { git: git[1] ?? '' }) });
      }
    }
    return { project: { app }, deps };
  }
  if (artifact === 'mix.lock') {
    const packages: Record<string, unknown> = {};
    for (const line of lines) {
      const found = line.match(/["']([A-Za-z0-9_.-]+)["']\s*=>\s*\{:hex,\s*:?[A-Za-z0-9_]+,\s*["']([^"']+)["']/);
      if (found !== null) {
        const hash = line.match(/["']hash["']:\s*["']([^"']+)["']/);
        packages[found[1] ?? ''] = { version: found[2] ?? '', ...(hash === null ? {} : { hash: hash[1] ?? '' }) };
      }
    }
    return { packages };
  }
  if (artifact === 'Podfile') {
    const sources: string[] = [];
    const pods: Array<Record<string, unknown>> = [];
    for (const line of lines) {
      const src = line.match(/^source\s+['"]([^'"]+)['"]/)?.[1];
      if (src !== undefined) sources.push(src);
      const pod = line.match(/^pod\s+['"]([^'"]+)['"]\s*,?\s*(?:['"]([^'"]*)['"])?/);
      if (pod !== null) {
        const git = line.match(/(?::git|git)\s*=>\s*["']([^"']+)["']/);
        const path = line.match(/(?::path|path)\s*=>\s*["']([^"']+)["']/);
        pods.push({ name: pod[1] ?? '', requirement: pod[2] ?? '', ...(git === null ? {} : { git: git[1] ?? '' }), ...(path === null ? {} : { path: path[1] ?? '' }) });
      }
    }
    return { sources, pods };
  }
  if (artifact === 'Package.swift') {
    const dependencies: Array<Record<string, unknown>> = [];
    for (const line of lines) {
      const url = line.match(/\.package\s*\([^)]*url:\s*["']([^"']+)["']/)?.[1];
      if (url === undefined) continue;
      const branch = line.match(/branch:\s*["']([^"']+)["']/)?.[1];
      const version = line.match(/from:\s*["']([^"']+)["']/)?.[1];
      dependencies.push({ url, ...(branch === undefined ? {} : { requirement: { branch } }), ...(version === undefined ? {} : { requirement: { version } }) });
    }
    return { dependencies };
  }
  if (artifact === 'Cargo.lock') {
    const packages: Array<Record<string, unknown>> = [];
    let version: unknown;
    let current: Record<string, unknown> | undefined;
    for (const line of lines) {
      if (line.startsWith('version =')) version = scalar(line.slice(line.indexOf('=') + 1));
      if (line === '[[package]]') { current = {}; packages.push(current); continue; }
      if (current === undefined) continue;
      const eq = line.indexOf('=');
      if (eq > 0) current[line.slice(0, eq).trim()] = scalar(line.slice(eq + 1));
    }
    return { version, packages };
  }
  // Generic fallback: a bounded list of entries for unknown lockfile shapes.
  const entries = lines.slice(0, 200).map((line) => ({ line }));
  return entries.length > 0 ? { entries } : undefined;
}

// ---------------------------------------------------------------------------
// Public dispatcher
// ---------------------------------------------------------------------------

/** Parse a real artifact into the normalized document the rules expect. */
export function parseDeclarationDocument(parser: ScaParser, artifact: string, content: string): unknown | undefined {
  if (typeof content !== 'string' || content.length === 0) return undefined;
  if (artifact === 'DESCRIPTION') return readProperties(content, artifact);
  if (artifact === 'go.mod') return readGoMod(content);
  switch (parser) {
    case 'json': {
      try { return JSON.parse(content.slice(0, READER_MAX_BYTES)) as unknown; } catch { return undefined; }
    }
    case 'toml': {
      const doc = readToml(content);
      if (!isRecord(doc)) return doc;
      if (artifact === 'Cargo.lock' && Array.isArray(doc['package'])) return { ...doc, packages: doc['package'] };
      return doc;
    }
    case 'yaml': return readYaml(content);
    case 'xml': return readXml(content);
    case 'ini': return readIni(content, artifact);
    case 'properties': return readProperties(content, artifact);
    case 'requirements': return readRequirements(content);
    case 'gradle': return readGradle(content, artifact);
    case 'lockfile-text': return readLockfileText(content, artifact);
    default: return undefined;
  }
}

/** Closed registry: every parser kind the dataset uses has a reader. */
export const DECLARATION_READER_PARSERS: readonly ScaParser[] = [
  'json', 'toml', 'yaml', 'requirements', 'xml', 'gradle', 'properties', 'ini', 'lockfile-text',
];

export type { Json };
