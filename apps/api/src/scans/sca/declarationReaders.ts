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
import { maskComments, maskLiterals } from '../sast/semantic.js';

export const READER_MAX_BYTES = 262_144;
export const READER_MAX_LINES = 8_000;
export const READER_MAX_DEPTH = 64;
export const READER_MAX_NODES = 2_000;

type Json = Record<string, unknown> | unknown[] | string | number | boolean | null;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Untrusted manifest keys must never reach an Object.prototype-backed map. */
function emptyMap(): Record<string, unknown> {
  return Object.create(null) as Record<string, unknown>;
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

function assign(root: Record<string, unknown>, path: readonly string[], value: unknown): void {
  if (path.length === 0 || path.length > READER_MAX_DEPTH) return;
  let cursor: Record<string, unknown> = root;
  for (let i = 0; i < path.length - 1; i += 1) {
    const key = path[i] ?? '';
    const next = cursor[key];
    if (!isRecord(next)) cursor[key] = emptyMap();
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

function inlineValue(raw: string, depth = 0): unknown {
  if (depth > READER_MAX_DEPTH) throw new RangeError('Declaration nesting limit exceeded.');
  const text = raw.trim();
  if (text.startsWith('[') && text.endsWith(']')) {
    return splitTopLevel(text.slice(1, -1), ',').map((part) => inlineValue(part, depth + 1));
  }
  if (text.startsWith('{') && text.endsWith('}')) {
    const out = emptyMap();
    for (const part of splitTopLevel(text.slice(1, -1), ',')) {
      const eq = part.indexOf('=');
      if (eq < 0) continue;
      out[unquote(part.slice(0, eq).trim())] = inlineValue(part.slice(eq + 1), depth + 1);
    }
    return out;
  }
  return scalar(text);
}

export function readToml(content: string): unknown | undefined {
  const root = emptyMap();
  let container = root;
  let nodeCount = 0;
  let pending: { path: string[]; raw: string } | undefined;

  const flush = (): void => {
    if (pending === undefined) return;
    assign(container, pending.path, inlineValue(pending.raw));
    pending = undefined;
  };

  const sectionAt = (path: readonly string[]): Record<string, unknown> => {
    if (path.length > READER_MAX_DEPTH) throw new RangeError('Declaration nesting limit exceeded.');
    let cursor = root;
    for (const key of path) {
      const next = cursor[key];
      if (Array.isArray(next)) {
        const last = next[next.length - 1];
        if (!isRecord(last)) throw new TypeError('Invalid table array.');
        cursor = last;
      } else {
        if (!isRecord(next)) cursor[key] = emptyMap();
        cursor = cursor[key] as Record<string, unknown>;
      }
    }
    return cursor;
  };

  for (const rawLine of boundedText(content)) {
    const line = stripComment(rawLine, ['#']).trim();
    if (line.length === 0) continue;
    if (line.startsWith('[[') && line.endsWith(']]')) {
      flush();
      const path = splitTopLevel(line.slice(2, -2), '.').map(unquote);
      const key = path.pop();
      if (key === undefined || key.length === 0) return undefined;
      const parent = sectionAt(path);
      if (!Array.isArray(parent[key])) parent[key] = [];
      container = emptyMap();
      (parent[key] as unknown[]).push(container);
      continue;
    }
    if (line.startsWith('[') && line.endsWith(']')) {
      flush();
      const path = splitTopLevel(line.slice(1, -1), '.').map(unquote);
      if (path.length === 0 || path.some((part) => part.length === 0)) return undefined;
      // Materialize empty tables too: their presence matters to absence rules.
      container = sectionAt(path);
      continue;
    }
    if (pending === undefined) {
      const eq = line.indexOf('=');
      if (eq < 0) continue;
      pending = { path: splitTopLevel(line.slice(0, eq), '.').map(unquote), raw: line.slice(eq + 1).trim() };
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
  let exceeded = false;

  const parseNode = (indent: number, depth: number): unknown => {
    if (depth > READER_MAX_DEPTH || nodes >= READER_MAX_NODES) { exceeded = true; return undefined; }
    if (index >= lines.length) return undefined;
    nodes += 1;
    const current = lines[index];
    if (current === undefined) return undefined;
    if (current.text === '-' || current.text.startsWith('- ')) {
      const list: unknown[] = [];
      while (index < lines.length) {
        const line = lines[index];
        if (line === undefined || line.indent !== indent || (line.text !== '-' && !line.text.startsWith('- '))) break;
        const rest = line.text.slice(1).trim();
        index += 1;
        if (rest.length === 0) {
          const next = lines[index];
          list.push(next !== undefined && next.indent > indent ? parseNode(next.indent, depth + 1) : null);
          continue;
        }
        // A colon in an unquoted URL is not a mapping separator.
        const colon = rest.search(/:(?=\s|$)/);
        if (colon > 0 && !rest.startsWith('"') && !rest.startsWith("'")) {
          const entry = emptyMap();
          const firstValue = rest.slice(colon + 1).trim();
          const next = lines[index];
          entry[unquote(rest.slice(0, colon).trim())] = firstValue.length > 0 ? inlineValue(firstValue)
            : next !== undefined && next.indent > indent + 2 ? parseNode(next.indent, depth + 1) : emptyMap();
          while (index < lines.length) {
            const child = lines[index];
            if (child === undefined || child.indent <= indent) break;
            const childColon = child.text.search(/:(?=\s|$)/);
            if (childColon < 0) { index += 1; continue; }
            index += 1;
            const childValue = child.text.slice(childColon + 1).trim();
            const nested = lines[index];
            entry[unquote(child.text.slice(0, childColon).trim())] = childValue.length > 0 ? inlineValue(childValue)
              : nested !== undefined && nested.indent > child.indent ? parseNode(nested.indent, depth + 1) : emptyMap();
          }
          list.push(entry);
        } else if (rest.startsWith('[') && rest.endsWith(']')) {
          list.push(...splitTopLevel(rest.slice(1, -1), ',').map((part) => inlineValue(part)));
        } else {
          list.push(inlineValue(rest));
        }
        if (list.length > READER_MAX_NODES) break;
      }
      return list;
    }
    const out = emptyMap();
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
        out[key] = next !== undefined && next.indent > indent ? parseNode(next.indent, depth + 1) : emptyMap();
      } else if (rest.startsWith('[') && rest.endsWith(']')) {
        out[key] = splitTopLevel(rest.slice(1, -1), ',').map((part) => inlineValue(part));
      } else if (rest.startsWith('{') && rest.endsWith('}')) {
        out[key] = inlineValue(rest);
      } else {
        out[key] = inlineValue(rest);
      }
      if (Object.keys(out).length > READER_MAX_NODES) break;
    }
    return out;
  };

  const result = parseNode(lines[0]?.indent ?? 0, 0);
  return exceeded || result === undefined ? undefined : result;
}

// ---------------------------------------------------------------------------
// XML (elements + attributes, repeated children → arrays)
// ---------------------------------------------------------------------------

interface XmlNode { name: string; attributes: Record<string, unknown>; children: XmlNode[]; text: string }

function xmlName(name: string): string {
  if (/Group$/.test(name) && /^[A-Z]/.test(name)) return name[0]?.toLowerCase() + name.slice(1);
  return name;
}

// XML's five predefined entities and bounded numeric character references only.
// No DTD, external entity, recursive expansion, network or filesystem access.
function decodeXmlReferences(value: string): string | undefined {
  const named: Record<string, string> = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" };
  const validCodePoint = (code: number): boolean => code === 9 || code === 10 || code === 13 ||
    (code >= 0x20 && code <= 0xd7ff) || (code >= 0xe000 && code <= 0xfffd) || (code >= 0x10000 && code <= 0x10ffff);
  let result = '';
  for (let index = 0; index < value.length; index += 1) {
    if (value[index] !== '&') {
      const code = value.codePointAt(index);
      if (code === undefined || !validCodePoint(code)) return undefined;
      result += String.fromCodePoint(code);
      if (code > 0xffff) index += 1;
      continue;
    }
    const end = value.indexOf(';', index + 1);
    if (end < 0 || end - index > 18) return undefined;
    const reference = value.slice(index + 1, end);
    let replacement = Object.hasOwn(named, reference) ? named[reference] : undefined;
    if (replacement === undefined && /^(?:#[0-9]+|#x[0-9a-fA-F]+)$/.test(reference)) {
      const hex = reference.startsWith('#x');
      const code = Number.parseInt(reference.slice(hex ? 2 : 1), hex ? 16 : 10);
      if (!validCodePoint(code)) return undefined;
      replacement = String.fromCodePoint(code);
    }
    if (replacement === undefined) return undefined;
    result += replacement;
    index = end;
  }
  return result;
}

// Ignore comments and processing instructions without interpreting tag-like
// text inside them. Unsupported declarations/CDATA fail closed.
function maskXmlTrivia(text: string): string | undefined {
  const pieces: string[] = [];
  let cursor = 0;
  for (let index = 0; index < text.length; index += 1) {
    const comment = text.startsWith('<!--', index);
    const instruction = text.startsWith('<?', index);
    if (!comment && !instruction) {
      if (text.startsWith('<!', index)) return undefined;
      continue;
    }
    const closer = comment ? '-->' : '?>';
    const end = text.indexOf(closer, index + (comment ? 4 : 2));
    if (end < 0 || (comment && text.slice(index + 4, end).includes('--'))) return undefined;
    const after = end + closer.length;
    pieces.push(text.slice(cursor, index), text.slice(index, after).replace(/[^\r\n]/g, ' '));
    cursor = after;
    index = after - 1;
  }
  pieces.push(text.slice(cursor));
  return pieces.join('');
}

export function readXml(content: string): unknown | undefined {
  const input = content.slice(0, READER_MAX_BYTES);
  // Reject declarations/entities; this is a bounded reader, not an XML processor.
  if (/<!\s*(?:DOCTYPE|ENTITY)\b/i.test(input)) return undefined;
  const text = maskXmlTrivia(input);
  if (text === undefined) return undefined;
  // Deliberately conservative: angle brackets in attributes are unsupported.
  const tagPattern = /<(\/?)([A-Za-z_][\w:.-]*)([^<>]*?)(\/?)>/g;
  const root: XmlNode = { name: '#root', attributes: {}, children: [], text: '' };
  const stack: XmlNode[] = [root];
  let cursor = 0;
  let nodes = 0;
  for (const match of text.matchAll(tagPattern)) {
    nodes += 1;
    if (nodes > READER_MAX_NODES) return undefined;
    const closing = match[1] === '/';
    const name = match[2] ?? '';
    const attrText = match[3] ?? '';
    const selfClosing = match[4] === '/';
    const parent = stack[stack.length - 1];
    if (parent === undefined) return undefined;
    const between = text.slice(cursor, match.index);
    // XML character data may not contain a literal CDATA terminator. Outside
    // the single root, only the four XML whitespace characters are allowed.
    if (between.includes('<') || between.includes(']]>') ||
        (stack.length === 1 && !/^[ \t\r\n]*$/.test(between))) return undefined;
    const decoded = decodeXmlReferences(between.trim());
    if (decoded === undefined) return undefined;
    parent.text += decoded;
    cursor = (match.index ?? 0) + (match[0]?.length ?? 0);
    if (closing) {
      if (!/^[ \t\r\n]*$/.test(attrText) || selfClosing || stack.length <= 1 || parent.name !== xmlName(name)) return undefined;
      stack.pop();
      continue;
    }
    const attributes = emptyMap();
    const attrPattern = /([A-Za-z_][\w:.-]*)[ \t\r\n]*=[ \t\r\n]*("([^"]*)"|'([^']*)')/g;
    let attrCursor = 0;
    for (const attr of attrText.matchAll(attrPattern)) {
      // Attribute boundaries require XML whitespace; adjacent attributes and
      // non-XML Unicode whitespace are malformed, not empty separators.
      if (!/^[ \t\r\n]+$/.test(attrText.slice(attrCursor, attr.index))) return undefined;
      const key = xmlName(attr[1] ?? '');
      const value = decodeXmlReferences(attr[3] ?? attr[4] ?? '');
      if (value === undefined || Object.hasOwn(attributes, key)) return undefined;
      attributes[key] = value;
      attrCursor = (attr.index ?? 0) + (attr[0]?.length ?? 0);
    }
    if (!/^[ \t\r\n]*$/.test(attrText.slice(attrCursor))) return undefined;
    const node: XmlNode = { name: xmlName(name), attributes, children: [], text: '' };
    parent.children.push(node);
    if (!selfClosing) {
      if (stack.length >= READER_MAX_DEPTH) return undefined;
      stack.push(node);
    }
  }
  if (stack.length !== 1 || root.children.length !== 1 || !/^[ \t\r\n]*$/.test(text.slice(cursor))) return undefined;

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
    const out = Object.assign(emptyMap(), node.attributes);
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

/** Normalize the two NuGet formats used by the declaration pack. */
function normalizeNugetXml(document: unknown, artifact: string): unknown {
  if (!isRecord(document)) return document;
  if (artifact === 'packages.config') {
    const packages = document['packages'];
    if (!Array.isArray(packages)) return document;
    const framework = packages.find((entry) => isRecord(entry) && typeof entry['targetFramework'] === 'string');
    return { ...document, ...(isRecord(framework) ? { targetFramework: framework['targetFramework'] } : {}) };
  }
  if (artifact.toLowerCase() !== 'nuget.config') return document;
  const body = isRecord(document['configuration']) ? document['configuration'] : document;
  const result = Object.assign(emptyMap(), body);
  const packageSources = body['packageSources'];
  const sourceMap = isRecord(packageSources) ? packageSources : undefined;
  const rawSources = Array.isArray(packageSources) ? packageSources : sourceMap?.['add'];
  const sources = (Array.isArray(rawSources) ? rawSources : rawSources === undefined ? [] : [rawSources]).filter(isRecord).map((entry) => ({ ...entry }));
  const credentials = body['packageSourceCredentials'];
  if (isRecord(credentials)) {
    for (const source of sources) {
      const block = typeof source['key'] === 'string' ? credentials[source['key']] : undefined;
      const rawEntries = isRecord(block) ? block['add'] : block;
      const entries = Array.isArray(rawEntries) ? rawEntries : rawEntries === undefined ? [] : [rawEntries];
      for (const entry of entries) {
        if (isRecord(entry) && typeof entry['key'] === 'string' && /^(?:cleartext)?password$/i.test(entry['key']) && typeof entry['value'] === 'string') {
          source['password'] = entry['value'];
        }
      }
    }
  }
  if (packageSources !== undefined) {
    const normalized = Object.assign(emptyMap(), sourceMap ?? {});
    if (rawSources !== undefined) normalized['add'] = sources;
    normalized['clear'] = sourceMap?.['clear'] !== undefined;
    result['packageSources'] = normalized;
    result['sources'] = sources;
  }
  const config = body['config'];
  if (isRecord(config) || Array.isArray(config)) {
    const rawEntries = Array.isArray(config) ? config : config['add'];
    const entries = Array.isArray(rawEntries) ? rawEntries : rawEntries === undefined ? [] : [rawEntries];
    const values = isRecord(config) ? Object.assign(emptyMap(), config) : emptyMap();
    for (const entry of entries) {
      if (isRecord(entry) && typeof entry['key'] === 'string' && typeof entry['value'] === 'string') values[entry['key']] = entry['value'];
    }
    result['config'] = values;
    if (values['signatureValidationMode'] !== undefined) {
      const settings = isRecord(body['settings']) ? body['settings'] : emptyMap();
      result['settings'] = { ...settings, signatureValidationMode: values['signatureValidationMode'] };
    }
  }
  return result;
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
    if (!isRecord(current[key])) current[key] = emptyMap();
    current = current[key] as Record<string, unknown>;
  }
  return current;
}

export function readIni(content: string, artifact: string): unknown | undefined {
  if (artifact === 'conanfile.txt') {
    const result = emptyMap();
    let section = '';
    for (const raw of boundedText(content)) {
      // Conan revisions contain '#'; only whitespace-prefixed '#' starts a comment.
      const line = raw.replace(/(?:^|\s)[#;].*$/, '').trim();
      if (line.length === 0) continue;
      if (line.startsWith('[') && line.endsWith(']')) { section = line.slice(1, -1).trim(); continue; }
      if (section === 'requires' || section === 'generators' || section === 'tool_requires') {
        const list = Array.isArray(result[section]) ? result[section] as string[] : [];
        list.push(line);
        result[section] = list;
      } else if (section.length === 0) {
        // Accept the simple key[] form used by existing bounded fixtures too.
        const entry = line.match(/^([A-Za-z_]+)\[\]\s*[=:]\s*(.*)$/);
        if (entry !== null) result[entry[1] ?? ''] = splitTopLevel(entry[2] ?? '', ',').map(unquote);
      }
    }
    return Object.keys(result).length > 0 ? result : undefined;
  }
  const root = emptyMap();
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
  const root = emptyMap();
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
  const options = emptyMap();
  const rootOptions = emptyMap();
  let unsupported = false;
  for (const raw of boundedText(content)) {
    // A URL fragment (e.g. #egg or #sha256) is not a pip comment.
    const line = raw.replace(/(?:^|\s)#.*$/, '').trim();
    if (line.length === 0) continue;
    // An explicit empty argument (--option=) is accepted by pip; a missing
    // argument (--option) remains unsupported. Do not turn either form into
    // an invented non-empty value or silently ignore unknown options.
    const option = line.match(/^(?:--(index-url|extra-index-url|trusted-host|no-binary)|(-i))(?:(?:=(\S*)|\s+(\S+)))?$/);
    if (option !== null) {
      const value = option[3] ?? option[4];
      if (value === undefined) { unsupported = true; continue; }
      const key = option[2] === '-i' ? 'index-url' : (option[1] ?? '');
      if (key === 'trusted-host') {
        const hosts = Array.isArray(options['trusted_host']) ? options['trusted_host'] as string[] : [];
        hosts.push(value);
        options['trusted_host'] = hosts;
      } else options[key.replace(/-/g, '_')] = value;
      rootOptions[key] = value;
      continue;
    }
    if (line.startsWith('-')) { unsupported = true; continue; }
    const match = line.match(/^([A-Za-z0-9._-]+)\s*(.*)$/);
    if (match === null) { unsupported = true; continue; }
    const name = match[1] ?? '';
    const rest = (match[2] ?? '').trim();
    const entry: Record<string, unknown> = { name, specifier: '' };
    const stripped = rest.replace(/^\[[^\]]+\]\s*/, '');
    const extras = rest.match(/^\[([^\]]+)\]/);
    if (extras !== null) entry['extras'] = splitTopLevel(extras[1] ?? '', ',');
    const direct = stripped.match(/^@\s+(\S+)/);
    if (direct !== null) {
      entry['source'] = direct[1] ?? '';
      entry['specifier'] = stripped;
    } else {
      // Keep PEP 508 environment markers as part of the declaration.
      const specifier = stripped.replace(/\s+--hash(?:=|\s+)\S+/g, '').trim();
      entry['specifier'] = /^[=<>~!@;]/.test(specifier) ? specifier : '';
    }
    const hashes = [...rest.matchAll(/--hash=([^\s]+)/g)].map((item) => item[1] ?? '');
    if (hashes.length > 0) entry['hashes'] = hashes;
    requirements.push(entry);
    if (requirements.length >= READER_MAX_NODES) break;
  }
  // Includes, editable installs and unknown options may introduce additional
  // declarations; do not turn an incompletely read file into an absence claim.
  if (unsupported) return undefined;
  return { requirements, ...rootOptions, ...(Object.keys(options).length > 0 ? { options } : {}) };
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
      const indirect = /\/\/\s*indirect\s*$/.test(raw);
      (out['require'] as unknown[]).push({ module: module ?? '', version: unquote(version ?? ''), ...(indirect ? { indirect: true } : {}) });
    } else if (block === 'replace' || head === 'replace') {
      const target = block === 'replace' ? parts : parts.slice(1);
      const arrow = target.indexOf('=>');
      if (arrow < 1 || target[arrow + 1] === undefined) continue;
      const nextVersion = target[arrow + 2];
      (out['replace'] as unknown[]).push({ old: { path: target[0] ?? '' }, new: { path: target[arrow + 1], version: unquote(nextVersion ?? '') } });
    } else if (block === 'exclude' || head === 'exclude') {
      (out['exclude'] as unknown[]).push({ module: parts[block === 'exclude' ? 0 : 1] ?? '', version: unquote(parts[block === 'exclude' ? 1 : 2] ?? '') });
    } else if (block === 'retract' || head === 'retract') {
      (out['retract'] as unknown[]).push({ version: unquote(parts[block === 'retract' ? 0 : 1] ?? '') });
    } else if (head === 'module' || head === 'go' || head === 'toolchain') {
      out[head] = unquote(parts.slice(1).join(' '));
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Gradle (bounded block scanner)
// ---------------------------------------------------------------------------

interface NamedBlock { body: string; start: number }

/** Locate bounded DSL blocks without counting braces inside strings/comments. */
function namedBlocks(text: string, header: string): NamedBlock[] {
  const visible = maskLiterals(text, 'groovy');
  const pattern = new RegExp(`\\b${header}\\s*\\{`, 'g');
  const result: NamedBlock[] = [];
  let previousClose = 0;
  for (const match of visible.matchAll(pattern)) {
    if (result.length >= 50) break;
    if ((match.index ?? 0) < previousClose) continue;
    const open = (match.index ?? 0) + match[0].lastIndexOf('{');
    let depth = 1;
    let close = open + 1;
    for (; close < visible.length && depth > 0; close += 1) {
      if (visible[close] === '{') depth += 1;
      else if (visible[close] === '}') depth -= 1;
      if (depth > READER_MAX_DEPTH) return [];
    }
    if (depth !== 0) return [];
    result.push({ body: text.slice(open + 1, close - 1), start: match.index ?? 0 });
    previousClose = close;
  }
  return result;
}

function extractBlock(text: string, header: string): string {
  // Python literal maps have an assignment before the opening brace.
  if (header === 'remotes') {
    const open = text.indexOf('{');
    if (open < 0) return '';
    let depth = 0;
    let quote = '';
    for (let i = open; i < text.length; i += 1) {
      const char = text[i] ?? '';
      if (quote !== '') { if (char === '\\') i += 1; else if (char === quote) quote = ''; continue; }
      if (char === '"' || char === "'") { quote = char; continue; }
      if (char === '{') depth += 1;
      else if (char === '}' && --depth === 0) return text.slice(open + 1, i);
      if (depth > READER_MAX_DEPTH) return '';
    }
    return '';
  }
  return namedBlocks(text, header)[0]?.body ?? '';
}

function repositoriesFrom(text: string): Array<Record<string, unknown>> {
  const items: Array<{ start: number; value: Record<string, unknown> }> = [];
  for (const block of namedBlocks(text, 'maven')) {
    const body = block.body;
    const name = body.match(/\bname\s*(?:=\s*)?\(?\s*['"]([^'"]+)['"]/)?.[1];
    const url = body.match(/\b(?:url|setUrl)\s*(?:=\s*)?(?:uri\s*\()?\s*\(?\s*['"]([^'"]+)['"]/)?.[1];
    const insecure = body.match(/\b(?:allowInsecureProtocol|isAllowInsecureProtocol)\s*(?:=\s*)?(true|false)\b/)?.[1];
    const credentialBlock = namedBlocks(body, 'credentials')[0];
    const username = credentialBlock?.body.match(/\busername\s*(?:=\s*)?['"]([^'"]*)['"]/)?.[1];
    const password = credentialBlock?.body.match(/\bpassword\s*(?:=\s*)?['"]([^'"]*)['"]/)?.[1];
    const contentBlock = namedBlocks(body, 'content')[0];
    const mavenContent = namedBlocks(body, 'mavenContent')[0];
    items.push({ start: block.start, value: {
      ...(name === undefined ? {} : { name }), ...(url === undefined ? {} : { url }),
      ...(insecure === undefined ? {} : { allowInsecureProtocol: insecure === 'true' }),
      ...(credentialBlock === undefined ? {} : { credentials: { ...(username === undefined ? {} : { username }), ...(password === undefined ? {} : { password }) } }),
      ...(contentBlock === undefined ? {} : { content: {} }),
      ...(mavenContent === undefined ? {} : { mavenContent: { snapshotsOnly: /\bsnapshotsOnly\s*\(/.test(maskLiterals(mavenContent.body, 'groovy')) } }),
    } });
  }
  for (const block of namedBlocks(text, 'flatDir')) {
    const dirs = [...block.body.matchAll(/['"]([^'"]+)['"]/g)].map((match) => match[1] ?? '');
    items.push({ start: block.start, value: { name: 'flatDir', flatDir: true, dirs } });
  }
  const visible = maskLiterals(text, 'groovy');
  for (const match of visible.matchAll(/\b(mavenCentral|mavenLocal|gradlePluginPortal)\s*\(\s*\)/g)) {
    items.push({ start: match.index ?? 0, value: { name: match[1] ?? '' } });
  }
  return items.sort((a, b) => a.start - b.start).map((item) => item.value);
}

function gradlePlugins(text: string): Array<Record<string, unknown>> {
  const plugins: Array<Record<string, unknown>> = [];
  for (const line of text.split('\n')) {
    const found = line.match(/\bid\s*\(?\s*['"]([^'"]+)['"]\s*\)?/);
    if (found !== null) {
      const tail = line.slice((found.index ?? 0) + found[0].length);
      const version = tail.match(/^\s*version\s*\(?\s*['"]([^'"]+)['"]\s*\)?/)?.[1];
      // The DSL permits dynamic version expressions. A present but unknown
      // expression is not the same thing as a missing version field.
      const dynamicVersion = version === undefined && /^\s*version\b/.test(tail);
      plugins.push({ id: found[1] ?? '', ...(version === undefined ? (dynamicVersion ? { version: null } : {}) : { version }) });
    }
    if (plugins.length >= 100) break;
  }
  return plugins;
}

function gradleDependencies(text: string): Array<Record<string, unknown>> {
  const dependencies: Array<Record<string, unknown>> = [];
  const pattern = /^\s*([A-Za-z][A-Za-z0-9_]*)\s*\(?\s*['"]([^'"]{1,160})['"]/gm;
  const matches = [...text.matchAll(pattern)].slice(0, 200);
  for (const [index, found] of matches.entries()) {
    const notation = found[2] ?? '';
    const parts = notation.split(':');
    const tail = text.slice(found.index ?? 0, matches[index + 1]?.index ?? text.length);
    const changing = tail.match(/\bchanging\s*(?:=\s*)?(true|false)\b/)?.[1];
    const transitive = tail.match(/\btransitive\s*(?:=\s*)?(true|false)\b/)?.[1];
    const target = tail.match(/\btargetConfiguration\s*(?:=\s*)?['"]([^'"]+)['"]/)?.[1];
    const exclude = [...tail.matchAll(/\bexclude\s*\(?\s*group\s*[:=]\s*['"]([^'"]+)['"]/g)].map((match) => ({ group: match[1] ?? '' }));
    dependencies.push({ configuration: found[1] ?? '', notation,
      ...(parts.length >= 3 ? { group: parts[0], name: parts[1], version: parts.slice(2).join(':') } : {}),
      ...(changing === undefined ? {} : { changing: changing === 'true' }),
      ...(transitive === undefined ? {} : { transitive: transitive === 'true' }),
      ...(target === undefined ? {} : { targetConfiguration: target }),
      ...(exclude.length === 0 ? {} : { exclude }),
    });
  }
  return dependencies;
}

export function readGradle(content: string, artifact: string): unknown | undefined {
  const text = maskComments(content.slice(0, READER_MAX_BYTES), 'groovy');
  const visible = maskLiterals(text, 'groovy');
  let depth = 0;
  for (const char of visible) {
    if (char === '{') depth += 1;
    else if (char === '}') depth -= 1;
    if (depth < 0 || depth > READER_MAX_DEPTH) return undefined;
  }
  if (depth !== 0) return undefined;
  // An unrecognized Gradle DSL cannot safely be normalized to an empty
  // document: absence checks would turn unsupported syntax into findings.
  if (!/\b(?:repositories|dependencies|plugins|dependencyLocking|configurations|pluginManagement|dependencyResolutionManagement|dependencySubstitution)\s*\{/.test(visible)) return undefined;
  if (artifact === 'settings.gradle') {
    const pluginManagement = extractBlock(text, 'pluginManagement');
    const resolution = extractBlock(text, 'dependencyResolutionManagement');
    const plugins = namedBlocks(pluginManagement, 'plugins')[0];
    const metadata = namedBlocks(resolution, 'metadataSources')[0];
    const substitution = extractBlock(text, 'dependencySubstitution');
    const substitutions = [...substitution.matchAll(/\bsubstitute\s+module\s*\(\s*['"]([^'"]+)['"]\s*\)\s+using\s+project\s*\(\s*['"]([^'"]+)['"]\s*\)/g)]
      .map((match) => ({ module: match[1], substitute: { project: { path: match[2] } } }));
    return {
      pluginManagement: { repositories: repositoriesFrom(pluginManagement), ...(plugins === undefined ? {} : { plugins: gradlePlugins(plugins.body) }) },
      dependencyResolutionManagement: { repositories: repositoriesFrom(resolution), ...(metadata === undefined ? {} : { metadataSources: {} }) },
      ...(substitutions.length === 0 ? {} : { dependencySubstitution: substitutions }),
    };
  }
  const plugins = namedBlocks(text, 'plugins')[0];
  const locking = namedBlocks(text, 'dependencyLocking')[0];
  const configBlock = extractBlock(text, 'configurations');
  const forces = [...configBlock.matchAll(/\bforce\s*\(?\s*['"]([^'"]+)['"]/g)].map((match) => {
    const [group, name, version] = (match[1] ?? '').split(':');
    return { group, name, version };
  });
  return { repositories: namedBlocks(text, 'repositories').flatMap((block) => repositoriesFrom(block.body)),
    dependencies: namedBlocks(text, 'dependencies').flatMap((block) => gradleDependencies(block.body)),
    ...(plugins === undefined ? {} : { plugins: gradlePlugins(plugins.body) }),
    ...(locking === undefined ? {} : { dependencyLocking: { lockAllConfigurations: /\blockAllConfigurations\s*\(/.test(maskLiterals(locking.body, 'groovy')) } }),
    ...(forces.length === 0 ? {} : { configurations: [{ resolutionStrategy: { force: forces } }] }),
  };
}

// ---------------------------------------------------------------------------
// lockfile-text (artifact-specific bounded line readers)
// ---------------------------------------------------------------------------

function readLockfileText(content: string, artifact: string): unknown | undefined {
  const lines = boundedText(content).map((line) => line.trim()).filter((line) => line.length > 0);
  if (artifact === 'go.mod') return readGoMod(content);
  if (artifact === 'go.work') {
    const result: Record<string, unknown> = { use: [] };
    let inUse = false;
    let recognized = false;
    for (const raw of lines) {
      const line = stripComment(raw, ['//']).trim();
      if (line.length === 0) continue;
      if (line === 'use (') { inUse = true; recognized = true; continue; }
      if (line === ')' && inUse) { inUse = false; continue; }
      if (inUse) { (result['use'] as string[]).push(unquote(line)); continue; }
      const single = line.match(/^use\s+(.+)$/);
      if (single !== null) { (result['use'] as string[]).push(unquote(single[1] ?? '')); recognized = true; continue; }
      const version = line.match(/^go\s+(.+)$/);
      if (version !== null) { result['go'] = unquote(version[1] ?? ''); recognized = true; }
    }
    return recognized && !inUse ? result : undefined;
  }
  if (artifact === 'Podfile.lock') {
    const pods: Array<Record<string, unknown>> = [];
    const checksums = new Map<string, string>();
    let section = '';
    let recognized = false;
    for (const raw of boundedText(content)) {
      const line = raw.trim();
      if (/^[A-Z][A-Z ]+:$/.test(line) && !/^\s/.test(raw)) { section = line.slice(0, -1); recognized = true; continue; }
      if (section === 'PODS') {
        const pod = raw.match(/^\s{2}-\s+([^\s(]+)\s+\(([^)]+)\)/);
        if (pod !== null) pods.push({ name: pod[1] ?? '', version: pod[2] ?? '' });
      } else if (section === 'SPEC CHECKSUMS') {
        const checksum = line.match(/^([^:]+):\s*(\S+)$/);
        if (checksum !== null) checksums.set(checksum[1] ?? '', checksum[2] ?? '');
      }
    }
    for (const pod of pods) {
      const checksum = checksums.get(String(pod['name']).split('/')[0] ?? '');
      if (checksum !== undefined) pod['checksum'] = checksum;
    }
    return recognized ? { pods } : undefined;
  }
  if (artifact === 'conanfile.py') {
    // Read a literal remotes mapping only; never execute a Python recipe or
    // infer values computed by arbitrary expressions.
    const text = boundedText(content).map((line) => stripComment(line, ['#'])).join('\n');
    const start = text.search(/^\s*remotes\s*=\s*\{/m);
    if (start < 0) return undefined;
    const body = extractBlock(text.slice(start), 'remotes');
    const remotes = emptyMap();
    const entryPattern = /["']([A-Za-z0-9_.-]+)["']\s*:\s*\{([^{}]{0,2000})\}/g;
    for (const match of body.matchAll(entryPattern)) {
      const name = match[1] ?? '';
      const fields = match[2] ?? '';
      const url = fields.match(/["']url["']\s*:\s*["']([^"']+)["']/)?.[1];
      if (url === undefined) continue;
      const verify = fields.match(/["']verify_ssl["']\s*:\s*(True|False)/)?.[1];
      remotes[name] = { url, ...(verify === undefined ? {} : { verify_ssl: verify === 'True' }) };
    }
    return { remotes };
  }
  if (artifact === 'yarn.lock') {
    const entries: Array<Record<string, unknown>> = [];
    let current: Record<string, unknown> | undefined;
    for (const raw of boundedText(content)) {
      const line = raw.trim();
      if (line.length === 0 || line.startsWith('#')) continue;
      if (!/^\s/.test(raw) && line.endsWith(':')) {
        const header = unquote((line.slice(0, -1).split(',')[0] ?? '').trim());
        if (header === '__metadata') { current = undefined; continue; }
        const at = header.lastIndexOf('@');
        // Do not fabricate a version: a missing field is meaningful to rules.
        current = { name: at > 0 ? header.slice(0, at) : header };
        entries.push(current);
        continue;
      }
      if (current === undefined) continue;
      const pair = line.match(/^([A-Za-z][A-Za-z0-9_-]*)(?::\s*|\s+)["']?([^"'\s]*)["']?/);
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
      const foundDep = line.match(/\{:([A-Za-z0-9_]+)\s*,\s*(.*)$/);
      if (foundDep !== null) {
        const tail = foundDep[2] ?? '';
        const requirement = tail.match(/^["']([^"']*)["']/)?.[1];
        const git = tail.match(/\bgit:\s*["']([^"']+)["']/)?.[1];
        const path = tail.match(/\bpath:\s*["']([^"']+)["']/)?.[1];
        const only = tail.match(/\bonly:\s*:?([A-Za-z0-9_]+)/)?.[1];
        const override = tail.match(/\boverride:\s*(true|false)\b/)?.[1];
        deps.push({ name: foundDep[1] ?? '', ...(requirement === undefined ? {} : { requirement }),
          ...(git === undefined ? {} : { git }), ...(path === undefined ? {} : { path }),
          ...(only === undefined ? {} : { only }), ...(override === undefined ? {} : { override: override === 'true' }) });
      }
    }
    const licenses = content.match(/\blicenses:\s*\[([^\]]*)\]/)?.[1];
    return { project: { app }, deps, ...(licenses === undefined ? {} : { package: { licenses: splitTopLevel(licenses, ',').map(unquote) } }) };
  }
  if (artifact === 'mix.lock') {
    const packages = emptyMap();
    for (const line of lines) {
      const found = line.match(/["']([A-Za-z0-9_.-]+)["']\s*(?:=>|:)\s*\{:hex,\s*:?[A-Za-z0-9_]+,\s*["']([^"']+)["']/);
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
      const range = line.match(/["']([^"']+)["']\s*\.\.<\s*["']([^"']+)["']/);
      const requirement = branch !== undefined ? { branch } : version !== undefined ? { version }
        : range !== null ? { range: { lowerBound: range[1] ?? '', upperBound: range[2] ?? '' } } : undefined;
      dependencies.push({ url, ...(requirement === undefined ? {} : { requirement }) });
    }
    const toolsVersion = content.match(/^\s*\/\/\s*swift-tools-version:\s*([^\s]+)/m)?.[1];
    return { dependencies, ...(toolsVersion === undefined ? {} : { toolsVersion }) };
  }
  if (artifact === 'Cargo.lock') {
    const packages: Array<Record<string, unknown>> = [];
    let version: unknown;
    let current: Record<string, unknown> | undefined;
    for (const line of lines) {
      if (line.startsWith('version =')) version = scalar(line.slice(line.indexOf('=') + 1));
      if (line === '[[package]]') { current = emptyMap(); packages.push(current); continue; }
      if (current === undefined) continue;
      const eq = line.indexOf('=');
      if (eq > 0) current[line.slice(0, eq).trim()] = scalar(line.slice(eq + 1));
    }
    return { version, packages };
  }
  // An unknown lockfile is not an empty/line-only document of known shape.
  // Returning one could make absence rules generate fabricated findings.
  return undefined;
}

// ---------------------------------------------------------------------------
// Public dispatcher
// ---------------------------------------------------------------------------

/** Check node/depth limits without recursive traversal of untrusted documents. */
function documentWithinLimits(document: unknown): boolean {
  const pending: Array<{ value: unknown; depth: number }> = [{ value: document, depth: 0 }];
  const visited = new WeakSet<object>();
  let nodes = 0;
  while (pending.length > 0) {
    const item = pending.pop();
    if (item === undefined || item.depth > READER_MAX_DEPTH || ++nodes > READER_MAX_NODES) return false;
    if (typeof item.value !== 'object' || item.value === null) continue;
    if (visited.has(item.value)) continue;
    visited.add(item.value);
    for (const value of Object.values(item.value)) pending.push({ value, depth: item.depth + 1 });
  }
  return true;
}

/** Parse a real artifact into a bounded document; unsupported shapes stay unknown. */
export function parseDeclarationDocument(parser: ScaParser, artifact: string, content: string): unknown | undefined {
  if (typeof content !== 'string' || content.length === 0) return undefined;
  if (Buffer.byteLength(content, 'utf8') > READER_MAX_BYTES || content.split('\n').length > READER_MAX_LINES) return undefined;
  let document: unknown;
  try {
    if (artifact === 'DESCRIPTION') document = readProperties(content, artifact);
    else if (artifact === 'go.mod') document = readGoMod(content);
    else if (artifact === 'Package.swift') document = readLockfileText(content, artifact);
    else switch (parser) {
      case 'json':
        try { document = JSON.parse(content) as unknown; } catch { return undefined; }
        break;
      case 'toml': {
        const parsed = readToml(content);
        document = isRecord(parsed) && artifact === 'Cargo.lock' && Array.isArray(parsed['package'])
          ? { ...parsed, packages: parsed['package'] } : parsed;
        break;
      }
      case 'yaml': document = readYaml(content); break;
      case 'xml': document = normalizeNugetXml(readXml(content), artifact); break;
      case 'ini': document = readIni(content, artifact); break;
      case 'properties': document = readProperties(content, artifact); break;
      case 'requirements': document = readRequirements(content); break;
      case 'gradle': document = readGradle(content, artifact); break;
      case 'lockfile-text': document = readLockfileText(content, artifact); break;
      default: return undefined;
    }
    return document === undefined || !documentWithinLimits(document) ? undefined : document;
  } catch {
    // Malformed or unsupported structures must not escape into the processor
    // as a crash or a fabricated empty document.
    return undefined;
  }
}

/** Closed registry: every parser kind the dataset uses has a reader. */
export const DECLARATION_READER_PARSERS: readonly ScaParser[] = [
  'json', 'toml', 'yaml', 'requirements', 'xml', 'gradle', 'properties', 'ini', 'lockfile-text',
];

export type { Json };
