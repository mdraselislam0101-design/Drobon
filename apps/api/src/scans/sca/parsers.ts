/**
 * SCA manifest parsers (Pump 9) — defensive, read-only, deterministic.
 *
 * Supported (v1): npm `package.json` + `package-lock.json` (v1/v2/v3),
 * Python `requirements.txt` and `pyproject.toml` (PEP 621
 * `[project].dependencies` + `[project.optional-dependencies]` +
 * `[tool.poetry.dependencies]` subset). Every other construct is
 * reported UNSUPPORTED — never guessed.
 *
 * SECURITY (all adversarial shapes are tested):
 * - READ-ONLY: parsers receive TEXT. They never execute anything —
 *   no npm/pip, no setup.py, no lifecycle scripts, no shell, no
 *   fetches. A manifest containing `"postinstall": "touch /tmp/…"`
 *   is DATA; the marker file is never created (proven by tests).
 * - DEFENSIVE STRUCTURE WALKS: own-property reads only, no `key in
 *   object`, no recursion into unknown values (a deeply nested
 *   malicious JSON is ignored by construction — nothing recurses),
 *   prototype-chain key names (`__proto__`, `constructor`,
 *   `prototype`) are skipped, every scalar is length- and
 *   charset-bounded, and per-manifest entry counts are capped.
 * - NO FABRICATION: a value that cannot be determined is simply
 *   absent — declared ranges are never rewritten into "resolved"
 *   versions, and names/versions that fail ecosystem validation are
 *   dropped (counted), never coerced.
 */

import type {
  ScaDependencyClass,
  ScaDependencyType,
  ScaEcosystem,
  ScaVersionSource,
} from '@drobon/shared';
import {
  SCA_NAME_MAX_LENGTH,
  SCA_VERSION_MAX_LENGTH,
  SCA_INTEGRITY_MAX_LENGTH,
} from '@drobon/shared';

// ---------------------------------------------------------------------------
// Bounds (parser-level; the engine adds discovery-level caps)
// ---------------------------------------------------------------------------

/** Maximum dependency entries parsed out of ONE manifest. */
export const SCA_PARSER_MAX_ENTRIES = 500;

/** Maximum lines a text manifest (requirements/pyproject) may have. */
export const SCA_PARSER_MAX_LINES = 10_000;

/** Section precedence for a name declared in several package.json maps. */
const NPM_SECTION_ORDER = [
  { map: 'dependencies', type: 'runtime' },
  { map: 'optionalDependencies', type: 'optional' },
  { map: 'peerDependencies', type: 'peer' },
  { map: 'devDependencies', type: 'development' },
] as const;

/** Key names that must never be treated as data (prototype chain). */
const FORBIDDEN_KEYS = ['__proto__', 'constructor', 'prototype'] as const;

// ---------------------------------------------------------------------------
// The raw dependency (pre-normalization; the inventory step merges these)
// ---------------------------------------------------------------------------

export interface RawDependency {
  ecosystem: ScaEcosystem;
  name: string;
  declaredVersion?: string;
  resolvedVersion?: string;
  versionSource: ScaVersionSource;
  dependencyType: ScaDependencyType;
  dependencyClass: ScaDependencyClass;
  packageManager: string;
  manifestPath: string;
  lockfilePath?: string;
  /** Internal npm lock evidence: this installed node sits at the root. */
  lockfileRoot?: boolean;
  /**
   * Internal lock evidence (P2-11): the node's installation path
   * (`''` = root, else `node_modules/...` for npm and `name@version` for
   * PyPI). Used ONLY to join graph edges to inventory nodes; it is never
   * surfaced in a dependency or an SBOM.
   */
  pathKey?: string;
  integrity?: string;
}

export interface ManifestParseResult {
  status: 'ANALYZED' | 'PARTIAL' | 'UNSUPPORTED' | 'INVALID_INPUT';
  dependencies: RawDependency[];
  /** Names this manifest itself classifies as direct (lockfile root entry). */
  directNames: string[];
  /** The root project identity, when the manifest declares one (package.json). */
  rootName?: string;
  rootVersion?: string;
  note?: string;
}

// ---------------------------------------------------------------------------
// Ecosystem validation/normalization
// ---------------------------------------------------------------------------

/**
 * npm name rules (conservative): optional @scope/, lowercase, bounded.
 * Case normalization IS the ecosystem rule (npm names are lowercase);
 * everything else must match the conservative pattern exactly.
 */
export function normalizeNpmName(raw: string): string | undefined {
  let name = raw.toLowerCase();
  let scoped = false;
  if (name.startsWith('@')) {
    scoped = true;
    name = name.slice(1);
  }
  if (name.length === 0 || (scoped && !name.includes('/'))) {
    return undefined;
  }
  const pattern = scoped ? /^[a-z0-9][a-z0-9._-]*\/[a-z0-9][a-z0-9._-]*$/ : /^[a-z0-9][a-z0-9._-]*$/;
  if (!pattern.test(name)) {
    return undefined;
  }
  const fullName = scoped ? `@${name}` : name;
  return fullName.length > SCA_NAME_MAX_LENGTH ? undefined : fullName;
}

/** PEP 503 name normalization: lowercase, runs of `-_.` collapse to `-`. */
export function normalizePypiName(raw: string): string | undefined {
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(raw)) {
    return undefined;
  }
  const normalized = raw.toLowerCase().replace(/[-_.]+/g, '-');
  if (normalized.length === 0 || normalized.length > SCA_NAME_MAX_LENGTH) {
    return undefined;
  }
  return normalized;
}

/** Bounded, printable, no control characters — every exposed string. */
function isBoundedVersion(value: string): boolean {
  if (value.length === 0 || value.length > SCA_VERSION_MAX_LENGTH) {
    return false;
  }
  for (const char of value) {
    const code = char.codePointAt(0) ?? 0;
    if (code < 0x20 || code === 0x7f) {
      return false;
    }
  }
  return true;
}

function isBoundedIntegrity(value: string): boolean {
  // npm: "sha512-<base64>"; pip: "sha256:<hex>". Nothing else is accepted.
  if (value.length === 0 || value.length > SCA_INTEGRITY_MAX_LENGTH) {
    return false;
  }
  return /^(sha512-[A-Za-z0-9+/=]+|sha256:[A-Za-z0-9]+)$/.test(value);
}

/** A version usable in a purl (no slashes, colons or whitespace). */
export function isPurlSafeVersion(value: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9._+-]*$/.test(value) && value.length <= 64;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Own-property string read with bounds (no inherited lookups). */
function ownString(map: Record<string, unknown>, key: string): string | undefined {
  return Object.prototype.hasOwnProperty.call(map, key) && typeof map[key] === 'string'
    ? (map[key] as string)
    : undefined;
}

// ---------------------------------------------------------------------------
// package.json
// ---------------------------------------------------------------------------

export function parsePackageJson(
  text: string,
  manifestPath: string,
): ManifestParseResult {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return invalid('Manifest is not valid JSON.');
  }
  if (!isPlainObject(parsed)) {
    return invalid('Manifest root is not a JSON object.');
  }
  const dependencies: RawDependency[] = [];
  let truncated = false;
  const seen = new Set<string>();

  const rootNameRaw = ownString(parsed, 'name');
  const rootVersionRaw = ownString(parsed, 'version');
  const rootName =
    rootNameRaw === undefined ? undefined : normalizeNpmName(rootNameRaw);
  const rootVersion =
    rootVersionRaw !== undefined && isBoundedVersion(rootVersionRaw)
      ? rootVersionRaw
      : undefined;

  // Fixed section order = deterministic type precedence for a name
  // declared in several maps (first section wins; duplicates within a
  // map are impossible after JSON.parse — last key wins there).
  for (const section of NPM_SECTION_ORDER) {
    const map = parsed[section.map];
    if (!isPlainObject(map)) {
      continue;
    }
    // Deterministic key order: sort before iterating.
    const keys = Object.keys(map).sort();
    for (const key of keys) {
      if ((FORBIDDEN_KEYS as readonly string[]).includes(key)) {
        continue; // Prototype-shaped keys are never data.
      }
      const name = normalizeNpmName(key);
      if (name === undefined || seen.has(name)) {
        continue;
      }
      const declared = map[key];
      if (typeof declared !== 'string' || !isBoundedVersion(declared)) {
        continue; // Invalid declaration shape: dropped, never coerced.
      }
      if (dependencies.length >= SCA_PARSER_MAX_ENTRIES) {
        truncated = true;
        break;
      }
      seen.add(name);
      dependencies.push({
        ecosystem: 'npm',
        name,
        declaredVersion: declared,
        versionSource: 'manifest',
        dependencyType: section.type,
        dependencyClass: 'direct', // Everything in package.json is direct.
        packageManager: 'npm',
        manifestPath,
      });
    }
    if (truncated) {
      break;
    }
  }

  if (dependencies.length === 0 && truncated) {
    return partial('Dependency maps exceeded the parser limit.', [], rootName, rootVersion);
  }
  return {
    status: truncated ? 'PARTIAL' : 'ANALYZED',
    dependencies,
    directNames: dependencies.map((dependency) => dependency.name),
    ...(rootName === undefined ? {} : { rootName }),
    ...(rootVersion === undefined ? {} : { rootVersion }),
    ...(truncated
      ? { note: `Dependency maps exceeded the parser limit (${SCA_PARSER_MAX_ENTRIES}).` }
      : {}),
  };

  function invalid(note: string): ManifestParseResult {
    return { status: 'INVALID_INPUT', dependencies: [], directNames: [], note };
  }

  function partial(
    note: string,
    deps: RawDependency[],
    name: string | undefined,
    version: string | undefined,
  ): ManifestParseResult {
    return {
      status: 'PARTIAL',
      dependencies: deps,
      directNames: [],
      ...(name === undefined ? {} : { rootName: name }),
      ...(version === undefined ? {} : { rootVersion: version }),
      note,
    };
  }
}

// ---------------------------------------------------------------------------
// package-lock.json (lockfileVersion 1, 2, 3)
// ---------------------------------------------------------------------------

interface LockEntry {
  name: string;
  version: string;
  integrity?: string;
  dependencyType: ScaDependencyType;
  /**
   * Installed location inside the lockfile's own model ('' = the project
   * root, otherwise an npm-style `node_modules/...` path). Used to resolve
   * dependency EDGES without guessing: the same package name can be
   * installed at several depths and each depth is a distinct node.
   */
  pathKey?: string;
}

/**
 * One evidenced dependency edge: `from` depends on `to`, both expressed as
 * installed path keys ('' = the project root). Only edges the lockfile
 * actually states are emitted — no range-based guessing.
 */
export interface LockEdge {
  from: string;
  to: string;
}

/** Bounded edge budget: the graph can never outgrow the entry budget. */
export const LOCK_MAX_EDGES = 4_000;

/**
 * Resolve an npm dependency name from a package's own installed location,
 * exactly like Node's resolver: look inside the package first, then walk up
 * one `node_modules/<pkg>` segment at a time to the project root.
 * Returns undefined when the lockfile does not contain that installation.
 */
function resolveNpmTarget(known: ReadonlySet<string>, fromKey: string, name: string): string | undefined {
  // A package can never depend on itself through its own nested tree.
  if (fromKey.includes(`/node_modules/${name}`) && fromKey.endsWith(`/node_modules/${name}`)) {
    // Only skip the exact self-reference; sibling copies remain valid.
    if (fromKey === `node_modules/${name}`) return undefined;
  }
  let base = fromKey;
  for (let depth = 0; depth < 64; depth += 1) {
    const candidate = base === '' ? `node_modules/${name}` : `${base}/node_modules/${name}`;
    if (known.has(candidate)) return candidate;
    const marker = base.lastIndexOf('/node_modules/');
    if (marker === -1) {
      if (base.startsWith('node_modules/')) { base = ''; continue; }
      break;
    }
    base = base.slice(0, marker);
  }
  return undefined;
}

/** The dependency names a lockfile package entry declares. */
function declaredDependencyNames(entry: Record<string, unknown>, isRoot = false): string[] {
  const names = new Set<string>();
  // Root devDependencies ARE installed by `npm install`; a nested package's
  // devDependencies are not, so they only count for the root node.
  const sections = isRoot
    ? (['dependencies', 'optionalDependencies', 'devDependencies'] as const)
    : (['dependencies', 'optionalDependencies'] as const);
  for (const section of sections) {
    const map = entry[section];
    if (!isPlainObject(map)) continue;
    for (const key of Object.keys(map)) {
      if ((FORBIDDEN_KEYS as readonly string[]).includes(key)) continue;
      const name = normalizeNpmName(key);
      if (name !== undefined) names.add(name);
    }
  }
  return [...names].sort();
}

export function parsePackageLock(
  text: string,
  manifestPath: string,
): ManifestParseResult & {
  lockfileVersion?: number;
  entries: LockEntry[];
  edges: LockEdge[];
  /** True when the edge budget clipped the graph (never silently incomplete). */
  edgesTruncated?: boolean;
} {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return {
      status: 'INVALID_INPUT',
      dependencies: [],
      directNames: [],
      entries: [],
      edges: [],
      note: 'Lockfile is not valid JSON.',
    };
  }
  if (!isPlainObject(parsed)) {
    return {
      status: 'INVALID_INPUT',
      dependencies: [],
      directNames: [],
      entries: [],
      edges: [],
      note: 'Lockfile root is not a JSON object.',
    };
  }
  const lockfileVersionRaw = parsed['lockfileVersion'];
  if (
    typeof lockfileVersionRaw !== 'number' ||
    !Number.isInteger(lockfileVersionRaw) ||
    lockfileVersionRaw < 1 ||
    lockfileVersionRaw > 3
  ) {
    return {
      status: 'INVALID_INPUT',
      dependencies: [],
      directNames: [],
      entries: [],
      edges: [],
      note: 'Unsupported or missing lockfileVersion.',
    };
  }
  const lockfileVersion = lockfileVersionRaw;
  if (lockfileVersion >= 2) {
    const packages = parsed['packages'];
    // A v2/v3 lock always carries at least the "" root entry — an
    // absent or empty packages map is malformed.
    if (!isPlainObject(packages) || Object.keys(packages).length === 0) {
      return {
        status: 'INVALID_INPUT',
        dependencies: [],
        directNames: [],
        entries: [],
        edges: [],
        lockfileVersion,
        note: 'Lockfile carries no packages map.',
      };
    }
  }

  const dependencies: RawDependency[] = [];
  const entries: LockEntry[] = [];
  const edges: LockEdge[] = [];
  const directNames = new Set<string>();
  let truncated = false;
  let edgesTruncated = false;

  if (lockfileVersion >= 2 && isPlainObject(parsed['packages'])) {
    const packages = parsed['packages'];
    // Root "" entry: the direct-dependency set (own-property reads).
    const root = packages[''];
    if (isPlainObject(root)) {
      for (const section of NPM_SECTION_ORDER) {
        const map = root[section.map];
        if (!isPlainObject(map)) {
          continue;
        }
        for (const key of Object.keys(map).sort()) {
          if ((FORBIDDEN_KEYS as readonly string[]).includes(key)) {
            continue;
          }
          const name = normalizeNpmName(key);
          if (name !== undefined) {
            directNames.add(name);
          }
        }
      }
    }
    // Deterministic walk: sorted keys.
    for (const key of Object.keys(packages).sort()) {
      if (key === '') {
        continue;
      }
      if (!key.startsWith('node_modules/')) {
        continue; // Workspace/link paths are not installed packages.
      }
      const entry = packages[key];
      if (!isPlainObject(entry) || entry['link'] === true) {
        continue; // Symlinked workspace entries carry no resolution.
      }
      const name = lockfileNameFromPath(key);
      if (name === undefined) {
        continue;
      }
      const version = ownString(entry, 'version');
      if (version === undefined || !isBoundedVersion(version)) {
        continue; // No version: not a resolved package node.
      }
      const integrityRaw = ownString(entry, 'integrity');
      const integrity =
        integrityRaw !== undefined && isBoundedIntegrity(integrityRaw) ? integrityRaw : undefined;
      if (entries.length >= SCA_PARSER_MAX_ENTRIES) {
        truncated = true;
        break;
      }
      const dependencyType = lockEntryType(entry);
      entries.push({
        name,
        version,
        ...(integrity === undefined ? {} : { integrity }),
        dependencyType,
        pathKey: key,
      });
      dependencies.push({
        ecosystem: 'npm',
        name,
        versionSource: 'lockfile',
        dependencyType,
        // A nested node_modules copy is not the root's direct installation,
        // even if the root also declares the same package name.
        dependencyClass: directNames.has(name) && key.lastIndexOf('node_modules/') === 0 ? 'direct' : 'transitive',
        packageManager: 'npm',
        manifestPath,
        lockfilePath: manifestPath,
        lockfileRoot: key.lastIndexOf('node_modules/') === 0,
        resolvedVersion: version,
        pathKey: key,
        ...(integrity === undefined ? {} : { integrity }),
      });
    }

    // --- evidenced EDGES (P2-11) -------------------------------------------
    // Every installed node declares its own dependency names; Node's resolver
    // decides WHICH installation of that name it gets. Only edges the lockfile
    // states are emitted, and only between nodes we actually accepted.
    const known = new Set<string>(entries.flatMap((entry) => (entry.pathKey === undefined ? [] : [entry.pathKey])));
    for (const key of ['', ...entries.flatMap((entry) => (entry.pathKey === undefined ? [] : [entry.pathKey]))].sort()) {
      if (edges.length >= LOCK_MAX_EDGES) break;
      const node = packages[key];
      if (!isPlainObject(node)) continue;
      for (const name of declaredDependencyNames(node, key === '')) {
        if (edges.length >= LOCK_MAX_EDGES) {
          edgesTruncated = true;
          break;
        }
        const target = resolveNpmTarget(known, key, name);
        if (target === undefined || target === key) continue;
        edges.push({ from: key, to: target });
      }
    }
  } else if (isPlainObject(parsed['dependencies'])) {
    // v1 can contain nested resolved dependency maps. Inspect them without
    // recursion, with a shared node/depth budget; top-level directness still
    // needs a companion manifest, while nested copies are transitive.
    const queue: Array<{ map: Record<string, unknown>; depth: number; path: string }> =
      [{ map: parsed['dependencies'], depth: 0, path: '' }];
    let visited = 0;
    outer: for (let index = 0; index < queue.length; index += 1) {
      const frame = queue[index];
      if (frame === undefined) break;
      for (const key of Object.keys(frame.map).sort()) {
        if (++visited > SCA_PARSER_MAX_ENTRIES) { truncated = true; break outer; }
        if ((FORBIDDEN_KEYS as readonly string[]).includes(key)) continue;
        const name = normalizeNpmName(key);
        const entry = frame.map[key];
        if (name === undefined || !isPlainObject(entry)) continue;
        const pathKey = frame.path === '' ? `node_modules/${name}` : `${frame.path}/node_modules/${name}`;
        // v1 nests the resolved tree: a node appearing inside a map IS a child
        // of that map's owner, so the edge is structural evidence, not a
        // resolution guess (a nested copy really is installed under its parent).
        if (edges.length < LOCK_MAX_EDGES) edges.push({ from: frame.path, to: pathKey });
        else edgesTruncated = true;
        if (isPlainObject(entry['dependencies'])) {
          if (frame.depth >= 32) truncated = true;
          else queue.push({ map: entry['dependencies'], depth: frame.depth + 1, path: pathKey });
        }
        const version = ownString(entry, 'version');
        if (version === undefined || !isBoundedVersion(version)) continue;
        const integrityRaw = ownString(entry, 'integrity');
        const integrity = integrityRaw !== undefined && isBoundedIntegrity(integrityRaw) ? integrityRaw : undefined;
        const dependencyType = entry['dev'] === true ? 'development' : entry['optional'] === true ? 'optional' : 'runtime';
        entries.push({ name, version, ...(integrity === undefined ? {} : { integrity }), dependencyType, pathKey });
        dependencies.push({
          ecosystem: 'npm', name, versionSource: 'lockfile', dependencyType,
          dependencyClass: frame.depth === 0 ? 'unknown' : 'transitive',
          packageManager: 'npm', manifestPath, lockfilePath: manifestPath, resolvedVersion: version,
          pathKey,
          ...(integrity === undefined ? {} : { integrity }),
        });
      }
    }
  } else {
    return {
      status: 'INVALID_INPUT',
      dependencies: [],
      directNames: [],
      entries: [],
      edges: [],
      lockfileVersion,
      note: 'Lockfile carries no packages or dependencies map.',
    };
  }

  return {
    status: truncated ? 'PARTIAL' : 'ANALYZED',
    dependencies,
    directNames: [...directNames].sort(),
    entries,
    edges,
    ...(edgesTruncated ? { edgesTruncated: true } : {}),
    lockfileVersion,
    ...(truncated
      ? { note: `Lockfile exceeded the parser limit (${SCA_PARSER_MAX_ENTRIES} entries).` }
      : {}),
  };
}

/** "node_modules/@scope/name" → "@scope/name"; "node_modules/x" → "x". */
function lockfileNameFromPath(path: string): string | undefined {
  const marker = 'node_modules/';
  const index = path.lastIndexOf(marker);
  if (index === -1) {
    return undefined;
  }
  let tail = path.slice(index + marker.length);
  if (tail.startsWith('@')) {
    const slash = tail.indexOf('/');
    if (slash === -1 || slash === tail.length - 1) {
      return undefined;
    }
    tail = tail.slice(0, slash + 1) + (tail.slice(slash + 1).split('/')[0] ?? '');
  } else if (tail.includes('/')) {
    tail = tail.split('/')[0] ?? '';
  }
  return normalizeNpmName(tail);
}

function lockEntryType(entry: Record<string, unknown>): ScaDependencyType {
  if (entry['peer'] === true) {
    return 'peer';
  }
  if (entry['dev'] === true || entry['devOptional'] === true) {
    return 'development';
  }
  if (entry['optional'] === true) {
    return 'optional';
  }
  return 'runtime';
}

// ---------------------------------------------------------------------------
// requirements.txt
// ---------------------------------------------------------------------------

/**
 * Parse ONE requirement line (PEP 508 subset: name, extras, version
 * specifiers, environment markers, --hash). Returns the normalized
 * name + the raw declared specifier — the caller decides types.
 */
export function parseRequirementLine(
  line: string,
): { name: string; declaredVersion?: string; integrity?: string } | undefined {
  // Strip a comment ('#' at line start or after whitespace).
  let text = line.trim();
  const commentIndex = text.search(/(^|\s)#/);
  if (commentIndex !== -1) {
    text = text.slice(0, commentIndex).trim();
  }
  if (text.length === 0) {
    return undefined;
  }
  // Option/flag lines (-r, -e, --index-url, …) and BARE URLs are
  // skipped upstream; defensive double-check here. A PEP 508 direct
  // reference (`name @ https://…`) is handled below (name kept, no
  // version invented).
  if (text.startsWith('-') || /^https?:\/\//.test(text)) {
    return undefined;
  }
  // --hash=… (may repeat; the first legitimate hash is the evidence).
  let integrity: string | undefined;
  const hashMatch = text.match(/--hash\s*=\s*(sha256:[A-Za-z0-9]+)/);
  if (hashMatch !== null) {
    const candidate = hashMatch[1] ?? '';
    if (isBoundedIntegrity(candidate)) {
      integrity = candidate;
    }
    text = text.slice(0, text.indexOf('--hash')).trim();
  }
  // Environment markers: everything after ';'.
  const semicolon = text.indexOf(';');
  if (semicolon !== -1) {
    text = text.slice(0, semicolon).trim();
  }
  // Name (with optional extras).
  const nameMatch = text.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^[\]]*\])?/);
  if (nameMatch === null) {
    return undefined;
  }
  const name = normalizePypiName(nameMatch[1] ?? '');
  if (name === undefined) {
    return undefined;
  }
  let rest = text.slice((nameMatch[0] ?? '').length).trim();
  // A URL requirement (name @ https://…): the version is not a
  // specifier — record no declared version rather than guessing.
  if (rest.startsWith('@')) {
    return integrity === undefined ? { name } : { name, integrity };
  }
  // Specifiers: comma-separated operators. Validate the shape loosely
  // (bounded, printable) and keep the RAW string — never normalized
  // into a fake pin.
  if (rest.startsWith('(') && rest.endsWith(')')) {
    rest = rest.slice(1, -1).trim();
  }
  if (rest.length > 0) {
    // Specifiers must look like operators with bounded operands
    // (e.g. `==1.2.3`, `>=2.0, <3.0`, `~=1.4`). PEP 508 allows
    // whitespace around operators — normalize it away (a pure format
    // change, never a value change). Trailing junk that is NOT a
    // specifier drops the WHOLE line: a malformed declaration is not
    // evidence of anything and must not be guessed into a bare name.
    const normalized = rest.replace(/\s+/g, '');
    if (
      !isBoundedVersion(normalized) ||
      !/^[=<>!~][=<>!~.,A-Za-z0-9._+-]*$/.test(normalized)
    ) {
      return undefined;
    }
    return {
      name,
      declaredVersion: normalized,
      ...(integrity === undefined ? {} : { integrity }),
    };
  }
  return integrity === undefined ? { name } : { name, integrity };
}

export function parseRequirementsTxt(
  text: string,
  manifestPath: string,
): ManifestParseResult {
  const physicalLines = text.split('\n');
  if (physicalLines.length > SCA_PARSER_MAX_LINES) {
    return {
      status: 'INVALID_INPUT',
      dependencies: [],
      directNames: [],
      note: `Requirements file exceeds the line limit (${SCA_PARSER_MAX_LINES}).`,
    };
  }
  // Logical lines: trailing backslash continues a requirement.
  const logical: string[] = [];
  let buffer = '';
  for (const raw of physicalLines) {
    const line = raw.replace(/\r$/, '');
    if (line.endsWith('\\')) {
      buffer += line.slice(0, -1) + ' ';
      continue;
    }
    buffer += line;
    logical.push(buffer);
    buffer = '';
  }
  if (buffer.length > 0) {
    logical.push(buffer);
  }

  const dependencies: RawDependency[] = [];
  const seen = new Set<string>();
  let skippedOptions = 0;
  let unparsedLines = 0;
  let truncated = false;

  for (const line of logical) {
    const trimmed = line.trim();
    if (trimmed.length === 0 || trimmed.startsWith('#')) continue;
    if (trimmed.startsWith('-')) {
      // Includes, constraints, editable installs and even unsupported options
      // may affect the inventory. Never describe a skipped directive as full
      // analysis and never follow it or read another file automatically.
      skippedOptions += 1;
      continue;
    }
    if (/^https?:\/\//.test(trimmed)) { unparsedLines += 1; continue; }
    const parsedLine = parseRequirementLine(line);
    if (parsedLine === undefined) {
      unparsedLines += 1;
      continue;
    }
    // Distinct constraints for the same name can represent different
    // environment markers or requirements. Keep each declaration; collapse
    // only the same normalized name + constraint within this file.
    const declarationKey = `${parsedLine.name}\n${parsedLine.declaredVersion ?? ''}`;
    if (seen.has(declarationKey)) continue;
    if (dependencies.length >= SCA_PARSER_MAX_ENTRIES) {
      truncated = true;
      break;
    }
    seen.add(declarationKey);
    dependencies.push({
      ecosystem: 'pypi',
      name: parsedLine.name,
      ...(parsedLine.declaredVersion === undefined
        ? {}
        : { declaredVersion: parsedLine.declaredVersion }),
      ...(parsedLine.integrity === undefined ? {} : { integrity: parsedLine.integrity }),
      versionSource: 'manifest',
      dependencyType: 'runtime',
      // Every requirements.txt line is a DIRECT requirement of the
      // project; the transitive graph is NOT available from this
      // format (the engine reports that honestly).
      dependencyClass: 'direct',
      packageManager: 'pip',
      manifestPath,
    });
  }

  const noteParts: string[] = [];
  if (truncated) noteParts.push(`Requirements exceeded the parser limit (${SCA_PARSER_MAX_ENTRIES}).`);
  if (skippedOptions > 0) noteParts.push(`${skippedOptions} option/directive line(s) skipped.`);
  if (unparsedLines > 0) noteParts.push(`${unparsedLines} requirement line(s) could not be parsed.`);
  return {
    status: truncated || skippedOptions > 0 || unparsedLines > 0 ? 'PARTIAL' : 'ANALYZED',
    dependencies,
    directNames: dependencies.map((dependency) => dependency.name),
    ...(noteParts.length === 0 ? {} : { note: noteParts.join(' ').slice(0, 200) }),
  };
}

// ---------------------------------------------------------------------------
// pyproject.toml (defensive subset: PEP 621 + poetry dependency tables)
// ---------------------------------------------------------------------------

export function parsePyprojectToml(
  text: string,
  manifestPath: string,
): ManifestParseResult {
  const physicalLines = text.split('\n');
  if (physicalLines.length > SCA_PARSER_MAX_LINES) {
    return {
      status: 'INVALID_INPUT',
      dependencies: [],
      directNames: [],
      note: `pyproject.toml exceeds the line limit (${SCA_PARSER_MAX_LINES}).`,
    };
  }

  const dependencies: RawDependency[] = [];
  const seen = new Set<string>();
  let recognizedSection = false;
  let truncated = false;
  let section = '';
  // The project's own identity (for the SBOM root component). `[project]`
  // wins over the legacy Poetry table; a value is only taken verbatim from a
  // bounded, printable scalar.
  let projectName: string | undefined;
  let projectVersion: string | undefined;
  const readIdentity = (key: string, value: string): void => {
    const scalar = value.match(/^"([^"]{1,120})"/) ?? value.match(/^'([^']{1,120})'/);
    const text = scalar?.[1]?.trim();
    if (text === undefined || text.length === 0) return;
    if (key === 'name' && projectName === undefined) projectName = text;
    if (key === 'version' && projectVersion === undefined && isBoundedVersion(text)) {
      projectVersion = text;
    }
  };

  const pushPep508 = (raw: string, type: ScaDependencyType): void => {
    const parsedLine = parseRequirementLine(raw);
    if (parsedLine === undefined) return;
    const declarationKey = `${parsedLine.name}\n${parsedLine.declaredVersion ?? ''}`;
    if (seen.has(declarationKey)) return;
    if (dependencies.length >= SCA_PARSER_MAX_ENTRIES) {
      truncated = true;
      return;
    }
    seen.add(declarationKey);
    dependencies.push({
      ecosystem: 'pypi',
      name: parsedLine.name,
      ...(parsedLine.declaredVersion === undefined
        ? {}
        : { declaredVersion: parsedLine.declaredVersion }),
      versionSource: 'manifest',
      dependencyType: type,
      dependencyClass: 'direct',
      packageManager: 'pip',
      manifestPath,
    });
  };

  const parseStringArray = (line: string): string[] | undefined => {
    const match = line.match(/^=\s*\[(.*)\]\s*$/);
    if (match === null) {
      return undefined; // Multi-line or malformed — handled by caller.
    }
    const inner = match[1] ?? '';
    const items: string[] = [];
    for (const element of inner.matchAll(/"([^"]*)"|'([^']*)'/g)) {
      const value = element[1] ?? element[2] ?? '';
      if (value.length > 0) {
        items.push(value);
      }
    }
    return items;
  };

  for (let index = 0; index < physicalLines.length; index += 1) {
    const line = (physicalLines[index] ?? '').replace(/\r$/, '').trim();
    if (line.length === 0 || line.startsWith('#')) {
      continue;
    }
    const header = line.match(/^\[([^[\]]+)\]$/);
    if (header !== null) {
      section = header[1] ?? '';
      continue;
    }
    if (section === 'project' || section === 'tool.poetry') {
      const assignment = line.match(/^([A-Za-z0-9_.-]+)\s*=\s*(.*)$/);
      if (assignment === null) {
        continue;
      }
      const key = assignment[1] ?? '';
      const value = assignment[2] ?? '';
      if (key === 'name' || key === 'version') readIdentity(key, value);
      if (section === 'tool.poetry') {
        // `[tool.poetry]` outside `dependencies` declares identity only; its
        // dependency table is handled by the branch below.
        continue;
      }
      if (key === 'dependencies') {
        recognizedSection = true;
        const inline = parseStringArray(value);
        if (inline !== undefined) {
          for (const item of inline) {
            pushPep508(item, 'runtime');
          }
        } else if (value.startsWith('[')) {
          // Multi-line array: consume until the closing bracket.
          let buffer = value;
          while (!/\]\s*$/.test(buffer) && index + 1 < physicalLines.length) {
            index += 1;
            buffer += (physicalLines[index] ?? '').replace(/\r$/, '');
          }
          const inner = buffer.replace(/^\[/, '').replace(/\]\s*$/, '');
          for (const element of inner.matchAll(/"([^"]*)"|'([^']*)'/g)) {
            pushPep508(element[1] ?? element[2] ?? '', 'runtime');
          }
        }
      }
    } else if (section === 'project.optional-dependencies') {
      // `<group> = [ "dep>=1.0", … ]` — extras are optional deps.
      const assignment = line.match(/^[A-Za-z0-9_.-]+\s*=\s*(.*)$/);
      if (assignment === null) {
        continue;
      }
      const value = assignment[1] ?? '';
      recognizedSection = true;
      const inline = parseStringArray(value);
      if (inline !== undefined) {
        for (const item of inline) {
          pushPep508(item, 'optional');
        }
      } else if (value.startsWith('[')) {
        let buffer = value;
        while (!/\]\s*$/.test(buffer) && index + 1 < physicalLines.length) {
          index += 1;
          buffer += (physicalLines[index] ?? '').replace(/\r$/, '');
        }
        const inner = buffer.replace(/^\[/, '').replace(/\]\s*$/, '');
        for (const element of inner.matchAll(/"([^"]*)"|'([^']*)'/g)) {
          pushPep508(element[1] ?? element[2] ?? '', 'optional');
        }
      }
    } else if (section === 'tool.poetry.dependencies') {
      // `name = "constraint"` or `name = { version = "…", … }`.
      // `python = "…"` is the interpreter constraint, not a dependency.
      const assignment = line.match(/^([A-Za-z0-9_.-]+)\s*=\s*(.*)$/);
      if (assignment === null) {
        continue;
      }
      const key = assignment[1] ?? '';
      const value = assignment[2] ?? '';
      if (key === 'python') {
        continue;
      }
      const name = normalizePypiName(key);
      if (name === undefined) continue;
      let declared: string | undefined;
      const simple = value.match(/^"([^"]*)"|^\x27([^\x27]*)\x27/);
      if (simple !== null) {
        declared = simple[1] ?? simple[2] ?? '';
      } else if (value.startsWith('{')) {
        const versionMatch = value.match(/version\s*=\s*"([^"]*)"/);
        declared = versionMatch === null ? undefined : versionMatch[1];
      }
      if (declared !== undefined && !isBoundedVersion(declared)) {
        declared = undefined;
      }
      recognizedSection = true;
      const declarationKey = `${name}\n${declared ?? ''}`;
      if (seen.has(declarationKey)) continue;
      if (dependencies.length >= SCA_PARSER_MAX_ENTRIES) {
        truncated = true;
        break;
      }
      seen.add(declarationKey);
      dependencies.push({
        ecosystem: 'pypi',
        name,
        ...(declared === undefined || declared.length === 0 ? {} : { declaredVersion: declared }),
        versionSource: 'manifest',
        dependencyType: 'runtime',
        dependencyClass: 'direct',
        packageManager: 'pip',
        manifestPath,
      });
    }
    // Every other section (build-system, tool.x, …) is ignored —
    // build requirements are NOT runtime dependencies and parsing
    // them would require executing build logic.
  }

  if (!recognizedSection) {
    return {
      status: 'UNSUPPORTED',
      dependencies: [],
      directNames: [],
      note: 'No supported dependency declaration found (expected [project] dependencies, [project.optional-dependencies] or [tool.poetry.dependencies]).',
    };
  }
  return {
    status: truncated ? 'PARTIAL' : 'ANALYZED',
    dependencies,
    directNames: dependencies.map((dependency) => dependency.name),
    ...(projectName === undefined ? {} : { rootName: projectName }),
    ...(projectVersion === undefined ? {} : { rootVersion: projectVersion }),
    ...(truncated
      ? { note: `pyproject.toml exceeded the parser limit (${SCA_PARSER_MAX_ENTRIES}).` }
      : {}),
  };
}

// ---------------------------------------------------------------------------
// poetry.lock (defensive subset: [[package]] tables + [package.dependencies])
// ---------------------------------------------------------------------------
//
// A poetry lock IS installation-level evidence: every `[[package]]` entry is a
// concrete resolved artifact (`name` + `version`), and `[package.dependencies]`
// states which other locked packages it needs. That gives PyPI a real
// transitive graph instead of a declaration list. Nothing is guessed: an edge
// is emitted only when BOTH endpoints are packages the lock itself lists, and
// an edge whose target is missing is counted (`unresolvedEdges`) so the graph
// is never presented as complete. Bounds: 10,000 lines, 500 packages, 200
// dependency entries per package, 4,000 edges.

export interface PoetryLockParseResult extends ManifestParseResult {
  edges: LockEdge[];
  /** True when the edge/package budget clipped the graph. */
  edgesTruncated?: boolean;
  /** Dependency edges whose target the lock does not list. */
  unresolvedEdges: number;
}

/** Strip one layer of TOML quotes and bound the value length. */
function poetryScalar(raw: string, maxLength = 200): string {
  const trimmed = raw.trim();
  const quoted =
    (trimmed.startsWith('"') && trimmed.endsWith('"') && trimmed.length >= 2) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'") && trimmed.length >= 2);
  const inner = quoted ? trimmed.slice(1, -1) : trimmed;
  return inner.slice(0, maxLength);
}

export function parsePoetryLock(
  text: string,
  manifestPath: string,
  rootNames: readonly string[] = [],
): PoetryLockParseResult {
  const lines = text.split('\n');
  if (lines.length > SCA_PARSER_MAX_LINES) {
    return {
      status: 'INVALID_INPUT',
      dependencies: [],
      directNames: [],
      edges: [],
      unresolvedEdges: 0,
      note: `poetry.lock exceeds the line limit (${SCA_PARSER_MAX_LINES}).`,
    };
  }

  interface DraftDependency {
    name: string;
    optional: boolean;
    declaredVersion?: string;
  }
  interface DraftPackage {
    name?: string;
    version?: string;
    optional: boolean;
    dependencies: DraftDependency[];
  }

  const drafts: DraftPackage[] = [];
  let current: DraftPackage | undefined;
  let inDependencyTable = false;
  let sawPackageTable = false;
  let truncated = false;

  const close = (draft: DraftPackage): void => {
    if (drafts.length >= SCA_PARSER_MAX_ENTRIES) {
      truncated = true;
      return;
    }
    drafts.push(draft);
  };

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (line.length === 0 || line.startsWith('#')) continue;
    if (line.startsWith('[')) {
      inDependencyTable = false;
      if (line.startsWith('[[package]]')) {
        if (current !== undefined) close(current);
        current = { optional: false, dependencies: [] };
        sawPackageTable = true;
        continue;
      }
      if (current !== undefined && line === '[package.dependencies]') {
        inDependencyTable = true;
      }
      // [package.extras], [package.source], [[package.files]], [metadata] …
      // carry no additional locked dependency edge.
      continue;
    }
    const equals = line.indexOf('=');
    if (equals <= 0 || current === undefined) continue;
    const key = poetryScalar(line.slice(0, equals));
    const value = line.slice(equals + 1).trim();
    if (!inDependencyTable) {
      if (key === 'name') current.name = poetryScalar(value);
      else if (key === 'version') current.version = poetryScalar(value, 80);
      else if (key === 'optional') current.optional = value === 'true';
      continue;
    }
    if (current.dependencies.length >= 200) {
      truncated = true;
      continue;
    }
    const name = normalizePypiName(key);
    // `python` is the interpreter constraint, not a package.
    if (name === undefined || name === 'python') continue;
    const optional = /\boptional\s*=\s*true\b/.test(value);
    const declared = value.match(/\bversion\s*=\s*"([^"]{1,80})"/)?.[1];
    current.dependencies.push({
      name,
      optional,
      ...(declared === undefined ? {} : { declaredVersion: declared }),
    });
  }
  if (current !== undefined && !truncated) close(current);

  if (!sawPackageTable) {
    return {
      status: 'INVALID_INPUT',
      dependencies: [],
      directNames: [],
      edges: [],
      unresolvedEdges: 0,
      note: 'Lockfile carries no [[package]] tables.',
    };
  }

  const dependencies: RawDependency[] = [];
  const byName = new Map<string, string[]>();
  const nodeDeps = new Map<string, DraftDependency[]>();
  let skipped = 0;
  for (const draft of drafts) {
    if (draft.name === undefined || draft.version === undefined) {
      skipped += 1;
      continue;
    }
    const name = normalizePypiName(draft.name);
    if (name === undefined || !isBoundedVersion(draft.version)) {
      skipped += 1;
      continue;
    }
    const pathKey = `${name}@${draft.version}`;
    if (nodeDeps.has(pathKey)) continue; // identical duplicate entry
    nodeDeps.set(pathKey, draft.dependencies);
    const keys = byName.get(name);
    if (keys === undefined) byName.set(name, [pathKey]);
    else if (!keys.includes(pathKey)) keys.push(pathKey);
    dependencies.push({
      ecosystem: 'pypi',
      name,
      versionSource: 'lockfile',
      dependencyType: draft.optional ? 'optional' : 'runtime',
      // Directness needs the companion pyproject declaration; the inventory
      // assigns it. Without one, this stays honestly unknown.
      dependencyClass: 'unknown',
      packageManager: 'pip',
      manifestPath,
      lockfilePath: manifestPath,
      resolvedVersion: draft.version,
      pathKey,
    });
  }

  const edges: LockEdge[] = [];
  let edgesTruncated = false;
  let unresolvedEdges = 0;
  const pushEdge = (from: string, to: string): void => {
    if (from !== '' && from === to) return;
    if (edges.length >= LOCK_MAX_EDGES) {
      edgesTruncated = true;
      return;
    }
    edges.push({ from, to });
  };

  // Root edges come only from declarations the companion pyproject states.
  const declaredDirect = [...new Set(rootNames.map((name) => normalizePypiName(name)))].filter(
    (name): name is string => name !== undefined,
  );
  for (const name of declaredDirect.sort()) {
    const targets = byName.get(name);
    if (targets === undefined) {
      unresolvedEdges += 1; // declared but absent from the lock
      continue;
    }
    for (const target of targets) pushEdge('', target);
  }

  for (const pathKey of [...nodeDeps.keys()].sort()) {
    for (const dependency of nodeDeps.get(pathKey) ?? []) {
      const targets = byName.get(dependency.name);
      if (targets === undefined) {
        unresolvedEdges += 1;
        continue;
      }
      for (const target of targets) pushEdge(pathKey, target);
    }
  }

  const noteParts: string[] = [];
  if (truncated) noteParts.push(`poetry.lock exceeded the parser limit (${SCA_PARSER_MAX_ENTRIES} packages).`);
  if (edgesTruncated) noteParts.push(`The lockfile edge budget (${LOCK_MAX_EDGES}) clipped the graph.`);
  if (unresolvedEdges > 0) noteParts.push(`${unresolvedEdges} locked dependency edge(s) point at packages this lock does not list.`);
  if (skipped > 0) noteParts.push(`${skipped} [[package]] entr${skipped === 1 ? 'y' : 'ies'} had no usable name/version.`);

  return {
    // An unresolved edge means the lock does not describe the whole tree, so
    // the manifest itself is partial — the graph is never presented as whole.
    status: truncated || unresolvedEdges > 0 ? 'PARTIAL' : 'ANALYZED',
    dependencies,
    directNames: declaredDirect.filter((name) => byName.has(name)).sort(),
    edges,
    unresolvedEdges,
    ...(edgesTruncated ? { edgesTruncated: true } : {}),
    ...(noteParts.length === 0 ? {} : { note: noteParts.join(' ').slice(0, 200) }),
  };
}

// ---------------------------------------------------------------------------
// uv.lock (defensive subset: [[package]] + `dependencies = [{ name = ... }]`)
// ---------------------------------------------------------------------------
//
// `uv.lock` is a resolved installation tree: every `[[package]]` is a concrete
// artifact (`name` + `version`), its `dependencies` array names the locked
// packages it needs, and the project's own entry (`source = { editable|virtual
// = "." }`) is the root. Edges are therefore real lock evidence, not guesses:
// a dependency entry is joined to a node only when the lock lists exactly that
// coordinate (an explicit `version` in the entry) or when the name maps to a
// single locked version. Anything else is counted (`unresolvedEdges`,
// `ambiguousEdges`) and makes the manifest PARTIAL.
//
// Bounds: 20,000 lines (a real uv.lock is verbose), 500 packages, 200
// dependency entries per package, 4,000 edges.

export const UV_LOCK_MAX_LINES = 20_000;

interface UvDependencyRef {
  name: string;
  version?: string;
}

/** `[{ name = "x", version = "1.0" }, { name = "y" }]` → bounded refs. */
function uvDependencyRefs(raw: string): UvDependencyRef[] {
  const refs: UvDependencyRef[] = [];
  for (const match of raw.matchAll(/\{([^{}]{0,200})\}/g)) {
    if (refs.length >= 200) break;
    const body = match[1] ?? '';
    const namePart = body.match(/\bname\s*=\s*"([^"]{1,120})"/)?.[1];
    const versionPart = body.match(/\bversion\s*=\s*"([^"]{1,80})"/)?.[1];
    const name = namePart === undefined ? undefined : normalizePypiName(namePart);
    if (name === undefined) continue;
    refs.push({
      name,
      ...(versionPart === undefined || !isBoundedVersion(versionPart) ? {} : { version: versionPart }),
    });
  }
  return refs;
}

export function parseUvLock(
  text: string,
  manifestPath: string,
  declaredNames: readonly string[] = [],
): PoetryLockParseResult {
  const allLines = text.split('\n');
  const truncatedByLines = allLines.length > UV_LOCK_MAX_LINES;
  const lines = truncatedByLines ? allLines.slice(0, UV_LOCK_MAX_LINES) : allLines;

  interface DraftPackage {
    name?: string;
    version?: string;
    root: boolean;
    dependencies: UvDependencyRef[];
  }

  const drafts: DraftPackage[] = [];
  let current: DraftPackage | undefined;
  let inPackageBody = false;
  let sawPackageTable = false;
  let truncated = false;

  const close = (draft: DraftPackage): void => {
    if (drafts.length >= SCA_PARSER_MAX_ENTRIES) {
      truncated = true;
      return;
    }
    drafts.push(draft);
  };

  for (let index = 0; index < lines.length; index += 1) {
    const line = (lines[index] ?? '').trim();
    if (line.length === 0 || line.startsWith('#')) continue;
    if (line.startsWith('[')) {
      if (line.startsWith('[[package]]')) {
        if (current !== undefined) close(current);
        current = { root: false, dependencies: [] };
        inPackageBody = true;
        sawPackageTable = true;
      } else {
        // [package.metadata], [package.optional-dependencies], [options], …
        // carry no additional locked runtime edge or node identity.
        inPackageBody = false;
      }
      continue;
    }
    if (current === undefined || !inPackageBody) continue;
    const equals = line.indexOf('=');
    if (equals <= 0) continue;
    const key = line.slice(0, equals).trim();
    const value = line.slice(equals + 1).trim();
    if (key === 'dependencies') {
      let buffer = value;
      // Multi-line array: consume until the brackets balance (bounded).
      let guard = 0;
      while (
        (buffer.match(/\[/g) ?? []).length > (buffer.match(/\]/g) ?? []).length &&
        index + 1 < lines.length && guard < 200
      ) {
        index += 1;
        guard += 1;
        buffer += ` ${(lines[index] ?? '').trim()}`;
      }
      current.dependencies = uvDependencyRefs(buffer);
      continue;
    }
    if (key === 'name') current.name = poetryScalar(value);
    else if (key === 'version') current.version = poetryScalar(value, 80);
    else if (key === 'source') {
      // Only the project's own entry is a root (editable/workspace/virtual).
      current.root = /\b(editable|virtual|directory)\s*=\s*"\.[/"]?/.test(value);
    }
  }
  if (current !== undefined && !truncated) close(current);

  if (!sawPackageTable) {
    return {
      status: 'INVALID_INPUT',
      dependencies: [],
      directNames: [],
      edges: [],
      unresolvedEdges: 0,
      note: 'Lockfile carries no [[package]] tables.',
    };
  }

  const dependencies: RawDependency[] = [];
  const byName = new Map<string, string[]>();
  const depsByKey = new Map<string, UvDependencyRef[]>();
  const roots = new Set<string>();
  let skipped = 0;
  let rootName: string | undefined;
  let rootVersion: string | undefined;

  for (const draft of drafts) {
    if (draft.name === undefined || draft.version === undefined) {
      skipped += 1;
      continue;
    }
    const name = normalizePypiName(draft.name);
    if (name === undefined || !isBoundedVersion(draft.version)) {
      skipped += 1;
      continue;
    }
    const pathKey = `${name}@${draft.version}`;
    if (depsByKey.has(pathKey)) continue;
    depsByKey.set(pathKey, draft.dependencies);
    if (draft.root) {
      roots.add(pathKey);
      rootName ??= name;
      rootVersion ??= draft.version;
    }
    const keys = byName.get(name);
    if (keys === undefined) byName.set(name, [pathKey]);
    else if (!keys.includes(pathKey)) keys.push(pathKey);
    // The project's own package is the ROOT of the graph, never one of its
    // dependencies — listing "demo" as an installed dependency would invent a
    // node the project does not depend on.
    if (draft.root) continue;
    dependencies.push({
      ecosystem: 'pypi',
      name,
      versionSource: 'lockfile',
      dependencyType: 'runtime',
      // Directness needs the declaration; the inventory assigns it.
      dependencyClass: 'unknown',
      packageManager: 'pip',
      manifestPath,
      lockfilePath: manifestPath,
      resolvedVersion: draft.version,
      pathKey,
    });
  }

  const edges: LockEdge[] = [];
  const seenEdges = new Set<string>();
  let edgesTruncated = false;
  let unresolvedEdges = 0;
  let ambiguousEdges = 0;
  const pushEdge = (from: string, to: string): void => {
    if (from !== '' && from === to) return;
    const key = `${from}\n${to}`;
    if (seenEdges.has(key)) return;
    if (edges.length >= LOCK_MAX_EDGES) {
      edgesTruncated = true;
      return;
    }
    seenEdges.add(key);
    edges.push({ from, to });
  };

  const resolveTarget = (dependency: UvDependencyRef): string | undefined => {
    if (dependency.version !== undefined) {
      const exact = `${dependency.name}@${dependency.version}`;
      return depsByKey.has(exact) ? exact : undefined;
    }
    const candidates = byName.get(dependency.name);
    if (candidates === undefined) return undefined;
    // Several locked versions of one name cannot be disambiguated by the
    // entry itself — that is not evidence, so no edge is invented.
    if (candidates.length > 1) {
      ambiguousEdges += 1;
      return undefined;
    }
    return candidates[0];
  };

  const declaredDirect = new Set<string>(
    declaredNames
      .map((name) => normalizePypiName(name))
      .filter((name): name is string => name !== undefined),
  );
  // The project package's own dependencies are the declared direct set when
  // the lock states them (and the companion pyproject may add more).
  for (const rootKey of roots) {
    for (const dependency of depsByKey.get(rootKey) ?? []) {
      declaredDirect.add(dependency.name);
      const target = resolveTarget(dependency);
      if (target === undefined) {
        unresolvedEdges += 1;
        continue;
      }
      pushEdge('', target);
    }
  }

  for (const pathKey of [...depsByKey.keys()].sort()) {
    if (roots.has(pathKey)) continue;
    for (const dependency of depsByKey.get(pathKey) ?? []) {
      const target = resolveTarget(dependency);
      if (target === undefined) {
        unresolvedEdges += 1;
        continue;
      }
      pushEdge(pathKey, target);
    }
  }

  const noteParts: string[] = [];
  if (truncated || truncatedByLines) {
    noteParts.push(`uv.lock exceeded the parser limit (${SCA_PARSER_MAX_ENTRIES} packages).`);
  }
  if (edgesTruncated) noteParts.push(`The lockfile edge budget (${LOCK_MAX_EDGES}) clipped the graph.`);
  if (unresolvedEdges > 0) noteParts.push(`${unresolvedEdges} locked dependency edge(s) could not be resolved inside this lock.`);
  if (ambiguousEdges > 0) noteParts.push(`${ambiguousEdges} dependency (or dependency) name${ambiguousEdges === 1 ? '' : 's'} matched several locked versions and produced no edge.`);
  if (skipped > 0) noteParts.push(`${skipped} [[package]] entr${skipped === 1 ? 'y' : 'ies'} had no usable name/version.`);

  return {
    status: truncated || truncatedByLines || unresolvedEdges > 0 || ambiguousEdges > 0 ? 'PARTIAL' : 'ANALYZED',
    dependencies,
    directNames: [...declaredDirect].filter((name) => byName.has(name)).sort(),
    edges,
    unresolvedEdges,
    ...(edgesTruncated ? { edgesTruncated: true } : {}),
    ...(rootName === undefined ? {} : { rootName }),
    ...(rootVersion === undefined ? {} : { rootVersion }),
    ...(noteParts.length === 0 ? {} : { note: noteParts.join(' ').slice(0, 200) }),
  };
}

// ---------------------------------------------------------------------------
// Pipfile / Pipfile.lock (JSON lock: resolved versions, no inter-package edges)
// ---------------------------------------------------------------------------
//
// A Pipfile is TOML that only declares direct requirements; a Pipfile.lock is
// JSON that pins every resolved package (default + develop). Neither states
// which package depends on which — Pipenv does not record edges — so this
// reader CANNOT evidence a dependency graph. It is still worth reading: the
// pinned versions are installation evidence, which is what advisory matching
// needs. The graph therefore stays `UNAVAILABLE` for Pipenv projects, and the
// manifest note says why.

export function parsePipfile(text: string, manifestPath: string): ManifestParseResult {
  const lines = text.split('\n');
  if (lines.length > SCA_PARSER_MAX_LINES) {
    return {
      status: 'INVALID_INPUT',
      dependencies: [],
      directNames: [],
      note: `Pipfile exceeds the line limit (${SCA_PARSER_MAX_LINES}).`,
    };
  }
  const dependencies: RawDependency[] = [];
  const seen = new Set<string>();
  let section = '';
  let recognized = false;
  let truncated = false;

  for (const rawLine of lines) {
    const line = rawLine.replace(/\r$/, '').trim();
    if (line.length === 0 || line.startsWith('#')) continue;
    const header = line.match(/^\[([^[\]]+)\]$/);
    if (header !== null) {
      section = header[1] ?? '';
      continue;
    }
    if (section !== 'packages' && section !== 'dev-packages') continue;
    recognized = true;
    const assignment = line.match(/^([A-Za-z0-9_.\-[\]@/:]{1,120})\s*=\s*(.*)$/);
    if (assignment === null) continue;
    const name = normalizePypiName(assignment[1] ?? '');
    if (name === undefined) continue;
    const value = assignment[2] ?? '';
    const versionMatch = value.match(/\bversion\s*=\s*"([^"]{0,80})"/)?.[1];
    const declaredVersion = versionMatch === undefined || versionMatch.length === 0
      ? undefined
      : parseRequirementLine(`${name}${versionMatch}`)?.declaredVersion;
    const dependencyType: ScaDependencyType = section === 'dev-packages' ? 'development' : 'runtime';
    const key = `${name}\n${declaredVersion ?? ''}\n${dependencyType}`;
    if (seen.has(key)) continue;
    if (dependencies.length >= SCA_PARSER_MAX_ENTRIES) {
      truncated = true;
      break;
    }
    seen.add(key);
    dependencies.push({
      ecosystem: 'pypi',
      name,
      ...(declaredVersion === undefined ? {} : { declaredVersion }),
      versionSource: 'manifest',
      dependencyType,
      dependencyClass: 'direct',
      packageManager: 'pipenv',
      manifestPath,
    });
  }

  if (!recognized) {
    return {
      status: 'UNSUPPORTED',
      dependencies: [],
      directNames: [],
      note: 'No supported dependency declaration found (expected [packages] or [dev-packages]).',
    };
  }
  return {
    status: truncated ? 'PARTIAL' : 'ANALYZED',
    dependencies,
    directNames: dependencies.map((dependency) => dependency.name),
    ...(truncated ? { note: `Pipfile exceeded the parser limit (${SCA_PARSER_MAX_ENTRIES}).` } : {}),
  };
}

export function parsePipfileLock(
  text: string,
  manifestPath: string,
  declaredNames: readonly string[] = [],
): PoetryLockParseResult {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return {
      status: 'INVALID_INPUT',
      dependencies: [],
      directNames: [],
      edges: [],
      unresolvedEdges: 0,
      note: 'Lockfile is not valid JSON.',
    };
  }
  if (!isPlainObject(parsed)) {
    return {
      status: 'INVALID_INPUT',
      dependencies: [],
      directNames: [],
      edges: [],
      unresolvedEdges: 0,
      note: 'Lockfile root is not a JSON object.',
    };
  }

  const declaredDirect = new Set<string>(
    declaredNames.map((name) => normalizePypiName(name)).filter((name): name is string => name !== undefined),
  );
  const dependencies: RawDependency[] = [];
  const byName = new Set<string>();
  const directNames: string[] = [];
  let truncated = false;
  let skipped = 0;

  for (const section of ['default', 'develop'] as const) {
    const table = parsed[section];
    if (!isPlainObject(table)) continue;
    for (const key of Object.keys(table).sort()) {
      if ((FORBIDDEN_KEYS as readonly string[]).includes(key)) continue;
      const name = normalizePypiName(key);
      if (name === undefined) {
        skipped += 1;
        continue;
      }
      const entry = table[key];
      const versionRaw = isPlainObject(entry) ? ownString(entry, 'version') : undefined;
      // Pipenv pins with `==`, but a VCS/path requirement has no version.
      const version = versionRaw === undefined ? undefined : versionRaw.replace(/^==\s*/, '');
      const usable = version !== undefined && isBoundedVersion(version);
      if (dependencies.length >= SCA_PARSER_MAX_ENTRIES) {
        truncated = true;
        break;
      }
      if (!usable) {
        skipped += 1;
        continue;
      }
      const isDirect = declaredDirect.has(name);
      if (isDirect) directNames.push(name);
      byName.add(name);
      dependencies.push({
        ecosystem: 'pypi',
        name,
        versionSource: 'lockfile',
        dependencyType: section === 'develop' ? 'development' : 'runtime',
        // Without a Pipfile, Pipenv's sections do not tell direct from
        // transitive (all resolved packages live in `default`).
        dependencyClass: isDirect ? 'direct' : declaredDirect.size === 0 ? 'unknown' : 'transitive',
        packageManager: 'pipenv',
        manifestPath,
        lockfilePath: manifestPath,
        resolvedVersion: version,
        pathKey: `${name}@${version}`,
      });
    }
  }

  if (dependencies.length === 0 && skipped === 0) {
    return {
      status: 'INVALID_INPUT',
      dependencies: [],
      directNames: [],
      edges: [],
      unresolvedEdges: 0,
      note: 'Lockfile carries no default/develop package tables.',
    };
  }

  const noteParts: string[] = [
    'A Pipfile.lock pins resolved versions but records no inter-package edges, so no dependency graph can be evidenced from it.',
  ];
  if (truncated) noteParts.push(`Lockfile exceeded the parser limit (${SCA_PARSER_MAX_ENTRIES} packages).`);
  if (skipped > 0) noteParts.push(`${skipped} locked entr${skipped === 1 ? 'y' : 'ies'} had no usable version.`);

  return {
    status: truncated ? 'PARTIAL' : 'ANALYZED',
    dependencies,
    directNames: [...new Set(directNames)].sort(),
    edges: [],
    unresolvedEdges: 0,
    ...(noteParts.length === 0 ? {} : { note: noteParts.join(' ').slice(0, 200) }),
  };
}

// ---------------------------------------------------------------------------
// pip-compile output (`requirements.txt` with `# via` provenance)
// ---------------------------------------------------------------------------
//
// `pip-compile` (pip-tools) writes a fully pinned file AND records where each
// pin came from:
//
//     requests==2.31.0
//         # via -r requirements.in
//     certifi==2023.7.22
//         # via requests
//
// That `# via` block is real dependency evidence: "<parent> via" means the
// parent requires the pinned line. So a compiled file can evidence a PyPI
// graph — but ONLY when the provenance is present and complete. A hand-written
// requirements file has no `# via` lines at all, and then this function reports
// `graphEvidence: false` so the caller keeps the old, honest "no graph" answer.
//
// Nothing is guessed: an edge needs BOTH endpoints pinned in this file, and any
// pin whose provenance is missing or points outside the file is counted and
// makes the result PARTIAL.

export interface RequirementsGraphResult extends ManifestParseResult {
  edges: LockEdge[];
  edgesTruncated?: boolean;
  unresolvedEdges: number;
  /** True only when pip-compile `# via` provenance was actually found. */
  graphEvidence: boolean;
}

const PINNED = /^==\s*([^,;]{1,80})$/;

export function parseCompiledRequirements(
  text: string,
  manifestPath: string,
): RequirementsGraphResult {
  const physicalLines = text.split('\n');
  if (physicalLines.length > SCA_PARSER_MAX_LINES) {
    return {
      status: 'INVALID_INPUT',
      dependencies: [],
      directNames: [],
      edges: [],
      unresolvedEdges: 0,
      graphEvidence: false,
      note: `Requirements file exceeds the line limit (${SCA_PARSER_MAX_LINES}).`,
    };
  }
  // Same logical-line joining as parseRequirementsTxt (trailing backslash).
  const logical: string[] = [];
  let buffer = '';
  for (const raw of physicalLines) {
    const line = raw.replace(/\r$/, '');
    if (line.endsWith('\\')) {
      buffer += `${line.slice(0, -1)} `;
      continue;
    }
    buffer += line;
    logical.push(buffer);
    buffer = '';
  }
  if (buffer.length > 0) logical.push(buffer);

  interface Pinned {
    name: string;
    version: string;
    integrity?: string;
    line: number;
    parents: string[];
    direct: boolean;
    sawVia: boolean;
  }
  const pins: Pinned[] = [];
  let current: Pinned | undefined;
  let inViaBlock = false;
  let sawAnyVia = false;

  const parseParents = (raw: string): { names: string[]; direct: boolean } => {
    const names: string[] = [];
    let direct = false;
    for (const token of raw.split(',')) {
      const trimmed = token.trim();
      if (trimmed.length === 0) continue;
      // `-r requirements.in`, `-c constraints.txt`, `-e …`: the pin came from
      // a project file, i.e. it is a direct requirement of that file.
      if (trimmed.startsWith('-')) {
        direct = true;
        continue;
      }
      const withoutVersion = trimmed.replace(/\s*\([^()]{0,80}\)\s*$/, '').trim();
      const name = normalizePypiName(withoutVersion);
      if (name === undefined) continue;
      names.push(name);
    }
    return { names, direct };
  };

  for (const rawLine of logical) {
    const line = rawLine.replace(/\r$/, '');
    const commentAt = line.indexOf('#');
    const code = (commentAt === -1 ? line : line.slice(0, commentAt)).trim();
    const comment = commentAt === -1 ? '' : line.slice(commentAt).trim();

    // 1) A requirement on this logical line. `pip-compile --generate-hashes`
    // writes the `# via` marker on the CONTINUATION of a backslash-joined
    // block, so the requirement, its hashes and its provenance can all arrive
    // in one logical line. Split at `#` and read both halves.
    if (code.length > 0 && !code.startsWith('-') && !/^https?:\/\//.test(code)) {
      const parsedLine = parseRequirementLine(code);
      const pinned = parsedLine?.declaredVersion === undefined
        ? undefined
        : parsedLine.declaredVersion.match(PINNED)?.[1];
      if (
        parsedLine === undefined || pinned === undefined ||
        !isBoundedVersion(pinned) || pins.length >= SCA_PARSER_MAX_ENTRIES
      ) {
        current = undefined;
      } else {
        current = {
          name: parsedLine.name,
          version: pinned,
          ...(parsedLine.integrity === undefined ? {} : { integrity: parsedLine.integrity }),
          line: pins.length,
          parents: [],
          direct: false,
          sawVia: false,
        };
        pins.push(current);
      }
      inViaBlock = false;
    } else if (code.length > 0) {
      // Options, URLs, includes: no node, and no provenance applies to them.
      current = undefined;
      inViaBlock = false;
    }

    // 2) The provenance comment.
    const via = comment.match(/^#\s*via\b(.*)$/);
    if (via !== null) {
      if (current !== undefined) {
        sawAnyVia = true;
        current.sawVia = true;
        const { names, direct } = parseParents(via[1] ?? '');
        current.parents.push(...names);
        current.direct = current.direct || direct;
      }
      inViaBlock = true;
      continue;
    }
    if (comment.length === 0) continue;
    if (inViaBlock && current !== undefined && /^#\s{2,}\S/.test(comment)) {
      // Continuation of a multi-parent block: "#   -r requirements.in".
      const { names, direct } = parseParents(comment.replace(/^#\s+/, ''));
      current.parents.push(...names);
      current.direct = current.direct || direct;
      continue;
    }
    // Any other comment ends the provenance block.
    inViaBlock = false;
  }

  if (!sawAnyVia || pins.length === 0) {
    return {
      status: 'ANALYZED',
      dependencies: [],
      directNames: [],
      edges: [],
      unresolvedEdges: 0,
      graphEvidence: false,
    };
  }

  const byName = new Map<string, string[]>();
  const dependencies: RawDependency[] = [];
  const nodeByLine = new Map<number, string>();
  for (const pin of pins) {
    const pathKey = `${pin.name}@${pin.version}`;
    const keys = byName.get(pin.name);
    if (keys === undefined) byName.set(pin.name, [pathKey]);
    else if (!keys.includes(pathKey)) keys.push(pathKey);
    nodeByLine.set(pin.line, pathKey);
    dependencies.push({
      ecosystem: 'pypi',
      name: pin.name,
      // The compiled file IS the lock for this project: every line is a
      // resolved pin, so the version is installation evidence.
      versionSource: 'lockfile',
      dependencyType: 'runtime',
      dependencyClass: 'unknown', // assigned by the inventory
      packageManager: 'pip',
      manifestPath,
      lockfilePath: manifestPath,
      resolvedVersion: pin.version,
      pathKey,
      ...(pin.integrity === undefined ? {} : { integrity: pin.integrity }),
    });
  }

  const edges: LockEdge[] = [];
  const seenEdges = new Set<string>();
  let edgesTruncated = false;
  let unresolvedEdges = 0;
  let missingProvenance = 0;
  const directNames: string[] = [];
  const pushEdge = (from: string, to: string): void => {
    if (from === to) return;
    const key = `${from}\n${to}`;
    if (seenEdges.has(key)) return;
    if (edges.length >= LOCK_MAX_EDGES) {
      edgesTruncated = true;
      return;
    }
    seenEdges.add(key);
    edges.push({ from, to });
  };

  for (const pin of pins) {
    const node = nodeByLine.get(pin.line);
    if (node === undefined) continue;
    if (!pin.sawVia) {
      missingProvenance += 1;
      continue;
    }
    if (pin.direct) {
      directNames.push(pin.name);
      pushEdge('', node);
    }
    for (const parent of pin.parents) {
      const targets = byName.get(parent);
      if (targets === undefined) {
        unresolvedEdges += 1; // parent is not pinned in this file
        continue;
      }
      for (const parentKey of targets) {
        if (parentKey === node) continue;
        pushEdge(parentKey, node);
      }
    }
  }

  const noteParts: string[] = [];
  if (unresolvedEdges > 0) noteParts.push(`${unresolvedEdges} '# via' parent(s) are not pinned in this file.`);
  if (missingProvenance > 0) noteParts.push(`${missingProvenance} pinned requirement(s) carry no '# via' provenance.`);
  if (edgesTruncated) noteParts.push(`The lockfile edge budget (${LOCK_MAX_EDGES}) clipped the graph.`);

  return {
    status: unresolvedEdges > 0 || missingProvenance > 0 || edgesTruncated ? 'PARTIAL' : 'ANALYZED',
    dependencies,
    directNames: [...new Set(directNames)].sort(),
    edges,
    unresolvedEdges,
    graphEvidence: true,
    ...(edgesTruncated ? { edgesTruncated: true } : {}),
    ...(noteParts.length === 0 ? {} : { note: noteParts.join(' ').slice(0, 200) }),
  };
}
