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
}

export function parsePackageLock(
  text: string,
  manifestPath: string,
): ManifestParseResult & { lockfileVersion?: number; entries: LockEntry[] } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return {
      status: 'INVALID_INPUT',
      dependencies: [],
      directNames: [],
      entries: [],
      note: 'Lockfile is not valid JSON.',
    };
  }
  if (!isPlainObject(parsed)) {
    return {
      status: 'INVALID_INPUT',
      dependencies: [],
      directNames: [],
      entries: [],
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
        lockfileVersion,
        note: 'Lockfile carries no packages map.',
      };
    }
  }

  const dependencies: RawDependency[] = [];
  const entries: LockEntry[] = [];
  const directNames = new Set<string>();
  let truncated = false;

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
      });
      dependencies.push({
        ecosystem: 'npm',
        name,
        versionSource: 'lockfile',
        dependencyType,
        // Direct when the root entry declares it; everything else in a
        // lockfile's closure is transitive.
        dependencyClass: directNames.has(name) ? 'direct' : 'transitive',
        packageManager: 'npm',
        manifestPath,
        lockfilePath: manifestPath,
        resolvedVersion: version,
        ...(integrity === undefined ? {} : { integrity }),
      });
    }
  } else if (isPlainObject(parsed['dependencies'])) {
    // lockfileVersion 1 (or v2 lock without packages): the flat map.
    // No root entry → the direct set comes from the companion
    // package.json (merged by the inventory step). Without it the
    // class stays unknown — never guessed.
    const map = parsed['dependencies'];
    for (const key of Object.keys(map).sort()) {
      if ((FORBIDDEN_KEYS as readonly string[]).includes(key)) {
        continue;
      }
      const name = normalizeNpmName(key);
      if (name === undefined) {
        continue;
      }
      const entry = map[key];
      if (!isPlainObject(entry)) {
        continue;
      }
      const version = ownString(entry, 'version');
      if (version === undefined || !isBoundedVersion(version)) {
        continue;
      }
      const integrityRaw = ownString(entry, 'integrity');
      const integrity =
        integrityRaw !== undefined && isBoundedIntegrity(integrityRaw) ? integrityRaw : undefined;
      if (entries.length >= SCA_PARSER_MAX_ENTRIES) {
        truncated = true;
        break;
      }
      const dependencyType =
        entry['dev'] === true
          ? 'development'
          : entry['optional'] === true
            ? 'optional'
            : 'runtime';
      entries.push({
        name,
        version,
        ...(integrity === undefined ? {} : { integrity }),
        dependencyType,
      });
      dependencies.push({
        ecosystem: 'npm',
        name,
        versionSource: 'lockfile',
        dependencyType,
        dependencyClass: 'unknown', // Direct set unavailable at v1 parse time.
        packageManager: 'npm',
        manifestPath,
        lockfilePath: manifestPath,
        resolvedVersion: version,
        ...(integrity === undefined ? {} : { integrity }),
      });
    }
  } else {
    return {
      status: 'INVALID_INPUT',
      dependencies: [],
      directNames: [],
      entries: [],
      lockfileVersion,
      note: 'Lockfile carries no packages or dependencies map.',
    };
  }

  return {
    status: truncated ? 'PARTIAL' : 'ANALYZED',
    dependencies,
    directNames: [...directNames].sort(),
    entries,
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
  let truncated = false;

  for (const line of logical) {
    const trimmed = line.trim();
    if (
      trimmed.length === 0 ||
      trimmed.startsWith('#') ||
      trimmed.startsWith('-') ||
      /^https?:\/\//.test(trimmed)
    ) {
      if (trimmed.startsWith('-')) {
        skippedOptions += 1;
      }
      continue;
    }
    const parsedLine = parseRequirementLine(line);
    if (parsedLine === undefined) {
      continue;
    }
    if (seen.has(parsedLine.name)) {
      continue; // Duplicate declaration: first (deterministic) wins.
    }
    if (dependencies.length >= SCA_PARSER_MAX_ENTRIES) {
      truncated = true;
      break;
    }
    seen.add(parsedLine.name);
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
  if (truncated) {
    noteParts.push(`Requirements exceeded the parser limit (${SCA_PARSER_MAX_ENTRIES}).`);
  } else if (skippedOptions > 0) {
    noteParts.push(`${skippedOptions} option/directive line(s) skipped.`);
  }
  return {
    status: truncated ? 'PARTIAL' : 'ANALYZED',
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

  const pushPep508 = (raw: string, type: ScaDependencyType): void => {
    const parsedLine = parseRequirementLine(raw);
    if (parsedLine === undefined || seen.has(parsedLine.name)) {
      return;
    }
    if (dependencies.length >= SCA_PARSER_MAX_ENTRIES) {
      truncated = true;
      return;
    }
    seen.add(parsedLine.name);
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
    if (section === 'project') {
      const assignment = line.match(/^([A-Za-z0-9_.-]+)\s*=\s*(.*)$/);
      if (assignment === null) {
        continue;
      }
      const key = assignment[1] ?? '';
      const value = assignment[2] ?? '';
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
      if (name === undefined || seen.has(name)) {
        continue;
      }
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
      if (dependencies.length >= SCA_PARSER_MAX_ENTRIES) {
        truncated = true;
        break;
      }
      seen.add(name);
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
    ...(truncated
      ? { note: `pyproject.toml exceeded the parser limit (${SCA_PARSER_MAX_ENTRIES}).` }
      : {}),
  };
}
