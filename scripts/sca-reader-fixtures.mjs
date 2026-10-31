/**
 * Round-trip fixtures for the bounded SCA declaration readers.
 *
 * The dataset's declared tests ship PARSED documents, not raw text. This
 * module renders those documents back into realistic (bounded) manifest text
 * so `verify-dataset.mjs` can compare the app's readers against each fixture.
 * Renderings are approximations and may not represent every valid artifact.
 * It is VERIFICATION TOOLING, not production code: the app never
 * calls a renderer, and no dataset bytes live in this repo.
 *
 * A renderer returning `undefined` means "no canonical fixture for this
 * artifact shape" — the harness reports that honestly instead of pretending.
 */

import { isDeepStrictEqual } from 'node:util';

function isRecord(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function quote(value) {
  return `"${String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

function scalarText(value) {
  if (typeof value === 'string') return quote(value);
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (value === null) return quote('');
  return quote('');
}

function tomlKey(key) {
  return /^[A-Za-z0-9_-]+$/.test(key) ? key : quote(key);
}

function renderTomlValue(value) {
  if (Array.isArray(value)) return `[${value.map(scalarText).join(', ')}]`;
  if (isRecord(value)) {
    return `{ ${Object.entries(value).map(([key, item]) => `${tomlKey(key)} = ${scalarText(item)}`).join(', ')} }`;
  }
  return scalarText(value);
}

function renderToml(document) {
  const out = [];
  const walk = (obj, path) => {
    const scalars = [];
    const tables = [];
    const arrays = [];
    for (const [key, value] of Object.entries(obj)) {
      if (Array.isArray(value) && value.length > 0 && value.every(isRecord)) arrays.push([key, value]);
      else if (isRecord(value)) tables.push([key, value]);
      else scalars.push([key, value]);
    }
    if (path.length > 0) out.push(`[${path.join('.')}]`);
    for (const [key, value] of scalars) out.push(`${tomlKey(key)} = ${renderTomlValue(value)}`);
    for (const [key, value] of arrays) {
      for (const item of value) {
        const itemPath = [...path, tomlKey(key)];
        out.push(`[[${itemPath.join('.')}]]`);
        const nestedArrays = [];
        for (const [innerKey, innerValue] of Object.entries(item)) {
          if (Array.isArray(innerValue) && innerValue.length > 0 && innerValue.every(isRecord)) nestedArrays.push([innerKey, innerValue]);
          else if (isRecord(innerValue)) {
            for (const [nk, nv] of Object.entries(innerValue)) if (!isRecord(nv) && !Array.isArray(nv)) out.push(`${tomlKey(innerKey)}.${tomlKey(nk)} = ${renderTomlValue(nv)}`);
          } else out.push(`${tomlKey(innerKey)} = ${renderTomlValue(innerValue)}`);
        }
        // Enter nested arrays only after the parent keys have been written.
        for (const [innerKey, innerValue] of nestedArrays) {
          for (const nested of innerValue) {
            out.push(`[[${[...itemPath, tomlKey(innerKey)].join('.')}]]`);
            for (const [nk, nv] of Object.entries(nested)) if (!isRecord(nv) && !Array.isArray(nv)) out.push(`${tomlKey(nk)} = ${renderTomlValue(nv)}`);
          }
        }
      }
    }
    for (const [key, value] of tables) walk(value, [...path, tomlKey(key)]);
  };
  walk(document, []);
  return `${out.join('\n')}\n`;
}

function yamlScalar(value) {
  if (typeof value === 'string') return quote(value);
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return quote('');
}

function renderYaml(document) {
  const out = [];
  const pad = (indent) => ' '.repeat(indent);
  const walk = (obj, indent) => {
    for (const [key, value] of Object.entries(obj)) {
      if (Array.isArray(value)) {
        out.push(`${pad(indent)}${key}:`);
        for (const item of value) {
          if (isRecord(item)) {
            if (Object.keys(item).length === 0) out.push(`${pad(indent + 2)}- {}`);
            else { out.push(`${pad(indent + 2)}-`); walk(item, indent + 4); }
          } else {
            out.push(`${pad(indent + 2)}- ${yamlScalar(item)}`);
          }
        }
      } else if (isRecord(value)) {
        out.push(`${pad(indent)}${key}:`);
        walk(value, indent + 2);
      } else {
        out.push(`${pad(indent)}${key}: ${yamlScalar(value)}`);
      }
    }
  };
  walk(document, 0);
  return `${out.join('\n')}\n`;
}

function singular(name) {
  if (name.endsWith('ies')) return `${name.slice(0, -3)}y`;
  if (name.endsWith('s') && !name.endsWith('ss')) return name.slice(0, -1);
  return name;
}

function xmlEscape(value) {
  return String(value).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function xmlElement(name, value) {
  if (Array.isArray(value)) {
    const child = singular(name);
    return `<${name}>${value.map((item) => xmlElement(child, item)).join('')}</${name}>`;
  }
  if (isRecord(value)) {
    const attrs = [];
    const children = [];
    for (const [key, item] of Object.entries(value)) {
      if (isRecord(item) || Array.isArray(item)) children.push(xmlElement(key, item));
      else if (item !== undefined) attrs.push(`${key}=${quote(xmlEscape(item))}`);
    }
    return `<${name}${attrs.length > 0 ? ` ${attrs.join(' ')}` : ''}>${children.join('')}</${name}>`;
  }
  return `<${name}>${xmlEscape(value ?? '')}</${name}>`;
}

function renderXml(document, artifact) {
  if (artifact.toLowerCase() === 'nuget.config') {
    const declared = isRecord(document['packageSources']) ? document['packageSources'] : undefined;
    // In the reader's NuGet model `sources` is derived from packageSources.add.
    // A populated sources alias with an explicitly missing add list cannot be
    // represented by one real nuget.config without changing the fixture.
    if (declared !== undefined && declared.add === undefined && Array.isArray(document['sources']) && document['sources'].length > 0) return undefined;
    // Even when both aliases exist, the reader derives them from one source
    // list; conflicting values cannot be represented by a real NuGet file.
    if (declared?.add !== undefined && Array.isArray(document['sources'])) {
      const added = Array.isArray(declared.add) ? declared.add : [declared.add];
      if (!isDeepStrictEqual(added, document['sources'])) return undefined;
    }
    const supplied = declared?.add ?? document['sources'];
    const sources = Array.isArray(supplied) ? supplied : supplied === undefined ? [] : [supplied];
    const attrs = (entry) => Object.entries(entry).filter(([key, value]) => key !== 'password' && !isRecord(value) && !Array.isArray(value))
      .map(([key, value]) => ` ${key}=${quote(xmlEscape(value))}`).join('');
    const parts = [];
    if (declared !== undefined || sources.length > 0) {
      parts.push(`<packageSources>${String(declared?.clear).toLowerCase() === 'true' ? '<clear />' : ''}${sources.map((entry) => `<add${attrs(entry)} />`).join('')}</packageSources>`);
    }
    const credentials = sources.filter((entry) => entry.password !== undefined);
    if (credentials.length > 0) {
      if (credentials.some((entry) => !/^[A-Za-z_][A-Za-z0-9_.-]*$/.test(entry.key ?? ''))) return undefined;
      parts.push(`<packageSourceCredentials>${credentials.map((entry) => `<${entry.key}><add key="ClearTextPassword" value=${quote(xmlEscape(entry.password))} /></${entry.key}>`).join('')}</packageSourceCredentials>`);
    }
    const config = { ...(isRecord(document['config']) ? document['config'] : {}), ...(isRecord(document['settings']) ? document['settings'] : {}) };
    if (Object.keys(config).length > 0) parts.push(`<config>${Object.entries(config).map(([key, value]) => `<add key=${quote(key)} value=${quote(xmlEscape(value))} />`).join('')}</config>`);
    for (const key of ['packageSourceMapping', 'disabledPackageSources']) {
      if (document[key] !== undefined) parts.push(xmlElement(key, document[key]));
    }
    return { text: `<configuration>${parts.join('')}</configuration>`, wrapped: false };
  }
  if (artifact.toLowerCase() === 'packages.config') {
    const packages = Array.isArray(document['packages']) ? document['packages'] : [];
    if (document['targetFramework'] !== undefined && packages.length === 0) return undefined;
    return { text: `<packages>${packages.map((entry, index) => xmlElement('package', {
      ...entry, ...(index === 0 && document['targetFramework'] !== undefined ? { targetFramework: document['targetFramework'] } : {}),
    })).join('')}</packages>`, wrapped: false };
  }
  const entries = Object.entries(document);
  if (entries.length === 1) {
    const [key, value] = entries[0];
    return { text: xmlElement(key, value), wrapped: false };
  }
  const body = entries.map(([key, value]) => xmlElement(key, value)).join('');
  return { text: `<root>${body}</root>`, wrapped: true };
}

function renderIni(document, artifact) {
  if (artifact === 'conanfile.txt') {
    return ['requires', 'generators', 'tool_requires']
      .filter((key) => Array.isArray(document[key]))
      .flatMap((key) => [`[${key}]`, ...document[key].map(String)])
      .join('\n');
  }
  const out = [];
  const isConfig = artifact === 'pip.conf' || artifact === '.pypirc';
  let source = isConfig && isRecord(document['config']) ? document['config'] : document;
  // `.npmrc` has no [config] section in real files: the reader wraps root
  // keys under `config` itself.
  if (artifact === '.npmrc' && isRecord(document['config'])) source = { name: document['name'] ?? '', ...document['config'] };
  const roots = [];
  const sections = [];
  for (const [key, value] of Object.entries(source)) {
    if (isRecord(value)) {
      const flat = Object.entries(value).filter(([, item]) => !isRecord(item));
      const nested = Object.entries(value).filter(([, item]) => isRecord(item));
      if (flat.length > 0 || nested.length === 0) sections.push([[key], Object.fromEntries(flat)]);
      for (const [innerKey, innerValue] of nested) sections.push([[key, innerKey], innerValue]);
    } else {
      roots.push([key, value]);
    }
  }
  const line = (key, value) => Array.isArray(value) ? `${key}[] = ${value.join(', ')}` : `${key} = ${value}`;
  for (const [key, value] of roots) out.push(line(key, value));
  for (const [path, values] of sections) {
    out.push(`[${path.join('.')}]`);
    for (const [key, value] of Object.entries(values)) out.push(line(key, value));
  }
  return `${out.join('\n')}\n`;
}

function renderProperties(document, artifact) {
  const source = artifact === 'gradle.properties' && isRecord(document['properties']) ? document['properties'] : document;
  const out = [];
  for (const [key, value] of Object.entries(source)) {
    out.push(Array.isArray(value) ? `${key}[]: ${value.join(', ')}` : `${key}: ${value}`);
  }
  return `${out.join('\n')}\n`;
}

function renderRequirements(document) {
  const items = Array.isArray(document['requirements']) ? document['requirements'] : [];
  const lines = items.map((item) => {
    const extras = Array.isArray(item.extras) && item.extras.length > 0 ? `[${item.extras.join(',')}]` : '';
    const base = `${item.name ?? ''}${extras}`;
    if (item.source !== undefined) return `${base} @ ${item.source}`;
    const hashes = Array.isArray(item.hashes) ? item.hashes.map((h) => ` --hash=${h}`).join('') : '';
    return `${base}${item.specifier ?? ''}${hashes}`;
  });
  if (isRecord(document['options'])) {
    for (const [key, value] of Object.entries(document['options'])) {
      for (const item of Array.isArray(value) ? value : [value]) lines.push(`--${key.replace(/_/g, '-')}=${item}`);
    }
  }
  for (const key of ['index-url', 'extra-index-url', 'trusted-host', 'no-binary']) {
    if (document[key] !== undefined) lines.push(`--${key}=${document[key]}`);
  }
  return lines.length > 0 ? `${lines.join('\n')}\n` : '# empty requirements\n';
}

function renderGoMod(document) {
  const out = [];
  if (document['module'] !== undefined) out.push(`module ${document['module']}`);
  if (document['go'] !== undefined) out.push(`go ${document['go']}`);
  if (document['toolchain'] !== undefined) out.push(`toolchain ${document['toolchain']}`);
  for (const section of ['require', 'replace', 'exclude', 'retract']) {
    const items = Array.isArray(document[section]) ? document[section] : [];
    if (items.length === 0) continue;
    out.push(`${section} (`);
    for (const item of items) {
      if (section === 'require') out.push(`  ${item.module ?? ''} ${item.version ?? ''}${String(item.indirect).toLowerCase() === 'true' ? ' // indirect' : ''}`);
      else if (section === 'replace') out.push(`  ${item.old?.path ?? ''} => ${item.new?.path ?? ''} ${item.new?.version ?? ''}`);
      else if (section === 'retract') out.push(`  ${item.version ?? ''}`);
      else out.push(`  ${item.module ?? ''} ${item.version ?? ''}`);
    }
    out.push(')');
  }
  return `${out.join('\n')}\n`;
}

function renderGradle(document, artifact) {
  const repositories = (list) => (Array.isArray(list) ? list : []).map((item) => {
    if (String(item.flatDir).toLowerCase() === 'true') return `  flatDir { dirs ${(item.dirs ?? ['libs']).map(quote).join(', ')} }`;
    if (item.name === 'mavenLocal' && item.url === undefined) return '  mavenLocal()';
    const parts = [];
    if (item.name !== undefined) parts.push(`name ${quote(item.name)}`);
    if (item.url !== undefined) parts.push(`url ${quote(item.url)}`);
    if (item.allowInsecureProtocol !== undefined) parts.push(`allowInsecureProtocol = ${item.allowInsecureProtocol}`);
    if (isRecord(item.credentials)) parts.push(`credentials { ${Object.entries(item.credentials).map(([key, value]) => `${key} ${quote(value)}`).join('; ')} }`);
    if (item.content !== undefined) parts.push('content { includeGroup("fixture") }');
    if (item.mavenContent !== undefined) parts.push(`mavenContent { ${item.mavenContent.snapshotsOnly ? 'snapshotsOnly()' : ''} }`);
    return `  maven { ${parts.join('; ')} }`;
  }).join('\n');
  const plugins = (list) => (Array.isArray(list) ? list : []).map((item) =>
    `  id ${quote(item.id ?? '')}${item.version === undefined ? '' : ` version ${quote(item.version)}`}`).join('\n');
  if (artifact === 'settings.gradle') {
    const pm = document['pluginManagement'] ?? {};
    const dr = document['dependencyResolutionManagement'] ?? {};
    const substitutions = Array.isArray(document['dependencySubstitution']) ? document['dependencySubstitution'] : [];
    return [
      'pluginManagement {', '  repositories {', repositories(pm.repositories), '  }',
      ...(pm.plugins === undefined ? [] : ['  plugins {', plugins(pm.plugins), '  }']), '}',
      'dependencyResolutionManagement {', '  repositories {', repositories(dr.repositories), '  }',
      ...(dr.metadataSources === undefined ? [] : ['  metadataSources { gradleMetadata() }']), '}',
      ...(substitutions.length === 0 ? [] : ['dependencySubstitution {', ...substitutions.map((item) =>
        `  substitute module(${quote(item.module ?? '')}) using project(${quote(item.substitute?.project?.path ?? '')})`), '}']),
    ].join('\n');
  }
  const dependencies = (Array.isArray(document['dependencies']) ? document['dependencies'] : []).map((item) => {
    const dep = isRecord(item) ? item : { notation: item };
    const notation = dep.notation ?? [dep.group, dep.name, dep.version].filter((value) => value !== undefined).join(':');
    const parts = [];
    if (dep.changing !== undefined) parts.push(`changing = ${dep.changing}`);
    if (dep.transitive !== undefined) parts.push(`transitive = ${dep.transitive}`);
    if (dep.targetConfiguration !== undefined) parts.push(`targetConfiguration = ${quote(dep.targetConfiguration)}`);
    for (const exclusion of Array.isArray(dep.exclude) ? dep.exclude : []) parts.push(`exclude group: ${quote(exclusion.group ?? '')}`);
    return `  ${dep.configuration ?? 'implementation'} ${quote(notation)}${parts.length === 0 ? '' : ` { ${parts.join('; ')} }`}`;
  }).join('\n');
  const force = (Array.isArray(document['configurations']) ? document['configurations'] : []).flatMap((config) =>
    (Array.isArray(config.resolutionStrategy?.force) ? config.resolutionStrategy.force : []).map((item) =>
      `    force ${quote([item.group, item.name, item.version].filter((value) => value !== undefined).join(':'))}`));
  return [
    'repositories {', repositories(document['repositories']), '}',
    ...(document['plugins'] === undefined ? [] : ['plugins {', plugins(document['plugins']), '}']),
    'dependencies {', dependencies, '}',
    ...(document['dependencyLocking'] === undefined ? [] : ['dependencyLocking {',
      String(document['dependencyLocking'].lockAllConfigurations).toLowerCase() === 'true' ? '  lockAllConfigurations()' : '', '}']),
    ...(force.length === 0 ? [] : ['configurations { runtimeClasspath { resolutionStrategy {', ...force, '} } }']),
  ].join('\n');
}

function renderLockfileText(document, artifact) {
  if (artifact === 'go.mod') return renderGoMod(document);
  if (artifact === 'go.work') {
    const uses = Array.isArray(document['use']) ? document['use'] : [];
    return [`go ${document['go'] ?? '1.22'}`, 'use (', ...uses.map((item) => `  ${item}`), ')'].join('\n');
  }
  if (artifact === 'Podfile.lock') {
    const pods = Array.isArray(document['pods']) ? document['pods'] : [];
    return ['PODS:', ...pods.map((item) => `  - ${item.name ?? ''} (${item.version ?? ''})`), 'SPEC CHECKSUMS:',
      ...pods.filter((item) => item.checksum !== undefined).map((item) => `  ${item.name}: ${item.checksum}`)].join('\n');
  }
  if (artifact === 'conanfile.py') {
    const remotes = isRecord(document['remotes']) ? document['remotes'] : {};
    return ['class FixtureRecipe:', '    remotes = {', ...Object.entries(remotes).map(([name, value]) =>
      `        ${quote(name)}: {"url": ${quote(value.url ?? '')}, "verify_ssl": ${value.verify_ssl === false ? 'False' : 'True'}},`), '    }'].join('\n');
  }
  if (artifact === 'yarn.lock') {
    const entries = Array.isArray(document['entries']) ? document['entries'] : [];
    return `${entries.map((item) => {
      const rest = Object.entries(item).filter(([key]) => key !== 'name')
        .map(([key, value]) => `  ${key} "${value ?? ''}"`).join('\n');
      return `${item.name ?? 'pkg'}@^1.0.0:${rest.length > 0 ? `\n${rest}` : ''}`;
    }).join('\n')}\n`;
  }
  if (artifact === 'go.sum') {
    const entries = Array.isArray(document['entries']) ? document['entries'] : [];
    return `${entries.map((item) => `${item.module ?? ''} ${item.version ?? ''}${item.hash !== undefined ? ` ${item.hash}` : ''}`).join('\n')}\n`;
  }
  if (artifact === 'Gemfile') {
    const gems = Array.isArray(document['gems']) ? document['gems'] : [];
    return [`source "${document['source'] ?? 'https://rubygems.org'}"`,
      ...gems.map((item) => {
        const extra = [];
        if (item.git !== undefined) extra.push(`git: "${item.git}"`);
        if (item.path !== undefined) extra.push(`path: "${item.path}"`);
        return `gem "${item.name ?? ''}", "${item.requirement ?? ''}"${extra.length > 0 ? `, ${extra.join(', ')}` : ''}`;
      }),
      ...(document['gemspec'] !== undefined ? [`gemspec path: "${document['gemspec']}"`] : [])].join('\n');
  }
  if (artifact === 'mix.exs') {
    const deps = Array.isArray(document['deps']) ? document['deps'] : [];
    return ['defmodule Demo.MixProject do', `  def project, do: [app: :${document['project']?.app ?? 'demo'}]`, '  defp deps do', '    [', ...deps.map((item) => {
      const parts = [];
      if (item.requirement !== undefined) parts.push(quote(item.requirement));
      for (const key of ['git', 'path']) if (item[key] !== undefined) parts.push(`${key}: ${quote(item[key])}`);
      if (item.only !== undefined) parts.push(`only: :${item.only}`);
      if (item.override !== undefined) parts.push(`override: ${item.override}`);
      return `      {:${item.name ?? 'dep'}, ${parts.join(', ')}},`;
    }), '    ]', '  end',
    ...(Array.isArray(document['package']?.licenses) ? [`  defp package, do: [licenses: [${document['package'].licenses.map(quote).join(', ')}]]`] : []),
    'end'].join('\n');
  }
  if (artifact === 'mix.lock') {
    const packages = isRecord(document['packages']) ? document['packages'] : {};
    return Object.entries(packages).map(([key, value]) => {
      const entry = isRecord(value) ? value : { version: value };
      const extra = Object.entries(entry).filter(([k]) => !['version'].includes(k)).map(([k, v]) => `, "${k}": "${v ?? ''}"`).join('');
      return `  ${quote(key)}: {:hex, :${key}, "${entry.version ?? ''}"${extra}},`;
    }).join('\n');
  }
  if (artifact === 'Podfile') {
    const sources = Array.isArray(document['sources']) ? document['sources'] : [];
    const pods = Array.isArray(document['pods']) ? document['pods'] : [];
    return [...sources.map((item) => `source "${item}"`), ...pods.map((item) => {
      const extra = [];
      if (item.git !== undefined) extra.push(`:git => "${item.git}"`);
      if (item.path !== undefined) extra.push(`:path => "${item.path}"`);
      return `pod "${item.name ?? ''}", "${item.requirement ?? ''}"${extra.length > 0 ? `, ${extra.join(', ')}` : ''}`;
    })].join('\n');
  }
  if (artifact === 'Package.swift') {
    const deps = Array.isArray(document['dependencies']) ? document['dependencies'] : [];
    return [
      ...(document['toolsVersion'] === undefined ? [] : [`// swift-tools-version: ${document['toolsVersion']}`]),
      'import PackageDescription',
      'let package = Package(name: "Fixture", dependencies: [',
      ...deps.map((item) => {
        const branch = item.requirement?.branch !== undefined ? `, branch: "${item.requirement.branch}"` : '';
        const version = item.requirement?.version !== undefined ? `, from: "${item.requirement.version}"` : '';
        const upper = item.requirement?.range?.upperBound;
        const lower = item.requirement?.range?.lowerBound ?? '0.0.0';
        const range = upper !== undefined ? `, "${lower}"..<"${upper}"` : '';
        return `  .package(url: "${item.url ?? ''}"${branch}${version}${range}),`;
      }),
      '])',
    ].join('\n');
  }
  if (artifact === 'Cargo.lock') {
    const packages = Array.isArray(document['packages']) ? document['packages'] : [];
    return [`version = ${document['version'] ?? 4}`, ...packages.map((item) => `[[package]]\nname = "${item.name ?? ''}"\nversion = "${item.version ?? ''}"`)].join('\n');
  }
  if (artifact === 'Gemfile.lock') {
    const specs = Array.isArray(document['specs']) ? document['specs'] : [];
    return ['specs:', ...specs.map((item) => `    ${item.name ?? ''} (${item.version ?? ''})`), 'PLATFORMS', '  ruby', 'DEPENDENCIES', 'RUBY VERSION', `   ${document['ruby_version'] ?? ''}`, 'BUNDLED WITH', `   ${document['bundled_with'] ?? ''}`].join('\n');
  }
  return undefined;
}

/** Render a declared-test document into realistic text for one parser kind. */
export function renderDeclarationDocument(parser, artifact, document) {
  if (!isRecord(document)) return undefined;
  try {
    // Some pack rules name a generic parser for a well-known artifact. Mirror
    // the production dispatch and render the artifact's real text format.
    if (artifact === 'DESCRIPTION') return renderProperties(document, artifact);
    if (artifact === 'go.mod') return renderGoMod(document);
    if (artifact === 'Package.swift') return renderLockfileText(document, artifact);
    switch (parser) {
      case 'json': return JSON.stringify(document);
      case 'toml': return renderToml(document);
      case 'yaml': return renderYaml(document);
      case 'xml': return renderXml(document, artifact);
      case 'ini': return artifact === 'go.mod' ? renderGoMod(document) : renderIni(document, artifact);
      case 'properties': return renderProperties(document, artifact);
      case 'requirements': return renderRequirements(document);
      case 'gradle': return renderGradle(document, artifact);
      case 'lockfile-text': return renderLockfileText(document, artifact);
      default: return undefined;
    }
  } catch {
    return undefined;
  }
}

/**
 * Diagnostic only: render and parse a fixture without the source-upload gate.
 * This does NOT make a blocked artifact scan-reachable. Callers supply the
 * production reader and evaluator and must report the result separately.
 */
export function diagnoseReaderFixture(rule, test, compiled, parseDocument, evaluateCheck) {
  if (compiled === undefined) return 'compile-failure';
  const rendered = renderDeclarationDocument(rule.parser, rule.artifact, test.document);
  if (rendered === undefined) return 'unrenderable';
  const text = typeof rendered === 'string' ? rendered : rendered.text;
  const document = parseDocument(rule.parser, rule.artifact.split('/').pop(), text);
  if (document === undefined) return 'parse-failure';
  const observed = evaluateCheck(compiled, document);
  return observed === test.match ? 'matches' : observed ? 'false-positive' : 'false-negative';
}

/** XML fixtures with multiple root keys are wrapped in a synthetic root. */
export function unwrapXml(parser, artifact, document, parsed) {
  if (parser !== 'xml' || !isRecord(parsed) || Object.keys(document).length === 1) return parsed;
  return isRecord(parsed['root']) ? parsed['root'] : parsed;
}
