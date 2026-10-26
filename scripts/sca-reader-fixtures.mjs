/**
 * Round-trip fixtures for the bounded SCA declaration readers.
 *
 * The dataset's declared tests ship PARSED documents, not raw text. This
 * module renders those documents back into realistic (bounded) manifest text
 * so `verify-dataset.mjs` can prove the app's readers reproduce the shape a
 * rule needs. It is VERIFICATION TOOLING, not production code: the app never
 * calls a renderer, and no dataset bytes live in this repo.
 *
 * A renderer returning `undefined` means "no canonical fixture for this
 * artifact shape" — the harness reports that honestly instead of pretending.
 */

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
        for (const [innerKey, innerValue] of Object.entries(item)) {
          if (Array.isArray(innerValue) && innerValue.length > 0 && innerValue.every(isRecord)) {
            for (const nested of innerValue) {
              out.push(`[[${[...itemPath, tomlKey(innerKey)].join('.')}]]`);
              for (const [nk, nv] of Object.entries(nested)) if (!isRecord(nv) && !Array.isArray(nv)) out.push(`${tomlKey(nk)} = ${renderTomlValue(nv)}`);
            }
          } else if (isRecord(innerValue)) {
            for (const [nk, nv] of Object.entries(innerValue)) if (!isRecord(nv) && !Array.isArray(nv)) out.push(`${tomlKey(innerKey)}.${tomlKey(nk)} = ${renderTomlValue(nv)}`);
          } else if (!Array.isArray(innerValue)) out.push(`${tomlKey(innerKey)} = ${renderTomlValue(innerValue)}`);
          else out.push(`${tomlKey(innerKey)} = ${renderTomlValue(innerValue)}`);
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
            const entries = Object.entries(item);
            const first = entries[0];
            if (first !== undefined) out.push(`${pad(indent + 2)}- ${first[0]}: ${yamlScalar(first[1])}`);
            for (const [innerKey, innerValue] of entries.slice(1)) out.push(`${pad(indent + 4)}${innerKey}: ${yamlScalar(innerValue)}`);
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

function renderXml(document) {
  const entries = Object.entries(document);
  if (entries.length === 1) {
    const [key, value] = entries[0];
    return { text: xmlElement(key, value), wrapped: false };
  }
  const body = entries.map(([key, value]) => xmlElement(key, value)).join('');
  return { text: `<root>${body}</root>`, wrapped: true };
}

function renderIni(document, artifact) {
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
      if (flat.length > 0) sections.push([[key], Object.fromEntries(flat)]);
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
  for (const [key, value] of Object.entries(document)) {
    if (key !== 'requirements' && isRecord(value)) {
      for (const [innerKey, innerValue] of Object.entries(value)) lines.push(`--${key}.${innerKey}=${innerValue}`);
    }
  }
  return `${lines.join('\n')}\n`;
}

function renderGoMod(document) {
  const out = [];
  if (document['module'] !== undefined) out.push(`module ${document['module']}`);
  if (document['go'] !== undefined) out.push(`go ${document['go']}`);
  for (const section of ['require', 'replace', 'exclude', 'retract']) {
    const items = Array.isArray(document[section]) ? document[section] : [];
    if (items.length === 0) continue;
    out.push(`${section} (`);
    for (const item of items) {
      if (section === 'require') out.push(`  ${item.module ?? ''} ${item.version ?? ''}`);
      else if (section === 'replace') out.push(`  ${item.old?.path ?? ''} => ${item.new?.path ?? ''} ${item.new?.version ?? ''}`);
      else if (section === 'retract') out.push(`  ${item.version ?? ''}`);
      else out.push(`  ${item.module ?? ''} ${item.version ?? ''}`);
    }
    out.push(')');
  }
  return `${out.join('\n')}\n`;
}

function renderGradle(document, artifact) {
  const repositories = (list) => {
    const items = Array.isArray(list) ? list : [];
    return items.map((item) => `  maven { name "${item.name ?? 'acme'}"; url "${item.url ?? ''}" }`).join('\n');
  };
  if (artifact === 'settings.gradle') {
    return [
      'pluginManagement {', '  repositories {', repositories(document['pluginManagement']?.repositories), '  }', '}',
      'dependencyResolutionManagement {', '  repositories {', repositories(document['dependencyResolutionManagement']?.repositories), '  }', '}',
    ].join('\n');
  }
  return [
    'repositories {', repositories(document['repositories']), '}',
    'dependencies {', (Array.isArray(document['dependencies']) ? document['dependencies'] : []).map((item) => `  implementation "${item}"`).join('\n'), '}',
  ].join('\n');
}

function renderLockfileText(document, artifact) {
  if (artifact === 'go.mod') return renderGoMod(document);
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
      const extra = item.git !== undefined ? `, git: "${item.git}"` : '';
      return `      {:${item.name ?? 'dep'}, "${item.requirement ?? ''}"${extra}},`;
    }), '    ]', '  end', 'end'].join('\n');
  }
  if (artifact === 'mix.lock') {
    const packages = isRecord(document['packages']) ? document['packages'] : {};
    return Object.entries(packages).map(([key, value]) => {
      const extra = Object.entries(value).filter(([k]) => !['version'].includes(k)).map(([k, v]) => `, "${k}": "${v ?? ''}"`).join('');
      return `  ${quote(key)} => {:hex, :${key}, "${value?.version ?? ''}"${extra}},`;
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
    return deps.map((item) => {
      const branch = item.requirement?.branch !== undefined ? `, branch: "${item.requirement.branch}"` : '';
      const version = item.requirement?.version !== undefined ? `, from: "${item.requirement.version}"` : '';
      const upper = item.requirement?.range?.upperBound;
      const range = upper !== undefined ? `, range: "...${upper}"` : '';
      return `  .package(url: "${item.url ?? ''}"${branch}${version}${range}),`;
    }).join('\n');
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
    switch (parser) {
      case 'json': return JSON.stringify(document);
      case 'toml': return renderToml(document);
      case 'yaml': return renderYaml(document);
      case 'xml': return renderXml(document);
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

/** XML fixtures with multiple root keys are wrapped in a synthetic root. */
export function unwrapXml(parser, artifact, document, parsed) {
  if (parser !== 'xml' || !isRecord(parsed) || Object.keys(document).length === 1) return parsed;
  return isRecord(parsed['root']) ? parsed['root'] : parsed;
}
