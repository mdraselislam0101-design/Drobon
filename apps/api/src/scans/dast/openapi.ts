/**
 * Active DAST — bounded OpenAPI/Swagger seed ingestion (P2-12).
 *
 * A specification is a *hint list*, never an authorization: every path this
 * module returns is re-validated by the DAST target policy before a request is
 * made, and only query-free `GET` operations are ever produced.
 *
 * Design constraints (deliberate):
 * - JSON only. No YAML parser is bundled in this workspace (zero runtime
 *   dependencies), so a YAML spec is refused with an honest status instead of
 *   being half-parsed.
 * - Templated path parameters are filled ONLY from literal values the spec
 *   itself states (`example`, `default`, `enum[0]`). A parameter without such
 *   a value means the operation is skipped — no invented ids.
 * - Operations that require a query parameter are skipped: the DAST target
 *   policy refuses query-bearing URLs, so probing them would be a phantom.
 * - Everything is bounded and deterministic (sorted iteration, hard caps).
 */

/** Most spec documents are inspected, not emitted: bounded work per scan. */
export const OPENAPI_MAX_INSPECTED_PATHS = 500;
/** Endpoints handed to the crawler. */
export const OPENAPI_MAX_ENDPOINTS = 50;
/** Spec documents fetched per active scan. */
export const OPENAPI_MAX_SPEC_PROBES = 2;
/** Raw bytes of a spec document we are willing to parse. */
export const OPENAPI_MAX_SPEC_BYTES = 512 * 1024;

/** Well-known spec locations, probed in this fixed order. */
export const OPENAPI_SPEC_CANDIDATES = [
  '/openapi.json',
  '/swagger.json',
  '/v3/api-docs',
  '/api-docs',
] as const;

export const OPENAPI_STATUSES = ['ANALYZED', 'NOT_FOUND', 'UNSUPPORTED', 'INVALID_INPUT'] as const;
export type OpenApiStatus = (typeof OPENAPI_STATUSES)[number];

export interface OpenApiEndpoint {
  /** Absolute path from the spec (`/users/42`), already parameter-substituted. */
  path: string;
}

export interface OpenApiParseResult {
  status: OpenApiStatus;
  endpoints: OpenApiEndpoint[];
  /** e.g. `OpenAPI 3.0.3` or `Swagger 2.0` — bounded metadata, never content. */
  specVersion?: string;
  /** Operations the spec declares as GET but which could not be safely built. */
  skipped: number;
  note?: string;
}

const PARAM_VALUE = /^[A-Za-z0-9._~-]{1,32}$/;

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * A path is accepted only if it is a relative, query-free, fragment-free,
 * form-encoded-free path with no traversal or control characters. The target
 * policy re-checks the resulting URL; this is the syntax gate.
 */
function safeSpecPath(path: unknown): path is string {
  if (typeof path !== 'string') return false;
  if (path.length < 2 || path.length > 200) return false;
  if (!path.startsWith('/')) return false;
  if (path.startsWith('//')) return false;
  if (path.includes('..') || path.includes('//')) return false;
  if (path.includes('\\') || path.includes('%') || path.includes('?') || path.includes('#')) return false;
  // eslint-disable-next-line no-control-regex -- control characters are never valid in a path.
  if (/[\u0000-\u001f\u007f\s]/.test(path)) return false;
  return true;
}

/** Literal value the spec itself states for a parameter, if any. */
function literalParamValue(parameter: Record<string, unknown>): string | undefined {
  const candidates: unknown[] = [parameter['example']];
  const schema = parameter['schema'];
  if (isPlainObject(schema)) {
    candidates.push(schema['example'], schema['default']);
    const enumValues = schema['enum'];
    if (Array.isArray(enumValues) && enumValues.length > 0) candidates.push(enumValues[0]);
  }
  candidates.push(parameter['default']);
  for (const candidate of candidates) {
    if (typeof candidate === 'string' && PARAM_VALUE.test(candidate)) return candidate;
    if (typeof candidate === 'number' && Number.isFinite(candidate)) {
      const text = String(candidate);
      if (PARAM_VALUE.test(text)) return text;
    }
  }
  return undefined;
}

interface ParameterFacts {
  pathValues: Map<string, string>;
  missingPath: boolean;
  requiredQuery: boolean;
}

/** Combine path-level and operation-level parameters (operation wins). */
function collectParameters(
  pathParameters: unknown,
  operationParameters: unknown,
): ParameterFacts {
  const merged = new Map<string, Record<string, unknown>>();
  for (const list of [pathParameters, operationParameters]) {
    if (!Array.isArray(list)) continue;
    for (const item of list.slice(0, 64)) {
      if (!isPlainObject(item)) continue;
      const name = item['name'];
      const where = item['in'];
      if (typeof name !== 'string' || name.length === 0 || name.length > 64) continue;
      if (where !== 'path' && where !== 'query') continue;
      merged.set(`${where}:${name}`, item);
    }
  }
  const pathValues = new Map<string, string>();
  let missingPath = false;
  let requiredQuery = false;
  for (const [key, parameter] of merged) {
    if (key.startsWith('path:')) {
      const value = literalParamValue(parameter);
      if (value === undefined) missingPath = true;
      else pathValues.set(key.slice('path:'.length), value);
    } else if (parameter['required'] === true) {
      // The target policy rejects query-bearing URLs; a required query
      // parameter therefore makes the operation unprobeable (not silently
      // probed without its mandatory input).
      requiredQuery = true;
    }
  }
  return { pathValues, missingPath, requiredQuery };
}

function substitutePath(template: string, values: Map<string, string>): string | undefined {
  let missing = false;
  const substituted = template.replace(/\{([^{}]{1,64})\}/g, (match, name: string) => {
    const value = values.get(name);
    if (value === undefined) {
      missing = true;
      return match;
    }
    return value;
  });
  if (missing || substituted.includes('{') || substituted.includes('}')) return undefined;
  return safeSpecPath(substituted) ? substituted : undefined;
}

/**
 * Parse an OpenAPI 3.x / Swagger 2.0 JSON document into bounded GET endpoints.
 * Never throws; anything it cannot prove becomes an honest status.
 */
export function parseOpenApiSpec(text: string): OpenApiParseResult {
  const empty: { endpoints: OpenApiEndpoint[]; skipped: number } = { endpoints: [], skipped: 0 };
  if (typeof text !== 'string' || text.length === 0) {
    return { ...empty, status: 'INVALID_INPUT', note: 'The specification document was empty.' };
  }
  if (Buffer.byteLength(text, 'utf8') > OPENAPI_MAX_SPEC_BYTES) {
    return { ...empty, status: 'INVALID_INPUT', note: 'The specification document exceeded the inspection limit.' };
  }
  const trimmed = text.trimStart();
  if (!trimmed.startsWith('{') && !trimmed.startsWith('[')) {
    return {
      ...empty,
      status: 'UNSUPPORTED',
      note: 'Only JSON specifications are parsed; YAML documents are not interpreted.',
    };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { ...empty, status: 'INVALID_INPUT', note: 'The specification document was not valid JSON.' };
  }
  if (!isPlainObject(parsed)) {
    return { ...empty, status: 'INVALID_INPUT', note: 'The specification document was not a JSON object.' };
  }

  let specVersion: string | undefined;
  const openapi = parsed['openapi'];
  const swagger = parsed['swagger'];
  if (typeof openapi === 'string' && /^3\.\d{1,2}(?:\.\d{1,3})?$/.test(openapi)) {
    specVersion = `OpenAPI ${openapi}`;
  } else if (swagger === '2.0') {
    specVersion = 'Swagger 2.0';
  } else {
    return {
      ...empty,
      status: 'UNSUPPORTED',
      note: 'The document is not an OpenAPI 3.x or Swagger 2.0 specification.',
    };
  }

  const paths = parsed['paths'];
  if (!isPlainObject(paths)) {
    return { ...empty, status: 'INVALID_INPUT', note: 'The specification has no paths object.', ...(specVersion === undefined ? {} : { specVersion }) };
  }

  const keys = Object.keys(paths).sort();
  const inspected = keys.slice(0, OPENAPI_MAX_INSPECTED_PATHS);
  const endpoints: OpenApiEndpoint[] = [];
  let skipped = 0;
  let endpointCapReached = false;
  for (const template of inspected) {
    const item = paths[template];
    if (!isPlainObject(item)) {
      skipped += 1;
      continue;
    }
    const operation = item['get'];
    if (!isPlainObject(operation)) continue; // Non-GET operations are out of scope, not skipped work.
    const facts = collectParameters(item['parameters'], operation['parameters']);
    if (facts.requiredQuery) {
      skipped += 1;
      continue;
    }
    if (facts.missingPath) {
      skipped += 1;
      continue;
    }
    const resolved = substitutePath(template, facts.pathValues);
    if (resolved === undefined) {
      skipped += 1;
      continue;
    }
    endpoints.push({ path: resolved });
    if (endpoints.length >= OPENAPI_MAX_ENDPOINTS) {
      endpointCapReached = true;
      break;
    }
  }

  // A spec with more paths than we inspect is not silently complete.
  const uninspected = keys.length - inspected.length;
  const notes: string[] = [];
  if (uninspected > 0) notes.push(`${uninspected} additional path(s) were outside the inspection limit.`);
  if (skipped > 0) notes.push(`${skipped} GET operation(s) needed input the specification did not state.`);
  if (endpointCapReached) {
    notes.push(`The ${OPENAPI_MAX_ENDPOINTS}-endpoint limit was reached; later GET operations were not selected.`);
  }
  return {
    status: 'ANALYZED',
    endpoints,
    ...(specVersion === undefined ? {} : { specVersion }),
    skipped,
    ...(notes.length === 0 ? {} : { note: notes.join(' ').slice(0, 200) }),
  };
}
