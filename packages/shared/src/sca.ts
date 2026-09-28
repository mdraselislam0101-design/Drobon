/**
 * SCA contracts (Pump 9) — software-composition analysis.
 *
 * The pipeline: source snapshot → manifest discovery → defensive
 * parsers → normalized dependency inventory → deterministic SBOM
 * (CycloneDX JSON subset) → OPTIONAL vulnerability intelligence →
 * honest assessment.
 *
 * THE DATASET LOCK (absolute, see docs/SCA.md): this contract family
 * describes a dependency inventory and an ASSESSMENT STATE — never
 * vulnerability data. No CVE/NVD/GHSA/OSV/KEV/EPSS record may enter
 * this repository. When no real intelligence dataset is loaded, the
 * assessment is `NOT_ASSESSED` with `datasetStatus` explaining why —
 * that is the DESIGNED honest state, not a failure. Advisories exist
 * in the contract so a REAL provider (a future, separately-deployed
 * dataset) can surface verified records; with the locked Null
 * provider the array is always empty.
 *
 * Every shape here is CLOSED (guards reject unknown properties) and
 * bounded: a hostile payload cannot smuggle fields, unbounded arrays
 * or fabricated assessment state through these contracts.
 */

import { isFindingSeverity, type FindingSeverity } from './scans.js';
// The Pump 8 snapshot path policy, reused verbatim — SCA evidence
// paths are snapshot paths; there is deliberately no second
// implementation of these rules.
import { SOURCE_PATH_PATTERN } from './sources.js';

// ---------------------------------------------------------------------------
// Vocabularies (closed, server-authoritative)
// ---------------------------------------------------------------------------

/**
 * Ecosystems with REAL parsers in Pump 9. The architecture is
 * per-manifest (see `apps/api/src/scans/sca/`); future ecosystems
 * (Java, Go, Rust, PHP, .NET, pnpm/yarn lockfiles) add parsers, not
 * new orchestration.
 */
export const SCA_ECOSYSTEMS = ['npm', 'pypi'] as const;
export type ScaEcosystem = (typeof SCA_ECOSYSTEMS)[number];

export function isScaEcosystem(value: unknown): value is ScaEcosystem {
  return typeof value === 'string' && (SCA_ECOSYSTEMS as readonly string[]).includes(value);
}

/** How a dependency participates in the build (best-effort, from the manifest). */
export const SCA_DEPENDENCY_TYPES = [
  'runtime',
  'development',
  'optional',
  'peer',
  'unknown',
] as const;
export type ScaDependencyType = (typeof SCA_DEPENDENCY_TYPES)[number];

export function isScaDependencyType(value: unknown): value is ScaDependencyType {
  return (
    typeof value === 'string' && (SCA_DEPENDENCY_TYPES as readonly string[]).includes(value)
  );
}

/**
 * Direct vs transitive. `unknown` is HONEST: when no lockfile/root
 * evidence exists (e.g. a bare requirements.txt), the graph is
 * `UNAVAILABLE` and entries stay `unknown` — never guessed.
 */
export const SCA_DEPENDENCY_CLASSES = ['direct', 'transitive', 'unknown'] as const;
export type ScaDependencyClass = (typeof SCA_DEPENDENCY_CLASSES)[number];

export function isScaDependencyClass(value: unknown): value is ScaDependencyClass {
  return (
    typeof value === 'string' && (SCA_DEPENDENCY_CLASSES as readonly string[]).includes(value)
  );
}

/** Where the primary version came from: the manifest declaration or a lockfile resolution. */
export const SCA_VERSION_SOURCES = ['manifest', 'lockfile'] as const;
export type ScaVersionSource = (typeof SCA_VERSION_SOURCES)[number];

export function isScaVersionSource(value: unknown): value is ScaVersionSource {
  return (
    typeof value === 'string' && (SCA_VERSION_SOURCES as readonly string[]).includes(value)
  );
}

/** Per-manifest outcome (a scan completes even when some manifests fail — honestly counted). */
export const SCA_MANIFEST_STATUSES = [
  'ANALYZED',
  'PARTIAL',
  'UNSUPPORTED',
  'INVALID_INPUT',
] as const;
export type ScaManifestStatus = (typeof SCA_MANIFEST_STATUSES)[number];

export function isScaManifestStatus(value: unknown): value is ScaManifestStatus {
  return (
    typeof value === 'string' && (SCA_MANIFEST_STATUSES as readonly string[]).includes(value)
  );
}

/**
 * Why no vulnerability assessment happened (or did). `NO_DATA_LOADED`
 * is the locked default (the Null provider); `DATASET_UNAVAILABLE`
 * is the explicit no-external-dataset state a future real provider
 * reports when its source is configured but not reachable/loaded.
 */
export const SCA_DATASET_STATUSES = ['NO_DATA_LOADED', 'DATASET_UNAVAILABLE'] as const;
export type ScaDatasetStatus = (typeof SCA_DATASET_STATUSES)[number];

export function isScaDatasetStatus(value: unknown): value is ScaDatasetStatus {
  return (
    typeof value === 'string' && (SCA_DATASET_STATUSES as readonly string[]).includes(value)
  );
}

/**
 * The assessment verdict. `NOT_ASSESSED` means exactly that: no
 * verified intelligence was consulted — it is NOT "clean" and NOT a
 * vulnerability finding. `ASSESSED` requires a real provider that
 * actually matched records against loaded data.
 */
export const SCA_ASSESSMENT_STATES = ['NOT_ASSESSED', 'ASSESSED'] as const;
export type ScaAssessmentState = (typeof SCA_ASSESSMENT_STATES)[number];

export function isScaAssessmentState(value: unknown): value is ScaAssessmentState {
  return (
    typeof value === 'string' && (SCA_ASSESSMENT_STATES as readonly string[]).includes(value)
  );
}

/** Transitive-graph availability — honest, never assumed. */
export const SCA_TRANSITIVE_GRAPH_STATES = ['AVAILABLE', 'UNAVAILABLE'] as const;
export type ScaTransitiveGraphState = (typeof SCA_TRANSITIVE_GRAPH_STATES)[number];

export function isScaTransitiveGraphState(value: unknown): value is ScaTransitiveGraphState {
  return (
    typeof value === 'string' &&
    (SCA_TRANSITIVE_GRAPH_STATES as readonly string[]).includes(value)
  );
}

// ---------------------------------------------------------------------------
// Bounds (mirror the findings discipline from Pump 8)
// ---------------------------------------------------------------------------

/** Inventory bound per scan (identical to the findings cap by design). */
export const SCA_MAX_DEPENDENCIES_PER_SCAN = 200;

/** Per-manifest result records kept per scan. */
export const SCA_MAX_MANIFESTS_PER_SCAN = 50;

/** Dependency id: `dep_` + the first 24 hex chars of the fingerprint. */
export const SCA_DEPENDENCY_ID_PATTERN = /^dep_[0-9a-f]{24}$/;

/** Fingerprint: full sha256 hex (64 chars). */
export const SCA_FINGERPRINT_PATTERN = /^[0-9a-f]{64}$/;

/** Bound on package names after normalization (both ecosystems). */
export const SCA_NAME_MAX_LENGTH = 214;

/** Bound on version/specifier strings (declared ranges and resolved pins). */
export const SCA_VERSION_MAX_LENGTH = 200;

/** Bound on integrity strings from lockfiles (npm integrity, pip --hash). */
export const SCA_INTEGRITY_MAX_LENGTH = 200;

/** Bound on package URLs (purl). */
export const SCA_PURL_MAX_LENGTH = 400;

/** Bound on manifest-path evidence (the shared source-path policy caps paths at 160). */
export const SCA_PATH_MAX_LENGTH = 160;

/** Bound on per-manifest notes (why a manifest was PARTIAL/UNSUPPORTED/INVALID). */
export const SCA_NOTE_MAX_LENGTH = 200;

/** Bound on advisory ids/summaries/urls a provider may attach. */
export const SCA_ADVISORY_ID_MAX_LENGTH = 100;
export const SCA_ADVISORY_TEXT_MAX_LENGTH = 400;
export const SCA_ADVISORY_URL_MAX_LENGTH = 400;

/** CycloneDX subset this product emits. */
export const SCA_SBOM_FORMAT = 'CycloneDX';
export const SCA_SBOM_SPEC_VERSION = '1.5';

// ---------------------------------------------------------------------------
// Shared text predicates (own-property discipline, no control chars)
// ---------------------------------------------------------------------------

function isBoundedText(value: unknown, maxLength: number): value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > maxLength) {
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

function isOptionalBoundedText(
  value: unknown,
  maxLength: number,
): value is string | undefined {
  return value === undefined || isBoundedText(value, maxLength);
}

function isCount(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0;
}

function isHex(value: unknown, length: number): value is string {
  return typeof value === 'string' && value.length === length && /^[0-9a-f]+$/.test(value);
}

// ---------------------------------------------------------------------------
// The dependency record
// ---------------------------------------------------------------------------

/**
 * One normalized dependency. Every field is server-derived from
 * manifest/lockfile evidence — nothing here is client-suppliable.
 * `declaredVersion` and `resolvedVersion` are DISTINCT by contract:
 * a declared range is never overwritten by a lockfile pin; a resolved
 * version exists only when a lockfile actually provided it.
 */
export interface ScaDependency {
  /** Deterministic id: `dep_` + fingerprint prefix (stable across rescans). */
  dependencyId: string;
  ecosystem: ScaEcosystem;
  /** Normalized per ecosystem rules (npm: as-declared lowercase scope rules; pypi: PEP 503). */
  name: string;
  /** The declared requirement (range or pin) from the manifest, when one exists. */
  declaredVersion?: string;
  /** Where the primary version came from. */
  versionSource: ScaVersionSource;
  /** The exact version a lockfile resolved — only when one actually did. */
  resolvedVersion?: string;
  /** The package manager the manifest belongs to ('npm' | 'pip' today). */
  packageManager: string;
  /** Evidence: the manifest that declared the dependency. */
  manifestPath: string;
  /** Evidence: the lockfile that resolved it, when applicable. */
  lockfilePath?: string;
  dependencyType: ScaDependencyType;
  dependencyClass: ScaDependencyClass;
  /** Integrity/hash metadata legitimately present in the lockfile (never fabricated). */
  integrity?: string;
  /** Package URL — constructed only from ecosystem + name (+ exact version when known). */
  purl?: string;
  /** Deterministic identity: sha256 over the canonical coordinate + evidence paths. */
  fingerprint: string;
}

const DEPENDENCY_REQUIRED_KEYS = [
  'dependencyId',
  'ecosystem',
  'name',
  'versionSource',
  'packageManager',
  'manifestPath',
  'dependencyType',
  'dependencyClass',
  'fingerprint',
] as const;

const DEPENDENCY_OPTIONAL_KEYS = [
  'declaredVersion',
  'resolvedVersion',
  'lockfilePath',
  'integrity',
  'purl',
] as const;

const DEPENDENCY_ALLOWED_KEYS = [...DEPENDENCY_REQUIRED_KEYS, ...DEPENDENCY_OPTIONAL_KEYS] as const;

export function isScaDependency(value: unknown): value is ScaDependency {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  if (keys.length > DEPENDENCY_ALLOWED_KEYS.length) {
    return false;
  }
  if (keys.some((key) => !(DEPENDENCY_ALLOWED_KEYS as readonly string[]).includes(key))) {
    return false;
  }
  for (const required of DEPENDENCY_REQUIRED_KEYS) {
    if (record[required] === undefined) {
      return false;
    }
  }
  if (!SCA_DEPENDENCY_ID_PATTERN.test(record['dependencyId'] as string)) {
    return false;
  }
  if (!isScaEcosystem(record['ecosystem'])) {
    return false;
  }
  if (!isBoundedText(record['name'], SCA_NAME_MAX_LENGTH)) {
    return false;
  }
  if (!isScaVersionSource(record['versionSource'])) {
    return false;
  }
  if (!isBoundedText(record['packageManager'], 32)) {
    return false;
  }
  // Evidence paths are snapshot paths — the Pump 8 pattern rejects
  // traversal, absolute paths, backslashes, drive letters, percent
  // encoding and control characters in one closed rule.
  if (
    !isBoundedText(record['manifestPath'], SCA_PATH_MAX_LENGTH) ||
    !SOURCE_PATH_PATTERN.test(record['manifestPath'] as string)
  ) {
    return false;
  }
  if (!isScaDependencyType(record['dependencyType'])) {
    return false;
  }
  if (!isScaDependencyClass(record['dependencyClass'])) {
    return false;
  }
  if (!isHex(record['fingerprint'], 64)) {
    return false;
  }
  if (
    !isOptionalBoundedText(record['declaredVersion'], SCA_VERSION_MAX_LENGTH) ||
    !isOptionalBoundedText(record['resolvedVersion'], SCA_VERSION_MAX_LENGTH) ||
    (record['lockfilePath'] !== undefined &&
      !SOURCE_PATH_PATTERN.test(record['lockfilePath'] as string)) ||
    !isOptionalBoundedText(record['integrity'], SCA_INTEGRITY_MAX_LENGTH) ||
    !isOptionalBoundedText(record['purl'], SCA_PURL_MAX_LENGTH)
  ) {
    return false;
  }
  // Version semantics: a resolved version implies lockfile evidence —
  // a lockfile path AND lockfile provenance. A manifest never
  // resolves; declaring `versionSource: 'manifest'` with a resolved
  // version is a fabricated pin. Conversely, a lockfile path is
  // evidence OF a resolution — it never appears without one.
  if (record['resolvedVersion'] !== undefined) {
    if (record['lockfilePath'] === undefined || record['versionSource'] !== 'lockfile') {
      return false;
    }
  }
  if (record['lockfilePath'] !== undefined && record['resolvedVersion'] === undefined) {
    return false;
  }
  // The id must be derived from the fingerprint (deterministic identity).
  if ((record['dependencyId'] as string).slice(4) !== (record['fingerprint'] as string).slice(0, 24)) {
    return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// Per-manifest results (evidence discipline: paths + counts, never content)
// ---------------------------------------------------------------------------

export interface ScaManifestResult {
  path: string;
  ecosystem: ScaEcosystem;
  status: ScaManifestStatus;
  /** Dependencies extracted from THIS manifest (pre-merge, honest count). */
  dependencyCount: number;
  /** Bounded reason for a non-ANALYZED status (never manifest content). */
  note?: string;
}

const MANIFEST_RESULT_ALLOWED_KEYS = ['path', 'ecosystem', 'status', 'dependencyCount', 'note'] as const;

export function isScaManifestResult(value: unknown): value is ScaManifestResult {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  if (keys.length === 0 || keys.length > MANIFEST_RESULT_ALLOWED_KEYS.length) {
    return false;
  }
  if (keys.some((key) => !(MANIFEST_RESULT_ALLOWED_KEYS as readonly string[]).includes(key))) {
    return false;
  }
  if (
    !isBoundedText(record['path'], SCA_PATH_MAX_LENGTH) ||
    !SOURCE_PATH_PATTERN.test(record['path'] as string)
  ) {
    return false;
  }
  if (!isScaEcosystem(record['ecosystem'])) {
    return false;
  }
  if (!isScaManifestStatus(record['status'])) {
    return false;
  }
  if (!isCount(record['dependencyCount'])) {
    return false;
  }
  return isOptionalBoundedText(record['note'], SCA_NOTE_MAX_LENGTH);
}

// ---------------------------------------------------------------------------
// Advisories (the ONLY shape a real provider may use — empty while locked)
// ---------------------------------------------------------------------------

/**
 * A verified vulnerability record a REAL provider matched against a
 * loaded dataset. Pump 9 ships NO dataset: with the Null provider
 * this array is always empty and the assessment stays NOT_ASSESSED.
 * These are NOT SAST findings — they belong to the SCA result, and
 * the UI renders them separately.
 */
export interface ScaAdvisory {
  /** The provider's advisory identifier (e.g. GHSA id) — bounded, provider-authored. */
  id: string;
  severity: FindingSeverity;
  /** One-line summary (bounded, provider-authored). */
  summary: string;
  /** Link to the full advisory, when the provider supplies one. */
  url?: string;
  /** The dependency record this advisory matched. */
  dependencyId: string;
  /** The coordinate that matched (name + exact version when known). */
  ecosystem: ScaEcosystem;
  name: string;
  version?: string;
}

const ADVISORY_REQUIRED_KEYS = ['id', 'severity', 'summary', 'dependencyId', 'ecosystem', 'name'] as const;
const ADVISORY_ALLOWED_KEYS = [...ADVISORY_REQUIRED_KEYS, 'url', 'version'] as const;

export function isScaAdvisory(value: unknown): value is ScaAdvisory {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  if (keys.length > ADVISORY_ALLOWED_KEYS.length) {
    return false;
  }
  if (keys.some((key) => !(ADVISORY_ALLOWED_KEYS as readonly string[]).includes(key))) {
    return false;
  }
  for (const required of ADVISORY_REQUIRED_KEYS) {
    if (record[required] === undefined) {
      return false;
    }
  }
  if (!isBoundedText(record['id'], SCA_ADVISORY_ID_MAX_LENGTH)) {
    return false;
  }
  if (!isFindingSeverity(record['severity'])) {
    return false;
  }
  if (!isBoundedText(record['summary'], SCA_ADVISORY_TEXT_MAX_LENGTH)) {
    return false;
  }
  if (!SCA_DEPENDENCY_ID_PATTERN.test(record['dependencyId'] as string)) {
    return false;
  }
  if (!isScaEcosystem(record['ecosystem'])) {
    return false;
  }
  if (!isBoundedText(record['name'], SCA_NAME_MAX_LENGTH)) {
    return false;
  }
  return (
    isOptionalBoundedText(record['url'], SCA_ADVISORY_URL_MAX_LENGTH) &&
    isOptionalBoundedText(record['version'], SCA_VERSION_MAX_LENGTH)
  );
}

// ---------------------------------------------------------------------------
// The SCA summary (counts are honest, cross-checked by guards)
// ---------------------------------------------------------------------------

export interface ScaSummary {
  assessmentState: ScaAssessmentState;
  datasetStatus: ScaDatasetStatus;
  /** Which provider was consulted ('none' = the locked Null provider). */
  providerId: string;
  /** Unique dependencies in the full inventory (may exceed the persisted bound when truncated). */
  dependenciesTotal: number;
  directDependencies: number;
  transitiveDependencies: number;
  /** Entries whose class could not be determined (honest `unknown`). */
  unclassifiedDependencies: number;
  /** Advisories a REAL provider matched (0 while the dataset is locked). */
  advisoriesTotal: number;
  manifestsAnalyzed: number;
  manifestsPartial: number;
  manifestsUnsupported: number;
  manifestsInvalid: number;
  transitiveGraph: ScaTransitiveGraphState;
  /** True when the inventory cap truncated the persisted list. */
  truncated: boolean;
}

const SUMMARY_SCA_ALLOWED_KEYS = [
  'assessmentState',
  'datasetStatus',
  'providerId',
  'dependenciesTotal',
  'directDependencies',
  'transitiveDependencies',
  'unclassifiedDependencies',
  'advisoriesTotal',
  'manifestsAnalyzed',
  'manifestsPartial',
  'manifestsUnsupported',
  'manifestsInvalid',
  'transitiveGraph',
  'truncated',
] as const;

export function isScaSummary(value: unknown): value is ScaSummary {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  if (keys.length !== SUMMARY_SCA_ALLOWED_KEYS.length) {
    return false;
  }
  if (keys.some((key) => !(SUMMARY_SCA_ALLOWED_KEYS as readonly string[]).includes(key))) {
    return false;
  }
  if (!isScaAssessmentState(record['assessmentState'])) {
    return false;
  }
  if (!isScaDatasetStatus(record['datasetStatus'])) {
    return false;
  }
  if (!isBoundedText(record['providerId'], 64)) {
    return false;
  }
  for (const key of [
    'dependenciesTotal',
    'directDependencies',
    'transitiveDependencies',
    'unclassifiedDependencies',
    'advisoriesTotal',
    'manifestsAnalyzed',
    'manifestsPartial',
    'manifestsUnsupported',
    'manifestsInvalid',
  ] as const) {
    if (!isCount(record[key])) {
      return false;
    }
  }
  if (!isScaTransitiveGraphState(record['transitiveGraph'])) {
    return false;
  }
  if (typeof record['truncated'] !== 'boolean') {
    return false;
  }
  // Cross-field honesty: NOT_ASSESSED can never claim advisories.
  if (record['assessmentState'] === 'NOT_ASSESSED' && record['advisoriesTotal'] !== 0) {
    return false;
  }
  // Cross-field honesty: the locked Null provider (id 'none') never
  // assesses — an ASSESSED claim under it is fabricated.
  if (record['assessmentState'] === 'ASSESSED' && record['providerId'] === 'none') {
    return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// SBOM (CycloneDX 1.5 JSON subset — see docs/SCA.md for exactly what is
// emitted and what is deliberately omitted)
// ---------------------------------------------------------------------------

export interface SbomHash {
  alg: 'SHA-256' | 'SHA-512';
  content: string;
}

export interface SbomComponent {
  type: 'library';
  /** Deterministic bom-ref (the dependency fingerprint). */
  'bom-ref': string;
  name: string;
  /** Resolved version when known, else an exact declared pin; omitted for ranges. */
  version?: string;
  purl?: string;
  /** runtime→required, optional→optional, development/peer→excluded. */
  scope?: 'required' | 'optional' | 'excluded';
  /** Only hashes legitimately present in the lockfile — never fabricated. */
  hashes?: SbomHash[];
}

export interface SbomDependencyEdge {
  ref: string;
  dependsOn: string[];
}

export interface SbomDocument {
  bomFormat: 'CycloneDX';
  specVersion: '1.5';
  /** Deterministic: urn:uuid:<uuid derived from the component set> — never random. */
  serialNumber: string;
  version: number;
  metadata: {
    tools: {
      components: Array<{ type: 'application'; name: string; version: string }>;
    };
    /** The analyzed project, when a root manifest named it; omitted otherwise. */
    component?: { type: 'application'; 'bom-ref': string; name: string; version?: string };
  };
  components: SbomComponent[];
  /** Only evidenced edges: root → direct dependencies. Absent when unknown. */
  dependencies: SbomDependencyEdge[];
}

const SBOM_SERIAL_PATTERN = /^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export function isSbomHash(value: unknown): value is SbomHash {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const record = value as Record<string, unknown>;
  if (Object.keys(record).length !== 2) {
    return false;
  }
  if (record['alg'] !== 'SHA-256' && record['alg'] !== 'SHA-512') {
    return false;
  }
  // Hash CONTENT is digest material (base64/hex shape, padded to a
  // multiple of 4) — a URL or filesystem path smuggled into the SBOM
  // as a "hash" is not a hash.
  const content = record['content'] as string;
  return (
    isBoundedText(content, SCA_INTEGRITY_MAX_LENGTH) &&
    content.length >= 8 &&
    content.length % 4 === 0 &&
    !content.startsWith('/') &&
    /^[A-Za-z0-9+/]+={0,2}$/.test(content)
  );
}

export function isSbomComponent(value: unknown): value is SbomComponent {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  const allowed = ['type', 'bom-ref', 'name', 'version', 'purl', 'scope', 'hashes'] as const;
  if (keys.length < 3 || keys.length > allowed.length) {
    return false;
  }
  if (keys.some((key) => !(allowed as readonly string[]).includes(key))) {
    return false;
  }
  if (record['type'] !== 'library') {
    return false;
  }
  if (!isBoundedText(record['bom-ref'], 80)) {
    return false;
  }
  if (!isBoundedText(record['name'], SCA_NAME_MAX_LENGTH)) {
    return false;
  }
  if (!isOptionalBoundedText(record['version'], SCA_VERSION_MAX_LENGTH)) {
    return false;
  }
  if (!isOptionalBoundedText(record['purl'], SCA_PURL_MAX_LENGTH)) {
    return false;
  }
  if (
    record['scope'] !== undefined &&
    !['required', 'optional', 'excluded'].includes(record['scope'] as string)
  ) {
    return false;
  }
  if (record['hashes'] !== undefined) {
    if (!Array.isArray(record['hashes']) || record['hashes'].length > 4) {
      return false;
    }
    if (!record['hashes'].every((hash) => isSbomHash(hash))) {
      return false;
    }
  }
  return true;
}

export function isSbomDocument(value: unknown): value is SbomDocument {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  const allowed = [
    'bomFormat',
    'specVersion',
    'serialNumber',
    'version',
    'metadata',
    'components',
    'dependencies',
  ] as const;
  if (keys.length !== allowed.length) {
    return false;
  }
  if (keys.some((key) => !(allowed as readonly string[]).includes(key))) {
    return false;
  }
  if (record['bomFormat'] !== SCA_SBOM_FORMAT || record['specVersion'] !== SCA_SBOM_SPEC_VERSION) {
    return false;
  }
  if (!SBOM_SERIAL_PATTERN.test(record['serialNumber'] as string)) {
    return false;
  }
  if (record['version'] !== 1) {
    return false;
  }
  const metadata = record['metadata'];
  if (typeof metadata !== 'object' || metadata === null) {
    return false;
  }
  const metadataKeys = Object.keys(metadata as Record<string, unknown>);
  if (metadataKeys.length < 1 || metadataKeys.length > 2) {
    return false;
  }
  if (metadataKeys.some((key) => key !== 'tools' && key !== 'component')) {
    return false;
  }
  const tools = (metadata as Record<string, unknown>)['tools'];
  if (typeof tools !== 'object' || tools === null) {
    return false;
  }
  const toolsComponents = (tools as Record<string, unknown>)['components'];
  if (!Array.isArray(toolsComponents) || toolsComponents.length !== 1) {
    return false;
  }
  const tool = toolsComponents[0] as Record<string, unknown>;
  if (
    tool['type'] !== 'application' ||
    !isBoundedText(tool['name'], 64) ||
    !isBoundedText(tool['version'], 32)
  ) {
    return false;
  }
  const rootComponent = (metadata as Record<string, unknown>)['component'];
  if (rootComponent !== undefined) {
    if (typeof rootComponent !== 'object' || rootComponent === null) {
      return false;
    }
    const rootRecord = rootComponent as Record<string, unknown>;
    const rootKeys = Object.keys(rootRecord);
    if (
      rootKeys.length < 3 ||
      rootKeys.length > 4 ||
      rootRecord['type'] !== 'application' ||
      !isBoundedText(rootRecord['bom-ref'], 80) ||
      !isBoundedText(rootRecord['name'], SCA_NAME_MAX_LENGTH) ||
      !isOptionalBoundedText(rootRecord['version'], SCA_VERSION_MAX_LENGTH)
    ) {
      return false;
    }
    if (rootKeys.some((key) => !['type', 'bom-ref', 'name', 'version'].includes(key))) {
      return false;
    }
  }
  if (!Array.isArray(record['components']) || record['components'].length > SCA_MAX_DEPENDENCIES_PER_SCAN) {
    return false;
  }
  if (!record['components'].every((component) => isSbomComponent(component))) {
    return false;
  }
  if (!Array.isArray(record['dependencies'])) {
    return false;
  }
  if (record['dependencies'].length > SCA_MAX_DEPENDENCIES_PER_SCAN + 1) {
    return false;
  }
  return (record['dependencies'] as unknown[]).every((edge) => {
    if (typeof edge !== 'object' || edge === null) {
      return false;
    }
    const edgeRecord = edge as Record<string, unknown>;
    if (Object.keys(edgeRecord).length !== 2) {
      return false;
    }
    if (!isBoundedText(edgeRecord['ref'], 80)) {
      return false;
    }
    if (!Array.isArray(edgeRecord['dependsOn']) || edgeRecord['dependsOn'].length > SCA_MAX_DEPENDENCIES_PER_SCAN) {
      return false;
    }
    return edgeRecord['dependsOn'].every((ref) => isBoundedText(ref, 80));
  });
}

// ---------------------------------------------------------------------------
// The SCA result (scan-detail payload; SCA COMPLETED scans only)
// ---------------------------------------------------------------------------

export interface ScaResult {
  summary: ScaSummary;
  /** Bounded, deterministically ordered (ecosystem, name, version, path). */
  dependencies: ScaDependency[];
  /** Per-manifest outcomes (paths + counts + bounded notes — never content). */
  manifests: ScaManifestResult[];
  /** Deterministic CycloneDX 1.5 subset document. */
  sbom: SbomDocument;
  /** Advisories (empty unless a REAL provider matched loaded data). */
  advisories: ScaAdvisory[];
}

export function isScaResult(value: unknown): value is ScaResult {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  if (keys.length !== 5) {
    return false;
  }
  if (
    keys.some(
      (key) => !['summary', 'dependencies', 'manifests', 'sbom', 'advisories'].includes(key),
    )
  ) {
    return false;
  }
  if (!isScaSummary(record['summary'])) {
    return false;
  }
  if (!Array.isArray(record['dependencies']) || record['dependencies'].length > SCA_MAX_DEPENDENCIES_PER_SCAN) {
    return false;
  }
  if (!record['dependencies'].every((dependency) => isScaDependency(dependency))) {
    return false;
  }
  if (!Array.isArray(record['manifests']) || record['manifests'].length > SCA_MAX_MANIFESTS_PER_SCAN) {
    return false;
  }
  if (!record['manifests'].every((manifest) => isScaManifestResult(manifest))) {
    return false;
  }
  if (!isSbomDocument(record['sbom'])) {
    return false;
  }
  if (!Array.isArray(record['advisories']) || record['advisories'].length > SCA_MAX_DEPENDENCIES_PER_SCAN) {
    return false;
  }
  if (!record['advisories'].every((advisory) => isScaAdvisory(advisory))) {
    return false;
  }
  const summary = record['summary'];
  // Cross-field honesty: counts agree with the persisted arrays.
  if (summary.truncated === false && summary.dependenciesTotal !== record['dependencies'].length) {
    return false;
  }
  if (summary.truncated === true && summary.dependenciesTotal < record['dependencies'].length) {
    return false;
  }
  if (summary.advisoriesTotal !== record['advisories'].length) {
    return false;
  }
  // An ASSESSED scan must have matched at least one advisory.
  if (summary.assessmentState === 'ASSESSED' && record['advisories'].length === 0) {
    return false;
  }
  // Advisories reference dependencies that actually exist in this scan.
  const dependencyIds = new Set(record['dependencies'].map((dependency) => (dependency as ScaDependency).dependencyId));
  return record['advisories'].every((advisory) =>
    dependencyIds.has((advisory as ScaAdvisory).dependencyId),
  );
}

/**
 * Deterministic SBOM/dependency ordering: ecosystem, then name, then
 * resolved-or-declared version, then manifest path — stable for
 * identical input on every platform.
 */
export function compareScaDependencies(a: ScaDependency, b: ScaDependency): number {
  if (a.ecosystem !== b.ecosystem) {
    return a.ecosystem < b.ecosystem ? -1 : 1;
  }
  if (a.name !== b.name) {
    return a.name < b.name ? -1 : 1;
  }
  const aVersion = a.resolvedVersion ?? a.declaredVersion ?? '';
  const bVersion = b.resolvedVersion ?? b.declaredVersion ?? '';
  if (aVersion !== bVersion) {
    return aVersion < bVersion ? -1 : 1;
  }
  return a.manifestPath < b.manifestPath ? -1 : a.manifestPath > b.manifestPath ? 1 : 0;
}
