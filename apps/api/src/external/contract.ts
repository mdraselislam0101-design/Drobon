/**
 * Dataset integration contract (Main App side only).
 *
 * Drobon-Dataset is a SEPARATE repository, maintained and released on its own
 * schedule. This module is the app's half of the boundary:
 *
 *  - it declares which external pack layout versions THIS application can load;
 *  - it turns what was observed on disk (directory version names, the optional
 *    `pack.json` schema version) into an explicit compatibility verdict;
 *  - it never reads dataset content itself, never copies it into this repo and
 *    never invents rules when the declared version is unsupported.
 *
 * All verdicts are computed from names and versions only. No dataset path,
 * filename, rule text or pattern ever appears in an issue string, so the
 * status surface stays safe to expose and log.
 *
 * Fail-closed rules:
 *  - an unsupported layout version is INCOMPATIBLE, never "empty but fine";
 *  - a manifest that declares a different schema version than this app supports
 *    is INCOMPATIBLE even if the directory name looks familiar;
 *  - an unreadable pack directory is UNKNOWN, never COMPATIBLE;
 *  - `NOT_CONFIGURED` is reported only when no external dataset is configured.
 *
 * `COMPATIBLE` means "this app understands the declared format" — it does not
 * mean the family has coverage. A dataset that simply ships no `packs/<family>`
 * directory is COMPATIBLE with `no-supported-pack-layout`; the missing rules are
 * then reported by the category status (`incomplete`, count 0) and by every
 * scan's own `partial` flag. Conflating "absent" with "incompatible" would make
 * an ordinary partial dataset look like a contract violation.
 */

export type PackFamilyName = 'sast' | 'secrets' | 'dast' | 'sca';

/** The app's own integration contract revision. Bump only with this file's tests. */
export const DATASET_CONTRACT_VERSION = 1;

/** Pack directory layout versions (`packs/<family>/vN/`) this build can load. */
export const SUPPORTED_PACK_LAYOUT_VERSIONS: readonly number[] = [1];

/** Manifest schema suffix versions (`drobon.pack.<family>/vN`) this build accepts. */
export const SUPPORTED_PACK_SCHEMA_VERSIONS: readonly number[] = [1];

export type ContractVerdict = 'COMPATIBLE' | 'INCOMPATIBLE' | 'UNKNOWN' | 'NOT_CONFIGURED';

/** Closed vocabulary: a bounded, path-free diagnostic code. */
export type ContractIssueCode =
  | 'pack-directory-unreadable'
  | 'pack-layout-version-unsupported'
  | 'pack-layout-version-newer-ignored'
  | 'manifest-schema-version-unsupported'
  | 'manifest-schema-version-unreadable'
  | 'no-supported-pack-layout';

export interface PackContractState {
  verdict: ContractVerdict;
  /** Layout version this app loaded (only supported versions are ever set). */
  layoutVersion?: number;
  /** Number of directory versions observed under `packs/<family>`. */
  observedLayoutVersions: number;
  /** Count of observed versions this build cannot load (never their names). */
  unsupportedLayoutVersions: number;
  /** Declared manifest schema version, when the optional manifest is readable. */
  manifestSchemaVersion?: number;
  issues: ContractIssueCode[];
}

export interface DatasetContractState {
  contractVersion: number;
  supportedLayoutVersions: readonly number[];
  supportedSchemaVersions: readonly number[];
  verdict: ContractVerdict;
  families: Record<PackFamilyName, PackContractState>;
  /** Union of family issue codes (sorted, bounded, path-free). */
  issues: ContractIssueCode[];
}

export const PACK_FAMILIES_FOR_CONTRACT: readonly PackFamilyName[] = ['sast', 'secrets', 'dast', 'sca'];

/**
 * Parse a pack directory name. Only `v<major>` is meaningful; anything else is
 * not a layout version this contract understands (and is therefore ignored at
 * directory level rather than guessed at).
 */
export function parsePackLayoutVersion(name: string): number | undefined {
  // No leading zeros and no `v0`: a directory the app cannot interpret must
  // stay uninterpreted rather than being rounded to a supported version.
  const match = typeof name === 'string' ? name.match(/^v([1-9][0-9]{0,2})$/) : null;
  if (match === null) return undefined;
  const value = Number(match[1]);
  return Number.isSafeInteger(value) && value > 0 ? value : undefined;
}

/** Parse a declared manifest schema version (`drobon.pack.sast/v1`). */
export function declaredPackSchemaVersion(
  raw: unknown,
  family: PackFamilyName,
): number | undefined {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return undefined;
  const declared = (raw as Record<string, unknown>)['schemaVersion'];
  if (typeof declared !== 'string' || declared.length > 64) return undefined;
  const match = declared.match(/^drobon\.pack\.(sast|secrets|dast|sca)\/v([1-9][0-9]{0,2})$/);
  if (match === null || match[1] !== family) return undefined;
  const value = Number(match[2]);
  return Number.isSafeInteger(value) && value > 0 ? value : undefined;
}

/** Highest supported layout version present, or undefined when none is. */
export function selectSupportedLayoutVersion(observed: readonly number[]): number | undefined {
  const supported = observed.filter((version) => SUPPORTED_PACK_LAYOUT_VERSIONS.includes(version));
  if (supported.length === 0) return undefined;
  return Math.max(...supported);
}

export interface PackContractInput {
  family: PackFamilyName;
  configured: boolean;
  /** Every layout version directory name observed directly under packs/<family>. */
  observedLayoutVersions: readonly number[];
  /** True when the family directory (or an entry inside it) could not be read. */
  directoryUnreadable?: boolean;
  /** Raw parsed `pack.json`, when one was read successfully. */
  manifest?: unknown;
  /** True when a manifest file exists but could not be read or parsed. */
  manifestUnreadable?: boolean;
}

/**
 * Evaluate one family. Pure and total: every input produces a verdict, and an
 * unrecognised situation degrades to UNKNOWN rather than COMPATIBLE.
 */
export function evaluatePackContract(input: PackContractInput): PackContractState {
  const observed = [...new Set(input.observedLayoutVersions)].filter((version) =>
    Number.isSafeInteger(version) && version > 0);
  const unsupported = observed.filter((version) => !SUPPORTED_PACK_LAYOUT_VERSIONS.includes(version));
  const layoutVersion = selectSupportedLayoutVersion(observed);
  const manifestSchemaVersion = input.manifest === undefined
    ? undefined : declaredPackSchemaVersion(input.manifest, input.family);
  const issues: ContractIssueCode[] = [];

  if (!input.configured) {
    return { verdict: 'NOT_CONFIGURED', observedLayoutVersions: observed.length,
      unsupportedLayoutVersions: unsupported.length, issues };
  }
  if (input.directoryUnreadable === true) issues.push('pack-directory-unreadable');
  if (layoutVersion === undefined) {
    if (unsupported.length > 0) issues.push('pack-layout-version-unsupported');
    else issues.push('no-supported-pack-layout');
  } else if (unsupported.some((version) => version > layoutVersion)) {
    // Loadable, but the dataset already ships a layout this build cannot read.
    issues.push('pack-layout-version-newer-ignored');
  }
  if (input.manifest !== undefined && manifestSchemaVersion === undefined) {
    issues.push('manifest-schema-version-unreadable');
  }
  if (input.manifest !== undefined && manifestSchemaVersion !== undefined &&
      !SUPPORTED_PACK_SCHEMA_VERSIONS.includes(manifestSchemaVersion)) {
    issues.push('manifest-schema-version-unsupported');
  } else if (input.manifestUnreadable === true) {
    issues.push('manifest-schema-version-unreadable');
  }

  const incompatible = issues.some((issue) =>
    issue === 'pack-layout-version-unsupported' || issue === 'manifest-schema-version-unsupported');
  const verdict: ContractVerdict = incompatible ? 'INCOMPATIBLE'
    : input.directoryUnreadable === true || input.manifestUnreadable === true ? 'UNKNOWN'
    : 'COMPATIBLE';

  return {
    verdict,
    ...(layoutVersion === undefined ? {} : { layoutVersion }),
    observedLayoutVersions: observed.length,
    unsupportedLayoutVersions: unsupported.length,
    ...(manifestSchemaVersion === undefined ? {} : { manifestSchemaVersion }),
    // Deterministic order keeps the status surface stable across loads.
    issues: [...new Set(issues)].sort(),
  };
}

/** Aggregate verdict: any incompatibility wins, then unknown, then compatible. */
export function aggregateContractVerdict(states: readonly PackContractState[]): ContractVerdict {
  if (states.length === 0) return 'UNKNOWN';
  if (states.every((state) => state.verdict === 'NOT_CONFIGURED')) return 'NOT_CONFIGURED';
  if (states.some((state) => state.verdict === 'INCOMPATIBLE')) return 'INCOMPATIBLE';
  if (states.some((state) => state.verdict === 'UNKNOWN')) return 'UNKNOWN';
  return 'COMPATIBLE';
}

export function emptyContractState(configured: boolean): DatasetContractState {
  const families = Object.fromEntries(PACK_FAMILIES_FOR_CONTRACT.map((family) => [family, {
    verdict: (configured ? 'UNKNOWN' : 'NOT_CONFIGURED') as ContractVerdict,
    observedLayoutVersions: 0, unsupportedLayoutVersions: 0, issues: [] as ContractIssueCode[],
  }])) as Record<PackFamilyName, PackContractState>;
  return {
    contractVersion: DATASET_CONTRACT_VERSION,
    supportedLayoutVersions: [...SUPPORTED_PACK_LAYOUT_VERSIONS],
    supportedSchemaVersions: [...SUPPORTED_PACK_SCHEMA_VERSIONS],
    verdict: configured ? 'UNKNOWN' : 'NOT_CONFIGURED',
    families,
    issues: [],
  };
}

/**
 * A bounded, path-free sentence for a scanner summary. Returns undefined when
 * the family is compatible (or when no dataset is configured at all — that case
 * already has its own honest wording and must not claim incompatibility).
 */
export function contractProblemMessage(state: PackContractState | undefined): string | undefined {
  if (state === undefined) return undefined;
  if (state.verdict === 'COMPATIBLE' || state.verdict === 'NOT_CONFIGURED') return undefined;
  if (state.verdict === 'INCOMPATIBLE') {
    return 'The configured Dataset pack version is not compatible with this application; its rules were NOT loaded.';
  }
  return 'The configured Dataset pack could not be validated for this application; its rules were NOT loaded.';
}
