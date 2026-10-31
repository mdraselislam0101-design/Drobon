// eslint-disable-next-line @typescript-eslint/ban-ts-comment -- legacy untyped boundary; new modules use unknown.
// @ts-nocheck
/**
 * Version-range syntax validation + evaluation for `affected[].range`.
 *
 * Zero dependencies. Supported subset (see docs/FORMAT.md):
 *
 *   npm:  comparators (>, >=, <, <=, =), bare versions (= implied),
 *         hyphen ranges ("A - B"), space/comma AND, "||" OR.
 *         Wildcards (x/X/*) allowed in version parts; a lone "*" is
 *         REJECTED (use explicit bounds).
 *   pypi: PEP 440 specifier sets: comma-separated AND of
 *         (===, ==, ~=, !=, <=, >=, <, >) + version.
 *         ".*" allowed only with == / !=. "~=" needs >= 2 segments.
 *
 * `validateRange` is total (never throws). `satisfiesRange` THROWS on
 * versions/ranges it cannot evaluate exactly — callers must treat
 * that as "unknown", never as match or no-match.
 */


const NPM_OP_PATTERN = /^(>=|<=|>|<|=)?(.*)$/;
const NPM_VERSION_PATTERN =
  /^v?(\d+|x|X|\*)(?:\.(\d+|x|X|\*))?(?:\.(\d+|x|X|\*))?(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?$/;
const NPM_EXACT_VERSION = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?$/;
const PYPI_SPEC_PATTERN = /^(===|==|~=|!=|<=|>=|<|>)\s*(.+)$/;
const PYPI_LOCAL_FORBIDDEN_OPERATORS = new Set(['~=', '<=', '>=', '<', '>']);
const PYPI_VERSION_PATTERN =
  /^(\d+!)?\d+(\.\d+)*((a|b|rc|alpha|beta|pre|preview)\d*)?(\.?(post|rev|r)\d*)?(\.?(dev)\d*)?(\+[a-zA-Z0-9]+(\.[a-zA-Z0-9]+)*)?$/i;

function isNpmVersionToken(token) {
  return NPM_VERSION_PATTERN.test(token);
}

/**
 * Validate one range string. Returns null when valid, else a reason.
 * Never throws.
 */
export function validateRange(ecosystem, range) {
  if (ecosystem !== 'npm' && ecosystem !== 'pypi') {
    return `unknown ecosystem "${String(ecosystem)}"`;
  }
  if (typeof range !== 'string' || range.trim() === '') {
    return 'range must be a non-empty string';
  }
  const trimmed = range.trim();
  if (trimmed === '*') {
    return 'bare "*" is not allowed — use explicit bounds';
  }
  try {
    return ecosystem === 'npm' ? validateNpmRange(trimmed) : validatePypiRange(trimmed);
  } catch (err) {
    return `unparseable range (${err.message})`;
  }
}

function validateNpmRange(range) {
  const groups = range.split('||').map((group) => group.trim());
  for (const group of groups) {
    if (group === '') {
      return 'empty "||" branch';
    }
    const error = validateNpmGroup(group);
    if (error !== null) {
      return error;
    }
  }
  return null;
}

function attachNpmOperators(group) {
  // GHSA-style spacing ("<= 2.7.0", ">= 1.0.0, < 2.0.0"): glue an
  // operator to the version that follows it.
  return group.replace(/([<>=]+)\s+/g, '$1');
}

function validateNpmGroup(group) {
  const attached = attachNpmOperators(group);
  const hyphen = attached.split(/\s+-\s+/);
  if (hyphen.length > 2) {
    return `bad hyphen range "${group}"`;
  }
  if (hyphen.length === 2) {
    const [low, high] = hyphen.map((side) => side.trim());
    if (!isNpmVersionToken(low) || !isNpmVersionToken(high)) {
      return `bad hyphen range "${group}"`;
    }
    parseNpmRangeVersion(low);
    parseNpmRangeVersion(high);
    return null;
  }
  const tokens = attached.split(/[\s,]+/).filter((token) => token !== '');
  if (tokens.length === 0) {
    return 'empty range group';
  }
  for (const token of tokens) {
    if (token === '*') {
      return 'bare "*" is not allowed — use explicit bounds';
    }
    const match = token.match(NPM_OP_PATTERN);
    const version = (match?.[2] ?? '').trim();
    if (version === '' || !isNpmVersionToken(version)) {
      return `bad comparator "${token}"`;
    }
    // Validate every branch before evaluation; short-circuiting must not
    // turn malformed or imprecise comparators into a clean result.
    parseNpmRangeVersion(version);
  }
  return null;
}

function validatePypiRange(range) {
  const specs = range.split(',').map((spec) => spec.trim());
  for (const spec of specs) {
    if (spec === '') {
      return 'empty specifier in set';
    }
    const match = spec.match(PYPI_SPEC_PATTERN);
    if (!match) {
      return `bad specifier "${spec}" (operator + version required)`;
    }
    const [, operator, version] = match;
    if (version.endsWith('.*')) {
      if (operator !== '==' && operator !== '!=') {
        return `"${spec}": wildcard only allowed with == / !=`;
      }
      const prefix = version.slice(0, -2);
      if (!PYPI_VERSION_PATTERN.test(prefix)) {
        return `bad version in "${spec}"`;
      }
      // PEP 440 Version matching: "It is invalid to have a prefix match containing a development or local release".
      if (prefix.includes('+')) {
        return `"${spec}": prefix match with a local release is invalid`;
      }
      if (/\.?dev\d*$/i.test(prefix)) {
        return `"${spec}": prefix match with a development release is invalid`;
      }
    } else if (operator === '===') {
      if (/\s/.test(version)) {
        return `bad version in "${spec}"`;
      }
    } else {
      if (!PYPI_VERSION_PATTERN.test(version)) {
        return `bad version in "${spec}"`;
      }
      // PEP 440: local version identifiers are NOT permitted in ordered comparisons or ~=.
      // They are allowed only with == / != / === (the spec's stated exceptions).
      if (version.includes('+') && PYPI_LOCAL_FORBIDDEN_OPERATORS.has(operator)) {
        return `"${spec}": local version identifiers are not permitted with ${operator}`;
      }
      if (operator === '~=') {
        const withoutEpoch = version.includes('!') ? version.slice(version.indexOf('!') + 1) : version;
        const release = withoutEpoch.split(/[a-zA-Z+]/)[0].split('.');
        if (release.length < 2) {
          return `"${spec}": ~= needs at least two release segments`;
        }
      }
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Evaluation (exact or throw — never guess)
// ---------------------------------------------------------------------------

function compareNumbers(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}

function npmNumericPart(part) {
  if (!/^\d+$/.test(part) || (part.length > 1 && part.startsWith('0'))) {
    throw new Error('invalid npm numeric version identifier');
  }
  const value = Number(part);
  if (!Number.isSafeInteger(value)) throw new Error('npm numeric version identifier exceeds safe precision');
  return value;
}

function validateNpmPrerelease(pre) {
  if (pre === null) return;
  for (const part of pre.split('.')) {
    if (!part || !/^[0-9A-Za-z-]+$/.test(part)) throw new Error('invalid npm prerelease identifier');
    if (/^\d+$/.test(part)) npmNumericPart(part);
  }
}

function validateNpmBuild(build) {
  if (build !== undefined && build.split('.').some((part) => !part || !/^[0-9A-Za-z-]+$/.test(part))) {
    throw new Error('invalid npm build identifier');
  }
}

function parseNpmExact(version) {
  const match = version.trim().match(NPM_EXACT_VERSION);
  if (!match) {
    throw new Error(`cannot evaluate npm version "${version}" (need full x.y.z)`);
  }
  const pre = match[4] ?? null;
  validateNpmPrerelease(pre);
  validateNpmBuild(match[5]);
  return { nums: [npmNumericPart(match[1]), npmNumericPart(match[2]), npmNumericPart(match[3])], pre };
}

function compareSemverPre(a, b) {
  if (a === b) {
    return 0;
  }
  if (a === null) {
    return 1; // release > prerelease
  }
  if (b === null) {
    return -1;
  }
  const aParts = a.split('.');
  const bParts = b.split('.');
  const length = Math.max(aParts.length, bParts.length);
  for (let i = 0; i < length; i += 1) {
    const aPart = aParts[i];
    const bPart = bParts[i];
    if (aPart === undefined) {
      return -1;
    }
    if (bPart === undefined) {
      return 1;
    }
    const aNum = /^\d+$/.test(aPart) ? Number(aPart) : null;
    const bNum = /^\d+$/.test(bPart) ? Number(bPart) : null;
    if (aNum !== null && bNum !== null) {
      const order = compareNumbers(aNum, bNum);
      if (order !== 0) {
        return order;
      }
    } else if (aNum !== null) {
      return -1; // numeric < alphanumeric
    } else if (bNum !== null) {
      return 1;
    } else {
      const order = compareNumbers(aPart, bPart);
      if (order !== 0) {
        return order;
      }
    }
  }
  return 0;
}

function compareNpm(a, b) {
  for (let i = 0; i < 3; i += 1) {
    const order = compareNumbers(a.nums[i], b.nums[i]);
    if (order !== 0) {
      return order;
    }
  }
  return compareSemverPre(a.pre, b.pre);
}

function parseNpmRangeVersion(token) {
  const match = token.trim().match(NPM_VERSION_PATTERN);
  if (!match) {
    throw new Error(`cannot evaluate npm range version "${token}"`);
  }
  const parts = [match[1], match[2], match[3]].map((part) =>
    part === undefined || part === 'x' || part === 'X' || part === '*' ? null : npmNumericPart(part),
  );
  const firstWildcard = parts.indexOf(null);
  if (firstWildcard !== -1 && parts.slice(firstWildcard).some((part) => part !== null)) {
    throw new Error('numeric npm component after wildcard');
  }
  const pre = match[4] ?? null;
  validateNpmPrerelease(pre);
  validateNpmBuild(match[5]);
  return { parts, pre };
}

function npmDesugarEquality(rangeVersion) {
  // "=1.x" / bare "1.2" → [lower, upper) ; returns { low, high } where
  // high is null for "any".
  const { parts, pre } = rangeVersion;
  if (pre !== null) {
    throw new Error('cannot evaluate prerelease with wildcards');
  }
  const firstWild = parts.findIndex((part) => part === null);
  if (firstWild === -1) {
    return { exact: parts };
  }
  if (firstWild === 0) {
    return { low: [0, 0, 0], high: null };
  }
  const low = parts.map((part) => part ?? 0);
  const high = [...low];
  high[firstWild - 1] += 1;
  for (let i = firstWild; i < 3; i += 1) {
    high[i] = 0;
  }
  return { low, high };
}

function evalNpmComparator(parsed, operator, token) {
  const rangeVersion = parseNpmRangeVersion(token);
  const hasWildcard = rangeVersion.parts.some((part) => part === null);
  if (hasWildcard) {
    if (operator !== '=' && operator !== '') {
      throw new Error(`cannot evaluate "${operator}${token}" (wildcard with inequality)`);
    }
    const { exact, low, high } = npmDesugarEquality(rangeVersion);
    if (exact) {
      return compareNpm(parsed, { nums: exact, pre: rangeVersion.pre }) === 0;
    }
    const aboveLow = compareNpm(parsed, { nums: low, pre: null }) >= 0;
    return high === null
      ? aboveLow
      : aboveLow && compareNpm(parsed, { nums: high, pre: null }) < 0;
  }
  const other = {
    nums: rangeVersion.parts.map((part) => part ?? 0),
    pre: rangeVersion.pre,
  };
  const order = compareNpm(parsed, other);
  switch (operator) {
    case '':
    case '=':
      return order === 0;
    case '>':
      return order > 0;
    case '>=':
      return order >= 0;
    case '<':
      return order < 0;
    case '<=':
      return order <= 0;
    default:
      throw new Error(`unknown npm operator "${operator}"`);
  }
}

function evalNpmGroup(parsed, group) {
  const attached = attachNpmOperators(group);
  const hyphen = attached.split(/\s+-\s+/);
  const comparators = hyphen.length === 2
    ? [{ operator: '>=', version: hyphen[0].trim() }, { operator: '<=', version: hyphen[1].trim() }]
    : attached.split(/[\s,]+/).filter((token) => token !== '').map((token) => {
        const match = token.match(NPM_OP_PATTERN);
        return { operator: match?.[1] ?? '', version: (match?.[2] ?? '').trim() };
      });
  // Evaluate every comparator: an unsupported one must not be hidden by
  // an earlier false comparison.
  let matched = true;
  for (const comparator of comparators) {
    if (!evalNpmComparator(parsed, comparator.operator, comparator.version)) matched = false;
  }
  if (!matched || parsed.pre === null) return matched;
  // npm's default range semantics allow prereleases only when this AND
  // branch explicitly mentions a prerelease of the same major/minor/patch.
  // For advisory data an excluded prerelease might still be vulnerable, so
  // report it as unknown rather than a confident non-match or false match.
  const optedIn = comparators.some(({ version }) => {
    const bound = parseNpmRangeVersion(version);
    return bound.pre !== null && bound.parts.every((part, index) => part === parsed.nums[index]);
  });
  if (!optedIn) throw new Error('npm prerelease is not explicitly covered by this advisory range');
  return true;
}

function evalNpm(parsed, range) {
  let unknown;
  for (const group of range.split('||').map((entry) => entry.trim())) {
    try {
      if (evalNpmGroup(parsed, group)) return true;
    } catch (error) {
      unknown ??= error;
    }
  }
  if (unknown !== undefined) throw unknown;
  return false;
}

// --- PEP 440 ---

const PYPI_PRE_ORDER = { a: 0, alpha: 0, b: 1, beta: 1, rc: 2, pre: 2, preview: 2 };

// PEP 440 normalization of a local label (the part after '+'): case-insensitive, and a purely numeric
// segment is normalized as an integer (leading zeros removed; '0' stays '0'). Integers inside an
// alphanumeric segment are NOT normalized ("1.0+foo0100" is already normalized). Compared by strict
// string equality. The parser accepts only [a-z0-9] segments separated by '.', so '-' and '_' separators
// are rejected (fail closed) rather than normalized.
function normalizePypiLocal(label) {
  return label
    .toLowerCase()
    .split('.')
    .map((segment) => (/^\d+$/.test(segment) ? segment.replace(/^0+(?=\d)/, '') : segment))
    .join('.');
}

function pypiNumber(part) {
  const value = Number(part);
  if (!Number.isSafeInteger(value)) throw new Error('pypi version exceeds safe precision');
  return value;
}

function parsePypiVersion(version) {
  const trimmed = version.trim();
  if (!PYPI_VERSION_PATTERN.test(trimmed)) throw new Error(`cannot evaluate pypi version "${version}"`);
  const match = trimmed.match(/^(\d+!)?(.+?)(\+[a-zA-Z0-9]+(\.[a-zA-Z0-9]+)*)?$/);
  if (!match) {
    throw new Error(`cannot evaluate pypi version "${version}"`);
  }
  const epoch = match[1] ? pypiNumber(match[1].slice(0, -1)) : 0;
  let rest = match[2];
  let dev = null;
  const devMatch = rest.match(/^(.*)\.?(dev)(\d*)$/i);
  if (devMatch && /(\d|[a-zA-Z])/.test(devMatch[1])) {
    dev = devMatch[3] === '' ? 0 : pypiNumber(devMatch[3]);
    rest = devMatch[1].replace(/\.$/, '');
  }
  let post = null;
  const postMatch = rest.match(/^(.*)\.?(post|rev|r)(\d*)$/i);
  if (postMatch && /^\d/.test(postMatch[1].replace(/\.$/, ''))) {
    post = postMatch[3] === '' ? 0 : pypiNumber(postMatch[3]);
    rest = postMatch[1].replace(/\.$/, '');
  }
  let pre = null;
  const preMatch = rest.match(/^(.*?(?:\d))(a|b|rc|alpha|beta|pre|preview)(\d*)$/i);
  if (preMatch) {
    pre = {
      order: PYPI_PRE_ORDER[preMatch[2].toLowerCase()],
      num: preMatch[3] === '' ? 0 : pypiNumber(preMatch[3]),
    };
    rest = preMatch[1];
  }
  const release = rest
    .replace(/\.$/, '')
    .split('.')
    .map((part) => {
      if (!/^\d+$/.test(part)) {
        throw new Error(`cannot evaluate pypi version "${version}"`);
      }
      return pypiNumber(part);
    });
  return { epoch, release, pre, post, dev, local: match[3] ? normalizePypiLocal(match[3].slice(1)) : null };
}

function comparePypi(a, b) {
  let order = compareNumbers(a.epoch, b.epoch);
  if (order !== 0) {
    return order;
  }
  const length = Math.max(a.release.length, b.release.length);
  for (let i = 0; i < length; i += 1) {
    order = compareNumbers(a.release[i] ?? 0, b.release[i] ?? 0);
    if (order !== 0) {
      return order;
    }
  }
  // PEP 440: a development release with no pre/post segment sorts
  // BEFORE alpha releases, not just before the final release.
  const aPre = a.pre === null ? (a.post === null && a.dev !== null ? [-1, 0] : [3, 0]) : [a.pre.order, a.pre.num];
  const bPre = b.pre === null ? (b.post === null && b.dev !== null ? [-1, 0] : [3, 0]) : [b.pre.order, b.pre.num];
  order = compareNumbers(aPre[0], bPre[0]) || compareNumbers(aPre[1], bPre[1]);
  if (order !== 0) {
    return order;
  }
  const aPost = a.post === null ? -1 : a.post;
  const bPost = b.post === null ? -1 : b.post;
  order = compareNumbers(aPost, bPost);
  if (order !== 0) {
    return order;
  }
  const aDev = a.dev === null ? [1, 0] : [0, a.dev];
  const bDev = b.dev === null ? [1, 0] : [0, b.dev];
  return compareNumbers(aDev[0], bDev[0]) || compareNumbers(aDev[1], bDev[1]);
}

function sameEpochRelease(a, b) {
  if (a.epoch !== b.epoch) {
    return false;
  }
  const length = Math.max(a.release.length, b.release.length);
  for (let i = 0; i < length; i += 1) {
    if ((a.release[i] ?? 0) !== (b.release[i] ?? 0)) {
      return false;
    }
  }
  return true;
}

// '>V' MUST NOT allow a post-release of the same base release unless V
// itself is a post-release, even if V is a prerelease of that base.
function isPostReleaseOfExclusiveBound(candidate, bound) {
  return bound.post === null && candidate.post !== null && sameEpochRelease(candidate, bound);
}

// '<V' MUST NOT allow a prerelease of the same base release unless V is
// itself a prerelease. A development release is a prerelease, including a
// development release of a post-release; an ordinary post-release is not.
function isPreReleaseOfFinalBound(candidate, bound) {
  if (bound.pre !== null || bound.dev !== null) {
    return false;
  }
  if (candidate.pre === null && candidate.dev === null) {
    return false;
  }
  return sameEpochRelease(candidate, bound);
}

function evalPypiSpecifier(parsed, spec) {
  const match = spec.trim().match(PYPI_SPEC_PATTERN);
  if (!match) {
    throw new Error(`cannot evaluate pypi specifier "${spec}"`);
  }
  const [, operator, version] = match;
  if (operator === '===') {
    if (parsed.raw.toLowerCase() === version.toLowerCase()) return true;
    // Arbitrary equality interacts with normalized version spellings; do
    // not claim a non-match when we cannot establish that normalization.
    throw new Error('pypi arbitrary equality cannot be evaluated exactly');
  }
  if (version.endsWith('.*')) {
    const rawPrefix = version.slice(0, -2);
    // Epoch/prerelease prefixes need PEP 440 prefix semantics that this
    // evaluator does not implement; never turn NaN into a clean verdict.
    if (!/^\d+(?:\.\d+)*$/.test(rawPrefix)) throw new Error('unsupported pypi wildcard prefix');
    const prefix = rawPrefix.split('.').map((part) => {
      const value = Number(part);
      if (!Number.isSafeInteger(value)) throw new Error('pypi version exceeds safe precision');
      return value;
    });
    const hit = parsed.epoch === 0 && prefix.every((num, index) => (parsed.release[index] ?? 0) === num);
    if (operator === '==') {
      return hit;
    }
    if (operator === '!=') {
      return !hit;
    }
    throw new Error(`cannot evaluate "${spec}"`);
  }
  const other = parsePypiVersion(version);
  const order = comparePypi(parsed, other);
  // PEP 440 "Version matching" (D5): with a local label on the specifier, the candidate MUST carry an equal
  // local label (strict string equality after normalization). Without one, the candidate label is ignored.
  // '!=' is the inverse of this match. '===' is handled above as plain string equality.
  if (operator === '==' || operator === '!=') {
    const hit = order === 0 && (other.local === null || parsed.local === other.local);
    return operator === '==' ? hit : !hit;
  }
  // PEP 440 exclusive ordered comparison (MUST NOT). Only '<' and '>' are affected.
  if (operator === '>' && (
    isPostReleaseOfExclusiveBound(parsed, other) ||
    (parsed.local !== null && sameEpochRelease(parsed, other))
  )) {
    return false;
  }
  if (operator === '<' && isPreReleaseOfFinalBound(parsed, other)) {
    return false;
  }
  switch (operator) {
    case '==':
      return order === 0;
    case '!=':
      return order !== 0;
    case '<':
      return order < 0;
    case '<=':
      return order <= 0;
    case '>':
      return order > 0;
    case '>=':
      return order >= 0;
    case '~=': {
      if (order < 0) {
        return false;
      }
      const prefix = other.release.slice(0, -1);
      return parsed.epoch === other.epoch && prefix.every((num, index) => (parsed.release[index] ?? 0) === num);
    }
    default:
      throw new Error(`unknown pypi operator "${operator}"`);
  }
}

function evalPypi(parsed, range) {
  const specs = range.split(',').map((spec) => spec.trim());
  let matched = true;
  for (const spec of specs) {
    // Evaluate all specifiers so unsupported syntax cannot be hidden by
    // an earlier non-match and then presented as a complete assessment.
    if (!evalPypiSpecifier(parsed, spec)) matched = false;
  }
  if (!matched || (parsed.pre === null && parsed.dev === null)) return matched;
  const optedIn = specs.some((spec) => {
    const match = spec.match(PYPI_SPEC_PATTERN);
    // Unlike an installer's default candidate filtering, an advisory bound
    // that explicitly names a prerelease includes prerelease comparisons for
    // both exclusive and inclusive operators. Otherwise a range such as
    // <1.0rc2 would hide the vulnerable 1.0rc1.
    if (!match || !['===', '==', '~=', '>=', '<=', '>', '<'].includes(match[1])) return false;
    const version = match[2].endsWith('.*') ? match[2].slice(0, -2) : match[2];
    try {
      const bound = parsePypiVersion(version);
      return bound.pre !== null || bound.dev !== null;
    } catch {
      return false;
    }
  });
  if (!optedIn) throw new Error('pypi prerelease is not explicitly covered by this advisory range');
  return true;
}

/**
 * Does `version` satisfy `range` for `ecosystem`?
 * THROWS when it cannot evaluate exactly — callers must treat that
 * as "unknown", never as match or no-match.
 */
export function satisfiesRange(ecosystem, version, range) {
  // Refuse invalid ranges instead of evaluating them: an invalid range must read as
  // "unknown" to callers, never as a match or no-match (see header contract).
  const invalid = validateRange(ecosystem, range);
  if (invalid !== null) {
    throw new Error(`invalid range: ${invalid}`);
  }
  if (ecosystem === 'npm') {
    return evalNpm(parseNpmExact(version), range);
  }
  if (ecosystem === 'pypi') {
    const parsed = { ...parsePypiVersion(version), raw: version.trim() };
    return evalPypi(parsed, range);
  }
  throw new Error(`unknown ecosystem "${String(ecosystem)}"`);
}
