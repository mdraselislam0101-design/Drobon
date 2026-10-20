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
const NPM_EXACT_VERSION = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/;
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
        const release = version.split(/[a-zA-Z+!]/)[0].split('.');
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

function parseNpmExact(version) {
  const match = version.trim().match(NPM_EXACT_VERSION);
  if (!match) {
    throw new Error(`cannot evaluate npm version "${version}" (need full x.y.z)`);
  }
  return { nums: [Number(match[1]), Number(match[2]), Number(match[3])], pre: match[4] ?? null };
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
    part === undefined || part === 'x' || part === 'X' || part === '*' ? null : Number(part),
  );
  return { parts, pre: match[4] ?? null };
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
  if (hyphen.length === 2) {
    return (
      evalNpmComparator(parsed, '>=', hyphen[0].trim()) &&
      evalNpmComparator(parsed, '<=', hyphen[1].trim())
    );
  }
  const tokens = attached.split(/[\s,]+/).filter((token) => token !== '');
  return tokens.every((token) => {
    const match = token.match(NPM_OP_PATTERN);
    const operator = match?.[1] ?? '';
    const version = (match?.[2] ?? '').trim();
    return evalNpmComparator(parsed, operator, version);
  });
}

function evalNpm(parsed, range) {
  return range
    .split('||')
    .map((group) => group.trim())
    .some((group) => evalNpmGroup(parsed, group));
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

function parsePypiVersion(version) {
  const trimmed = version.trim();
  const match = trimmed.match(/^(\d+!)?(.+?)(\+[a-zA-Z0-9]+(\.[a-zA-Z0-9]+)*)?$/);
  if (!match) {
    throw new Error(`cannot evaluate pypi version "${version}"`);
  }
  const epoch = match[1] ? Number(match[1].slice(0, -1)) : 0;
  let rest = match[2];
  let dev = null;
  const devMatch = rest.match(/^(.*)\.?(dev)(\d*)$/i);
  if (devMatch && /(\d|[a-zA-Z])/.test(devMatch[1])) {
    dev = devMatch[3] === '' ? 0 : Number(devMatch[3]);
    rest = devMatch[1].replace(/\.$/, '');
  }
  let post = null;
  const postMatch = rest.match(/^(.*)\.?(post|rev|r)(\d*)$/i);
  if (postMatch && /^\d/.test(postMatch[1].replace(/\.$/, ''))) {
    post = postMatch[3] === '' ? 0 : Number(postMatch[3]);
    rest = postMatch[1].replace(/\.$/, '');
  }
  let pre = null;
  const preMatch = rest.match(/^(.*?(?:\d))(a|b|rc|alpha|beta|pre|preview)(\d*)$/i);
  if (preMatch) {
    pre = {
      order: PYPI_PRE_ORDER[preMatch[2].toLowerCase()],
      num: preMatch[3] === '' ? 0 : Number(preMatch[3]),
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
      return Number(part);
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
  const aPre = a.pre === null ? [3, 0] : [a.pre.order, a.pre.num];
  const bPre = b.pre === null ? [3, 0] : [b.pre.order, b.pre.num];
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

// '>V' MUST NOT allow a post-release of V unless V is itself a post-release.
// A post-release of V has V's epoch, release and pre-release segment, plus a post segment.
function isPostReleaseOfExclusiveBound(candidate, bound) {
  if (bound.post !== null || candidate.post === null) {
    return false;
  }
  const samePre =
    candidate.pre === null
      ? bound.pre === null
      : bound.pre !== null &&
        candidate.pre.order === bound.pre.order &&
        candidate.pre.num === bound.pre.num;
  return samePre && sameEpochRelease(candidate, bound);
}

// '<V' MUST NOT allow a pre-release of V unless V is itself a pre-release.
// Developmental releases are pre-releases too. Only a final V is checked here; a V with a pre, post
// or dev segment is left to ordering, because this pump does not decide those forms.
function isPreReleaseOfFinalBound(candidate, bound) {
  if (bound.pre !== null || bound.post !== null || bound.dev !== null) {
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
    return parsed.raw === version;
  }
  if (version.endsWith('.*')) {
    const prefix = version
      .slice(0, -2)
      .split('.')
      .map(Number);
    const hit = prefix.every((num, index) => (parsed.release[index] ?? 0) === num);
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
  if (operator === '>' && isPostReleaseOfExclusiveBound(parsed, other)) {
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
      return prefix.every((num, index) => (parsed.release[index] ?? 0) === num);
    }
    default:
      throw new Error(`unknown pypi operator "${operator}"`);
  }
}

function evalPypi(parsed, range) {
  return range
    .split(',')
    .map((spec) => spec.trim())
    .every((spec) => evalPypiSpecifier(parsed, spec));
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
