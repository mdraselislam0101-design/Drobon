/**
 * Secrets baseline (P2-14) — an explicit, bounded suppression list that lives
 * INSIDE the project's own source snapshot.
 *
 * Rules of the design:
 * - A baseline never hides anything silently: every suppression is counted
 *   (`secretsBaseline.applied`) and surfaced in the scan summary, the report
 *   and the UI. Invalid entries are counted too, never ignored.
 * - A baseline may only suppress a finding it actually describes:
 *   `{ ruleId, file }` (any match of that rule in that file) or an exact
 *   `{ fingerprint }`. A baseline entry cannot suppress a different rule, a
 *   different file, or a secret it does not name.
 * - No secret material is ever read from or written to the baseline: an entry
 *   names a rule, a path and an optional reason. The fingerprint form uses the
 *   engine's existing identity (rule + path + line), never the secret value.
 * - Everything is bounded: 64 KiB document, 500 entries, 200-character
 *   reasons. A malformed or oversized baseline is reported as INVALID and
 *   suppresses nothing (fail-open on detection, fail-closed on suppression).
 */
import { isValidSourcePath } from '@drobon/shared';

/**
 * Only this exact root-level file is read as a baseline.
 *
 * A leading-dot name is deliberately NOT used: the shared source-path policy
 * refuses dotfiles (`.env`, `.git`, ...), so no snapshot could ever contain
 * one. This name is an ordinary path that passes the same policy every scanned
 * file does.
 */
export const SECRETS_BASELINE_PATH = 'drobon-secrets-baseline.json';
/** Hard document bound for the baseline file. */
export const SECRETS_BASELINE_MAX_BYTES = 64 * 1024;
/** Hard entry bound. */
export const SECRETS_BASELINE_MAX_ENTRIES = 500;
const RULE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const FINGERPRINT_PATTERN = /^[0-9a-f]{64}$/;

export type SecretsBaselineStatus = 'ABSENT' | 'ANALYZED' | 'INVALID' | 'UNSUPPORTED';

export interface SecretsBaselineEntry {
  ruleId?: string;
  file?: string;
  fingerprint?: string;
  reason?: string;
}

export interface SecretsBaseline {
  status: SecretsBaselineStatus;
  /** Usable suppression rules, in file order (deterministic). */
  entries: SecretsBaselineEntry[];
  /** Entries rejected for shape/bounds — disclosed, never dropped silently. */
  invalid: number;
  note?: string;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function boundedText(value: unknown, max: number): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= max &&
    // eslint-disable-next-line no-control-regex -- control characters are never valid here.
    !/[\u0000-\u001f\u007f]/.test(value);
}

/**
 * Parse a baseline document. Never throws; every failure is a status.
 * `ABSENT` means the file was not part of the snapshot (not an error).
 */
export function parseSecretsBaseline(text: string | undefined): SecretsBaseline {
  if (text === undefined) return { status: 'ABSENT', entries: [], invalid: 0 };
  if (Buffer.byteLength(text, 'utf8') > SECRETS_BASELINE_MAX_BYTES) {
    return {
      status: 'INVALID',
      entries: [],
      invalid: 0,
      note: 'The baseline document exceeded 64 KiB and was not applied.',
    };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { status: 'INVALID', entries: [], invalid: 0, note: 'The baseline document was not valid JSON and was not applied.' };
  }
  if (!isPlainObject(parsed)) {
    return { status: 'INVALID', entries: [], invalid: 0, note: 'The baseline document was not a JSON object and was not applied.' };
  }
  if (parsed['version'] !== 1) {
    return { status: 'INVALID', entries: [], invalid: 0, note: 'The baseline document does not declare version 1 and was not applied.' };
  }
  const rawEntries = parsed['entries'];
  if (!Array.isArray(rawEntries)) {
    return { status: 'INVALID', entries: [], invalid: 0, note: 'The baseline document has no entries array and was not applied.' };
  }
  if (rawEntries.length > SECRETS_BASELINE_MAX_ENTRIES) {
    return {
      status: 'INVALID',
      entries: [],
      invalid: 0,
      note: `The baseline has more than ${SECRETS_BASELINE_MAX_ENTRIES} entries and was not applied.`,
    };
  }
  const entries: SecretsBaselineEntry[] = [];
  let invalid = 0;
  for (const raw of rawEntries) {
    if (!isPlainObject(raw)) {
      invalid += 1;
      continue;
    }
    const ruleId = raw['ruleId'];
    const file = raw['file'];
    const fingerprint = raw['fingerprint'];
    const reason = raw['reason'];
    const hasRule = ruleId !== undefined;
    const hasFile = file !== undefined;
    const hasFingerprint = fingerprint !== undefined;
    if (hasRule && (typeof ruleId !== 'string' || !RULE_ID_PATTERN.test(ruleId))) {
      invalid += 1;
      continue;
    }
    // A path must pass the SAME containment policy as a scanned file.
    if (hasFile && (typeof file !== 'string' || !isValidSourcePath(file))) {
      invalid += 1;
      continue;
    }
    if (hasFingerprint && (typeof fingerprint !== 'string' || !FINGERPRINT_PATTERN.test(fingerprint))) {
      invalid += 1;
      continue;
    }
    if (reason !== undefined && !boundedText(reason, 200)) {
      invalid += 1;
      continue;
    }
    const usable =
      (hasRule && hasFile) || (hasRule && hasFingerprint) || hasFingerprint;
    if (!usable) {
      // An entry naming nothing (or only a reason) suppresses nothing.
      invalid += 1;
      continue;
    }
    entries.push({
      ...(hasRule ? { ruleId: ruleId as string } : {}),
      ...(hasFile ? { file: file as string } : {}),
      ...(hasFingerprint ? { fingerprint: fingerprint as string } : {}),
      ...(reason === undefined ? {} : { reason: reason as string }),
    });
  }
  const notes: string[] = [];
  if (invalid > 0) notes.push(`${invalid} baseline entr${invalid === 1 ? 'y was' : 'ies were'} invalid and were not applied.`);
  if (entries.length === 0 && invalid === 0) notes.push('The baseline document contains no entries.');
  return {
    status: 'ANALYZED',
    entries,
    invalid,
    ...(notes.length === 0 ? {} : { note: notes.join(' ').slice(0, 200) }),
  };
}

/**
 * Does the baseline suppress this finding? An entry must match EVERY field it
 * states, so a broad entry cannot suppress unrelated rules or files.
 */
export function isSecretsFindingBaselined(
  entries: readonly SecretsBaselineEntry[],
  finding: { ruleId: string; file: string; fingerprint: string },
): boolean {
  for (const entry of entries) {
    if (entry.fingerprint !== undefined) {
      if (entry.fingerprint !== finding.fingerprint) continue;
      if (entry.ruleId !== undefined && entry.ruleId !== finding.ruleId) continue;
      if (entry.file !== undefined && entry.file !== finding.file) continue;
      return true;
    }
    if (entry.ruleId === finding.ruleId && entry.file === finding.file) return true;
  }
  return false;
}
