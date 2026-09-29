import { validationError } from '../errors.js';

/**
 * Minimal runtime schema validator for request payloads.
 *
 * Deliberately dependency-free and strict: objects reject unknown keys so
 * that typos and mass-assignment attempts fail loudly instead of being
 * silently dropped. (The query hardening helper at the bottom of this
 * module applies the same fail-loud principle to the URL query string.)
 */

export interface ValidationIssue {
  path: string;
  message: string;
}

export type ValidationResult<T> =
  | { ok: true; value: T }
  | { ok: false; issues: ValidationIssue[] };

export interface Schema<T> {
  parse(value: unknown, path?: string): ValidationResult<T>;
}

function at(path: string | undefined, fallback: string): string {
  return path === undefined || path.length === 0 ? fallback : path;
}

function fail<T>(path: string, message: string): ValidationResult<T> {
  return { ok: false, issues: [{ path, message }] };
}

export interface StringOptions {
  minLength?: number;
  maxLength?: number;
  pattern?: RegExp;
  /** Trim surrounding whitespace before every other check. */
  trim?: boolean;
}

export function string(options: StringOptions = {}): Schema<string> {
  return {
    parse(value: unknown, path?: string): ValidationResult<string> {
      const where = at(path, 'value');
      if (typeof value !== 'string') {
        return fail(where, 'Expected a string.');
      }
      const text = options.trim === true ? value.trim() : value;
      if (options.minLength !== undefined && text.length < options.minLength) {
        return fail(where, `Must be at least ${options.minLength} characters.`);
      }
      if (options.maxLength !== undefined && text.length > options.maxLength) {
        return fail(where, `Must be at most ${options.maxLength} characters.`);
      }
      if (options.pattern !== undefined && !options.pattern.test(text)) {
        return fail(where, 'Has an invalid format.');
      }
      return { ok: true, value: text };
    },
  };
}

export interface NumberOptions {
  min?: number;
  max?: number;
  integer?: boolean;
}

export function number(options: NumberOptions = {}): Schema<number> {
  return {
    parse(value: unknown, path?: string): ValidationResult<number> {
      const where = at(path, 'value');
      if (typeof value !== 'number' || Number.isNaN(value)) {
        return fail(where, 'Expected a number.');
      }
      if (options.integer === true && !Number.isInteger(value)) {
        return fail(where, 'Expected an integer.');
      }
      if (options.min !== undefined && value < options.min) {
        return fail(where, `Must be >= ${options.min}.`);
      }
      if (options.max !== undefined && value > options.max) {
        return fail(where, `Must be <= ${options.max}.`);
      }
      return { ok: true, value };
    },
  };
}

export function boolean(): Schema<boolean> {
  return {
    parse(value: unknown, path?: string): ValidationResult<boolean> {
      const where = at(path, 'value');
      if (typeof value !== 'boolean') {
        return fail(where, 'Expected a boolean.');
      }
      return { ok: true, value };
    },
  };
}

export function literal<T extends string | number | boolean>(
  ...allowed: T[]
): Schema<T> {
  return {
    parse(value: unknown, path?: string): ValidationResult<T> {
      const where = at(path, 'value');
      const match = allowed.find((candidate) => candidate === value);
      if (match === undefined) {
        return fail(where, `Must be one of: ${allowed.map(String).join(', ')}.`);
      }
      return { ok: true, value: match };
    },
  };
}

export type Shape = Record<string, Schema<unknown>>;

export type InferShape<TShape extends Shape> = {
  [K in keyof TShape]: TShape[K] extends Schema<infer V> ? V : never;
};

/** Strict object: unknown keys are rejected. */
export function object<TShape extends Shape>(shape: TShape): Schema<InferShape<TShape>> {
  return {
    parse(value: unknown, path?: string): ValidationResult<InferShape<TShape>> {
      const where = at(path, 'value');
      if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        return fail(where, 'Expected an object.');
      }
      const record = value as Record<string, unknown>;
      const issues: ValidationIssue[] = [];
      const out = {} as InferShape<TShape>;
      for (const key of Object.keys(record)) {
        // hasOwnProperty, NOT `key in shape`: the well-known keys
        // inherited from Object.prototype (the accessor that walks the
        // prototype chain, and `constructor`) exist on every object,
        // so the `in` operator would silently ACCEPT them as known
        // keys — a strict-validation bypass found by the Pump 6 audit
        // and fixed here (they are now rejected like every other
        // unknown property; see the regression test in
        // test/validate.test.ts, which names them explicitly).
        if (!Object.prototype.hasOwnProperty.call(shape, key)) {
          issues.push({ path: where === 'value' ? key : `${where}.${key}`, message: 'Unexpected property.' });
        }
      }
      for (const [key, schema] of Object.entries(shape)) {
        const result = schema.parse(
          record[key],
          where === 'value' ? key : `${where}.${key}`,
        );
        if (!result.ok) {
          issues.push(...result.issues);
        } else {
          (out as Record<string, unknown>)[key] = result.value;
        }
      }
      if (issues.length > 0) {
        return { ok: false, issues };
      }
      return { ok: true, value: out };
    },
  };
}

export interface ArrayOptions {
  minLength?: number;
  maxLength?: number;
}

export function array<T>(item: Schema<T>, options: ArrayOptions = {}): Schema<T[]> {
  return {
    parse(value: unknown, path?: string): ValidationResult<T[]> {
      const where = at(path, 'value');
      if (!Array.isArray(value)) {
        return fail(where, 'Expected an array.');
      }
      if (options.minLength !== undefined && value.length < options.minLength) {
        return fail(where, `Must contain at least ${options.minLength} items.`);
      }
      if (options.maxLength !== undefined && value.length > options.maxLength) {
        return fail(where, `Must contain at most ${options.maxLength} items.`);
      }
      const issues: ValidationIssue[] = [];
      const out: T[] = [];
      value.forEach((entry, index) => {
        const result = item.parse(entry, `${where}[${index}]`);
        if (!result.ok) {
          issues.push(...result.issues);
        } else {
          out.push(result.value);
        }
      });
      if (issues.length > 0) {
        return { ok: false, issues };
      }
      return { ok: true, value: out };
    },
  };
}

/** Wrapper permitting an explicit `undefined` (missing) value. */
export function optional<T>(inner: Schema<T>): Schema<T | undefined> {
  return {
    parse(value: unknown, path?: string): ValidationResult<T | undefined> {
      if (value === undefined) {
        return { ok: true, value: undefined };
      }
      return inner.parse(value, path);
    },
  };
}

/**
 * Reject any request carrying a query string on a route that supports NO
 * query parameters (auth — Pump 2; payments — Pump 2; scans and source
 * snapshots — Pump 3).
 *
 * Fail closed, never silent-ignore: every distinct key becomes one
 * validation issue, so the response is the uniform 422 the schema layer
 * already produces. HTTP parameter pollution dies here too (there is no
 * supported key to repeat). Routes with a documented parameter allowlist
 * keep their own allowlist validator instead.
 */
export function rejectUnexpectedQuery(req: { url?: string | undefined }): void {
  const params = new URL(req.url ?? '/', 'http://drobon.invalid').searchParams;
  const keys = [...new Set(params.keys())];
  if (keys.length > 0) {
    throw validationError(keys.map((path) => ({ path, message: 'Unexpected query parameter.' })));
  }
}
