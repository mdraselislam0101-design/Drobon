import { describe, expect, test } from 'vitest';
import * as v from '../src/lib/validate.js';

describe('validate', () => {
  test('string enforces type, length, pattern and trim', () => {
    expect(v.string().parse('a')).toEqual({ ok: true, value: 'a' });
    expect(v.string().parse(7).ok).toBe(false);
    expect(v.string({ minLength: 2 }).parse('a').ok).toBe(false);
    expect(v.string({ maxLength: 1 }).parse('ab').ok).toBe(false);
    expect(v.string({ pattern: /^\d+$/ }).parse('abc').ok).toBe(false);
    expect(v.string({ trim: true, minLength: 1 }).parse('  hi  ')).toEqual({
      ok: true,
      value: 'hi',
    });
    expect(v.string({ trim: true, minLength: 1 }).parse('   ').ok).toBe(false);
  });

  test('number enforces type, range and integer', () => {
    expect(v.number().parse(1.5)).toEqual({ ok: true, value: 1.5 });
    expect(v.number().parse('1').ok).toBe(false);
    expect(v.number().parse(Number.NaN).ok).toBe(false);
    expect(v.number({ integer: true }).parse(1.5).ok).toBe(false);
    expect(v.number({ min: 2 }).parse(1).ok).toBe(false);
    expect(v.number({ max: 2 }).parse(3).ok).toBe(false);
  });

  test('boolean and literal narrow correctly', () => {
    expect(v.boolean().parse(true)).toEqual({ ok: true, value: true });
    expect(v.boolean().parse('true').ok).toBe(false);
    expect(v.literal('a', 'b').parse('b')).toEqual({ ok: true, value: 'b' });
    const bad = v.literal('a', 'b').parse('c');
    expect(bad.ok).toBe(false);
  });

  test('object is strict and reports every issue with paths', () => {
    const schema = v.object({ name: v.string({ minLength: 1 }), age: v.number({ integer: true }) });
    expect(schema.parse({ name: 'ada', age: 36 })).toEqual({
      ok: true,
      value: { name: 'ada', age: 36 },
    });
    const extra = schema.parse({ name: 'ada', age: 36, admin: true });
    expect(extra.ok).toBe(false);
    if (!extra.ok) {
      expect(extra.issues).toContainEqual({ path: 'admin', message: 'Unexpected property.' });
    }
    const missing = schema.parse({ name: 'ada' });
    expect(missing.ok).toBe(false);
    if (!missing.ok) {
      expect(missing.issues).toContainEqual({ path: 'age', message: 'Expected a number.' });
    }
    expect(schema.parse(null).ok).toBe(false);
    expect(schema.parse([]).ok).toBe(false);
  });

  test('array validates length and item paths', () => {
    const schema = v.array(v.string({ minLength: 1 }), { maxLength: 2 });
    expect(schema.parse(['a', 'b'])).toEqual({ ok: true, value: ['a', 'b'] });
    expect(schema.parse(['a', 'b', 'c']).ok).toBe(false);
    const bad = schema.parse(['ok', '']);
    expect(bad.ok).toBe(false);
    if (!bad.ok) {
      expect(bad.issues[0]?.path).toBe('value[1]');
    }
  });

  test('optional permits undefined only', () => {
    expect(v.optional(v.string()).parse(undefined)).toEqual({ ok: true, value: undefined });
    expect(v.optional(v.string()).parse('x')).toEqual({ ok: true, value: 'x' });
    expect(v.optional(v.string()).parse(1).ok).toBe(false);
  });

  test('prototype-chain keys (__proto__/constructor) are rejected, never silently accepted (Pump 6 audit fix)', () => {
    const schema = v.object({ name: v.string() });
    // JSON.parse creates OWN properties named __proto__/constructor. The
    // old `key in shape` check saw both on the prototype chain and
    // silently DROPPED them instead of rejecting — a strict-validation
    // bypass. They must now be rejected like every other unknown key.
    const proto = schema.parse(JSON.parse('{"name":"x","__proto__":{"isAdmin":true}}'));
    expect(proto.ok).toBe(false);
    if (!proto.ok) {
      expect(proto.issues).toContainEqual({
        path: '__proto__',
        message: 'Unexpected property.',
      });
    }
    const ctor = schema.parse(JSON.parse('{"name":"x","constructor":{"prototype":{}}}'));
    expect(ctor.ok).toBe(false);
    // And nothing ever leaked onto Object.prototype.
    expect(({} as Record<string, unknown>).isAdmin).toBeUndefined();
  });

  test('nested paths compose', () => {
    const schema = v.object({ items: v.array(v.object({ id: v.number() })) });
    const bad = schema.parse({ items: [{ id: 1 }, { id: 'x' }] });
    expect(bad.ok).toBe(false);
    if (!bad.ok) {
      expect(bad.issues).toEqual([{ path: 'items[1].id', message: 'Expected a number.' }]);
    }
  });
});
