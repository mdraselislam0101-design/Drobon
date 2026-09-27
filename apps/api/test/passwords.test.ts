import { describe, expect, test } from 'vitest';
import { dummyVerify, hashPassword, verifyPassword } from '../src/auth/passwords.js';

const COST = 1024; // same code path as production, cheaper test parameters

describe('password hashing', () => {
  test('produces a self-describing scrypt record with embedded parameters', async () => {
    const stored = await hashPassword('correct-horse-test-1', COST);
    const parts = stored.split('$');
    expect(parts).toHaveLength(6);
    expect(parts[0]).toBe('scrypt');
    expect(Number.parseInt(parts[1] ?? '', 10)).toBe(COST);
    expect(parts[2]).toBe('8');
    expect(parts[3]).toBe('1');
    // Base64 salt (16 bytes) and key (64 bytes).
    expect(Buffer.from(parts[4] ?? '', 'base64')).toHaveLength(16);
    expect(Buffer.from(parts[5] ?? '', 'base64')).toHaveLength(64);
  });

  test('never stores the plaintext password', async () => {
    const pw = 'PlaintextMustNotAppear-test-9';
    const stored = await hashPassword(pw, COST);
    expect(stored).not.toContain(pw);
    expect(stored.toLowerCase()).not.toContain('plaintext');
  });

  test('verifies the right password and rejects the wrong one', async () => {
    const stored = await hashPassword('right-password-test', COST);
    expect(await verifyPassword('right-password-test', stored)).toBe(true);
    expect(await verifyPassword('wrong-password-test', stored)).toBe(false);
    expect(await verifyPassword('', stored)).toBe(false);
  });

  test('salts are unique: hashing twice gives different records', async () => {
    const a = await hashPassword('same-password-test', COST);
    const b = await hashPassword('same-password-test', COST);
    expect(a).not.toBe(b);
    expect(await verifyPassword('same-password-test', a)).toBe(true);
    expect(await verifyPassword('same-password-test', b)).toBe(true);
  });

  test('corrupted or foreign records fail closed without throwing', async () => {
    const good = await hashPassword('pw-test-value', COST);
    for (const stored of [
      '',
      'garbage',
      'plaintext-password-test',
      'bcrypt$1024$8$1$aaaa$bbbb',
      `scrypt$${COST}$16$1$aaaa$bbbb`, // wrong r
      `scrypt$notanumber$8$1$aaaa$bbbb`,
      `scrypt$${COST}$8$1$onlysalt`, // wrong part count
      good.slice(0, good.length - 6), // truncated key
    ]) {
      expect(await verifyPassword('pw-test-value', stored)).toBe(false);
    }
  });

  test('dummyVerify burns work and always resolves', async () => {
    await expect(dummyVerify('anything-test', COST)).resolves.toBeUndefined();
  });
});
