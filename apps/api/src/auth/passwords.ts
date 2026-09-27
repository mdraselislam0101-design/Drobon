import { randomBytes, scrypt, timingSafeEqual } from 'node:crypto';

/**
 * Password hashing with scrypt — a memory-hard KDF built into Node's
 * standard library, so the API keeps its zero-dependency posture while
 * using a production-appropriate algorithm (OWASP-listed alternative to
 * Argon2id/bcrypt).
 *
 * Stored format (single string, self-describing so parameters can change
 * without a migration framework):
 *
 *   scrypt$<N>$<r>$<p>$<salt-base64>$<hash-base64>
 *
 * Salts are 16 random bytes per user; comparisons are constant-time.
 * Plaintext passwords never touch disk, logs or responses.
 */

const SCHEME = 'scrypt';
const KEY_LENGTH = 64;
const SALT_LENGTH = 16;
const R = 8;
const P = 1;

function maxmemFor(cost: number): number {
  // scrypt needs ~128 * N * r * p bytes; give it headroom over the default
  // 32 MiB cap (the default cost of 32768 sits exactly at the cap).
  return Math.max(64 * 1024 * 1024, 4 * 128 * cost * R * P);
}

function scryptAsync(password: string, salt: Buffer, cost: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scrypt(
      Buffer.from(password, 'utf8'),
      salt,
      KEY_LENGTH,
      { N: cost, r: R, p: P, maxmem: maxmemFor(cost) },
      (error, derivedKey) => {
        if (error !== null) {
          reject(error);
          return;
        }
        resolve(derivedKey);
      },
    );
  });
}

/** Hash a password for storage. Each call uses a fresh random salt. */
export async function hashPassword(password: string, cost: number): Promise<string> {
  const salt = randomBytes(SALT_LENGTH);
  const key = await scryptAsync(password, salt, cost);
  return `${SCHEME}$${cost}$${R}$${P}$${salt.toString('base64')}$${key.toString('base64')}`;
}

interface ParsedHash {
  cost: number;
  salt: Buffer;
  key: Buffer;
}

function parseStored(stored: string): ParsedHash | undefined {
  const parts = stored.split('$');
  if (parts.length !== 6 || parts[0] !== SCHEME) {
    return undefined;
  }
  const cost = Number.parseInt(parts[1] ?? '', 10);
  const r = Number.parseInt(parts[2] ?? '', 10);
  const p = Number.parseInt(parts[3] ?? '', 10);
  if (!Number.isInteger(cost) || cost < 1024 || cost > 1_048_576 || r !== R || p !== P) {
    return undefined;
  }
  try {
    const salt = Buffer.from(parts[4] ?? '', 'base64');
    const key = Buffer.from(parts[5] ?? '', 'base64');
    if (salt.length !== SALT_LENGTH || key.length !== KEY_LENGTH) {
      return undefined;
    }
    return { cost, salt, key };
  } catch {
    return undefined;
  }
}

/**
 * Verify a password against a stored hash. Returns false (never throws)
 * for corrupted or foreign formats — a broken record must not become an
 * authentication bypass or a 500 oracle.
 */
export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parsed = parseStored(stored);
  if (parsed === undefined) {
    return false;
  }
  let candidate: Buffer;
  try {
    candidate = await scryptAsync(password, parsed.salt, parsed.cost);
  } catch {
    return false;
  }
  return candidate.length === parsed.key.length && timingSafeEqual(candidate, parsed.key);
}

/**
 * Burn the same amount of CPU as a real verification for an email that has
 * no account. Login calls this for unknown emails so response timing does
 * not reveal whether an account exists.
 */
export async function dummyVerify(password: string, cost: number): Promise<void> {
  try {
    await scryptAsync(password, randomBytes(SALT_LENGTH), cost);
  } catch {
    // A failure here only weakens the decoy; never surface it.
  }
}
