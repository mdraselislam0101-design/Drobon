import type { ScaEcosystem } from '@drobon/shared';
import { satisfiesRange } from './range.js';

/**
 * Extract only a single evaluable declared pin, not a range or a resolved
 * installation. Python requirements normally spell a pin as `==1.2.3`;
 * wildcards, arbitrary equality, combined constraints and unsupported PEP 440
 * versions remain unknown. The returned candidate is still declaration
 * evidence, not proof of what was installed or deployed.
 */
export function exactDeclaredVersion(ecosystem: ScaEcosystem, declaration: string | undefined): string | undefined {
  if (declaration === undefined) return undefined;
  const value = declaration.trim();
  let candidate: string;
  if (ecosystem === 'pypi' && value.startsWith('==')) {
    const match = value.match(/^==\s*([^\s,]+)$/);
    if (match === null || match[1] === undefined) return undefined;
    candidate = match[1];
  } else {
    candidate = value;
  }
  if (candidate.includes('*')) return undefined;
  try {
    return satisfiesRange(ecosystem, candidate, `${ecosystem === 'pypi' ? '==' : '='}${candidate}`)
      ? candidate
      : undefined;
  } catch {
    return undefined;
  }
}
