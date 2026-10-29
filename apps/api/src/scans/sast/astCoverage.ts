import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import type { AstAnalysisCoverage } from '@drobon/shared';
import type { SastRule } from './rules.js';

/** Digest the effective, converted rule set as actually passed to this scan.
 * This is an integrity/comparison aid, not a dataset signature or safety proof. */
export function effectiveSastRuleDigest(rules: readonly SastRule[]): string {
  const material = [...rules].sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0).map((rule) => ({
    id: rule.id, title: rule.title, description: rule.description, severity: rule.severity,
    cwe: rule.cwe ?? null, category: rule.category, remediation: rule.remediation,
    limitation: rule.limitation, languages: rule.languages === undefined ? null : [...rule.languages].sort(),
    patterns: rule.patterns.map((pattern) => ({ source: pattern.source, flags: pattern.flags })),
    flow: rule.flow ?? null, hasEvidenceRedactor: rule.redactEvidence !== undefined,
  }));
  return createHash('sha256').update(JSON.stringify(material), 'utf8').digest('hex');
}

const require = createRequire(import.meta.url);
function packageVersion(name: string): string {
  try {
    // Only fixed application-owned package names are accepted; this never
    // resolves an uploaded module specifier or target path.
    const packageFile = join(dirname(require.resolve(name)), '..', 'package.json');
    const metadata: unknown = JSON.parse(readFileSync(packageFile, 'utf8'));
    if (typeof metadata === 'object' && metadata !== null) {
      const version = (metadata as { version?: unknown }).version;
      if (typeof version === 'string' && /^[A-Za-z0-9.+-]{1,64}$/.test(version)) return version;
    }
  } catch { /* unsupported packaging: provenance remains explicitly unknown */ }
  return 'unknown';
}

export function parserVersions(): AstAnalysisCoverage['parsers'] {
  return {
    typescript: packageVersion('typescript'),
    python: packageVersion('@lezer/python'),
    php: packageVersion('php-parser'),
    java: packageVersion('@lezer/java'),
  };
}
