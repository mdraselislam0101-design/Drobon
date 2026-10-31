import { hasAmbiguousDastPath } from '@drobon/shared';

/**
 * Inspect a URL reference before WHATWG URL resolution can erase encoded
 * dot-segments or normalize backslashes. Query/fragment data is not a path.
 * The existing policy intentionally treats %25 as ambiguous, even for benign
 * double-encoded paths; do not relax it without a target-decoding contract.
 */
export function hasAmbiguousDastReference(reference: string): boolean {
  // eslint-disable-next-line no-control-regex -- reject normalization of control characters in untrusted references.
  if (/[\u0000-\u001f\u007f\\]/.test(reference)) return true;
  const beforeQuery = reference.split(/[?#]/, 1)[0] ?? '';
  const path = beforeQuery.replace(/^(?:[a-z][a-z0-9+.-]*:)?\/\/[^/]*/i, '');
  return hasAmbiguousDastPath(path);
}
