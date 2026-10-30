import type { ScanType } from '@drobon/shared';
import type { ScanRecord } from '../scans/store.js';

/** Timestamps have millisecond precision; UUID ordering is not request order.
 * Never choose an older successful result when two latest requests tie. */
export function selectLatestAttempt(scans: readonly ScanRecord[], scanner: ScanType):
  | { kind: 'NONE' }
  | { kind: 'ORDER_UNCERTAIN'; requestedAt: string }
  | { kind: 'SELECTED'; scan: ScanRecord } {
  const matching = scans.filter((scan) => scan.scanType === scanner);
  if (matching.length === 0) return { kind: 'NONE' };
  let latest = matching[0];
  if (latest === undefined) return { kind: 'NONE' };
  let ties = 1;
  for (const scan of matching.slice(1)) {
    if (scan.createdAt > latest.createdAt) { latest = scan; ties = 1; }
    else if (scan.createdAt === latest.createdAt) ties += 1;
  }
  return ties > 1 ? { kind: 'ORDER_UNCERTAIN', requestedAt: latest.createdAt } : { kind: 'SELECTED', scan: latest };
}
