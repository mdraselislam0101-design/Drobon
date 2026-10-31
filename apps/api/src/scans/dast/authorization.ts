/**
 * Recheck an assessment-linked DAST request against the current owner scope.
 * This is an operator declaration, NOT independent proof of authorization.
 */
import { engagementAllowsScan } from '@drobon/shared';
import type { AssessmentStore } from '../../assessments/store.js';
import type { ScanRecord } from '../store.js';
import { hasAmbiguousDastReference } from './reference.js';

export type DastRequestAuthorizer = (record: ScanRecord, url: string) => Promise<boolean>;

/** The app-owned callback; network destination safety remains a separate policy. */
export function createAssessmentDastAuthorizer(
  assessments: AssessmentStore,
  now: () => number = Date.now,
  options: { requireEngagement?: boolean } = {},
): DastRequestAuthorizer {
  return async (record, url) => {
    // Check the original reference before URL parsing can normalize away
    // information needed for an authorization decision.
    if (hasAmbiguousDastReference(url)) return false;
    if (record.assessmentId === undefined) return options.requireEngagement !== true; // Legacy unlinked scans remain unverified.
    const assessment = await assessments.findByProjectAndId(record.ownerId, record.projectId, record.assessmentId);
    if (assessment === undefined || assessment.status !== 'ACTIVE') return false;
    if (options.requireEngagement === true && (assessment.engagements?.length ?? 0) === 0) return false;
    let target: URL;
    try { target = new URL(url); } catch { return false; }
    const hostname = target.hostname.toLowerCase();
    if (!assessment.scope.inScopeHosts.includes(hostname) || assessment.scope.outOfScopeHosts.includes(hostname)) return false;
    const gate = engagementAllowsScan(assessment.engagements, {
      scanType: 'DAST', hostname, path: target.pathname || '/', nowIso: new Date(now()).toISOString(),
    });
    return gate.allowed;
  };
}

/** A missing/failed authorizer fails closed for an assessment-linked scan. */
export async function isDastRequestAuthorized(record: ScanRecord, url: string, authorizer?: DastRequestAuthorizer): Promise<boolean> {
  if (record.assessmentId === undefined && authorizer === undefined) return true;
  if (authorizer === undefined) return false;
  try { return await authorizer(record, url); } catch { return false; }
}
