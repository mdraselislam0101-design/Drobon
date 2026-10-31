/** Case-level binary scores. This does not compute alert-level precision. */
const STATUSES = new Set(['DETECTED', 'NOT_DETECTED', 'UNASSESSED']);
const ratio = (numerator, denominator) => denominator === 0 ? null : numerator / denominator;

export function scoreCases(cases, observations) {
  const byId = new Map();
  for (const item of cases) {
    if (typeof item.id !== 'string' || typeof item.family !== 'string' ||
        (item.expected !== true && item.expected !== false && item.expected !== null) || byId.has(item.id)) {
      throw new Error('Invalid or duplicate case');
    }
    byId.set(item.id, item);
  }
  const results = new Map();
  for (const observation of observations) {
    if (!byId.has(observation.id) || results.has(observation.id) || !STATUSES.has(observation.status)) {
      throw new Error('Unknown case, duplicate observation or invalid status');
    }
    results.set(observation.id, observation);
  }
  const families = Object.create(null);
  const rows = cases.map((item) => {
    const obs = results.get(item.id) ?? { id: item.id, status: 'UNASSESSED', reason: 'No observation supplied' };
    const counts = families[item.family] ??= { cases: 0, truePositive: 0, falsePositive: 0, trueNegative: 0,
      falseNegative: 0, unassessed: 0, unknownTruth: 0 };
    counts.cases += 1;
    let verdict;
    if (item.expected === null) { counts.unknownTruth += 1; verdict = 'UNKNOWN_TRUTH'; }
    else if (obs.status === 'UNASSESSED') { counts.unassessed += 1; verdict = 'UNASSESSED'; }
    else if (item.expected && obs.status === 'DETECTED') { counts.truePositive += 1; verdict = 'TP'; }
    else if (item.expected) { counts.falseNegative += 1; verdict = 'FN'; }
    else if (obs.status === 'DETECTED') { counts.falsePositive += 1; verdict = 'FP'; }
    else { counts.trueNegative += 1; verdict = 'TN'; }
    return { id: item.id, family: item.family, expected: item.expected, status: obs.status, verdict,
      reason: obs.reason ?? null, matchingFindings: obs.matchingFindings ?? 0,
      otherFindingsUnjudged: obs.otherFindingsUnjudged ?? 0 };
  });
  for (const counts of Object.values(families)) {
    counts.assessed = counts.truePositive + counts.falsePositive + counts.trueNegative + counts.falseNegative;
    counts.precision = ratio(counts.truePositive, counts.truePositive + counts.falsePositive);
    counts.recall = ratio(counts.truePositive, counts.truePositive + counts.falseNegative);
  }
  return { families, rows };
}
