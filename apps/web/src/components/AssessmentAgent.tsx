import { useCallback, useEffect, useState } from 'react';
import type { AgentAssessment, AgentExecutionResponse } from '@drobon/shared';
import { ApiClientError } from '../api/client.js';
import { useApiClient } from '../api/context.js';

/**
 * Assessment-scoped coordinator over the existing scanners. Nothing is queued
 * until the operator explicitly confirms; server-side policy is authoritative.
 */
export function AssessmentAgent({ projectId, assessmentId, onQueued }: { projectId: string; assessmentId: string; onQueued: () => void }): React.JSX.Element {
  const client = useApiClient();
  const [agent, setAgent] = useState<AgentAssessment | null>(null);
  const [actions, setActions] = useState<AgentExecutionResponse['actions']>([]);
  const [confirmed, setConfirmed] = useState(false);
  const [cancelTarget, setCancelTarget] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async (signal?: AbortSignal): Promise<void> => {
    try {
      const result = await client.getAgentAssessment(projectId, assessmentId, signal);
      if (!signal?.aborted) { setAgent(result.agent); setError(null); }
    } catch (caught: unknown) {
      if (!signal?.aborted) setError(caught instanceof ApiClientError ? caught.message : 'Could not load the agent assessment.');
    }
  }, [assessmentId, client, projectId]);

  // Poll only while the loaded plan contains active agent scans. An aborted
  // request cannot update an unmounted or newly-selected assessment.
  useEffect(() => {
    if (agent?.state !== 'ACTIVE') return undefined;
    const controller = new AbortController();
    const timer = window.setInterval(() => void refresh(controller.signal), 3000);
    return () => { window.clearInterval(timer); controller.abort(); };
  }, [agent?.state, refresh]);

  const execute = async (): Promise<void> => {
    if (!confirmed || busy) return;
    setBusy(true);
    setError(null);
    try {
      const result = await client.executeAgent(projectId, assessmentId);
      setAgent(result.agent);
      setActions(result.actions);
      setConfirmed(false);
      onQueued();
    } catch (caught: unknown) {
      setError(caught instanceof ApiClientError ? caught.message : 'Could not start the agent plan.');
    } finally { setBusy(false); }
  };

  const cancel = async (scanId: string): Promise<void> => {
    if (busy || cancelTarget !== scanId) return;
    setBusy(true);
    setError(null);
    try {
      const result = await client.cancelAgentScan(projectId, assessmentId, scanId);
      setAgent((current) => current === null ? null : { ...current,
        tasks: current.tasks.map((task) => task.scanId === scanId ? { ...task, state: result.state,
          reason: result.state === 'CANCELLING' ? 'Cancellation recorded; the worker still needs to settle the job.'
            : 'The job is terminal; sent requests cannot be recalled.' } : task),
      });
      setCancelTarget(null);
      await refresh();
      onQueued();
    } catch (caught: unknown) {
      setError(caught instanceof ApiClientError ? caught.message : 'Could not request cancellation. Refresh the job before retrying.');
    } finally { setBusy(false); }
  };

  const exportSummary = (): void => {
    if (agent === null) return;
    // Export only the bounded public projection already delivered to this user.
    // Full evidence/remediation lives in the existing per-scan reports.
    const blob = new Blob([JSON.stringify({ reportType: 'drobon-agent-assessment-summary', agent }, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `drobon-agent-${assessmentId}.json`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  };

  return <section className="assessment-agent" aria-labelledby="agent-title" data-testid="assessment-agent">
    <h4 id="agent-title">Security agent assessment</h4>
    <p>Deterministic coordinator over existing scanners; no AI model or independent exploit validation. An active, scoped engagement is mandatory. Drobon cannot verify the operator's third-party permission.</p>
    <p className="muted">Experimental execution is disabled by default and blocked in production. Local opt-in is for isolated disposable stores only; a running older writer can still overwrite agent metadata. Existing version-1 stores require reviewed offline migration.</p>
    <p className="muted">Static route counts are not live discovery. DAST uses the existing passive, scoped target only. Jobs consume the existing scan quota. Review and apply fixes yourself.</p>
    <button type="button" className="button button-secondary" onClick={() => void refresh()} disabled={busy} data-testid="agent-load">
      {agent === null ? 'Load agent plan' : 'Refresh agent plan'}
    </button>
    {error !== null && <div className="form-alert" role="alert"><p>{error}</p></div>}
    {agent !== null && <div data-testid="agent-content">
      <p>Overall: <strong>{agent.state}</strong> · Mode: {agent.mode} · Model: {agent.model} · Updated: {agent.generatedAt}</p>
      <p>Inventory: {agent.inventory.sourceFiles} uploaded source file(s), {agent.inventory.manifestFiles} supported manifest(s), {agent.inventory.routeCandidates} static JS/TS route candidate(s) · bounded JS/TS syntax pass {agent.inventory.routeAnalysis}; DAST target {agent.inventory.targetConfigured ? 'configured' : 'not configured'}.</p>
      <h5>Plan and execution</h5>
      <ol data-testid="agent-tasks">{agent.tasks.map((task) => <li key={task.scanner}>
        <strong>{task.scanner}: {task.state}</strong> — {task.reason}
        {task.scanId !== undefined && <> · <a href={`#scan-${task.scanId}`}>View saved scan</a></>}
        {task.scanId !== undefined && (task.state === 'QUEUED' || task.state === 'RUNNING') && <div>
          {cancelTarget === task.scanId ? <>
            <p>Cancel this job? An in-flight request cannot be recalled and an uncooperative transport may continue.</p>
            <button type="button" disabled={busy} onClick={() => void cancel(task.scanId!)} data-testid={`agent-cancel-confirm-${task.scanner}`}>Confirm cancellation</button>{' '}
            <button type="button" disabled={busy} onClick={() => setCancelTarget(null)}>Keep job</button>
          </> : <button type="button" disabled={busy} onClick={() => setCancelTarget(task.scanId!)} data-testid={`agent-cancel-${task.scanner}`}>Cancel {task.scanner} job</button>}
        </div>}
      </li>)}</ol>
      {agent.tasks.some((task) => task.state === 'READY') && <div>
        <label><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} data-testid="agent-confirm" /> I confirm the engagement and scope are valid and authorize these eligible scans.</label>{' '}
        <button type="button" className="button button-primary" onClick={() => void execute()} disabled={!confirmed || busy} data-testid="agent-execute">{busy ? 'Queueing…' : 'Queue eligible scans'}</button>
      </div>}
      {actions.length > 0 && <ul data-testid="agent-actions">{actions.map((action) => <li key={action.scanner}>{action.scanner}: {action.result} — {action.reason}</li>)}</ul>}
      <h5>Evidence triage and priority</h5>
      <p className="muted">These are scanner alerts with structural checks, not AI hypotheses or independently validated vulnerabilities. A matching location or response does not by itself prove a vulnerability. INCONCLUSIVE and NOT_VERIFIED are not negative results. Priority uses recorded severity only, not exploitability or business impact.</p>
      {agent.reviews.length === 0 ? <p>No findings are available for triage. This does not establish that the target is safe.</p> : <ul data-testid="agent-reviews">{agent.reviews.map((review) => <li key={`${review.scanId}-${review.findingId}`}>
        <strong>{review.priority} · {review.severity} · {review.verdict}</strong> — {review.scanner} / {review.ruleId}: {review.basis} <a href={`#scan-${review.scanId}`}>Open scan evidence and remediation</a>
      </li>)}</ul>}
      <h5>Potential correlations</h5>
      {agent.paths.length === 0 ? <p>No bounded same-file correlations were identified. Attack paths have not been validated.</p> : <ul data-testid="agent-paths">{agent.paths.map((path) => <li key={path.findingIds.join('-')}>
        <strong>{path.status} · {path.confidence} confidence</strong> — {path.explanation} {path.prerequisites} {path.impact} {path.remediation}
        <ul>{path.findingIds.map((id) => <li key={id}><code>{id}</code></li>)}</ul>
      </li>)}</ul>}
      <button type="button" className="button button-secondary" onClick={exportSummary} data-testid="agent-export">Download agent summary (JSON)</button>
      <p className="muted">This bounded summary omits raw source and evidence. Use the existing scan reports for evidence, remediation and export formats.</p>
      <details><summary>Limits and provenance</summary>
        <ul>{agent.limitations.map((item) => <li key={item}>{item}</li>)}</ul>
        {agent.tasks.some((task) => task.datasetDigest !== undefined) && <ul>{agent.tasks.filter((task) => task.datasetDigest !== undefined).map((task) => <li key={task.scanner}>{task.scanner} · Dataset SHA-256 <code>{task.datasetDigest}</code>. A digest is not a signature.</li>)}</ul>}
      </details>
    </div>}
  </section>;
}
