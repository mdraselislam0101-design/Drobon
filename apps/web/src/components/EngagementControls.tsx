import { useState, type FormEvent } from 'react';
import { SCAN_TYPES, type Assessment, type ScanType } from '@drobon/shared';
import { ApiClientError } from '../api/client.js';
import { useApiClient } from '../api/context.js';

/** UI for the existing owner-attested engagement endpoints, not legal verification. */
export function EngagementControls({ projectId, projectStatus, assessment, targetUrl, onChanged }: {
  projectId: string; projectStatus: string; assessment: Assessment; targetUrl: string | undefined; onChanged: () => void;
}): React.JSX.Element {
  const client = useApiClient();
  const [open, setOpen] = useState(false);
  const [clientName, setClientName] = useState('');
  const [paths, setPaths] = useState('');
  const [scanTypes, setScanTypes] = useState<ScanType[]>([]);
  const [validFrom, setValidFrom] = useState('');
  const [validUntil, setValidUntil] = useState('');
  const [statement, setStatement] = useState('');
  const [confirmed, setConfirmed] = useState(false);
  const [withdrawId, setWithdrawId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const hostname = targetUrl === undefined ? '' : (() => { try { return new URL(targetUrl).hostname.toLowerCase(); } catch { return ''; } })();
  const targetInScope = hostname.length > 0 && assessment.scope.inScopeHosts.includes(hostname) && !assessment.scope.outOfScopeHosts.includes(hostname);
  const canDeclare = projectStatus === 'ACTIVE' && assessment.status === 'ACTIVE' && targetUrl !== undefined && targetInScope;
  const canWithdraw = projectStatus === 'ACTIVE' && (assessment.status === 'ACTIVE' || assessment.status === 'PLANNED');

  const create = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault();
    if (!canDeclare || targetUrl === undefined || !confirmed || scanTypes.length === 0 || busy) return;
    const from = new Date(validFrom);
    const until = new Date(validUntil);
    const scopePaths = paths.split('\n').map((item) => item.trim()).filter(Boolean);
    if (!Number.isFinite(from.getTime()) || !Number.isFinite(until.getTime()) || scopePaths.length === 0) {
      setError('Provide valid start and end times and at least one explicit path prefix.');
      return;
    }
    setBusy(true); setError(null);
    try {
      await client.createEngagement(projectId, assessment.id, { clientName: clientName.trim(), targetUrl,
        inScopeHosts: [hostname], scopePaths, allowedScanTypes: scanTypes, validFrom: from.toISOString(), validUntil: until.toISOString(), statement: statement.trim(), confirm: true });
      setOpen(false); setConfirmed(false); onChanged();
    } catch (caught: unknown) { setError(caught instanceof ApiClientError ? caught.message : 'Could not record this engagement.'); }
    finally { setBusy(false); }
  };
  const withdraw = async (id: string): Promise<void> => {
    if (busy) return;
    setBusy(true); setError(null);
    try { await client.withdrawEngagement(projectId, assessment.id, id); setWithdrawId(null); onChanged(); }
    catch (caught: unknown) { setError(caught instanceof ApiClientError ? caught.message : 'Could not withdraw this engagement.'); }
    finally { setBusy(false); }
  };

  return <div className="engagement-controls" data-testid="engagement-controls">
    {canDeclare ? <button type="button" className="button button-secondary" onClick={() => setOpen((value) => !value)} data-testid="engagement-open">{open ? 'Close engagement form' : 'Record scoped engagement'}</button>
      : <p className="muted">To record an engagement, activate the assessment and configure a target whose exact host is in its scope.</p>}
    {open && canDeclare && <form onSubmit={(event) => void create(event)} data-testid="engagement-form">
      <p>Target: <code>{targetUrl}</code> · exact host: <code>{hostname}</code>. No additional hosts or subdomains are included.</p>
      <div className="field"><label htmlFor="engagement-client">Client or owner name</label><input id="engagement-client" value={clientName} onChange={(event) => setClientName(event.target.value)} minLength={3} maxLength={120} required /></div>
      <div className="field"><label htmlFor="engagement-paths">Authorized path prefixes (one per line)</label><textarea id="engagement-paths" value={paths} onChange={(event) => setPaths(event.target.value)} rows={2} maxLength={4000} required /><p className="field-hint">Use <code>/</code> only if all paths on this host are authorized. The configured target path must be included.</p></div>
      <fieldset><legend>Explicitly allowed scanner types</legend>{SCAN_TYPES.map((scanner) => <label key={scanner}><input type="checkbox" checked={scanTypes.includes(scanner)} onChange={(event) => setScanTypes((current) => event.target.checked ? [...current, scanner] : current.filter((item) => item !== scanner))} /> {scanner} </label>)}</fieldset>
      <div className="assistant-selectors">
        <div className="field"><label htmlFor="engagement-from">Valid from (local time)</label><input id="engagement-from" type="datetime-local" value={validFrom} onChange={(event) => setValidFrom(event.target.value)} required /></div>
        <div className="field"><label htmlFor="engagement-until">Valid until (local time)</label><input id="engagement-until" type="datetime-local" value={validUntil} onChange={(event) => setValidUntil(event.target.value)} required /></div>
      </div>
      <div className="field"><label htmlFor="engagement-statement">Authorization statement</label><textarea id="engagement-statement" value={statement} onChange={(event) => setStatement(event.target.value)} minLength={10} maxLength={2000} required /></div>
      <label><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} /> I attest that I have permission for the exact target, paths, scanner types and time window above.</label>{' '}
      <button type="submit" className="button button-primary" disabled={!confirmed || scanTypes.length === 0 || busy} data-testid="engagement-submit">{busy ? 'Saving…' : 'Save engagement'}</button>
    </form>}
    {canWithdraw && (assessment.engagements ?? []).filter((item) => item.state === 'DECLARED').map((item) => <div key={item.id}>
      {withdrawId === item.id ? <div><p>Withdraw {item.clientName}'s engagement for <code>{item.targetUrl}</code>? New actions will be blocked; an in-flight request cannot be recalled.</p>
        <button type="button" className="button button-secondary" disabled={busy} onClick={() => void withdraw(item.id)} data-testid="engagement-withdraw-confirm">Confirm withdrawal</button>{' '}
        <button type="button" className="button button-ghost" onClick={() => setWithdrawId(null)}>Keep engagement</button></div>
        : <button type="button" className="button button-ghost" onClick={() => setWithdrawId(item.id)} data-testid="engagement-withdraw">Withdraw engagement for {item.clientName}</button>}
    </div>)}
    {error !== null && <div className="form-alert" role="alert"><p>{error}</p></div>}
  </div>;
}
