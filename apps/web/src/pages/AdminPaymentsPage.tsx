import { useCallback, useEffect, useState } from 'react';
import type { AdminPaymentConfigResponse, AdminPaymentSummary, AdminProGrant, EntitlementAuditEvent, PaymentAuditEvent } from '@drobon/shared';
import { ApiClientError } from '../api/client.js';
import { useApiClient } from '../api/context.js';

export function AdminPaymentsPage(): React.JSX.Element {
  const client = useApiClient();
  const [payments, setPayments] = useState<AdminPaymentSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [reasons, setReasons] = useState<Record<string, string>>({});
  const [audit, setAudit] = useState<Record<string, PaymentAuditEvent[]>>({});

  const reload = useCallback(async (): Promise<void> => {
    setLoading(true);
    setError(null);
    try {
      const result = await client.getAdminPayments(1, 50);
      setPayments(result.payments);
    } catch (cause: unknown) {
      setError(cause instanceof ApiClientError && cause.status === 403
        ? 'This payment review console is restricted to explicitly authorized platform reviewers.'
        : cause instanceof ApiClientError ? cause.message : 'Payment review data is unavailable.');
    } finally {
      setLoading(false);
    }
  }, [client]);

  useEffect(() => { void reload(); }, [reload]);

  const act = async (paymentId: string, action: 'review' | 'approve' | 'reject'): Promise<void> => {
    setBusyId(paymentId);
    setError(null);
    try {
      if (action === 'review') await client.startPaymentReview(paymentId);
      if (action === 'approve') await client.approvePayment(paymentId);
      if (action === 'reject') await client.rejectPayment(paymentId, reasons[paymentId] ?? '');
      await reload();
    } catch (cause: unknown) {
      setError(cause instanceof ApiClientError ? cause.message : 'The review action could not be completed.');
    } finally {
      setBusyId(null);
    }
  };

  const showAudit = async (paymentId: string): Promise<void> => {
    setError(null);
    try {
      const result = await client.getPaymentAudit(paymentId);
      setAudit((current) => ({ ...current, [paymentId]: result.events }));
    } catch (cause: unknown) {
      setError(cause instanceof ApiClientError ? cause.message : 'Audit history is unavailable.');
    }
  };

  return (
    <section className="panel payment-admin" aria-labelledby="payment-admin-title">
      <p className="eyebrow">Platform operations</p>
      <h1 id="payment-admin-title">Payment review</h1>
      <ProGrantsPanel client={client} />
      <PaymentConfigPanel client={client} />
      <p className="muted">Only server-configured platform reviewer accounts can view or mutate payment records. Account roles alone do not grant this access.</p>
      <p className="form-alert" role="note">Manual review only. A submitted reference is evidence supplied by the user, not independent proof of payment. No online gateway or webhook is configured.</p>
      {error !== null && <div className="form-alert" role="alert"><p>{error}</p><button type="button" className="button button-ghost" onClick={() => void reload()}>Refresh</button></div>}
      {loading && <p role="status">Loading payment requests…</p>}
      {!loading && error === null && payments.length === 0 && <p>No payment requests are awaiting display.</p>}
      {!loading && payments.length > 0 && (
        <div className="table-wrap">
          <table className="payment-table">
            <thead><tr><th>Payment / account</th><th>Request</th><th>Reference</th><th>Status &amp; times</th><th>Review</th></tr></thead>
            <tbody>
              {payments.map((payment) => <tr key={payment.paymentId} data-testid={`admin-payment-${payment.paymentId}`}>
                <td><code>{payment.paymentId}</code><br /><span>Account: <code>{payment.accountId}</code></span></td>
                <td>{payment.plan} · BDT {(payment.amountMinorUnits / 100).toFixed(2)}<br />{payment.paymentMethod.replaceAll('_', ' ')}</td>
                <td><code>{payment.reference}</code>{payment.reference === 'REDACTED' && <small>Masked by sensitive-data guard.</small>}</td>
                <td><strong>{payment.status.replaceAll('_', ' ')}</strong><br />Created: {payment.createdAt}<br />Submitted: {payment.submittedAt}{payment.reviewedAt !== null && <><br />Reviewed: {payment.reviewedAt}</>}</td>
                <td className="payment-actions">
                  {payment.status === 'PENDING' && <button className="button button-ghost" type="button" disabled={busyId === payment.paymentId} onClick={() => void act(payment.paymentId, 'review')}>Start review</button>}
                  {(payment.status === 'PENDING' || payment.status === 'UNDER_REVIEW') && <>
                    <button className="button button-primary" type="button" disabled={busyId === payment.paymentId} onClick={() => void act(payment.paymentId, 'approve')}>Approve after verification</button>
                    <label htmlFor={`reason-${payment.paymentId}`}>Reason shown to the requester</label>
                    <textarea id={`reason-${payment.paymentId}`} maxLength={300} rows={2} value={reasons[payment.paymentId] ?? ''} onChange={(event) => setReasons((current) => ({ ...current, [payment.paymentId]: event.target.value }))} />
                    <button className="button button-secondary" type="button" disabled={busyId === payment.paymentId || (reasons[payment.paymentId] ?? '').trim().length < 3} onClick={() => void act(payment.paymentId, 'reject')}>Reject with reason</button>
                  </>}
                  {payment.status === 'APPROVING' && <span role="status">Approval recovery is pending; refresh to check.</span>}
                  {payment.status === 'APPROVED' && <span>Approved {payment.approvedAt ?? '—'}</span>}
                  {payment.status === 'REJECTED' && <span>Rejected {payment.rejectedAt ?? '—'}</span>}
                  <button className="button button-ghost" type="button" onClick={() => void showAudit(payment.paymentId)}>View audit events</button>
                  {audit[payment.paymentId] !== undefined && <ul aria-label={`Audit events for ${payment.paymentId}`}>
                    {audit[payment.paymentId]?.map((event) => <li key={event.eventId}>{event.action} · {event.previousStatus ?? '—'} → {event.newStatus} · {event.timestamp}{event.reason !== null ? ` · ${event.reason}` : ''}</li>)}
                  </ul>}
                </td>
              </tr>)}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

/**
 * Admin Complimentary PRO grants. A grant is an ENTITLEMENT, never a
 * payment: it creates no transaction, touches no balance/revenue and no
 * partner commission. Every mutation is enforced server-side (dual-gated
 * platform admin); the UI only renders the server's verdicts.
 */
function ProGrantsPanel({ client }: { client: ReturnType<typeof useApiClient> }): React.JSX.Element {
  const [grants, setGrants] = useState<AdminProGrant[]>([]);
  const [audit, setAudit] = useState<EntitlementAuditEvent[]>([]);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [form, setForm] = useState({ accountId: '', expiresAt: '', reason: '' });
  const [revokeReasons, setRevokeReasons] = useState<Record<string, string>>({});

  const load = useCallback(async (): Promise<void> => {
    setLoadError(null);
    try {
      const [grantsResult, auditResult] = await Promise.all([
        client.getAdminProGrants({ page: 1, pageSize: 50 }),
        client.getAdminProGrantAudit({ page: 1, pageSize: 8 }),
      ]);
      setGrants(grantsResult.grants);
      setAudit(auditResult.events);
    } catch (cause: unknown) {
      setLoadError(cause instanceof ApiClientError && cause.status === 403
        ? 'Complimentary PRO administration is restricted to platform administrators.'
        : cause instanceof ApiClientError ? cause.message : 'Grant data is unavailable.');
    }
  }, [client]);

  useEffect(() => { void load(); }, [load]);

  const submitGrant = async (): Promise<void> => {
    setBusy(true); setNotice(null); setFormError(null);
    try {
      const result = await client.grantAdminPro({
        accountId: form.accountId.trim(),
        ...(form.expiresAt.trim() === '' ? {} : { expiresAt: new Date(form.expiresAt).toISOString() }),
        ...(form.reason.trim() === '' ? {} : { reason: form.reason.trim() }),
      });
      setForm({ accountId: '', expiresAt: '', reason: '' });
      await load();
      setNotice(result.grant.status === 'ACTIVE'
        ? `Complimentary PRO is active for ${result.grant.accountId}. This is not a payment — no charge, no revenue, no commission.`
        : `Grant loaded for ${result.grant.accountId}.`);
    } catch (cause: unknown) {
      setFormError(cause instanceof ApiClientError ? cause.message : 'The grant could not be completed.');
    } finally { setBusy(false); }
  };

  const revoke = async (grantId: string): Promise<void> => {
    setBusy(true); setNotice(null); setFormError(null);
    try {
      const reason = (revokeReasons[grantId] ?? '').trim();
      await client.revokeAdminProGrant(grantId, reason === '' ? {} : { reason });
      await load();
      setNotice('Grant revoked. The account keeps any PAID PRO it holds underneath; it becomes FREE only if no other PRO entitlement remains.');
    } catch (cause: unknown) {
      setFormError(cause instanceof ApiClientError ? cause.message : 'The revoke could not be completed.');
    } finally { setBusy(false); }
  };

  if (loadError !== null) {
    return (
      <div className="payment-config-panel" data-testid="pro-grants-denied">
        <h2>Complimentary PRO grants</h2>
        <div className="form-alert" role="alert"><p>{loadError}</p></div>
      </div>
    );
  }

  return (
    <div className="payment-config-panel" data-testid="pro-grants-panel">
      <h2>Complimentary PRO grants</h2>
      <p className="muted">
        Grants a persistent PRO entitlement WITHOUT any payment: no transaction, no balance change, no revenue,
        no partner commission, no coupon attribution. The account&apos;s paid subscription is never modified —
        revoke/expiry removes only the granted PRO.
      </p>
      {notice !== null && <p className="notice" role="status" data-testid="pro-grant-notice">{notice}</p>}
      {formError !== null && <div className="form-alert" role="alert" data-testid="pro-grant-error"><p>{formError}</p></div>}

      <div className="payment-config-add">
        <label htmlFor="pro-grant-account">Target account ID</label>
        <input id="pro-grant-account" maxLength={128} value={form.accountId} onChange={(event) => setForm((c) => ({ ...c, accountId: event.target.value }))} placeholder="usr_…" data-testid="pro-grant-account-input" />
        <label htmlFor="pro-grant-expiry">Expiry (optional)</label>
        <input id="pro-grant-expiry" type="datetime-local" value={form.expiresAt} onChange={(event) => setForm((c) => ({ ...c, expiresAt: event.target.value }))} data-testid="pro-grant-expiry-input" />
        <label htmlFor="pro-grant-reason">Reason (optional, audited)</label>
        <input id="pro-grant-reason" maxLength={300} value={form.reason} onChange={(event) => setForm((c) => ({ ...c, reason: event.target.value }))} data-testid="pro-grant-reason-input" />
        <button type="button" className="button button-secondary" onClick={() => void submitGrant()} disabled={busy || form.accountId.trim() === ''} aria-busy={busy} data-testid="pro-grant-submit">
          {busy ? 'Working…' : 'Grant complimentary PRO'}
        </button>
      </div>

      <h3>Grants</h3>
      {grants.length === 0 && <p className="muted" data-testid="pro-grants-empty">No complimentary PRO grants exist.</p>}
      {grants.length > 0 && (
        <div className="table-wrap">
          <table className="payment-table" data-testid="pro-grants-table">
            <thead><tr><th>Grant / account</th><th>State</th><th>Grant window</th><th>Reason</th><th>Revoke</th></tr></thead>
            <tbody>
              {grants.map((grant) => (
                <tr key={grant.grantId} data-testid={`pro-grant-${grant.grantId}`}>
                  <td><code>{grant.grantId}</code><br /><span>Account: <code>{grant.accountId}</code></span><br /><span>By: <code>{grant.grantedBy}</code></span></td>
                  <td><strong>{grant.status}</strong><br /><small>Entitlement only — never a payment.</small></td>
                  <td>Granted: {grant.grantedAt}<br />Expires: {grant.expiresAt ?? '—'}{grant.revokedAt !== null && <><br />Revoked: {grant.revokedAt}</>}</td>
                  <td>{grant.reason ?? '—'}</td>
                  <td>
                    {grant.status === 'ACTIVE' && <>
                      <label htmlFor={`revoke-${grant.grantId}`}>Reason (optional)</label>
                      <input id={`revoke-${grant.grantId}`} maxLength={300} value={revokeReasons[grant.grantId] ?? ''} onChange={(event) => setRevokeReasons((c) => ({ ...c, [grant.grantId]: event.target.value }))} data-testid={`pro-grant-revoke-reason-${grant.grantId}`} />
                      <button type="button" className="button button-secondary" onClick={() => void revoke(grant.grantId)} disabled={busy} data-testid={`pro-grant-revoke-${grant.grantId}`}>Revoke grant</button>
                    </>}
                    {grant.status === 'REVOKED' && <span>Revoked by {grant.revokedBy ?? '—'}</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {audit.length > 0 && (
        <>
          <h3>Grant audit (append-only)</h3>
          <ul aria-label="Complimentary PRO grant audit trail" data-testid="pro-grant-audit">
            {audit.map((event) => (
              <li key={event.eventId}>{event.action} · {event.accountId} · {event.timestamp}{event.reason !== null ? ` · ${event.reason}` : ''}</li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}

/**
 * Phase 20 — platform-admin payment configuration. This is a privileged Admin
 * control (NOT a UserType capability): the surface is visible here, but every
 * read and mutation is independently enforced server-side by the dual-gated
 * platform-admin check. A reviewer or ordinary account that somehow renders
 * this panel gets 403 from the API on every call — the UI never decides.
 */
function PaymentConfigPanel({ client }: { client: ReturnType<typeof useApiClient> }): React.JSX.Element {
  const [config, setConfig] = useState<AdminPaymentConfigResponse | null>(null);
  const [denied, setDenied] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [priceInput, setPriceInput] = useState('');
  const [notice, setNotice] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [newMethod, setNewMethod] = useState({ displayName: '', accountNumber: '', instructions: '' });

  const messageFor = (cause: unknown, fallback: string): string =>
    cause instanceof ApiClientError ? cause.message : fallback;

  const load = useCallback(async (): Promise<void> => {
    setLoadError(null);
    setDenied(false);
    try {
      const result = await client.getAdminPaymentConfig();
      setConfig(result);
      setPriceInput((result.proPriceMinorUnits / 100).toFixed(2));
    } catch (cause: unknown) {
      if (cause instanceof ApiClientError && cause.status === 403) setDenied(true);
      else setLoadError(messageFor(cause, 'Payment configuration is unavailable.'));
    }
  }, [client]);

  useEffect(() => { void load(); }, [load]);

  const savePrice = async (): Promise<void> => {
    setBusy(true); setNotice(null); setFormError(null);
    try {
      const minor = Math.round(Number.parseFloat(priceInput) * 100);
      if (!Number.isFinite(minor) || minor < 1) throw new Error('Enter a positive price.');
      const result = await client.updateAdminPaymentPrice(minor);
      setConfig(result);
      setNotice('PRO price updated. New payments use the new price immediately; existing payment records are unchanged.');
    } catch (cause: unknown) {
      setFormError(messageFor(cause, 'The price could not be updated.'));
    } finally { setBusy(false); }
  };

  const toggleMethod = async (methodId: string, enabled: boolean): Promise<void> => {
    setBusy(true); setNotice(null); setFormError(null);
    try {
      const result = await client.updateAdminPaymentMethod(methodId, { enabled });
      setConfig(result);
      setNotice(enabled ? 'Payment destination enabled.' : 'Payment destination disabled — it is no longer offered for new payments.');
    } catch (cause: unknown) {
      setFormError(messageFor(cause, 'The destination could not be updated.'));
    } finally { setBusy(false); }
  };

  const addMethod = async (): Promise<void> => {
    setBusy(true); setNotice(null); setFormError(null);
    try {
      const key = `paycfg-${crypto.randomUUID()}`;
      await client.addAdminPaymentMethod(
        { displayName: newMethod.displayName, accountNumber: newMethod.accountNumber, ...(newMethod.instructions.trim() === '' ? {} : { instructions: newMethod.instructions }) },
        key,
      );
      setNewMethod({ displayName: '', accountNumber: '', instructions: '' });
      await load();
      setNotice('Payment destination added.');
    } catch (cause: unknown) {
      setFormError(messageFor(cause, 'The destination could not be added.'));
    } finally { setBusy(false); }
  };

  if (denied) {
    return (
      <div className="form-alert" role="note" data-testid="payment-config-denied">
        <p>Payment configuration is restricted to explicitly authorized platform administrators. Your account can review payments but cannot change pricing or destinations.</p>
      </div>
    );
  }
  if (loadError !== null) {
    return <div className="form-alert" role="alert"><p>{loadError}</p><button type="button" className="button button-ghost" onClick={() => void load()}>Retry</button></div>;
  }
  if (config === null) {
    return <p role="status">Loading payment configuration…</p>;
  }

  return (
    <div className="payment-config-panel" data-testid="payment-config-panel">
      <h2>Payment configuration (platform admin)</h2>
      <p className="muted">
        Server-authoritative. Changes apply to new quotes and payments immediately; historical payment records keep their own snapshot and are never rewritten. Account numbers are masked in the audit trail.
      </p>
      {notice !== null && <p className="notice" role="status" data-testid="payment-config-notice">{notice}</p>}
      {formError !== null && <div className="form-alert" role="alert" data-testid="payment-config-error"><p>{formError}</p></div>}

      <div className="payment-config-price">
        <label htmlFor="pro-price">PRO price (BDT)</label>
        <input
          id="pro-price"
          type="number"
          min="0.01"
          step="0.01"
          value={priceInput}
          onChange={(event) => setPriceInput(event.target.value)}
          data-testid="payment-config-price-input"
        />
        <button type="button" className="button button-secondary" onClick={() => void savePrice()} disabled={busy} aria-busy={busy} data-testid="payment-config-save-price">
          {busy ? 'Saving…' : 'Save price'}
        </button>
        <p className="muted">Current server price: BDT {(config.proPriceMinorUnits / 100).toFixed(2)}. Last updated {config.updatedAt}.</p>
      </div>

      <h3>Manual-transfer destinations</h3>
      {config.destinations.length === 0 && (
        <p className="muted" data-testid="payment-config-no-methods">No destinations configured. Until one is added, the legacy boot-time manual-transfer behavior remains active.</p>
      )}
      {config.destinations.length > 0 && (
        <div className="table-wrap">
          <table className="payment-table" data-testid="payment-config-methods">
            <thead><tr><th>Display name</th><th>Account number</th><th>Instructions</th><th>Enabled</th><th>Toggle</th></tr></thead>
            <tbody>
              {config.destinations.map((method) => (
                <tr key={method.methodId} data-testid={`payment-config-method-${method.methodId}`}>
                  <td>{method.displayName}</td>
                  <td><code>{method.accountNumber}</code></td>
                  <td>{method.instructions === '' ? '—' : method.instructions}</td>
                  <td>{method.enabled ? 'Yes' : 'No'}</td>
                  <td>
                    <button type="button" className="button button-ghost" onClick={() => void toggleMethod(method.methodId, !method.enabled)} disabled={busy} data-testid={`payment-config-toggle-${method.methodId}`}>
                      {method.enabled ? 'Disable' : 'Enable'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <h3>Add a destination</h3>
      <div className="payment-config-add">
        <label htmlFor="method-name">Display name</label>
        <input id="method-name" maxLength={80} value={newMethod.displayName} onChange={(event) => setNewMethod((c) => ({ ...c, displayName: event.target.value }))} placeholder="e.g. bKash" data-testid="payment-config-new-name" />
        <label htmlFor="method-account">Account number</label>
        <input id="method-account" maxLength={40} value={newMethod.accountNumber} onChange={(event) => setNewMethod((c) => ({ ...c, accountNumber: event.target.value }))} placeholder="01XXXXXXXXX" data-testid="payment-config-new-account" />
        <label htmlFor="method-instructions">Instructions (optional)</label>
        <input id="method-instructions" maxLength={300} value={newMethod.instructions} onChange={(event) => setNewMethod((c) => ({ ...c, instructions: event.target.value }))} data-testid="payment-config-new-instructions" />
        <button type="button" className="button button-secondary" onClick={() => void addMethod()} disabled={busy || newMethod.displayName.trim() === '' || newMethod.accountNumber.trim().length < 4} aria-busy={busy} data-testid="payment-config-add-method">
          {busy ? 'Adding…' : 'Add destination'}
        </button>
      </div>

      {config.audit.length > 0 && (
        <>
          <h3>Configuration audit (masked)</h3>
          <ul aria-label="Payment configuration audit trail" data-testid="payment-config-audit">
            {config.audit.slice(-8).reverse().map((entry) => (
              <li key={entry.entryId}>{entry.action} · {entry.detail} · {entry.at}</li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}
