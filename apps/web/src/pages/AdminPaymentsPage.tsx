import { useCallback, useEffect, useState } from 'react';
import type { AdminPaymentSummary, PaymentAuditEvent } from '@drobon/shared';
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
