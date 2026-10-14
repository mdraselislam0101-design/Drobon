import { useCallback, useEffect, useState } from 'react';
import type { AdminPartnerSummary, CommissionSummary, PartnerAuditEvent, PaymentStatus } from '@drobon/shared';
import { ApiClientError } from '../api/client.js';
import { useApiClient } from '../api/context.js';

/**
 * Platform partner & commission operations console (Pump 7). Restricted
 * server-side to platform admins (role + allowlist); this page only renders
 * what the API returns. Attribution inspection intentionally shows payment
 * identifiers, statuses and amounts — never references or proof material.
 */
export function AdminPartnersPage(): React.JSX.Element {
  const client = useApiClient();
  const [partners, setPartners] = useState<AdminPartnerSummary[]>([]);
  const [commissions, setCommissions] = useState<CommissionSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [audit, setAudit] = useState<Record<string, PartnerAuditEvent[]>>({});
  const [attribution, setAttribution] = useState<Record<string, Array<{ paymentId: string; status: PaymentStatus; amountMinorUnits: number; createdAt: string }>>>({});
  const [form, setForm] = useState({ userId: '', couponCode: '', discountPercent: '10', commissionPercent: '5' });
  const [couponEdit, setCouponEdit] = useState<Record<string, { discountPercent: string; commissionPercent: string }>>({});

  const reload = useCallback(async (): Promise<void> => {
    setLoading(true);
    setError(null);
    try {
      const [partnerPage, commissionPage] = await Promise.all([
        client.getAdminPartners(1, 50),
        client.getAdminCommissions({ page: 1, pageSize: 50 }),
      ]);
      setPartners(partnerPage.partners);
      setCommissions(commissionPage.commissions);
    } catch (cause: unknown) {
      setError(cause instanceof ApiClientError && cause.status === 403
        ? 'Partner operations require an explicitly authorized platform administrator.'
        : cause instanceof ApiClientError ? cause.message : 'Partner data is unavailable.');
    } finally {
      setLoading(false);
    }
  }, [client]);

  useEffect(() => { void reload(); }, [reload]);

  const activate = async (): Promise<void> => {
    setBusyId('activate');
    setError(null);
    setNotice(null);
    try {
      await client.activatePartner({
        userId: form.userId.trim(),
        couponCode: form.couponCode.trim(),
        discountPercent: Number(form.discountPercent),
        commissionPercent: Number(form.commissionPercent),
      });
      setForm({ userId: '', couponCode: '', discountPercent: '10', commissionPercent: '5' });
      setNotice('Partner activated. Complimentary PRO was granted as entitlement only — no payment or revenue record was created.');
      await reload();
    } catch (cause: unknown) {
      setError(cause instanceof ApiClientError ? cause.message : 'Partner activation failed.');
    } finally {
      setBusyId(null);
    }
  };

  const partnerAction = async (partnerId: string, action: 'deactivate' | 'reactivate' | 'audit' | 'attribution'): Promise<void> => {
    setBusyId(partnerId);
    setError(null);
    try {
      if (action === 'deactivate' || action === 'reactivate') {
        await client.setPartnerStatus(partnerId, action === 'deactivate' ? 'DEACTIVATED' : 'ACTIVE');
        await reload();
      } else if (action === 'audit') {
        const detail = await client.getAdminPartner(partnerId);
        setAudit((current) => ({ ...current, [partnerId]: detail.audit }));
      } else {
        const page = await client.getAdminPartnerPayments(partnerId, 1, 50);
        setAttribution((current) => ({ ...current, [partnerId]: page.payments }));
      }
    } catch (cause: unknown) {
      setError(cause instanceof ApiClientError ? cause.message : 'The action could not be completed.');
    } finally {
      setBusyId(null);
    }
  };

  const saveCoupon = async (partner: AdminPartnerSummary): Promise<void> => {
    setBusyId(partner.partnerId);
    setError(null);
    try {
      const edit = couponEdit[partner.partnerId] ?? { discountPercent: String(partner.coupon.discountPercent), commissionPercent: String(partner.coupon.commissionPercent) };
      const patch: { discountPercent?: number; commissionPercent?: number } = {};
      if (Number(edit.discountPercent) !== partner.coupon.discountPercent) patch.discountPercent = Number(edit.discountPercent);
      if (Number(edit.commissionPercent) !== partner.coupon.commissionPercent) patch.commissionPercent = Number(edit.commissionPercent);
      await client.updatePartnerCoupon(partner.partnerId, patch);
      setNotice('Coupon configuration updated. Existing approved payments keep their snapshot rates.');
      await reload();
    } catch (cause: unknown) {
      setError(cause instanceof ApiClientError ? cause.message : 'Coupon update failed.');
    } finally {
      setBusyId(null);
    }
  };

  const toggleCoupon = async (partner: AdminPartnerSummary): Promise<void> => {
    setBusyId(partner.partnerId);
    setError(null);
    try {
      await client.updatePartnerCoupon(partner.partnerId, { status: partner.coupon.status === 'ACTIVE' ? 'INACTIVE' : 'ACTIVE' });
      await reload();
    } catch (cause: unknown) {
      setError(cause instanceof ApiClientError ? cause.message : 'Coupon status change failed.');
    } finally {
      setBusyId(null);
    }
  };

  const transitionCommission = async (commissionId: string, to: 'AVAILABLE' | 'PAID'): Promise<void> => {
    setBusyId(commissionId);
    setError(null);
    try {
      await client.transitionCommission(commissionId, to);
      setNotice(to === 'AVAILABLE' ? 'Commission marked available for payout.' : 'Commission marked paid.');
      await reload();
    } catch (cause: unknown) {
      setError(cause instanceof ApiClientError ? cause.message : 'Commission transition failed.');
    } finally {
      setBusyId(null);
    }
  };

  const money = (minorUnits: number): string => `BDT ${(minorUnits / 100).toFixed(2)}`;

  return (
    <section className="panel partner-admin" aria-labelledby="partner-admin-title">
      <p className="eyebrow">Platform operations</p>
      <h1 id="partner-admin-title">Partners &amp; commissions</h1>
      <p className="muted">
        Partners are admin-selected only; the coupon code is the attribution identity. Activation grants
        complimentary PRO as entitlement — never as revenue. Commission is created only from approved,
        coupon-attributed payments and settled manually.
      </p>
      {error !== null && <div className="form-alert" role="alert"><p>{error}</p><button type="button" className="button button-ghost" onClick={() => void reload()}>Refresh</button></div>}
      {notice !== null && <p className="capability-verdict granted" role="status" data-testid="partner-notice">{notice}</p>}
      {loading && <p role="status">Loading partner operations…</p>}

      {!loading && error === null && (
        <>
          <h2>Activate a partner</h2>
          <form className="partner-activate-form" onSubmit={(event) => { event.preventDefault(); void activate(); }}>
            <label htmlFor="partner-user-id">Existing account ID</label>
            <input id="partner-user-id" value={form.userId} pattern="usr_[A-Za-z0-9_-]{1,128}" required onChange={(event) => setForm((current) => ({ ...current, userId: event.target.value }))} />
            <label htmlFor="partner-coupon-code">Unique coupon code</label>
            <input id="partner-coupon-code" value={form.couponCode} pattern="[A-Za-z0-9][A-Za-z0-9-]{2,39}" required onChange={(event) => setForm((current) => ({ ...current, couponCode: event.target.value }))} />
            <label htmlFor="partner-discount">Discount % (0–90)</label>
            <input id="partner-discount" type="number" min={0} max={90} value={form.discountPercent} onChange={(event) => setForm((current) => ({ ...current, discountPercent: event.target.value }))} />
            <label htmlFor="partner-commission">Commission % (0–50)</label>
            <input id="partner-commission" type="number" min={0} max={50} value={form.commissionPercent} onChange={(event) => setForm((current) => ({ ...current, commissionPercent: event.target.value }))} />
            <button className="button button-primary" type="submit" disabled={busyId === 'activate'}>Activate partner</button>
          </form>

          <h2>Partners</h2>
          {partners.length === 0 ? <p className="muted">No partners have been activated.</p> : (
            <div className="table-wrap">
              <table className="payment-table">
                <thead><tr><th>Partner</th><th>Coupon</th><th>Rules</th><th>Status</th><th>Operations</th></tr></thead>
                <tbody>
                  {partners.map((partner) => {
                    const edit = couponEdit[partner.partnerId] ?? { discountPercent: String(partner.coupon.discountPercent), commissionPercent: String(partner.coupon.commissionPercent) };
                    return (
                      <tr key={partner.partnerId} data-testid={`admin-partner-${partner.partnerId}`}>
                        <td><code>{partner.partnerId}</code><br /><span>{partner.email}</span></td>
                        <td><code>{partner.coupon.couponCode}</code><br /><span>{partner.coupon.status}</span></td>
                        <td>
                          <label htmlFor={`disc-${partner.partnerId}`}>Discount %</label>
                          <input id={`disc-${partner.partnerId}`} type="number" min={0} max={90} value={edit.discountPercent} onChange={(event) => setCouponEdit((current) => ({ ...current, [partner.partnerId]: { ...edit, discountPercent: event.target.value } }))} />
                          <label htmlFor={`comm-${partner.partnerId}`}>Commission %</label>
                          <input id={`comm-${partner.partnerId}`} type="number" min={0} max={50} value={edit.commissionPercent} onChange={(event) => setCouponEdit((current) => ({ ...current, [partner.partnerId]: { ...edit, commissionPercent: event.target.value } }))} />
                          <button className="button button-ghost" type="button" disabled={busyId === partner.partnerId} onClick={() => void saveCoupon(partner)}>Save</button>
                        </td>
                        <td>{partner.status}{partner.deactivatedAt !== null && <><br /><small>since {partner.deactivatedAt}</small></>}</td>
                        <td className="payment-actions">
                          <button className="button button-ghost" type="button" disabled={busyId === partner.partnerId} onClick={() => void toggleCoupon(partner)}>{partner.coupon.status === 'ACTIVE' ? 'Disable coupon' : 'Enable coupon'}</button>
                          {partner.status === 'ACTIVE'
                            ? <button className="button button-secondary" type="button" disabled={busyId === partner.partnerId} onClick={() => void partnerAction(partner.partnerId, 'deactivate')}>Deactivate partner</button>
                            : <button className="button button-primary" type="button" disabled={busyId === partner.partnerId} onClick={() => void partnerAction(partner.partnerId, 'reactivate')}>Reactivate partner</button>}
                          <button className="button button-ghost" type="button" onClick={() => void partnerAction(partner.partnerId, 'attribution')}>Attributed payments</button>
                          <button className="button button-ghost" type="button" onClick={() => void partnerAction(partner.partnerId, 'audit')}>Audit trail</button>
                          {attribution[partner.partnerId] !== undefined && (
                            <ul aria-label={`Attributed payments for ${partner.coupon.couponCode}`}>
                              {attribution[partner.partnerId]?.map((payment) => (
                                <li key={payment.paymentId}><code>{payment.paymentId}</code> · {payment.status} · {money(payment.amountMinorUnits)} · {payment.createdAt}</li>
                              ))}
                              {attribution[partner.partnerId]?.length === 0 && <li>No attributed payments.</li>}
                            </ul>
                          )}
                          {audit[partner.partnerId] !== undefined && (
                            <ul aria-label={`Audit trail for ${partner.coupon.couponCode}`}>
                              {audit[partner.partnerId]?.map((event) => (
                                <li key={event.eventId}>{event.action} · {event.at}{event.detail !== null ? ` · ${event.detail}` : ''}</li>
                              ))}
                            </ul>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}

          <h2>Commissions</h2>
          {commissions.length === 0 ? <p className="muted">No commissions exist. Commissions are created only when a coupon-attributed payment is approved.</p> : (
            <div className="table-wrap">
              <table className="payment-table">
                <thead><tr><th>Commission</th><th>Basis (server-computed)</th><th>Amounts</th><th>Status</th><th>Settlement</th></tr></thead>
                <tbody>
                  {commissions.map((commission) => (
                    <tr key={commission.commissionId} data-testid={`admin-commission-${commission.commissionId}`}>
                      <td><code>{commission.commissionId}</code><br /><span>Coupon <code>{commission.couponCode}</code> · payment <code>{commission.paymentId}</code></span></td>
                      <td>{money(commission.baseAmountMinorUnits)} − {money(commission.discountAmountMinorUnits)} discount = {money(commission.collectedAmountMinorUnits)} collected</td>
                      <td>{commission.commissionPercent}% → {money(commission.commissionAmountMinorUnits)}<br /><small>business keeps {money(commission.collectedAmountMinorUnits - commission.commissionAmountMinorUnits)}</small></td>
                      <td>{commission.status}{commission.availableAt !== null && <><br /><small>available {commission.availableAt}</small></>}{commission.paidAt !== null && <><br /><small>paid {commission.paidAt}</small></>}</td>
                      <td className="payment-actions">
                        {commission.status === 'PENDING' && <button className="button button-primary" type="button" disabled={busyId === commission.commissionId} onClick={() => void transitionCommission(commission.commissionId, 'AVAILABLE')}>Mark available</button>}
                        {commission.status === 'AVAILABLE' && <button className="button button-primary" type="button" disabled={busyId === commission.commissionId} onClick={() => void transitionCommission(commission.commissionId, 'PAID')}>Mark paid</button>}
                        {commission.status === 'PAID' && <span>Settled.</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </section>
  );
}
