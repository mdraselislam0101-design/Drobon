import { useCallback, useEffect, useState } from 'react';
import type { PartnerDashboardResponse } from '@drobon/shared';
import { ApiClientError } from '../api/client.js';
import { useApiClient } from '../api/context.js';

/**
 * Partner self-service dashboard (Pump 7). Renders ONLY the aggregate
 * projection returned by the server — the API never sends customer-level
 * data on this surface, and this page has no means to request any. A
 * non-partner account receives an honest 404 verdict here.
 */
export function PartnerDashboardPage(): React.JSX.Element {
  const client = useApiClient();
  const [dashboard, setDashboard] = useState<PartnerDashboardResponse | null>(null);
  const [notPartner, setNotPartner] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const reload = useCallback(async (): Promise<void> => {
    setLoading(true);
    setError(null);
    setNotPartner(false);
    try {
      setDashboard(await client.getPartnerDashboard());
    } catch (cause: unknown) {
      if (cause instanceof ApiClientError && cause.status === 404) {
        setNotPartner(true);
      } else {
        setError(cause instanceof ApiClientError ? cause.message : 'The partner dashboard is unavailable.');
      }
    } finally {
      setLoading(false);
    }
  }, [client]);

  useEffect(() => { void reload(); }, [reload]);

  const money = (minorUnits: number): string => `BDT ${(minorUnits / 100).toFixed(2)}`;

  return (
    <section className="panel partner-dashboard" aria-labelledby="partner-dashboard-title">
      <p className="eyebrow">Partner program</p>
      <h1 id="partner-dashboard-title">Partner dashboard</h1>
      <p className="muted">
        Aggregate business statistics for your own coupon only. Customer identities, payment
        references, projects, scans, findings and reports are never part of this view.
      </p>
      {loading && <p role="status">Loading partner dashboard…</p>}
      {error !== null && <div className="form-alert" role="alert"><p>{error}</p><button type="button" className="button button-ghost" onClick={() => void reload()}>Try again</button></div>}
      {notPartner && (
        <div className="form-alert" role="note">
          <p data-testid="partner-not-found">No partner record exists for this account. Partner status is granted only by platform administrators — there is no self-enrollment.</p>
        </div>
      )}
      {dashboard !== null && (
        <>
          <div className="table-wrap">
            <table className="partner-summary">
              <tbody>
                <tr><th scope="row">Coupon code</th><td data-testid="partner-coupon-code"><code>{dashboard.partner.coupon.couponCode}</code></td></tr>
                <tr><th scope="row">Coupon status</th><td>{dashboard.partner.coupon.status}{dashboard.partner.coupon.expiresAt !== null && <> · expires {dashboard.partner.coupon.expiresAt}</>}</td></tr>
                <tr><th scope="row">Discount / commission</th><td>{dashboard.partner.coupon.discountPercent}% discount · {dashboard.partner.coupon.commissionPercent}% commission (server-configured)</td></tr>
                <tr><th scope="row">Partner status</th><td>{dashboard.partner.status}{dashboard.partner.status === 'DEACTIVATED' && ' — new coupon redemptions are disabled until reactivation'}</td></tr>
                <tr><th scope="row">Complimentary PRO</th><td data-testid="partner-pro">Granted {dashboard.partner.complimentaryPro.grantedAt} — entitlement only, never revenue</td></tr>
              </tbody>
            </table>
          </div>
          <h2>Attributed business (aggregate only)</h2>
          <div className="table-wrap">
            <table className="partner-summary" data-testid="partner-aggregates">
              <tbody>
                <tr><th scope="row">Coupon uses (attributed payments)</th><td>{dashboard.aggregates.attributedPayments}</td></tr>
                <tr><th scope="row">Approved payments</th><td>{dashboard.aggregates.approvedPayments}</td></tr>
                <tr><th scope="row">Rejected payments</th><td>{dashboard.aggregates.rejectedPayments}</td></tr>
                <tr><th scope="row">Cancelled payments</th><td>{dashboard.aggregates.cancelledPayments}</td></tr>
                <tr><th scope="row">Collected from approved payments</th><td>{money(dashboard.aggregates.collectedAmountMinorUnits)}</td></tr>
                <tr><th scope="row">Commission — pending</th><td>{money(dashboard.aggregates.commission.pendingAmountMinorUnits)}</td></tr>
                <tr><th scope="row">Commission — available</th><td>{money(dashboard.aggregates.commission.availableAmountMinorUnits)}</td></tr>
                <tr><th scope="row">Commission — paid out</th><td>{money(dashboard.aggregates.commission.paidAmountMinorUnits)}</td></tr>
                <tr><th scope="row">Commission — earned total</th><td data-testid="partner-earned">{money(dashboard.aggregates.commission.earnedAmountMinorUnits)}</td></tr>
              </tbody>
            </table>
          </div>
          <p className="muted">
            Commission is created only for approved coupon-attributed payments; rejected or cancelled
            payments never generate commission. Payouts are settled manually by platform operations.
          </p>
        </>
      )}
    </section>
  );
}
