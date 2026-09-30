import { useCallback, useEffect, useState } from 'react';
import type { PaymentConfigResponse, PaymentHistoryResponse, PaymentQuoteResponse, PaymentSummary } from '@drobon/shared';
import { ApiClientError } from '../api/client.js';
import { useApiClient } from '../api/context.js';

export function PaymentPanel(): React.JSX.Element {
  const client = useApiClient();
  const [config, setConfig] = useState<PaymentConfigResponse | null>(null);
  const [payments, setPayments] = useState<PaymentSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [reference, setReference] = useState('');
  const [couponCode, setCouponCode] = useState('');
  const [quote, setQuote] = useState<PaymentQuoteResponse | null>(null);
  const [couponNotice, setCouponNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const reload = useCallback(async (): Promise<void> => {
    setLoading(true);
    setError(null);
    try {
      const [nextConfig, history]: [PaymentConfigResponse, PaymentHistoryResponse] = await Promise.all([
        client.getPaymentConfig(),
        client.getPaymentHistory(),
      ]);
      setConfig(nextConfig);
      setPayments(history.payments);
    } catch (cause: unknown) {
      setError(cause instanceof ApiClientError ? cause.message : 'Payment information is unavailable.');
    } finally {
      setLoading(false);
    }
  }, [client]);

  useEffect(() => { void reload(); }, [reload]);

  const cancelRequest = async (paymentId: string): Promise<void> => {
    setBusy(true);
    setError(null);
    try {
      const result = await client.cancelPayment(paymentId);
      setPayments((current) => current.map((entry) => entry.paymentId === paymentId ? result.payment : entry));
      setNotice('The pending payment request was cancelled. No entitlement was changed.');
    } catch (cause: unknown) {
      setError(cause instanceof ApiClientError ? cause.message : 'The payment request could not be cancelled.');
    } finally {
      setBusy(false);
    }
  };

  const clearCoupon = (): void => {
    setQuote(null);
    setCouponNotice(null);
  };

  const applyCoupon = async (): Promise<void> => {
    setError(null);
    setCouponNotice(null);
    const code = couponCode.trim();
    try {
      const result = await client.getPaymentQuote(code === '' ? undefined : code);
      setQuote(result);
      if (result.coupon === null) setCouponNotice(code === '' ? null : 'No coupon applied — the server will charge the full PRO price.');
      else setCouponNotice(`Coupon ${result.coupon.code} accepted: ${result.coupon.discountPercent}% discount. Final amount is set by the server.`);
    } catch (cause: unknown) {
      setQuote(null);
      setCouponNotice(cause instanceof ApiClientError ? cause.message : 'The coupon could not be verified.');
    }
  };

  const submit = async (event: React.FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault();
    if (config === null || config.currentPlan !== 'FREE' || config.manualPaymentMethods.length === 0) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const appliedCode = couponCode.trim();
      // The amount sent is exactly what the server quoted (full price or the
      // server-computed discounted total); the client never computes pricing.
      const amountMinorUnits = quote !== null && quote.coupon !== null
        ? quote.coupon.finalAmountMinorUnits
        : config.proPriceMinorUnits;
      const response = await client.createPayment({
        plan: 'PRO',
        amountMinorUnits,
        currency: 'BDT',
        paymentMethod: config.manualPaymentMethods[0] ?? 'MANUAL_TRANSFER',
        reference: reference.trim(),
        ...(appliedCode === '' ? {} : { couponCode: appliedCode }),
      });
      setReference('');
      setCouponCode('');
      clearCoupon();
      setNotice('Payment reference submitted for manual review. It has not been verified.');
      setPayments((current) => [response.payment, ...current.filter((entry) => entry.paymentId !== response.payment.paymentId)]);
    } catch (cause: unknown) {
      setError(cause instanceof ApiClientError ? cause.message : 'Could not submit this payment request.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="payment-panel" aria-labelledby="upgrade-title" data-testid="payment-panel">
      <h3 id="upgrade-title">PRO upgrade &amp; payment request</h3>
      {loading && <p role="status">Loading payment options…</p>}
      {error !== null && <div className="form-alert" role="alert"><p>{error}</p><button type="button" className="button button-ghost" onClick={() => void reload()}>Try again</button></div>}
      {!loading && config !== null && (
        <>
          <p data-testid="payment-current-plan">Server-reported current plan: <strong>{config.currentPlan}</strong></p>
          <p className="muted">
            PRO price: <strong>BDT {(config.proPriceMinorUnits / 100).toFixed(2)}</strong>.
            {quote !== null && quote.coupon !== null && <> After coupon <strong>{quote.coupon.code}</strong> ({quote.coupon.discountPercent}% off, −BDT {(quote.coupon.discountAmountMinorUnits / 100).toFixed(2)}): <strong data-testid="payment-final-amount">BDT {(quote.coupon.finalAmountMinorUnits / 100).toFixed(2)}</strong>.</>}
            {' '}The server sets the amount and currency.
          </p>
          <p className="form-alert" role="note">Online payment processing is currently unavailable. This page supports a manual request only; no payment is automatically verified.</p>
          <p className="muted">{config.manualPaymentInstructions}</p>
          {config.currentPlan === 'FREE' && config.manualPaymentMethods.length > 0 && (
            <form className="payment-request-form" onSubmit={(event) => void submit(event)}>
              <label htmlFor="payment-method">Payment method</label>
              <select id="payment-method" value={config.manualPaymentMethods[0]} disabled>
                {config.manualPaymentMethods.map((method) => <option key={method} value={method}>{method.replaceAll('_', ' ')}</option>)}
              </select>
              <label htmlFor="payment-reference">Payment transaction/reference</label>
              <input
                id="payment-reference"
                name="reference"
                autoComplete="off"
                required
                minLength={6}
                maxLength={64}
                pattern="[A-Za-z0-9][A-Za-z0-9._-]{5,63}"
                value={reference}
                onChange={(event) => setReference(event.target.value)}
                aria-describedby="payment-reference-hint"
              />
              <label htmlFor="payment-coupon">Partner coupon code (optional)</label>
              <div className="coupon-row">
                <input
                  id="payment-coupon"
                  name="couponCode"
                  autoComplete="off"
                  minLength={3}
                  maxLength={40}
                  pattern="[A-Za-z0-9][A-Za-z0-9-]{2,39}"
                  placeholder="e.g. AEGIS-A"
                  value={couponCode}
                  onChange={(event) => { setCouponCode(event.target.value); clearCoupon(); }}
                  aria-describedby="payment-coupon-hint"
                />
                <button type="button" className="button button-ghost" disabled={busy} onClick={() => void applyCoupon()}>Check coupon</button>
              </div>
              <p id="payment-coupon-hint" className="muted">A valid partner coupon applies a server-verified discount. Invalid, inactive or expired coupons are rejected by the server.</p>
              {couponNotice !== null && <p role="status" data-testid="coupon-notice">{couponNotice}</p>}
              <p id="payment-reference-hint" className="muted">A reference is information you submit; it is not proof of successful payment. Contact support for transfer instructions before sending funds.</p>
              <button className="button button-primary" type="submit" disabled={busy || config.manualPaymentMethods.length === 0} aria-busy={busy}>
                {busy ? 'Submitting…' : 'Submit for manual review'}
              </button>
            </form>
          )}
          {config.currentPlan === 'FREE' && config.manualPaymentMethods.length === 0 && <p role="status">Manual payment requests are currently unavailable.</p>}
          {config.currentPlan === 'PRO' && <p className="pill pill-ok">The server reports PRO. See the plan entitlement above; payment status alone does not grant access.</p>}
          {notice !== null && <p className="capability-verdict granted" role="status">{notice}</p>}
          <h4>Your payment history</h4>
          {payments.length === 0 ? <p className="muted">No payment requests submitted.</p> : (
            <ul className="payment-history" aria-label="Your payment history">
              {payments.map((payment) => <li key={payment.paymentId} data-testid={`payment-${payment.paymentId}`}>
                <div><strong>{payment.status.replaceAll('_', ' ')}</strong> · {payment.paymentMethod.replaceAll('_', ' ')} · reference <code>{payment.reference}</code></div>
                <div>BDT {(payment.amountMinorUnits / 100).toFixed(2)} · submitted {payment.submittedAt}</div>
                {payment.status === 'PENDING' && <><p className="muted">Submitted; awaiting manual review. Payment is not verified.</p><button type="button" className="button button-ghost" disabled={busy} onClick={() => void cancelRequest(payment.paymentId)}>Cancel pending request</button></>}
                {payment.status === 'CANCELLED' && <p className="muted">This request was cancelled; no entitlement was activated.</p>}
                {payment.status === 'UNDER_REVIEW' && <p className="muted">Under administrator review; payment is not yet verified.</p>}
                {payment.status === 'APPROVING' && <p className="muted">Approval is being reconciled. Access is determined by the server-side subscription.</p>}
                {payment.status === 'APPROVED' && <p className="muted">An administrator approved this request. Current PRO access is shown only by the server-authoritative plan and entitlement above.</p>}
                {payment.status === 'REJECTED' && payment.rejectionReason !== null && <p>Reason: {payment.rejectionReason}</p>}
              </li>)}
            </ul>
          )}
        </>
      )}
      <p className="muted">Coupons are validated server-side only; discounts, commission and partner attribution are never client-controlled.</p>
    </section>
  );
}
