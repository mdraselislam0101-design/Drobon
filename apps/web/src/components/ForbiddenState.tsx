import { Link } from 'react-router-dom';

/**
 * Forbidden state: the user IS authenticated but the required capability
 * is beyond their role (or the API refused with 403).
 *
 * This is UX defense-in-depth — it never substitutes for the API's own
 * authorization boundary, which is where access is actually decided.
 * The message is deliberately generic: no required-role hints, no
 * account or configuration details.
 */
export function ForbiddenState({
  message = "You don't have access to this page.",
}: {
  message?: string;
}): React.JSX.Element {
  return (
    <div className="notice error" role="alert" data-testid="forbidden-state">
      <h2>Access denied</h2>
      <p>{message}</p>
      <p className="muted">
        Your account is signed in, but this action requires additional
        permissions. Nothing about your account was changed.
      </p>
      <p>
        <Link to="/account">Back to your account</Link>
        {' · '}
        <Link to="/">Home</Link>
      </p>
    </div>
  );
}
