import { useState, type FormEvent } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { isValidEmail, normalizeEmail, passwordPolicyIssue } from '@drobon/shared';
import { ApiClientError } from '../api/client.js';
import { useAuth } from '../auth/context.js';
import { readSafePath } from '../components/RouteGuards.js';
import { AuthFormError, fieldIssuesFrom, type FieldErrors } from '../components/AuthFormError.js';

/**
 * Login page. Client-side checks give instant feedback; the server is the
 * authority (its generic 401 is shown verbatim — it deliberately does not
 * say which credential failed).
 */
export function LoginPage(): React.JSX.Element {
  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [fieldErrors, setFieldErrors] = useState<FieldErrors>({});
  const [formError, setFormError] = useState<{ message: string; requestId?: string } | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const expired = readReason(location.state) === 'expired';
  const onSubmit = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault();
    const errors: FieldErrors = {};
    const trimmedEmail = normalizeEmail(email);
    if (!isValidEmail(trimmedEmail)) {
      errors.email = 'Enter a valid email address.';
    }
    const policyIssue = passwordPolicyIssue(password);
    if (policyIssue !== undefined) {
      errors.password = policyIssue;
    }
    setFieldErrors(errors);
    setFormError(null);
    if (Object.keys(errors).length > 0) {
      return;
    }
    setSubmitting(true);
    try {
      const authenticated = await login(trimmedEmail, password);
      const landing = authenticated.userType === 'DEVELOPER'
        ? '/dashboard'
        : authenticated.userType === 'STUDENT'
          ? '/student/dashboard'
          : authenticated.userType === 'SECURITY_PROFESSIONAL'
            ? '/security-professional/dashboard'
            : '/account';
      navigate(readSafePath(location.state) ?? landing, { replace: true });
    } catch (error: unknown) {
      if (error instanceof ApiClientError) {
        if (error.code === 'VALIDATION_ERROR') {
          setFieldErrors(fieldIssuesFrom(error.details));
        }
        setFormError({
          message: error.message,
          ...(error.requestId === undefined ? {} : { requestId: error.requestId }),
        });
      } else {
        setFormError({ message: 'An unexpected error occurred. Please try again.' });
      }
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <section className="panel auth-panel" aria-labelledby="login-title">
      <h1 id="login-title">Sign in</h1>
      {expired && (
        <p className="auth-notice" role="status">
          Your session expired. Please sign in again.
        </p>
      )}
      <AuthFormError error={formError} />
      <form className="auth-form" onSubmit={(event) => void onSubmit(event)} noValidate>
        <div className="field">
          <label htmlFor="login-email">Email</label>
          <input
            id="login-email"
            name="email"
            type="email"
            autoComplete="email"
            required
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            aria-invalid={fieldErrors.email !== undefined}
            aria-describedby={fieldErrors.email === undefined ? undefined : 'login-email-error'}
          />
          {fieldErrors.email !== undefined && (
            <p id="login-email-error" className="field-error" role="alert">
              {fieldErrors.email}
            </p>
          )}
        </div>
        <div className="field">
          <label htmlFor="login-password">Password</label>
          <input
            id="login-password"
            name="password"
            type="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            aria-invalid={fieldErrors.password !== undefined}
            aria-describedby={
              fieldErrors.password === undefined ? undefined : 'login-password-error'
            }
          />
          {fieldErrors.password !== undefined && (
            <p id="login-password-error" className="field-error" role="alert">
              {fieldErrors.password}
            </p>
          )}
        </div>
        <button type="submit" className="button" disabled={submitting} aria-busy={submitting}>
          {submitting ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
      <p className="auth-alt">
        No account yet? <Link to="/register">Create one</Link>.
      </p>
    </section>
  );
}

function readReason(state: unknown): string | undefined {
  if (typeof state !== 'object' || state === null) {
    return undefined;
  }
  const reason = (state as { reason?: unknown }).reason;
  return typeof reason === 'string' ? reason : undefined;
}
