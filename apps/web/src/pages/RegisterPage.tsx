import { useState, type FormEvent } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import {
  EMAIL_MAX_LENGTH,
  PASSWORD_MAX_LENGTH,
  PASSWORD_MIN_LENGTH,
  isValidEmail,
  type UserType,
  normalizeEmail,
  passwordPolicyIssue,
} from '@drobon/shared';
import { ApiClientError } from '../api/client.js';
import { useAuth } from '../auth/context.js';
import {
  AuthFormError,
  fieldIssuesFrom,
  type FieldErrors,
} from '../components/AuthFormError.js';
import { readSafePath } from '../components/RouteGuards.js';

/**
 * Registration page. Uses the same shared policy helpers as the API
 * (`isValidEmail`, `passwordPolicyIssue`) so client and server can never
 * disagree about what is acceptable — the server remains the authority.
 */
export function RegisterPage(): React.JSX.Element {
  const { register } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [userType, setUserType] = useState<UserType | ''>('');
  const [fieldErrors, setFieldErrors] = useState<FieldErrors>({});
  const [formError, setFormError] = useState<{ message: string; requestId?: string } | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const onSubmit = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
    event.preventDefault();
    const errors: FieldErrors = {};
    const trimmedEmail = normalizeEmail(email);
    if (trimmedEmail.length > EMAIL_MAX_LENGTH || !isValidEmail(trimmedEmail)) {
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
      const registered = await register(trimmedEmail, password, userType || undefined);
      const landing = registered.userType === 'DEVELOPER'
        ? '/dashboard'
        : registered.userType === 'STUDENT'
          ? '/student/dashboard'
          : registered.userType === 'SECURITY_PROFESSIONAL'
            ? '/security-professional/dashboard'
            : '/account';
      navigate(readSafePath(location.state) ?? landing, { replace: true });
    } catch (error: unknown) {
      if (error instanceof ApiClientError) {
        if (error.code === 'VALIDATION_ERROR') {
          setFieldErrors(fieldIssuesFrom(error.details));
        }
        // CONFLICT (email taken), UNAUTHORIZED, RATE_LIMITED and generic
        // failures all surface the server's safe message verbatim.
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
    <section className="panel auth-panel" aria-labelledby="register-title">
      <h1 id="register-title">Create your account</h1>
      <AuthFormError error={formError} />
      <form className="auth-form" onSubmit={(event) => void onSubmit(event)} noValidate>
        <div className="field">
          <label htmlFor="register-email">Email</label>
          <input
            id="register-email"
            name="email"
            type="email"
            autoComplete="email"
            required
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            aria-invalid={fieldErrors.email !== undefined}
            aria-describedby={
              fieldErrors.email === undefined ? 'register-email-hint' : 'register-email-error'
            }
          />
          <p id="register-email-hint" className="field-hint">
            Used to sign in. Never shared.
          </p>
          {fieldErrors.email !== undefined && (
            <p id="register-email-error" className="field-error" role="alert">
              {fieldErrors.email}
            </p>
          )}
        </div>
        <div className="field">
          <label htmlFor="register-password">Password</label>
          <input
            id="register-password"
            name="password"
            type="password"
            autoComplete="new-password"
            required
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            aria-invalid={fieldErrors.password !== undefined}
            aria-describedby={
              fieldErrors.password === undefined
                ? 'register-password-hint'
                : 'register-password-hint register-password-error'
            }
          />
          <p id="register-password-hint" className="field-hint">
            At least {PASSWORD_MIN_LENGTH} characters, up to {PASSWORD_MAX_LENGTH}.
          </p>
          {fieldErrors.password !== undefined && (
            <p id="register-password-error" className="field-error" role="alert">
              {fieldErrors.password}
            </p>
          )}
        </div>
        <div className="field">
          <label htmlFor="register-user-type">What best describes your work?</label>
          <select
            id="register-user-type"
            name="userType"
            value={userType}
            onChange={(event) => setUserType(event.target.value as UserType | '')}
            aria-describedby="register-user-type-hint"
          >
            <option value="">Select a type (optional)</option>
            <option value="DEVELOPER">Developer</option>
            <option value="STUDENT">Student</option>
            <option value="SECURITY_PROFESSIONAL">Security professional</option>
            <option value="PENTESTER">Pentester</option>
          </select>
          <p id="register-user-type-hint" className="field-hint">
            This is a profile classification only. It does not grant access or change your plan.
          </p>
        </div>
        <button type="submit" className="button" disabled={submitting} aria-busy={submitting}>
          {submitting ? 'Creating account…' : 'Create account'}
        </button>
      </form>
      <p className="auth-alt">
        Already have an account? <Link to="/login">Sign in</Link>.
      </p>
    </section>
  );
}
