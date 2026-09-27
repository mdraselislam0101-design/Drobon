import type { ReactNode } from 'react';

/** Per-field messages keyed by the server's issue `path`. */
export interface FieldErrors {
  email?: string;
  password?: string;
}

/**
 * Server error banner shared by the auth forms. `role="alert"` announces
 * failures to screen readers; the request ID (when present) gives support
 * a correlation handle without exposing internals.
 */
export function AuthFormError({
  error,
}: {
  error: { message: string; requestId?: string } | null;
}): ReactNode {
  if (error === null) {
    return null;
  }
  return (
    <div className="form-alert" role="alert">
      <p>{error.message}</p>
      {error.requestId !== undefined && error.requestId !== '' && (
        <p className="request-id">
          Reference: <code>{error.requestId}</code>
        </p>
      )}
    </div>
  );
}

/**
 * Map an API 422 `details` array onto per-field messages. Strictly
 * structural: only the two auth fields are accepted, so a malformed or
 * hostile payload can never inject markup or unknown field targets.
 */
export function fieldIssuesFrom(details: unknown): FieldErrors {
  const out: FieldErrors = {};
  if (!Array.isArray(details)) {
    return out;
  }
  for (const entry of details) {
    if (typeof entry !== 'object' || entry === null) {
      continue;
    }
    const { path, message } = entry as { path?: unknown; message?: unknown };
    if (typeof path !== 'string' || typeof message !== 'string') {
      continue;
    }
    if (path === 'email') {
      out.email = message;
    } else if (path === 'password') {
      out.password = message;
    }
  }
  return out;
}
