import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, test, vi } from 'vitest';
import { ApiClientError } from '../src/api/client.js';
import { renderAt, stubClient, unauthorizedError, TEST_USER } from './appFixtures.js';

function httpError(
  status: number,
  code: string,
  message: string,
  details?: unknown,
): ApiClientError {
  return new ApiClientError({
    kind: 'http',
    message,
    status,
    code,
    requestId: 'req-form-err',
    ...(details === undefined ? {} : { details }),
  });
}

describe('login page', () => {
  test('validates fields client-side before calling the API', async () => {
    const user = userEvent.setup();
    const client = stubClient();
    await renderAt('/login', client);
    await user.click(screen.getByRole('button', { name: 'Sign in' }));
    expect(screen.getByText('Enter a valid email address.')).toBeInTheDocument();
    // Same message the shared policy (and therefore the API) produces.
    expect(screen.getByText('Password must be at least 8 characters.')).toBeInTheDocument();
    expect(client.postLogin).not.toHaveBeenCalled();
    // Errors are announced accessibly.
    expect(screen.getAllByRole('alert').length).toBeGreaterThan(0);
  });

  test('successful sign-in lands on the account page', async () => {
    const user = userEvent.setup();
    const client = stubClient({
      postLogin: vi.fn(async () => ({ user: TEST_USER })),
      // Anonymous on the initial probe, authenticated after login.
      getMe: vi
        .fn()
        .mockRejectedValueOnce(unauthorizedError())
        .mockResolvedValue({ user: TEST_USER }),
    });
    await renderAt('/login', client);
    await user.type(screen.getByLabelText('Email'), 'user@example.test');
    await user.type(screen.getByLabelText('Password'), 'correct-pw-test');
    await user.click(screen.getByRole('button', { name: 'Sign in' }));
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Your account' })).toBeInTheDocument();
    });
    expect(client.postLogin).toHaveBeenCalledWith('user@example.test', 'correct-pw-test');
    expect(screen.getByText('user@example.test')).toBeInTheDocument();
  });

  test('Developer login lands on the workspace overview', async () => {
    const user = userEvent.setup();
    const client = stubClient({
      postLogin: vi.fn(async (email: string) => ({ user: { ...TEST_USER, email, userType: 'DEVELOPER' as const } })),
      getMe: vi.fn(async () => { throw unauthorizedError(); }),
    });
    await renderAt('/login', client);
    await user.type(screen.getByLabelText('Email'), 'developer@example.test');
    await user.type(screen.getByLabelText('Password'), 'developer-password');
    await user.click(screen.getByRole('button', { name: 'Sign in' }));
    expect(await screen.findByRole('heading', { name: 'Security overview' })).toBeInTheDocument();
    expect(client.getSecurityOverview).toHaveBeenCalledTimes(1);
  });

  test('Student login lands on the Student dashboard', async () => {
    const user = userEvent.setup();
    const client = stubClient({
      postLogin: vi.fn(async (email: string) => ({ user: { ...TEST_USER, email, userType: 'STUDENT' as const } })),
      getMe: vi.fn(async () => { throw unauthorizedError(); }),
    });
    await renderAt('/login', client);
    await user.type(screen.getByLabelText('Email'), 'student@example.test');
    await user.type(screen.getByLabelText('Password'), 'student-password');
    await user.click(screen.getByRole('button', { name: 'Sign in' }));
    expect(await screen.findByRole('heading', { name: 'Student security dashboard' })).toBeInTheDocument();
    expect(client.getSecurityOverview).toHaveBeenCalledTimes(1);
  });

  test('Security Professional login lands on the professional dashboard', async () => {
    const user = userEvent.setup();
    const client = stubClient({
      postLogin: vi.fn(async (email: string) => ({ user: { ...TEST_USER, email, userType: 'SECURITY_PROFESSIONAL' as const } })),
      getMe: vi.fn(async () => { throw unauthorizedError(); }),
    });
    await renderAt('/login', client);
    await user.type(screen.getByLabelText('Email'), 'professional@example.test');
    await user.type(screen.getByLabelText('Password'), 'professional-password');
    await user.click(screen.getByRole('button', { name: 'Sign in' }));
    expect(await screen.findByRole('heading', { name: 'Security Professional dashboard' })).toBeInTheDocument();
    expect(client.getSecurityOverview).toHaveBeenCalledTimes(1);
  });

  test('Pentester login lands on the Pentester assessment dashboard', async () => {
    const user = userEvent.setup();
    const client = stubClient({
      postLogin: vi.fn(async (email: string) => ({ user: { ...TEST_USER, email, userType: 'PENTESTER' as const } })),
      getMe: vi.fn(async () => { throw unauthorizedError(); }),
    });
    await renderAt('/login', client);
    await user.type(screen.getByLabelText('Email'), 'pentester@example.test');
    await user.type(screen.getByLabelText('Password'), 'pentester-password');
    await user.click(screen.getByRole('button', { name: 'Sign in' }));
    expect(await screen.findByRole('heading', { name: 'Pentester assessment dashboard' })).toBeInTheDocument();
    expect(client.getSecurityOverview).toHaveBeenCalledTimes(1);
  });

  test('server 401 is shown verbatim without leaking which factor failed', async () => {
    const user = userEvent.setup();
    const client = stubClient({
      postLogin: vi.fn(async () => {
        throw httpError(401, 'UNAUTHORIZED', 'Invalid email or password.');
      }),
    });
    await renderAt('/login', client);
    await user.type(screen.getByLabelText('Email'), 'user@example.test');
    await user.type(screen.getByLabelText('Password'), 'wrong-pw-test-1');
    await user.click(screen.getByRole('button', { name: 'Sign in' }));
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('Invalid email or password.');
    expect(alert).toHaveTextContent('Reference:');
    // Still on the login page.
    expect(screen.getByRole('heading', { name: 'Sign in' })).toBeInTheDocument();
  });

  test('server 422 maps issues onto the right fields', async () => {
    const user = userEvent.setup();
    const client = stubClient({
      postLogin: vi.fn(async () => {
        throw httpError(422, 'VALIDATION_ERROR', 'Request validation failed.', [
          { path: 'email', message: 'Enter a valid email address.' },
        ]);
      }),
    });
    await renderAt('/login', client);
    await user.type(screen.getByLabelText('Email'), 'x');
    await user.type(screen.getByLabelText('Password'), 'long-enough-pw');
    await user.click(screen.getByRole('button', { name: 'Sign in' }));
    expect(await screen.findByText('Enter a valid email address.')).toBeInTheDocument();
  });

  test('session-expired arrival shows the notice and keeps the redirect target', async () => {
    const client = stubClient();
    await renderAt('/login', client, { from: '/account', reason: 'expired' });
    expect(
      screen.getByText('Your session expired. Please sign in again.'),
    ).toBeInTheDocument();
  });

  test('submitting disables the button while in flight (double-submit guard)', async () => {
    const user = userEvent.setup();
    let release!: (value: { user: typeof TEST_USER }) => void;
    const gate = new Promise((resolve) => {
      release = resolve;
    });
    const client = stubClient({
      postLogin: vi.fn(() => gate as never),
    });
    await renderAt('/login', client);
    await user.type(screen.getByLabelText('Email'), 'user@example.test');
    await user.type(screen.getByLabelText('Password'), 'correct-pw-test');
    await user.click(screen.getByRole('button', { name: 'Sign in' }));
    const busy = await screen.findByRole('button', { name: 'Signing in…' });
    expect(busy).toBeDisabled();
    expect(busy).toHaveAttribute('aria-busy', 'true');
    release({ user: TEST_USER });
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Your account' })).toBeInTheDocument();
    });
  });
});

describe('register page', () => {
  test('enforces the shared email and password policy client-side', async () => {
    const user = userEvent.setup();
    const client = stubClient();
    await renderAt('/register', client);
    await user.click(screen.getByRole('button', { name: 'Create account' }));
    expect(screen.getByText('Enter a valid email address.')).toBeInTheDocument();
    expect(screen.getByText('Password must be at least 8 characters.')).toBeInTheDocument();
    expect(client.postRegister).not.toHaveBeenCalled();
    // The policy hint is visible up front.
    expect(screen.getByText('At least 8 characters, up to 128.')).toBeInTheDocument();
  });

  test('successful registration signs the user straight in', async () => {
    const user = userEvent.setup();
    const client = stubClient({
      postRegister: vi.fn(async (email: string) => ({
        user: { ...TEST_USER, email },
      })),
      // Anonymous on the initial probe, authenticated after registering.
      getMe: vi
        .fn()
        .mockRejectedValueOnce(unauthorizedError())
        .mockResolvedValue({ user: TEST_USER }),
    });
    await renderAt('/register', client);
    await user.type(screen.getByLabelText('Email'), 'NewUser@Example.test');
    await user.type(screen.getByLabelText('Password'), 'brand-new-pw-test');
    await user.click(screen.getByRole('button', { name: 'Create account' }));
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: 'Your account' })).toBeInTheDocument();
    });
    // Normalized email flows through.
    expect(client.postRegister).toHaveBeenCalledWith(
      'newuser@example.test',
      'brand-new-pw-test',
    );
  });

  test('Developer registration submits only the selected classification and lands on the workspace', async () => {
    const user = userEvent.setup();
    const client = stubClient({
      postRegister: vi.fn(async (email: string, _password: string, userType: 'DEVELOPER' | undefined) => ({
        user: { ...TEST_USER, email, userType: userType ?? null },
      })),
      getMe: vi.fn(async () => { throw unauthorizedError(); }),
    });
    await renderAt('/register', client);
    await user.type(screen.getByLabelText('Email'), 'developer@example.test');
    await user.type(screen.getByLabelText('Password'), 'developer-password');
    await user.selectOptions(screen.getByLabelText('What best describes your work?'), 'DEVELOPER');
    expect(screen.getByText(/This is a profile classification only/)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Create account' }));
    expect(await screen.findByRole('heading', { name: 'Security overview' })).toBeInTheDocument();
    expect(client.postRegister).toHaveBeenCalledWith('developer@example.test', 'developer-password', 'DEVELOPER');
    expect(client.getSecurityOverview).toHaveBeenCalledTimes(1);
  });

  test('Student registration submits the selected classification and lands on the Student dashboard', async () => {
    const user = userEvent.setup();
    const client = stubClient({
      postRegister: vi.fn(async (email: string, _password: string, userType: 'STUDENT' | undefined) => ({
        user: { ...TEST_USER, email, userType: userType ?? null },
      })),
      getMe: vi.fn(async () => { throw unauthorizedError(); }),
    });
    await renderAt('/register', client);
    await user.type(screen.getByLabelText('Email'), 'student@example.test');
    await user.type(screen.getByLabelText('Password'), 'student-password');
    await user.selectOptions(screen.getByLabelText('What best describes your work?'), 'STUDENT');
    await user.click(screen.getByRole('button', { name: 'Create account' }));
    expect(await screen.findByRole('heading', { name: 'Student security dashboard' })).toBeInTheDocument();
    expect(client.postRegister).toHaveBeenCalledWith('student@example.test', 'student-password', 'STUDENT');
    expect(client.getSecurityOverview).toHaveBeenCalledTimes(1);
  });

  test('Security Professional registration selects the classification and opens its overview', async () => {
    const user = userEvent.setup();
    const client = stubClient({
      postRegister: vi.fn(async (email: string, _password: string, userType: 'SECURITY_PROFESSIONAL' | undefined) => ({
        user: { ...TEST_USER, email, userType: userType ?? null },
      })),
      getMe: vi.fn(async () => { throw unauthorizedError(); }),
    });
    await renderAt('/register', client);
    await user.type(screen.getByLabelText('Email'), 'professional@example.test');
    await user.type(screen.getByLabelText('Password'), 'professional-password');
    await user.selectOptions(screen.getByLabelText('What best describes your work?'), 'SECURITY_PROFESSIONAL');
    expect(screen.getByText(/profile classification only/)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Create account' }));
    expect(await screen.findByRole('heading', { name: 'Security Professional dashboard' })).toBeInTheDocument();
    expect(client.postRegister).toHaveBeenCalledWith('professional@example.test', 'professional-password', 'SECURITY_PROFESSIONAL');
    expect(client.getSecurityOverview).toHaveBeenCalledTimes(1);
  });

  test('Pentester registration records the classification only and opens the assessment dashboard', async () => {
    const user = userEvent.setup();
    const client = stubClient({
      postRegister: vi.fn(async (email: string, _password: string, userType: 'PENTESTER' | undefined) => ({
        user: { ...TEST_USER, email, userType: userType ?? null },
      })),
      getMe: vi.fn(async () => { throw unauthorizedError(); }),
    });
    await renderAt('/register', client);
    await user.type(screen.getByLabelText('Email'), 'pentester@example.test');
    await user.type(screen.getByLabelText('Password'), 'pentester-password');
    await user.selectOptions(screen.getByLabelText('What best describes your work?'), 'PENTESTER');
    expect(screen.getByText(/profile classification only/)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Create account' }));
    expect(await screen.findByRole('heading', { name: 'Pentester assessment dashboard' })).toBeInTheDocument();
    expect(client.postRegister).toHaveBeenCalledWith('pentester@example.test', 'pentester-password', 'PENTESTER');
    expect(client.getSecurityOverview).toHaveBeenCalledTimes(1);
  });

  test('duplicate account (409) surfaces the server message', async () => {
    const user = userEvent.setup();
    const client = stubClient({
      postRegister: vi.fn(async () => {
        throw httpError(
          409,
          'CONFLICT',
          'An account with this email already exists.',
        );
      }),
    });
    await renderAt('/register', client);
    await user.type(screen.getByLabelText('Email'), 'taken@example.test');
    await user.type(screen.getByLabelText('Password'), 'some-long-pw-test');
    await user.click(screen.getByRole('button', { name: 'Create account' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'An account with this email already exists.',
    );
    expect(screen.getByRole('heading', { name: 'Create your account' })).toBeInTheDocument();
  });

  test('login and register cross-link each other', async () => {
    await renderAt('/register');
    // Scope to the panel: the header nav also offers a "Sign in" link.
    const panel = screen.getByRole('region', { name: 'Create your account' });
    const signIn = within(panel).getByRole('link', { name: 'Sign in' });
    expect(signIn).toHaveAttribute('href', '/login');
    signIn.focus();
    expect(document.activeElement).toBe(signIn);
  });

  test('the login page links to registration', async () => {
    await renderAt('/login');
    expect(screen.getByRole('link', { name: 'Create one' })).toHaveAttribute(
      'href',
      '/register',
    );
  });
});
