import type { AuthResponse, CurrentUserResponse, LogoutResponse } from '@drobon/shared';
import { readJson, type TestServer } from './helpers.js';

/**
 * Small HTTP fixtures shared by the auth integration suites. Everything
 * here goes through the real pipeline (same code path the Web app uses).
 */

export interface RegisterResult {
  res: Response;
  body: unknown;
  user: AuthResponse['user'];
}

export async function register(
  server: TestServer,
  email: string,
  pw: string,
  extra: { headers?: Record<string, string> } = {},
): Promise<RegisterResult> {
  const res = await fetch(`${server.baseUrl}/api/v1/auth/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...(extra.headers ?? {}) },
    body: JSON.stringify({ email, password: pw }),
  });
  const body = await readJson(res);
  const user = (body as { ok: true; data: AuthResponse } | undefined)?.data?.user;
  return { res, body, user: user as RegisterResult['user'] };
}

export async function login(
  server: TestServer,
  email: string,
  pw: string,
): Promise<{ res: Response; body: unknown }> {
  const res = await fetch(`${server.baseUrl}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: pw }),
  });
  return { res, body: await readJson(res) };
}

/** Register a fresh account and return its header-ready session cookie. */
export async function sessionFor(server: TestServer, email: string, pw: string): Promise<string> {
  const { res } = await register(server, email, pw);
  if (res.status !== 201) {
    throw new Error(`Registration failed with status ${res.status}.`);
  }
  const raw = res.headers.getSetCookie().find((entry) => entry.startsWith('drobon_session='));
  if (raw === undefined) {
    throw new Error('Registration did not issue a session cookie.');
  }
  return raw.split(';')[0] ?? '';
}

export async function logout(
  server: TestServer,
  cookie?: string,
): Promise<{ res: Response; body: LogoutResponse }> {
  const res = await fetch(`${server.baseUrl}/api/v1/auth/logout`, {
    method: 'POST',
    ...(cookie === undefined ? {} : { headers: { cookie } }),
  });
  const body = (await readJson(res)) as { ok: true; data: LogoutResponse };
  return { res, body: body.data };
}

export async function me(
  server: TestServer,
  cookie?: string,
): Promise<{ res: Response; body: unknown }> {
  const res = await fetch(`${server.baseUrl}/api/v1/me`, {
    ...(cookie === undefined ? {} : { headers: { cookie } }),
  });
  return { res, body: await readJson(res) };
}

export function currentUser(body: unknown): CurrentUserResponse['user'] {
  const data = (body as { data?: CurrentUserResponse }).data;
  if (data === undefined) {
    throw new Error('Expected a CurrentUserResponse payload.');
  }
  return data.user;
}

/** Strip the per-request correlation ID so payloads can be compared. */
export function withoutRequestId(body: unknown): unknown {
  const clone = JSON.parse(JSON.stringify(body)) as { meta?: { requestId?: string } };
  if (clone.meta !== undefined) {
    delete clone.meta.requestId;
  }
  return clone;
}
