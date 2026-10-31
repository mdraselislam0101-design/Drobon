import { randomUUID } from 'node:crypto';
import type {
  AuthResponse,
  AuthUser,
  CurrentUserResponse,
  LogoutResponse,
} from '@drobon/shared';
import {
  EMAIL_MAX_LENGTH,
  isUserType,
  isValidEmail,
  normalizeEmail,
  passwordPolicyIssue,
  type UserType,
} from '@drobon/shared';
import type { ApiConfig } from '../config.js';
import { conflict, invalidCredentials, unauthorized, validationError } from '../errors.js';
import type { Route } from '../http.js';
import { dummyVerify, hashPassword, verifyPassword } from '../auth/passwords.js';
import { readSessionToken, clearSessionCookie, sessionCookie } from '../auth/cookies.js';
import { toAuthUser, type UserRecord, type UserRepository } from '../auth/repositories.js';
import type { SessionStore } from '../auth/sessions.js';
import { readJsonBody } from '../lib/body.js';
import * as v from '../lib/validate.js';
import { sendSuccess } from '../respond.js';

export interface AuthRouteDeps {
  config: ApiConfig;
  users: UserRepository;
  sessions: SessionStore;
}

/**
 * Structural request shape. Both endpoints accept exactly these fields —
 * unknown properties are rejected (mass-assignment defense), passwords are
 * never trimmed (spaces are significant) and capped at the policy maximum
 * before hashing.
 */
const credentialsSchema = v.object({
  email: v.string({ maxLength: EMAIL_MAX_LENGTH, trim: true }),
  password: v.string({ maxLength: 128 }),
});

/**
 * Registration accepts an OPTIONAL classification tag. `role` is NOT in
 * any client schema — a `role` key in the payload is rejected as an
 * unknown property (mass-assignment defense; the server always writes
 * MEMBER and elevates roles only through operator/server actions). Since
 * Pump 4 the same defense covers commercial state: `plan`/`subscription`
 * keys are rejected too — the server always writes FREE + ACTIVE and
 * PRO is reachable only through the (future) authorized workflow.
 */
const registerSchema = v.object({
  email: v.string({ maxLength: EMAIL_MAX_LENGTH, trim: true }),
  password: v.string({ maxLength: 128 }),
  userType: v.optional(v.string({ maxLength: 64, trim: true })),
});

/**
 * Classification switch (Phase 20): exactly ONE field. Unknown keys are
 * rejected by the schema (mass-assignment defense) — role, plan, quota and
 * ownership can never ride along on a user-type switch.
 */
const updateUserTypeSchema = v.object({
  userType: v.string({ maxLength: 64, trim: true }),
});

const emptySchema = v.object({});

type Credentials = { email: string; password: string };

/** Shared policy pass: structural issues already validated by the schema. */
function policyIssues(credentials: Credentials): Array<{ path: string; message: string }> {
  const issues: Array<{ path: string; message: string }> = [];
  if (!isValidEmail(credentials.email)) {
    issues.push({ path: 'email', message: 'Enter a valid email address.' });
  }
  const passwordIssue = passwordPolicyIssue(credentials.password);
  if (passwordIssue !== undefined) {
    issues.push({ path: 'password', message: passwordIssue });
  }
  return issues;
}

/**
 * Authentication routes. All of them run through the standard pipeline
 * (request ID → security headers → CORS → rate limits → origin guard →
 * session resolution) and map failures onto the shared error contract.
 *
 * Enumeration posture (see docs/AUTHENTICATION.md):
 * - login answers identically for unknown email and wrong password, and
 *   burns the same CPU in both cases;
 * - logout is idempotent and never reveals session state through status
 *   codes (always 200);
 * - register's 409 is an inherent oracle without an email-verification
 *   phase; it is rate-limited and documented rather than faked.
 */
export function createAuthRoutes(deps: AuthRouteDeps): Route[] {
  const { config, users, sessions } = deps;

  return [
    {
      method: 'POST',
      path: '/api/v1/auth/register',
      handler: async (req, res, ctx): Promise<void> => {
        v.rejectUnexpectedQuery(req);
        const raw = await readJsonBody(req, { maxBytes: config.bodyMaxBytes });
        const parsed = registerSchema.parse(raw);
        if (!parsed.ok) {
          throw validationError(parsed.issues);
        }
        const issues = policyIssues(parsed.value);
        if (issues.length > 0) {
          throw validationError(issues);
        }
        // Optional classification tag — validated, and structurally
        // incapable of influencing authorization (role is not readable
        // from this payload at all).
        let userType: UserType | null = null;
        if (parsed.value.userType !== undefined) {
          if (!isUserType(parsed.value.userType)) {
            throw validationError([
              { path: 'userType', message: 'Unsupported user type.' },
            ]);
          }
          userType = parsed.value.userType;
        }
        const email = normalizeEmail(parsed.value.email);
        // Hash BEFORE the uniqueness check: the "email taken" path must
        // cost the same CPU as the "new account" path, otherwise response
        // timing becomes an enumeration oracle.
        const passwordHash = await hashPassword(parsed.value.password, config.authScryptCost);
        const now = new Date().toISOString();
        const record: UserRecord = {
          id: `usr_${randomUUID()}`,
          email,
          passwordHash,
          createdAt: now,
          // Server-assigned: every self-registration starts as MEMBER.
          role: 'MEMBER',
          userType,
          // Server-assigned commercial state (Pump 4): every new account
          // starts FREE + ACTIVE. No registration parameter, UserType or
          // role can select PRO — `plan`/`subscription` keys in the
          // payload are rejected as unknown properties by the schema.
          subscription: { plan: 'FREE', status: 'ACTIVE', createdAt: now, updatedAt: now },
        };
        const created = await users.create(record);
        if (!created) {
          throw conflict('An account with this email already exists.');
        }
        const priorToken = readSessionToken(req.headers.cookie);
        if (priorToken !== undefined) {
          sessions.revoke(priorToken);
        }
        const { token } = sessions.issue(record.id);
        ctx.logger.info('Account registered', { requestId: ctx.logId, userId: record.id });
        const body: AuthResponse = { user: toAuthUser(record) };
        sendSuccess(
          res,
          ctx,
          body,
          201,
          {
            'set-cookie': sessionCookie(token, {
              secure: config.cookieSecure,
              maxAgeSeconds: config.authSessionTtlSeconds,
            }),
          },
        );
      },
    },
    {
      method: 'POST',
      path: '/api/v1/auth/login',
      handler: async (req, res, ctx): Promise<void> => {
        v.rejectUnexpectedQuery(req);
        const raw = await readJsonBody(req, { maxBytes: config.bodyMaxBytes });
        const parsed = credentialsSchema.parse(raw);
        if (!parsed.ok) {
          throw validationError(parsed.issues);
        }
        // Malformed email is a format error (422); it reveals nothing
        // about whether an account exists.
        if (!isValidEmail(parsed.value.email)) {
          throw validationError([{ path: 'email', message: 'Enter a valid email address.' }]);
        }
        const email = normalizeEmail(parsed.value.email);
        const record = await users.findByEmail(email);
        if (record === undefined) {
          // Equalize CPU against the "wrong password" path so 401 timing
          // cannot distinguish unknown emails from failed verifications.
          await dummyVerify(parsed.value.password, config.authScryptCost);
          ctx.logger.warn('Login failed', { requestId: ctx.logId, reason: 'unknown_email' });
          throw invalidCredentials();
        }
        const ok = await verifyPassword(parsed.value.password, record.passwordHash);
        if (!ok) {
          ctx.logger.warn('Login failed', { requestId: ctx.logId, reason: 'bad_password' });
          throw invalidCredentials();
        }
        const priorToken = readSessionToken(req.headers.cookie);
        if (priorToken !== undefined) {
          sessions.revoke(priorToken);
        }
        const { token } = sessions.issue(record.id);
        ctx.logger.info('Login succeeded', { requestId: ctx.logId, userId: record.id });
        const body: AuthResponse = { user: toAuthUser(record) };
        sendSuccess(res, ctx, body, 200, {
          'set-cookie': sessionCookie(token, {
            secure: config.cookieSecure,
            maxAgeSeconds: config.authSessionTtlSeconds,
          }),
        });
      },
    },
    {
      method: 'POST',
      path: '/api/v1/auth/logout',
      handler: async (req, res, ctx): Promise<void> => {
        v.rejectUnexpectedQuery(req);
        if (req.headers['content-type'] !== undefined) {
          const raw = await readJsonBody(req, { maxBytes: config.bodyMaxBytes });
          const parsed = emptySchema.parse(raw);
          if (!parsed.ok) {
            throw validationError(parsed.issues);
          }
        }
        // Idempotent by contract: repeated logouts, logouts without a
        // session, and logouts with garbage cookies all answer 200.
        const token = readSessionToken(req.headers.cookie);
        const loggedOut = token !== undefined && sessions.revoke(token);
        if (loggedOut) {
          ctx.logger.info('Logout succeeded', { requestId: ctx.logId });
        }
        const body: LogoutResponse = { loggedOut };
        sendSuccess(res, ctx, body, 200, {
          'set-cookie': clearSessionCookie({ secure: config.cookieSecure }),
        });
      },
    },
    {
      method: 'GET',
      path: '/api/v1/me',
      requireAuth: true,
      handler: async (req, res, ctx): Promise<void> => {
        v.rejectUnexpectedQuery(req);
        const user: AuthUser | undefined = ctx.user;
        if (user === undefined) {
          // Defensive: requireAuth should have rejected already.
          throw unauthorized();
        }
        const body: CurrentUserResponse = { user };
        sendSuccess(res, ctx, body);
      },
    },
    {
      // Classification-only switch (Phase 20). The repository mutation
      // rewrites `userType` and nothing else: role, subscription, quota,
      // device anti-abuse state and ownership are structurally untouched.
      // The pipeline's origin guard + SameSite=Strict cookies provide the
      // CSRF defense; the global limiter covers bursts.
      method: 'PATCH',
      path: '/api/v1/me/user-type',
      requireAuth: true,
      handler: async (req, res, ctx): Promise<void> => {
        v.rejectUnexpectedQuery(req);
        const actor = ctx.user;
        if (actor === undefined) throw unauthorized();
        const raw = await readJsonBody(req, { maxBytes: Math.min(config.bodyMaxBytes, 4096) });
        const parsed = updateUserTypeSchema.parse(raw);
        if (!parsed.ok) throw validationError(parsed.issues);
        if (!isUserType(parsed.value.userType)) {
          throw validationError([{ path: 'userType', message: 'Unsupported user type.' }]);
        }
        const updated = await users.setUserType(actor.id, parsed.value.userType);
        if (updated === undefined) throw unauthorized();
        ctx.logger.info('User type updated', { requestId: ctx.logId, userId: updated.id });
        const body: CurrentUserResponse = { user: toAuthUser(updated) };
        sendSuccess(res, ctx, body);
      },
    },
  ];
}
