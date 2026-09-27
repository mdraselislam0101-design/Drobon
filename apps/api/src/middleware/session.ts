import type { Middleware } from '../http.js';
import { readSessionToken, clearSessionCookie } from '../auth/cookies.js';
import { toAuthUser, type UserRepository } from '../auth/repositories.js';
import type { SessionStore } from '../auth/sessions.js';

export interface SessionMiddlewareOptions {
  sessions: SessionStore;
  users: UserRepository;
  cookieSecure: boolean;
}

/**
 * Authentication step of the pipeline (after rate limiting, before
 * routing). Resolves the session cookie into `ctx.user`:
 *
 * - no cookie → anonymous (public routes unaffected);
 * - valid session + existing user → `ctx.user` set (routes with
 *   `requireAuth` will accept it);
 * - unknown/expired/revoked session, or a user that no longer exists →
 *   anonymous, and the stale cookie is actively cleared so browsers stop
 *   sending garbage.
 *
 * It never throws 401 itself: whether a route demands authentication is a
 * routing concern (`Route.requireAuth`), keeping public endpoints working
 * even with a broken cookie attached.
 */
export function sessionMiddleware(options: SessionMiddlewareOptions): Middleware {
  return async (req, res, ctx, next): Promise<void> => {
    const token = readSessionToken(req.headers.cookie);
    if (token !== undefined) {
      const session = options.sessions.resolve(token);
      let cleared = false;
      if (session !== undefined) {
        const record = await options.users.findById(session.userId);
        if (record === undefined) {
          // Account deleted after the session was issued — kill it.
          options.sessions.revoke(token);
          cleared = true;
        } else {
          ctx.user = toAuthUser(record);
        }
      } else {
        cleared = true;
      }
      if (cleared) {
        res.setHeader('set-cookie', clearSessionCookie({ secure: options.cookieSecure }));
      }
    }
    await next();
  };
}
