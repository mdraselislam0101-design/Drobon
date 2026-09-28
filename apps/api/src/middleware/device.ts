import type { Middleware } from '../http.js';
import {
  DEVICE_COOKIE_MAX_AGE_SECONDS,
  deviceCookie,
  deviceHashFor,
  generateDeviceToken,
  isValidDeviceTokenShape,
  readDeviceToken,
} from '../usage/devices.js';

export interface DeviceMiddlewareOptions {
  /** `Secure` cookie attribute (production only — same as the session cookie). */
  cookieSecure: boolean;
}

/**
 * Device resolution for usage anti-abuse (Pump 5). Runs after session
 * resolution, before routing:
 *
 * - a well-formed `drobon_device` cookie → its SHA-256 hash becomes
 *   `ctx.deviceHash` (recognized device — FREE accounts on it share the
 *   device allowance);
 * - missing or malformed cookie (for an AUTHENTICATED request) → a fresh
 *   cryptographically random token is issued as an HttpOnly/
 *   SameSite=Strict/Secure-in-production cookie and its hash becomes
 *   `ctx.deviceHash`;
 * - anonymous requests never need one, so no cookie is issued for them.
 *
 * `set-cookie` is APPENDED (never overwrites) so a response can carry
 * both a session cookie and a device cookie; `sendJson` combines all
 * sources at write time.
 *
 * The raw token never leaves this middleware: downstream code and logs
 * only ever see the hash.
 */
export function deviceMiddleware(options: DeviceMiddlewareOptions): Middleware {
  return async (req, res, ctx, next): Promise<void> => {
    if (ctx.user === undefined) {
      // Anonymous: no usage surface needs a device identity.
      await next();
      return;
    }
    const token = readDeviceToken(req.headers.cookie);
    if (isValidDeviceTokenShape(token)) {
      ctx.deviceHash = deviceHashFor(token);
      await next();
      return;
    }
    // Missing or malformed (wrong length/charset) → treat as deviceless
    // and issue a fresh opaque token. A garbage value can never map to
    // another device's allowance.
    const fresh = generateDeviceToken();
    ctx.deviceHash = deviceHashFor(fresh);
    const cookie = deviceCookie(fresh, {
      secure: options.cookieSecure,
      maxAgeSeconds: DEVICE_COOKIE_MAX_AGE_SECONDS,
    });
    const existing = res.getHeader('set-cookie');
    if (existing === undefined) {
      res.setHeader('set-cookie', cookie);
    } else if (Array.isArray(existing)) {
      res.setHeader('set-cookie', [...existing.map(String), cookie]);
    } else {
      res.setHeader('set-cookie', [String(existing), cookie]);
    }
    await next();
  };
}
