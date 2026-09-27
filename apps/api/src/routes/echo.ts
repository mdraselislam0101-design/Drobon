import type { EchoResponse } from '@drobon/shared';
import type { ApiConfig } from '../config.js';
import { validationError } from '../errors.js';
import type { Route } from '../http.js';
import { readJsonBody } from '../lib/body.js';
import * as v from '../lib/validate.js';
import { sendSuccess } from '../respond.js';

export interface EchoRouteDeps {
  config: ApiConfig;
}

const echoSchema = v.object({
  message: v.string({ minLength: 1, maxLength: 280, trim: true }),
});

/**
 * Validation showcase: accepts `{ "message": string }` and echoes it back
 * with metadata. Exercises the full request boundary (content-type, size
 * limit, JSON parsing, schema validation, envelope) end to end.
 */
export function createEchoRoutes(deps: EchoRouteDeps): Route[] {
  return [
    {
      method: 'POST',
      path: '/api/v1/echo',
      handler: async (req, res, ctx): Promise<void> => {
        const raw = await readJsonBody(req, { maxBytes: deps.config.bodyMaxBytes });
        const parsed = echoSchema.parse(raw);
        if (!parsed.ok) {
          throw validationError(parsed.issues);
        }
        const body: EchoResponse = {
          message: parsed.value.message,
          length: Array.from(parsed.value.message).length,
          receivedAt: new Date().toISOString(),
        };
        sendSuccess(res, ctx, body);
      },
    },
  ];
}
