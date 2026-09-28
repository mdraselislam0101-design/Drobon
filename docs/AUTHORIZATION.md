# Authorization Design (Pump 3)

How "what is this authenticated user allowed to do?" is answered today —
what is implemented, how it stays extensible, and what it is not.
Everything on this page is covered by executable tests
(see `docs/TESTING.md`).

## Two concepts, never conflated

| Concept | Values | Purpose | Grants access? |
| ------- | ------ | ------- | -------------- |
| `AccountRole` | `MEMBER` < `ADMIN` < `ACCOUNT_OWNER` | Authorization: what the account may do | Yes — the ONLY thing that may |
| `UserType` | `DEVELOPER`, `STUDENT`, `SECURITY_PROFESSIONAL`, `PENTESTER` | Classification/visibility: how the user describes themselves | **Never** |

`UserType` cannot bypass authentication, roles, permissions, plan limits
or any future entitlement. It does not appear in any authorization API by
construction (`hasPermission`/`roleAtLeast` accept an `AccountRole` and
nothing else).

## Capability table (the single source of truth)

Every capability declares its minimum role in one place —
`PERMISSIONS` in `packages/shared/src/authz.ts`:

```ts
'authz:capability:member': 'MEMBER',
'authz:capability:admin':  'ADMIN',
'authz:capability:owner':   'ACCOUNT_OWNER',
'users:read:self':          'MEMBER',
'users:read:others':        'ADMIN',
```

Hierarchy (`roleAtLeast`) is consulted only THROUGH a declaration — a
capability never assumes "high enough rank" implicitly. Future systems
(plans, scans, admin, partner) add entries here and/or new routes with
`requireRole`/`requirePermission`; they never fork the model.

## Enforcement architecture

The same router choke point that has always enforced `requireAuth` now
enforces authorization, in the pipeline's documented order
(session resolution → authentication → authorization → handler):

```
route match
  → needsAuth? (requireAuth | requireRole | requirePermission)
      → anonymous            → 401 UNAUTHORIZED  "Authentication required."
  → requirePermission check  → 403 FORBIDDEN     "You do not have access…"
  → requireRole check        → 403 FORBIDDEN     (same uniform message)
  → handler (ownership-sensitive handlers use assertCanReadUser)
```

- **401 vs 403**: 401 always means *authentication* is missing/invalid;
  403 always means *authenticated but not permitted*. Neither response
  reveals required roles, role configuration, or account existence.
- **Server-side state only**: role/userType live on the account record;
  the session stores an opaque token → user id. Every request re-reads
  the live record, so an elevation or demotion takes effect on the next
  request with no re-login (tested). Client headers/body/cookies carrying
  role-shaped data are ignored (tested).
- **Ownership**: `canReadUser`/`assertCanReadUser` implement the pattern
  future resources copy — self-read via `users:read:self`, cross-read
  only via the explicit `users:read:others` (ADMIN+). `GET /api/v1/users
  ?id=…` is the proof surface: unknown/malformed/oversized/unauthorized
  ids all answer the identical 403 (no IDOR, no existence oracle).

## Capability probes (observability, not product)

`GET /api/v1/authz/capabilities/member|admin|owner` — role-gated minimal
probes returning only `{ capability }`. They exist to make the foundation
observable and E2E-testable and are registered **only outside production**
(`config.authzProbeRoutes`, derived from `NODE_ENV`): in production they
404 like any unknown path, so they cannot accidentally ship as public
production functionality (tested).

## Web layer (UX defense-in-depth only)

- The single `AuthProvider` exposes `user.role`/`user.userType` — no
  second provider, no token in JS.
- `ProtectedRoute minRole` renders the **forbidden state** (alert, generic
  message, links) for authenticated-but-insufficient users — never a login
  redirect — and `/account` wires `minRole="MEMBER"` in the real tree.
- Permission-aware visibility (`hasPermission` from the shared table)
  decides what UI renders (e.g. the privileged lookup section is
  ADMIN+-only). The optional registration UserType selector is descriptive;
  Developers get a dashboard link and default post-login route for UX only.
  Admin pages use a MEMBER/ADMIN role guard in the Web tree, while the API
  independently checks the live role and configured operator allowlist.
- **Hiding UI is not authorization**: capability verdicts and lookups ask
  the API and render its 200/403 answer; the API suite proves direct API
  bypass fails regardless of what the UI does.

## Error & log hygiene

- Denials use one shared message (`AUTHZ_DENIED_MESSAGE`) — nothing to
  enumerate about roles or accounts.
- Denial logs carry request id/path/status only: no role names, emails,
  tokens or permission names (asserted by scanning captured logs).
- 403 responses keep the full security-header set (CSP, nosniff, DENY,
  request id, rate-limit headers, exact-origin CORS) — regression-tested.

## Not implemented (do not assume)

Role management UI/first-admin bootstrap (roles are assigned by operators
directly on the store today), roles-as-claims in tokens, ABAC/ReBAC
policies, per-resource ACLs, audit trail of role changes, UserType-based
authorization or entitlements, and admin/partner permissions beyond the
table above. Pump 17's Developer, Pump 18's Student, and Pump 19's Security
Professional dashboards use UserType only for workspace routing/navigation; the shared overview API
remains authenticated and self-scoped, and ordinary resource authorization
continues to use the existing role, plan, quota and ownership checks.

Plans/entitlements exist since Pump 4 but are a SEPARATE model — see
`docs/SUBSCRIPTIONS.md`. `AccountRole` and `UserType` are never
entitlement inputs: an ADMIN or ACCOUNT_OWNER on the FREE plan has
exactly FREE entitlements.

## Test coverage map

- Shared model/table: `packages/shared/test/authz.test.ts` + guard
  hardening in `auth.test.ts`.
- Capability matrix (required proofs 1–6), UserType bypass,
  mass-assignment, live-role reads: `apps/api/test/authzMatrix.test.ts`.
- Ownership/IDOR: `apps/api/test/authzOwnership.test.ts`.
- Forged/expired sessions, header smuggling, method tricks, denial-path
  headers/CORS, log disclosure: `apps/api/test/authzSecurity.test.ts`.
- Helper unit + route-level `requireRole`/`requirePermission`:
  `apps/api/test/authorization.test.ts`.
- Store migration/role validation: `apps/api/test/authStore.test.ts`;
  probe gating config: `config.test.ts`.
- Web: verdicts/forbidden state/visibility/guards —
  `apps/web/test/authzUi.test.tsx`; client boundary —
  `authClient.test.ts` (authorization describe block).
- Subscription/entitlement boundary (Pump 4, independent of roles):
  `subscriptionApi.test.ts`, `subscriptionMatrix.test.ts`,
  `apps/web/test/subscriptionUi.test.tsx` — see `docs/SUBSCRIPTIONS.md`.
- End-to-end evidence: `docs/BUILD_VERIFICATION.md`.
