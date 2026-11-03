# Ordix Platform

White-label marketing software for agencies (SEO, site health and fixes, paid media, social, reporting), owned by Ordix LLC. Agencies license it and run their own clients; Ordix provides software only. Echelon Staffing Solutions is the first test tenant. Product spec: the "Marketing Platform — Product Spec" doc.

## Stack
Same conventions as the Health Company Platform: TypeScript on Node 22.18+ (native type stripping: no enums, parameter properties or namespaces), PostgreSQL 16, Node's built-in test runner, zero npm dependencies so far. Hosting target: AWS (separate account from the health platform).

## Commands
- `npm test` with `PGHOST`/`PGPORT`/`PGUSER` set: runs every test against throwaway databases
- Migrations are ordered SQL files in `db/`; add new ones to `MIGRATIONS` in `test/helpers.ts` and to `db:init` in package.json

## Rules that must not regress
- Tenant isolation lives in the database: requests run as `ordix_member` with row-level security, so an agency sees only its own rows and client-level people only their own client. New tables with agency data need `agency_id` and a policy in the same pattern.
- Access is per area (module): none, view, edit, approve. Owners have full access; client-level people never get margins, team or branding access.
- An active agency always keeps an active owner. Ended agencies stay ended; suspending or ending needs a reason.
- Every change is in the append-only audit log with its actor (`app.actor`).
- Ordix never manages client accounts; agencies are responsible for client authorizations, ad spend and site changes.

## Phase 1 plan
1. Core: agencies, clients, people, access levels, audit log, isolation (done)
2. Sign-in: password + authenticator code, sessions, lockout (port from the health platform's 014)
3. Web server and agency/client screens (from the clickable prototype)
4. Connected-accounts screen (OAuth for Google and Meta, tokens in the secret store, bring-your-own-keys per agency)
5. Billing for agencies through Stripe
