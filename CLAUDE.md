# Ordix Platform

White-label marketing software for agencies (SEO, site health and fixes, paid media, social, reporting), owned by Ordix LLC. Agencies license it and run their own clients; Ordix provides software only. Echelon Staffing Solutions is the first test tenant. Product spec: the "Marketing Platform — Product Spec" doc.

## Stack
Same conventions as the Health Company Platform: TypeScript on Node 22.18+ (native type stripping: no enums, parameter properties or namespaces), PostgreSQL 16, Node's built-in test runner, zero npm dependencies so far. Hosting target: AWS (separate account from the health platform).

## Commands
- `npm test` with `PGHOST`/`PGPORT`/`PGUSER` set: runs every test against throwaway databases
- `bash start.sh` (OWNER_EMAIL, OWNER_NAME): fresh local database with Echelon as the first agency, then the app at http://127.0.0.1:8800; prints the owner's one-time temporary password
- `node src/admin.ts create-agency | reset | suspend | reactivate`: Ordix staff tasks
- Migrations are ordered SQL files in `db/`; add new ones to `MIGRATIONS` in `test/helpers.ts`, the list in `start.sh` and `db:init` in package.json

## Rules that must not regress
- Tenant isolation lives in the database: requests run as `ordix_member` with row-level security, so an agency sees only its own rows and client-level people only their own client. New tables with agency data need `agency_id` and a policy in the same pattern.
- Access is per area (module): none, view, edit, approve. Owners have full access; client-level people never get margins, team or branding access.
- An active agency always keeps an active owner. Ended agencies stay ended; suspending or ending needs a reason.
- Every change is in the append-only audit log with its actor (`app.actor`).
- People sign in individually with password + authenticator code; lockout (5 tries, 15 minutes), 30-minute idle and 12-hour session limits, code replay and workspace checks are enforced in the database (002). Sign-in state stays in `person_sign_in`, which members can't read; password hashes never reach the audit log. A session works in one agency workspace at a time, and a deactivated membership or suspended agency stops working at once.
- No secrets (authenticator keys, OAuth tokens, agency API keys) in the database or repo: the secret store holds them and the database keeps a reference.
- The API (`src/api.ts`) runs every request as the signed-in member through `asMember`; app-level checks give friendly messages but never replace the database's rules.
- Temporary passwords are issued only for people new to Ordix: an agency can never set a password for someone who already has a login or belongs to another agency.
- The browser app has no inline scripts or styles (Content-Security-Policy); white-label colors are set through the DOM.
- Ordix never manages client accounts; agencies are responsible for client authorizations, ad spend and site changes.

## Phase 1 plan
1. Core: agencies, clients, people, access levels, audit log, isolation (done)
2. Sign-in: password + authenticator code, sessions, lockout, workspace choice (done)
3. Web server and screens: sign-in, workspaces, overview, clients, team and access, branding, activity log (done)
4. Connected-accounts screen (OAuth for Google and Meta, tokens in the secret store, bring-your-own-keys per agency)
5. Billing for agencies through Stripe
