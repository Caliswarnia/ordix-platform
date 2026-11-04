# Ordix Platform

White-label marketing software for agencies. See CLAUDE.md for stack, commands and rules.

- `db/001_core.sql`: agencies, clients, people, access levels, audit log, row-level security
- `db/002_sign_in.sql`: sign-in, sessions, lockout, workspaces
- `src/access.ts`: create agencies, add clients and people, change access
- `src/auth.ts`: sign-in routes (`/auth/*`), temporary passwords
- `src/api.ts`, `src/server.ts`: JSON API and web server; `public/`: the browser app
- `src/admin.ts`: Ordix staff command line; `start.sh`: local setup
- `db/003_connections.sql`, `src/connections.ts`, `src/google.ts`: connected accounts and the Google connector; `db/004_meta.sql`, `src/meta.ts`: the Meta connector
- `src/secrets.ts`: secret store (local encrypted file now, AWS Secrets Manager later)
- `test/`: run with `npm test`

## Deploying
See `deploy/README.md`: one server with the app, PostgreSQL and automatic HTTPS; `bash deploy/setup.sh` once, `bash deploy/update.sh` after each push.
