# Ordix Platform

White-label marketing software for agencies. See CLAUDE.md for stack, commands and rules.

- `db/001_core.sql`: agencies, clients, people, access levels, audit log, row-level security
- `db/002_sign_in.sql`: sign-in, sessions, lockout, workspaces
- `src/access.ts`: create agencies, add clients and people, change access
- `src/auth.ts`: sign-in routes (`/auth/*`), temporary passwords
- `src/secrets.ts`: secret store (local encrypted file now, AWS Secrets Manager later)
- `test/`: run with `npm test`
