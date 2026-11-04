# Deploying app.ordixit.com

One small server runs everything: the app, PostgreSQL 16 and Caddy (automatic HTTPS from Let's Encrypt).

- `setup.sh`: first time only. Installs Docker, asks for settings (secrets typed on the server, saved to `deploy/.env` with owner-only permissions), starts the stack, creates Echelon with the owner's one-time password, and schedules daily backups to `~/backups` (14 days).
- `update.sh`: after new code is pushed. Pulls, rebuilds and restarts; `src/migrate.ts` applies new migrations on start.
- Keep a copy of `SECRETS_KEY` from `deploy/.env` in the password manager: without it the secrets file (authenticator keys, OAuth tokens) can't be read, including from backups.
- DNS: `app` A record to the server's static IP, DNS only (gray cloud), so Caddy can get its certificate.

MVP notes: the app connects as the postgres superuser inside the private Docker network (row-level security still applies, because every request switches to `ordix_member`). Later: a dedicated owner role, off-server backups (S3) and Secrets Manager instead of the local encrypted file.
