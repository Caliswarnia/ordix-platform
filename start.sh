#!/usr/bin/env bash
# Local setup: a fresh database with Echelon as the first agency, then the app at http://127.0.0.1:8800
#   OWNER_EMAIL=you@example.com OWNER_NAME="Your Name" bash start.sh
# Prints the owner's one-time temporary password. Uses PGHOST / PGPORT / PGUSER.
set -euo pipefail
cd "$(dirname "$0")"
export PGDATABASE="${PGDATABASE:-ordix}"
DB="$PGDATABASE"
psql -X -q -d postgres -c "DROP DATABASE IF EXISTS $DB WITH (FORCE);" -c "CREATE DATABASE $DB;"
for f in 001_core.sql 002_sign_in.sql; do psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f "db/$f"; done
node src/admin.ts create-agency --name "Echelon Staffing Solutions" --slug echelon \
  --owner-email "${OWNER_EMAIL:-owner@example.com}" --owner-name "${OWNER_NAME:-Echelon Owner}"
export SECRETS_KEY="${SECRETS_KEY:-$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")}"
export SECRETS_FILE="${SECRETS_FILE:-.secrets.local.json}"
rm -f "$SECRETS_FILE"
exec node src/server.ts
