#!/usr/bin/env bash
# One-time server setup for app.ordixit.com on a fresh Ubuntu 24.04 server (AWS Lightsail).
# Run from the cloned repo:  bash deploy/setup.sh
# Asks for the settings below; secrets are typed here, never pasted into chat or saved in the repo.
set -euo pipefail
cd "$(dirname "$0")"
ENV=.env

if ! command -v docker >/dev/null; then
  echo "Installing Docker..."
  curl -fsSL https://get.docker.com | sudo sh
  sudo usermod -aG docker "$USER"
fi
DC="sudo docker compose"

if [ ! -f "$ENV" ]; then
  read -rp "Domain [app.ordixit.com]: " DOMAIN; DOMAIN=${DOMAIN:-app.ordixit.com}
  read -rp "Your email (Echelon owner login): " OWNER_EMAIL
  read -rp "Your full name: " OWNER_NAME
  read -rp "Google OAuth Client ID: " GOOGLE_CLIENT_ID
  read -rsp "Google OAuth Client secret (hidden): " GOOGLE_CLIENT_SECRET; echo
  read -rp "Meta App ID (Enter to skip for now): " META_APP_ID
  META_APP_SECRET=""; [ -n "$META_APP_ID" ] && { read -rsp "Meta App secret (hidden): " META_APP_SECRET; echo; }
  umask 077
  cat > "$ENV" <<VARS
DOMAIN=$DOMAIN
POSTGRES_PASSWORD=$(openssl rand -hex 24)
SECRETS_KEY=$(openssl rand -hex 32)
GOOGLE_CLIENT_ID=$GOOGLE_CLIENT_ID
GOOGLE_CLIENT_SECRET=$GOOGLE_CLIENT_SECRET
META_APP_ID=$META_APP_ID
META_APP_SECRET=$META_APP_SECRET
VARS
  chmod 600 "$ENV"
  echo "Settings saved to deploy/.env (readable only by you). Copy SECRETS_KEY from it into your password manager."
else
  echo "deploy/.env exists; keeping its settings."; OWNER_EMAIL=""
fi

$DC up -d --build
echo "Waiting for the app..."
for i in $(seq 1 60); do $DC exec -T app node -e "fetch('http://127.0.0.1:8800/').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))" 2>/dev/null && break; sleep 2; done

if [ -n "${OWNER_EMAIL:-}" ] && [ "$($DC exec -T db psql -U postgres -d ordix -tAc "SELECT count(*) FROM agencies WHERE slug='echelon'")" = "0" ]; then
  $DC exec -T app node src/admin.ts create-agency --name "Echelon Staffing Solutions" --slug echelon \
    --owner-email "$OWNER_EMAIL" --owner-name "$OWNER_NAME"
fi

# Daily backup at 3:17 (server time): database dump plus the encrypted secrets file, kept 14 days.
mkdir -p "$HOME/backups"
CRON="17 3 * * * cd $(pwd) && sudo docker compose exec -T db pg_dump -U postgres ordix | gzip > \$HOME/backups/ordix-\$(date +\%F).sql.gz && sudo docker compose cp app:/data/secrets.json \$HOME/backups/secrets-\$(date +\%F).json && find \$HOME/backups -mtime +14 -delete"
( crontab -l 2>/dev/null | grep -v 'ordix-' ; echo "$CRON" ) | crontab -

echo
echo "Done. Open https://$(grep ^DOMAIN= $ENV | cut -d= -f2) and sign in with the temporary password above."
