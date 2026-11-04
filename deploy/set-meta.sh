#!/usr/bin/env bash
# Adds or replaces the Meta App ID and secret in deploy/.env, then restarts the app.
#   bash deploy/set-meta.sh
set -euo pipefail
cd "$(dirname "$0")"
[ -f .env ] || { echo "Run deploy/setup.sh first."; exit 1; }
read -rp "Meta App ID: " ID
read -rsp "Meta App secret (hidden): " SECRET; echo
[ -n "$ID" ] && [ -n "$SECRET" ] || { echo "Both are required."; exit 1; }
umask 077
grep -v -e '^META_APP_ID=' -e '^META_APP_SECRET=' .env > .env.new || true
printf 'META_APP_ID=%s\nMETA_APP_SECRET=%s\n' "$ID" "$SECRET" >> .env.new
mv .env.new .env && chmod 600 .env
sudo docker compose up -d app
echo "Meta settings saved and the app restarted."
