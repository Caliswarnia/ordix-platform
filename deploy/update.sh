#!/usr/bin/env bash
# Pull the latest code and restart; migrations run automatically when the app starts.
set -euo pipefail
cd "$(dirname "$0")"
git pull --ff-only
sudo docker compose up -d --build
sudo docker compose logs --tail 20 app
