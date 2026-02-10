#!/usr/bin/env bash
set -euo pipefail

APP_DIR="$HOME/apps/moltbot"

cd "$APP_DIR"

echo "[deploy] pulling latest..."
git pull --ff-only origin main

echo "[deploy] building image..."
sudo docker build -t moltbot:latest .

echo "[deploy] restarting container..."
sudo docker rm -f moltbot 2>/dev/null || true
sudo docker run -d --name moltbot --restart unless-stopped moltbot:latest

echo "[deploy] done"
