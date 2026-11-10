#!/usr/bin/env bash
# Fault 02: Fix Gunicorn Down
set -euo pipefail

echo "[FAULT 02: FIX] Restarting Gunicorn upstream application..."
docker start triageforge-app

# Wait for healthy socket
until docker exec triageforge-app curl -s http://localhost:8000/health >/dev/null 2>&1; do
    echo "Waiting for app to start..."
    sleep 1
done

echo "[FAULT 02: FIX] Gunicorn / FastAPI restored and responding."
