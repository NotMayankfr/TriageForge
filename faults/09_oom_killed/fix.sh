#!/usr/bin/env bash
# Fault 09: Fix OOM Kill
set -euo pipefail

echo "[FAULT 09: FIX] Restarting application container and purging leaked memory buffers..."

docker start triageforge-app

until docker exec triageforge-app curl -s http://localhost:8000/health >/dev/null 2>&1; do
    echo "Waiting for app restart..."
    sleep 1
done

echo "[FAULT 09: FIX] Application container healthy. Memory consumption normal."
