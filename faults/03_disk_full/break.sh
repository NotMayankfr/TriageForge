#!/usr/bin/env bash
# Fault 03: Disk Full / Log Exhaustion
set -euo pipefail

echo "[FAULT 03: BREAK] Simulating disk space exhaustion from unrotated logs..."

# Inside app container, create 1GB dummy log in /var/log/app to consume space
docker exec triageforge-app sh -c "mkdir -p /var/log/app && dd if=/dev/zero of=/var/log/app/runaway.log bs=1M count=250 2>/dev/null || true"

# Also set environment flag in app or flag file
docker exec triageforge-app touch /tmp/triageforge_disk_full

echo "[FAULT 03: BREAK] Disk space consumed. App will report 'No space left on device'."
