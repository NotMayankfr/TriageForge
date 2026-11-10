#!/usr/bin/env bash
# Fault 03: Fix Disk Full / Log Exhaustion
set -euo pipefail

echo "[FAULT 03: FIX] Truncating overgrown log files and reclaiming disk space..."

docker exec triageforge-app sh -c "rm -f /var/log/app/runaway.log /tmp/triageforge_disk_full"
echo "[FAULT 03: FIX] Disk space reclaimed. Normal filesystem writes restored."
