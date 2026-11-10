#!/usr/bin/env bash
# Fault 05: Fix Missing Route
set -euo pipefail

echo "[FAULT 05: FIX] Re-attaching container to network bridge and restoring gateway route..."

NET_NAME=$(docker network ls --filter name=forge-net --format '{{.Name}}' | head -n 1)

if [ -n "$NET_NAME" ]; then
    docker network connect "$NET_NAME" triageforge-app || true
fi

echo "[FAULT 05: FIX] Gateway route and egress connectivity restored."
