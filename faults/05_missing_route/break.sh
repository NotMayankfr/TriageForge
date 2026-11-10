#!/usr/bin/env bash
# Fault 05: Missing Route / Gateway Blackhole
set -euo pipefail

echo "[FAULT 05: BREAK] Severing default gateway routing for application container..."

# Find docker network name
NET_NAME=$(docker network ls --filter name=forge-net -q | head -n 1)

if [ -n "$NET_NAME" ]; then
    docker network disconnect "$NET_NAME" triageforge-app || true
fi

echo "[FAULT 05: BREAK] Egress route dropped. Container isolated from gateway."
