#!/usr/bin/env bash
# Fault 01: Fix Security Group / Firewall Port Drop
set -euo pipefail

echo "[FAULT 01: FIX] Restoring network access and unblocking port 80/443..."

if command -v iptables >/dev/null 2>&1; then
    sudo iptables -D DOCKER-USER -p tcp -m multiport --dports 80,443 -j DROP 2>/dev/null || true
    sudo iptables -D INPUT -p tcp -m multiport --dports 80,443 -j DROP 2>/dev/null || true
fi

docker unpause triageforge-nginx 2>/dev/null || true

echo "[FAULT 01: FIX] Ingress traffic restored."
