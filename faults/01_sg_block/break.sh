#!/usr/bin/env bash
# Fault 01: Security Group / Firewall Port Drop
# Symptom: TCP connect hangs (timeout, zero response)
set -euo pipefail

echo "[FAULT 01: BREAK] Simulating Security Group / Firewall dropping port 80/443 traffic..."

# If iptables is available in root context, insert DROP rule
if command -v iptables >/dev/null 2>&1; then
    sudo iptables -I DOCKER-USER -p tcp -m multiport --dports 80,443 -j DROP 2>/dev/null || \
    sudo iptables -I INPUT -p tcp -m multiport --dports 80,443 -j DROP 2>/dev/null || true
fi

# Fallback/simulation flag for container network pause
docker pause triageforge-nginx 2>/dev/null || true

echo "[FAULT 01: BREAK] Complete. Packets to port 80/443 are now silently dropped (simulating SG block)."
