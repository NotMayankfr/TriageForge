#!/usr/bin/env bash
# Fault 06: Bad DNS / Corrupt Resolver Configuration
set -euo pipefail

echo "[FAULT 06: BREAK] Simulating broken DNS resolver configuration..."

# In container, backup resolv.conf and point to a non-responsive IP
docker exec triageforge-app sh -c "
cp /etc/resolv.conf /etc/resolv.conf.bak 2>/dev/null || true
echo 'nameserver 198.51.100.1' > /etc/resolv.conf
echo 'options timeout:1 attempts:1' >> /etc/resolv.conf
" || true

echo "[FAULT 06: BREAK] DNS queries directed to non-responsive nameserver 198.51.100.1."
