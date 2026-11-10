#!/usr/bin/env bash
# Fault 06: Fix Bad DNS
set -euo pipefail

echo "[FAULT 06: FIX] Restoring valid DNS resolver configuration..."

docker exec triageforge-app sh -c "
if [ -f /etc/resolv.conf.bak ]; then
    cp /etc/resolv.conf.bak /etc/resolv.conf
else
    echo 'nameserver 127.0.0.11' > /etc/resolv.conf
    echo 'nameserver 1.1.1.1' >> /etc/resolv.conf
fi
" || true

echo "[FAULT 06: FIX] DNS resolver configuration restored."
