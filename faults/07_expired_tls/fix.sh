#!/usr/bin/env bash
# Fault 07: Fix Expired TLS Certificate
set -euo pipefail

echo "[FAULT 07: FIX] Installing valid TLS certificate in Nginx..."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STACK_CERTS="$SCRIPT_DIR/../../stack/nginx/certs"

cp "$STACK_CERTS/valid.crt" "$STACK_CERTS/active.crt"
cp "$STACK_CERTS/valid.key" "$STACK_CERTS/active.key"

docker cp "$STACK_CERTS/active.crt" triageforge-nginx:/etc/nginx/certs/active.crt 2>/dev/null || true
docker cp "$STACK_CERTS/active.key" triageforge-nginx:/etc/nginx/certs/active.key 2>/dev/null || true
docker exec triageforge-nginx nginx -s reload 2>/dev/null || true

echo "[FAULT 07: FIX] Valid certificate restored."
