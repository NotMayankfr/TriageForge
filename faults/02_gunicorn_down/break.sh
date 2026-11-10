#!/usr/bin/env bash
# Fault 02: Gunicorn Down -> Nginx 502 Bad Gateway
set -euo pipefail

echo "[FAULT 02: BREAK] Terminating Gunicorn upstream application..."
docker stop triageforge-app

echo "[FAULT 02: BREAK] App terminated. Nginx will now return HTTP 502 Bad Gateway."
