#!/usr/bin/env bash
# Fault 04: Fix PostgreSQL Connections Exhausted
set -euo pipefail

echo "[FAULT 04: FIX] Terminating orphaned / idle database sessions..."

docker exec triageforge-db psql -U forge_user -d triageforge -c "
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity
WHERE usename = 'forge_user' AND pid != pg_backend_pid();
"

echo "[FAULT 04: FIX] PostgreSQL connection slots reclaimed."
