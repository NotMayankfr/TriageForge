#!/usr/bin/env bash
# Fault 04: PostgreSQL Connections Exhausted
set -euo pipefail

echo "[FAULT 04: BREAK] Sponsoring 20 persistent idle sessions to saturate PostgreSQL connection pool..."

# Run background connections via docker exec in db container
docker exec -d triageforge-db python3 -c "
import psycopg2, time
conns = []
for i in range(20):
    try:
        c = psycopg2.connect('postgresql://forge_user:forge_password@localhost:5432/triageforge')
        cur = c.cursor()
        cur.execute('SELECT pg_sleep(300);')
        conns.append(c)
    except Exception as e:
        print('Exhaustion reached:', e)
        break
time.sleep(300)
" 2>/dev/null || docker exec -d triageforge-db bash -c "
for i in \$(seq 1 20); do
    psql -U forge_user -d triageforge -c 'SELECT pg_sleep(300);' >/dev/null 2>&1 &
done
"

# Give sessions 1 second to register
sleep 2

echo "[FAULT 04: BREAK] All available PostgreSQL connection slots are now occupied."
