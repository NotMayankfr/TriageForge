#!/usr/bin/env bash
# Fault 09: Memory Leak -> Kernel OOM Kill
set -euo pipefail

echo "[FAULT 09: BREAK] Triggering rapid memory allocation to invoke kernel OOM killer..."

# Send memory leak requests until container crashes or kill with SIGKILL (exit 137)
for i in 1 2 3 4; do
    curl -s -X POST "http://localhost:8000/api/leak-memory?mb=120" >/dev/null 2>&1 || break
    sleep 0.5
done

# If container still running, simulate OOM kill event
if docker inspect -f '{{.State.Running}}' triageforge-app 2>/dev/null | grep -q 'true'; then
    docker kill -s SIGKILL triageforge-app >/dev/null 2>&1 || true
fi

echo "[FAULT 09: BREAK] App worker process killed by SIGKILL (Exit code 137 / OOM)."
