#!/usr/bin/env bash
# Fault 08: Fix IAM S3 AccessDenied
set -euo pipefail

echo "[FAULT 08: FIX] Attaching S3 GetObject IAM policy..."

docker exec triageforge-mock-s3 rm -f /tmp/iam_s3_denied 2>/dev/null || true

echo "[FAULT 08: FIX] S3 bucket permissions restored."
