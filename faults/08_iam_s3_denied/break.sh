#!/usr/bin/env bash
# Fault 08: IAM Policy Missing S3 Access / AccessDenied
set -euo pipefail

echo "[FAULT 08: BREAK] Revoking S3 bucket IAM permissions..."

docker exec triageforge-mock-s3 touch /tmp/iam_s3_denied 2>/dev/null || true

echo "[FAULT 08: BREAK] S3 API will now return HTTP 403 AccessDenied."
