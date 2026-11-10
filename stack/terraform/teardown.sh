#!/usr/bin/env bash
# AWS Cost Safety: One-command clean teardown
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=========================================================================="
echo "[AWS TEARDOWN] Destroying all TriageForge cloud infrastructure..."
echo "=========================================================================="

terraform destroy -auto-approve

echo "[AWS TEARDOWN] Complete. Zero billable resources active."
