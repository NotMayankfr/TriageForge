#!/usr/bin/env bash
# Fault 10: Fix SSH Lockout
set -euo pipefail

echo "[FAULT 10: FIX] Restoring secure permissions on SSH key files..."

docker exec triageforge-sshd chmod 700 /home/forge_admin/.ssh
docker exec triageforge-sshd chmod 600 /home/forge_admin/.ssh/authorized_keys
docker exec triageforge-sshd chown -R forge_admin:forge_admin /home/forge_admin/.ssh

echo "[FAULT 10: FIX] SSH key permissions hardened. Public key authentication restored."
