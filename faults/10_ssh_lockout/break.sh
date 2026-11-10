#!/usr/bin/env bash
# Fault 10: SSH Lockout / Insecure File Permissions
set -euo pipefail

echo "[FAULT 10: BREAK] Setting insecure world-writable permissions on SSH authorized_keys..."

docker exec triageforge-sshd chmod 777 /home/forge_admin/.ssh/authorized_keys
docker exec triageforge-sshd chmod 777 /home/forge_admin/.ssh

echo "[FAULT 10: BREAK] StrictModes will now reject SSH public key authentication."
