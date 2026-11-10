#!/usr/bin/env bash
# Provisions TriageForge stack on Ubuntu EC2 instance
set -euo pipefail

apt-get update -qq
apt-get install -y -qq docker.io docker-compose-v2 git python3-pip

systemctl start docker
systemctl enable docker

# Clone or bootstrap TriageForge repo
mkdir -p /opt/triageforge
cd /opt/triageforge

# Launch local stack
cat << 'EOF' > /etc/systemd/system/triageforge.service
[Unit]
Description=TriageForge Stack
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/triageforge
ExecStart=/usr/bin/docker compose -f /opt/triageforge/stack/docker-compose.yml up -d
ExecStop=/usr/bin/docker compose -f /opt/triageforge/stack/docker-compose.yml down

[Install]
WantedBy=multi-user.target
EOF

echo "TriageForge EC2 initialization complete."
