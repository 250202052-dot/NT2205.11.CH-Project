#!/bin/sh
set -eu
ip route del default 2>/dev/null || true
ip route replace 172.30.20.0/24 via 172.30.10.254
ip route replace 172.30.30.0/24 via 172.30.10.254
mkdir -p /root/.ssh
cp /admin/id_ed25519 /root/.ssh/id_ed25519
chmod 700 /root/.ssh
chmod 600 /root/.ssh/id_ed25519
cat > /root/.ssh/config <<'EOF'
Host *
    User labadmin
    IdentityFile /root/.ssh/id_ed25519
    IdentitiesOnly yes
    BatchMode yes
    StrictHostKeyChecking yes
    ConnectTimeout 5
Host bastion
    HostName 172.30.20.20
    Port 2222
Host web web-frontend backend db
    ProxyJump bastion
Host web web-frontend
    HostName 172.30.30.10
Host backend
    HostName 172.30.30.20
Host db
    HostName 172.30.30.30
EOF
exec sleep infinity
