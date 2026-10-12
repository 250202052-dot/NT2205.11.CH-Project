#!/bin/sh
set -eu
# The pulled image includes BusyBox's ip utility, no custom image required.
ip route del default 2>/dev/null || true
ip route replace 172.30.10.0/24 via 172.30.20.254
ip route replace 172.30.30.0/24 via 172.30.20.254
cat > /config/sshd/sshd_config <<'EOF'
Port 2222
ListenAddress 0.0.0.0
HostKeyAlgorithms ssh-ed25519
PidFile /config/sshd.pid
AuthorizedKeysFile /config/.ssh/authorized_keys
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
AllowUsers labadmin
AllowTcpForwarding local
PermitOpen 172.30.30.10:22 172.30.30.20:22 172.30.30.30:22
AllowAgentForwarding no
X11Forwarding no
LogLevel QUIET
EOF
chmod 640 /config/sshd/sshd_config
/usr/sbin/sshd.pam -t -f /config/sshd/sshd_config -h /config/ssh_host_keys/ssh_host_ed25519_key
