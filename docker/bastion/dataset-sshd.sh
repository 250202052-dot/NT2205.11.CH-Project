#!/bin/sh
# Disposable SSH listener in the existing bastion. Never export its private key.
set -eu
profile=${1:-stop}
dir=/tmp/topic4-dataset-ssh
listening() {
    awk '$2 ~ /:08AF$/ && $4 == "0A" { found=1 } END { exit !found }' /proc/net/tcp
}
if [ "$profile" = stop ]; then
    if [ -f "$dir/pid" ]; then
        pid=$(cat "$dir/pid")
        case "$pid" in ''|*[!0-9]*) exit 1 ;; esac
        if [ -f "/proc/$pid/cmdline" ] && tr '\000' ' ' < "/proc/$pid/cmdline" | grep -q "$dir/config"; then
            kill "$pid"
            remaining=50
            while listening; do
                remaining=$((remaining - 1))
                [ "$remaining" -gt 0 ] || { echo 'Listener did not stop' >&2; exit 4; }
                sleep 0.1
            done
        fi
    fi
    rm -f "$dir/pid" "$dir/config" "$dir/host_rsa" "$dir/host_rsa.pub" "$dir/host_ecdsa" "$dir/host_ecdsa.pub" "$dir/known_hosts"
    rmdir "$dir" 2>/dev/null || true
    exit 0
fi
case "$profile" in weak-kex|weak-cipher|weak-mac|weak-host-key|modern|ssh_curve25519_chacha20|ssh_curve25519_aes256_gcm|ssh_group14_sha256_aes256_ctr|ssh_ecdh_ecdsa_aes128_ctr|ssh_legacy_group1_sha1|ssh_legacy_aes256_cbc|ssh_legacy_hmac_md5) ;; *) exit 2 ;; esac
mkdir -p "$dir"
chmod 700 "$dir"
if [ -f "$dir/pid" ]; then
    echo 'Dataset listener already exists; stop it first' >&2
    exit 3
fi
hostkey=/config/ssh_host_keys/ssh_host_ed25519_key
hostalg=ssh-ed25519
kex=curve25519-sha256
cipher=aes128-ctr
mac=hmac-sha2-256
case "$profile" in
    weak-kex) kex=diffie-hellman-group14-sha1 ;;
    weak-cipher) cipher=aes128-cbc ;;
    weak-mac) mac=hmac-sha1 ;;
    ssh_curve25519_chacha20) cipher=chacha20-poly1305@openssh.com ;;
    ssh_curve25519_aes256_gcm) cipher=aes256-gcm@openssh.com ;;
    ssh_group14_sha256_aes256_ctr)
        kex=diffie-hellman-group14-sha256; cipher=aes256-ctr; mac=hmac-sha2-512-etm@openssh.com
        ssh-keygen -q -t rsa -b 2048 -N '' -f "$dir/host_rsa"
        hostkey=$dir/host_rsa; hostalg=rsa-sha2-512 ;;
    ssh_ecdh_ecdsa_aes128_ctr)
        kex=ecdh-sha2-nistp256; mac=hmac-sha2-256-etm@openssh.com
        ssh-keygen -q -t ecdsa -b 256 -N '' -f "$dir/host_ecdsa"
        hostkey=$dir/host_ecdsa; hostalg=ecdsa-sha2-nistp256 ;;
    ssh_legacy_group1_sha1) kex=diffie-hellman-group1-sha1 ;;
    ssh_legacy_aes256_cbc) cipher=aes256-cbc ;;
    ssh_legacy_hmac_md5) mac=hmac-md5 ;;
    weak-host-key)
        ssh-keygen -q -t rsa -b 2048 -N '' -f "$dir/host_rsa"
        hostkey=$dir/host_rsa
        hostalg=ssh-rsa
        ;;
esac
cat > "$dir/config" <<EOF
Port 2223
ListenAddress 172.30.20.20
HostKey $hostkey
HostKeyAlgorithms $hostalg
KexAlgorithms $kex
Ciphers $cipher
MACs $mac
PidFile $dir/pid
AuthorizedKeysFile /config/.ssh/authorized_keys
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
AllowUsers labadmin
AllowTcpForwarding no
AllowAgentForwarding no
X11Forwarding no
LogLevel QUIET
# Deterministic bounded failed-key fixture; does not change port 2222 policy.
PerSourcePenalties no
EOF
/usr/sbin/sshd.pam -t -f "$dir/config"
key=$(cat "$hostkey.pub")
printf '[172.30.20.20]:2223 %s\n' "$key" > "$dir/known_hosts"
/usr/sbin/sshd.pam -f "$dir/config"
remaining=50
until [ -s "$dir/pid" ] && listening; do
    remaining=$((remaining - 1))
    [ "$remaining" -gt 0 ] || { echo 'Listener did not start' >&2; exit 5; }
    sleep 0.1
done
