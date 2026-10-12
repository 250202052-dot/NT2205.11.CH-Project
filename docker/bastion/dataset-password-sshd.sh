#!/bin/sh
# Real password authentication, ONLY on disposable port 2223 in the lab.
# No credentials, usernames, auth log or private keys exported to dataset.
set -eu
dir=/tmp/topic4-dataset-password-ssh
action=$1
accounts='topic4guess topic4spray1 topic4spray2 topic4spray3'
listening() {
    awk '$2 ~ /:08AF$/ && $4 == "0A" { found=1 } END { exit !found }' /proc/net/tcp
}
if [ "$action" = stop ]; then
    if [ -f "$dir/pid" ]; then
        pid=$(cat "$dir/pid")
        case "$pid" in ''|*[!0-9]*) exit 2 ;; esac
        if [ -f "/proc/$pid/cmdline" ] && tr '\000' ' ' < "/proc/$pid/cmdline" | grep -q "$dir/config"; then
            kill "$pid"
            i=0
            while listening; do
                i=$((i+1)); [ "$i" -lt 50 ] || exit 3; sleep 0.1
            done
        fi
    fi
    # Remove ONLY accounts recorded as created by THIS fixture.
    if [ -f "$dir/created" ]; then
        while read -r account; do
            case "$account" in topic4guess|topic4spray1|topic4spray2|topic4spray3) deluser "$account" ;; *) exit 4 ;; esac
        done < "$dir/created"
    fi
    rm -rf /tmp/topic4-dataset-password-ssh
    exit 0
fi
[ "$action" = start ] || exit 2
[ ! -e "$dir" ] || exit 3
# Never reuse/overwrite existing accounts.
for account in $accounts; do id "$account" >/dev/null 2>&1 && exit 4; done
mkdir -m 700 "$dir"
umask 077
touch "$dir/created"
for account in $accounts; do
    adduser -D -H -s /bin/sh "$account"
    echo "$account" >> "$dir/created"
    # A fresh high-entropy credential, not a known/default password. Only
    # incorrect attempts are generated. Value never crosses Docker stdout.
    password=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')
    printf '%s:%s\n' "$account" "$password" | chpasswd
    # Benign retry control uses this disposable credential; stop removes it.
    [ "$account" != topic4guess ] || printf '%s' "$password" > "$dir/authorized_password"
done
cat > "$dir/config" <<EOF
Port 2223
ListenAddress 172.30.20.20
HostKey /config/ssh_host_keys/ssh_host_ed25519_key
PidFile $dir/pid
PasswordAuthentication yes
PubkeyAuthentication no
KbdInteractiveAuthentication no
UsePAM no
PermitRootLogin no
AllowUsers $accounts
AllowTcpForwarding no
AllowAgentForwarding no
X11Forwarding no
PermitTTY no
MaxAuthTries 2
MaxSessions 1
LoginGraceTime 10
LogLevel QUIET
PerSourcePenalties no
EOF
/usr/sbin/sshd.pam -t -f "$dir/config"
printf '[172.30.20.20]:2223 %s\n' "$(cat /config/ssh_host_keys/ssh_host_ed25519_key.pub)" > "$dir/known_hosts"
/usr/sbin/sshd.pam -f "$dir/config"
i=0
until [ -s "$dir/pid" ] && listening; do i=$((i+1)); [ "$i" -lt 50 ] || exit 5; sleep 0.1; done
