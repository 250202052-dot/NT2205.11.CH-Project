#!/bin/sh
set -eu
/usr/local/bin/network.sh
if [ ! -s /etc/ssh/hostkeys/ssh_host_ed25519_key ]; then
    ssh-keygen -q -t ed25519 -N '' -f /etc/ssh/hostkeys/ssh_host_ed25519_key
fi
cp /public/admin.pub /home/labadmin/.ssh/authorized_keys
chown -R labadmin:labadmin /home/labadmin/.ssh
chmod 700 /home/labadmin/.ssh
chmod 600 /home/labadmin/.ssh/authorized_keys
/usr/sbin/sshd -t
if [ "$NODE_ROLE" = db ]; then
    mkdir -p /var/lib/postgresql/data
    chown postgres:postgres /var/lib/postgresql/data
    chmod 700 /var/lib/postgresql/data
    if [ ! -s /var/lib/postgresql/data/PG_VERSION ]; then
        su postgres -c 'initdb -D /var/lib/postgresql/data --auth-local=trust --auth-host=reject' >/dev/null
    fi
    # Network/host ACL restricts database connections to Backend.
    cp /opt/lab/pg_hba.conf /var/lib/postgresql/data/pg_hba.conf
fi
exec python3 /usr/local/bin/supervise.py
