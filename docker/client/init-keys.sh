#!/bin/sh
set -eu
umask 077
if [ ! -s /admin/id_ed25519 ]; then
    ssh-keygen -q -t ed25519 -N '' -C topic4-lab-admin -f /admin/id_ed25519
fi
ssh-keygen -y -f /admin/id_ed25519 > /public/admin.pub
chmod 644 /public/admin.pub
