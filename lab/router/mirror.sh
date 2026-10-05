#!/bin/sh
set -eu

# Tunnel chi van chuyen ban sao Ethernet tu router den Zeek.
# Chay lai script nay de khoi phuc mirror, khong tao tunnel trung.
if ! ip link show mirror0 >/dev/null 2>&1; then
    ip link add mirror0 type vxlan id 42 local 172.30.99.10 remote 172.30.99.20 dev eth2 dstport 4789 nolearning
fi
ip link set mirror0 mtu 1500 up

# clsact co hai diem quan sat: ingress (request) va egress (response).
tc qdisc replace dev eth0 clsact
tc filter replace dev eth0 ingress pref 10 protocol all u32 match u32 0 0 \
    action mirred egress mirror dev mirror0
tc filter replace dev eth0 egress pref 20 protocol all u32 match u32 0 0 \
    action mirred egress mirror dev mirror0
