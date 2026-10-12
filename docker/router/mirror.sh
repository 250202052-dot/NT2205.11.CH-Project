#!/bin/sh
set -eu
if ! ip link show mirror0 >/dev/null 2>&1; then
    ip link add mirror0 type vxlan id 42 local 172.30.99.10 remote 172.30.99.20 dev eth3 dstport 4789 nolearning
fi
ip link set mirror0 mtu 1500 up
# Outside captures TLS client->proxy and SSH client->bastion.
# Protected nodes mirror their own egress (including replies and east-west).
# Router mirrors only egress into Protected to avoid duplicate replies.
tc qdisc replace dev eth0 clsact
tc filter replace dev eth0 ingress pref 10 protocol all u32 match u32 0 0 action mirred egress mirror dev mirror0
tc filter replace dev eth0 egress pref 20 protocol all u32 match u32 0 0 action mirred egress mirror dev mirror0
tc qdisc replace dev eth2 clsact
tc filter replace dev eth2 egress pref 20 protocol all u32 match u32 0 0 action mirred egress mirror dev mirror0
