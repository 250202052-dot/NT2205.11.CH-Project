#!/bin/sh
set -eu
ip route replace 172.30.10.0/24 via 172.30.30.254
ip route replace 172.30.20.0/24 via 172.30.30.254
iptables -F INPUT
iptables -F OUTPUT
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
for chain in INPUT OUTPUT; do
    iptables -A "$chain" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
done
# Bastion is validated on router before SNAT to protected .254.
iptables -A INPUT -i eth0 -s 172.30.30.254 -p tcp --dport 22 -j ACCEPT
case "$NODE_ROLE" in
    frontend)
        iptables -A INPUT -i eth0 -s 172.30.30.254 -p tcp --dport 8080 -j ACCEPT
        iptables -A OUTPUT -o eth0 -d 172.30.30.20 -p tcp --dport 8000 -j ACCEPT
        ;;
    backend)
        iptables -A INPUT -i eth0 -s 172.30.30.10 -p tcp --dport 8000 -j ACCEPT
        iptables -A OUTPUT -o eth0 -d 172.30.30.30 -p tcp --dport 5432 -j ACCEPT
        ;;
    db)
        iptables -A INPUT -i eth0 -s 172.30.30.20 -p tcp --dport 5432 -j ACCEPT
        ;;
    *) echo 'Invalid NODE_ROLE' >&2; exit 1 ;;
esac
# No application traffic over Monitor: VXLAN to the one sensor only.
iptables -A OUTPUT -o eth1 -d 172.30.99.20 -p udp --dport 4789 -j ACCEPT
ip link add mirror0 type vxlan id 42 local "$MIRROR_LOCAL" remote 172.30.99.20 dev eth1 dstport 4789 nolearning
ip link set mirror0 mtu 1500 up
tc qdisc replace dev eth0 clsact
tc filter replace dev eth0 egress pref 20 protocol all u32 match u32 0 0 action mirred egress mirror dev mirror0
