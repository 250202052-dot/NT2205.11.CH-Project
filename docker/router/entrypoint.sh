#!/bin/sh
set -eu
ip route del default 2>/dev/null || true
iptables -F FORWARD
iptables -P FORWARD DROP
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -s 172.30.10.10 -d 172.30.20.10 -p tcp --dport 443 -j ACCEPT
iptables -A FORWARD -s 172.30.10.10 -d 172.30.20.20 -p tcp --dport 2222 -j ACCEPT
iptables -A FORWARD -s 172.30.20.10 -d 172.30.30.10 -p tcp --dport 8080 -j ACCEPT
for server in 172.30.30.10 172.30.30.20 172.30.30.30; do
    iptables -A FORWARD -s 172.30.20.20 -d "$server" -p tcp --dport 22 -j ACCEPT
done
iptables -t nat -F POSTROUTING
iptables -t nat -A POSTROUTING -s 172.30.10.0/24 -d 172.30.20.0/24 -o eth1 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 172.30.20.0/24 -d 172.30.30.0/24 -o eth2 -j MASQUERADE
/usr/local/bin/configure-mirror
exec sleep infinity
