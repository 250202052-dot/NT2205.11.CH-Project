#!/bin/sh
set -eu

iptables -F FORWARD
iptables -P FORWARD DROP

iptables -A FORWARD \
  -m conntrack --ctstate ESTABLISHED,RELATED \
  -j ACCEPT

iptables -A FORWARD \
  -s 172.30.10.0/24 -d 172.30.20.10/32 \
  -p tcp --dport 443 \
  -j ACCEPT

iptables -A FORWARD \
  -s 172.30.10.0/24 -d 172.30.20.11/32 \
  -p tcp --dport 443 \
  -j ACCEPT

iptables -A FORWARD \
  -s 172.30.10.0/24 -d 172.30.20.20/32 \
  -p tcp --dport 22 \
  -j ACCEPT

iptables -A FORWARD \
  -s 172.30.10.0/24 -d 172.30.20.21/32 \
  -p tcp --dport 22 \
  -j ACCEPT

# Source-NAT traffic crossing Docker bridges so return packets always traverse
# this firewall/router instead of being filtered by host bridge isolation.
iptables -t nat -A POSTROUTING \
  -s 172.30.10.0/24 -d 172.30.20.0/24 \
  -o eth1 \
  -j MASQUERADE

# Sao chep traffic sang sensor rieng; khong thay doi duong di packet goc.
/usr/local/bin/configure-mirror

exec sleep infinity
