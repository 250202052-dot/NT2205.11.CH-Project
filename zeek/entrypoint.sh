#!/bin/sh
set -eu

# Giu lai log ten co ban cua lan chay truoc, tranh Zeek ghi de khi restart.
for log_type in conn ssl x509 ssh; do
    previous="/logs/${log_type}.log"
    if [ -s "$previous" ]; then
        archived=$(mktemp "/logs/${log_type}.$(date -u +%Y-%m-%d-%H-%M-%S).XXXXXX.log")
        mv "$previous" "$archived"
    fi
done

# Nhan va giai dong goi ban sao Ethernet qua mang monitor rieng.
ip link add mirror0 type vxlan id 42 local 172.30.99.20 remote 172.30.99.10 dev eth0 dstport 4789 nolearning
ip link set mirror0 mtu 1500 up promisc on

# Khong cap IPv4 cho mirror0: sensor quan sat frame duoc sao chep.
# eth0 chi van chuyen tunnel; Zeek doc frame goc tai mirror0.
exec zeek -C -i mirror0 /config/local.zeek
