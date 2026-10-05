#!/bin/sh
set -eu

ip route replace 172.30.20.0/24 via 172.30.10.254

exec sleep infinity
