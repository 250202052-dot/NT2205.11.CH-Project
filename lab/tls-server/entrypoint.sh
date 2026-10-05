#!/bin/sh
set -eu

ip route replace 172.30.10.0/24 via 172.30.20.254

exec nginx -g "daemon off;"
