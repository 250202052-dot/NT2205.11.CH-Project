#!/bin/sh
set -eu
ip route del default 2>/dev/null || true
ip route replace 172.30.10.0/24 via 172.30.20.254
ip route replace 172.30.30.0/24 via 172.30.20.254
export TLS_PROFILE="${TLS_PROFILE:-modern}"
case "$TLS_PROFILE" in
    modern|weak|weak-cert|expired-cert|wrong-host|replaced-cert) ;;
    *) echo 'Invalid TLS_PROFILE' >&2; exit 1 ;;
esac
/usr/local/bin/create-certificate "$TLS_PROFILE"
if [ "$TLS_PROFILE" = weak ]; then
    cp /etc/nginx/profiles/weak.conf /etc/nginx/conf.d/default.conf
else
    # Certificate cases retain the modern negotiation policy, except RSA-1024
    # needs a deliberately permissive TLS 1.2 fixture to remain observable.
    sed -e "s|/modern/|/$TLS_PROFILE/|g" \
        -e "s|X-Lab-Profile modern|X-Lab-Profile $TLS_PROFILE|" \
        /etc/nginx/profiles/modern.conf > /etc/nginx/conf.d/default.conf
    if [ "$TLS_PROFILE" = weak-cert ]; then
        sed -i -e 's/ssl_protocols TLSv1.2 TLSv1.3;/ssl_protocols TLSv1.2;/' \
            -e 's/ECDHE-RSA-AES128-GCM-SHA256;/ECDHE-RSA-AES128-GCM-SHA256:@SECLEVEL=0;/' \
            /etc/nginx/conf.d/default.conf
    fi
fi
nginx -t
exec nginx -g 'daemon off;'
