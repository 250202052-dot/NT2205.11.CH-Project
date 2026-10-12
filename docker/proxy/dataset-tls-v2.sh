#!/bin/sh
# Temporary listeners in the EXISTING proxy: modern web port 443 stays running.
# No access log, private key export, packet capture or TLS key log.
set -eu
action=$1
base=/tmp/topic4-dataset-tls-v2
config=/etc/nginx/conf.d/topic4-dataset-v2.conf
if [ "$action" = stop ]; then
    rm -f "$config"
    nginx -t >/dev/null 2>&1 && nginx -s reload
    # Exact disposable directory, never the normal /etc/nginx/tls volume.
    rm -rf /tmp/topic4-dataset-tls-v2
    exit 0
fi
mkdir -p "$base"
umask 077
if [ "$action" = init ]; then
    [ ! -e "$config" ] || exit 3
    for profile in modern weak-cert expired-cert wrong-host replaced-cert; do
        if [ "$profile" = modern ]; then
            /usr/local/bin/create-certificate "$profile"
        else
            /usr/local/bin/create-certificate "$profile" refresh-fixture
        fi
    done
    # Isolate cipher weakness: RSA 2048, SHA256, correct hostname and validity.
    openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 30 \
        -subj /CN=proxy.topic4.lab -addext subjectAltName=DNS:proxy.topic4.lab \
        -keyout "$base/weak.key" -out "$base/weak.crt" >/dev/null 2>&1
    # A separate controlled CA signs the interception endpoint identity.
    openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 30 \
        -subj /CN=Topic4-Interception-Lab-CA -addext basicConstraints=critical,CA:TRUE \
        -keyout "$base/ca.key" -out "$base/ca.crt" >/dev/null 2>&1
    openssl req -new -newkey rsa:2048 -nodes -subj /CN=proxy.topic4.lab \
        -keyout "$base/interception.key" -out "$base/interception.csr" >/dev/null 2>&1
    printf 'subjectAltName=DNS:proxy.topic4.lab\nbasicConstraints=CA:FALSE\n' > "$base/extensions"
    openssl x509 -req -in "$base/interception.csr" -CA "$base/ca.crt" \
        -CAkey "$base/ca.key" -CAcreateserial -days 30 -sha256 -extfile "$base/extensions" \
        -out "$base/interception.crt" >/dev/null 2>&1
    action=modern
fi
case "$action" in
    modern|weak-cert|expired-cert|wrong-host|replaced-cert)
        cert=/etc/nginx/tls/$action/server.crt; key=/etc/nginx/tls/$action/server.key ;;
    weak) cert=$base/weak.crt; key=$base/weak.key ;;
    interception) cert=/etc/nginx/tls/modern/server.crt; key=/etc/nginx/tls/modern/server.key ;;
    interception-sameport) cert=$base/interception.crt; key=$base/interception.key ;;
    *) exit 2 ;;
esac
ciphers=ECDHE-RSA-AES128-GCM-SHA256
[ "$action" != weak ] || ciphers=AES128-SHA
case "$action" in weak|weak-cert) ciphers="$ciphers:@SECLEVEL=0" ;; esac
cat > "$config" <<EOF
server {
 listen 4443 ssl;
 server_name proxy.topic4.lab;
 access_log off; error_log /dev/null crit;
 ssl_certificate $cert; ssl_certificate_key $key;
 ssl_protocols TLSv1.2 TLSv1.3;
 ssl_ciphers $ciphers;
 ssl_session_cache shared:dataset_v2:1m;
 ssl_session_tickets on;
 location / { proxy_pass http://172.30.30.10:8080; }
}
server {
 listen 4444 ssl;
 server_name proxy.topic4.lab;
 access_log off; error_log /dev/null crit;
 ssl_certificate $base/interception.crt; ssl_certificate_key $base/interception.key;
 ssl_protocols TLSv1.2;
 location / {
  proxy_pass https://127.0.0.1:4443;
  proxy_ssl_verify on;
  proxy_ssl_trusted_certificate /etc/nginx/tls/modern/server.crt;
  proxy_ssl_name proxy.topic4.lab;
  proxy_ssl_server_name on;
 }
}
EOF
nginx -t >/dev/null 2>&1
nginx -s reload
# Same client port as controls; forward via the modern upstream listener.
if [ "$action" = interception-sameport ]; then
    cat > "$config" <<EOF
server {
 listen 4443 ssl;
 server_name proxy.topic4.lab;
 access_log off; error_log /dev/null crit;
 ssl_certificate $base/interception.crt; ssl_certificate_key $base/interception.key;
 ssl_protocols TLSv1.2 TLSv1.3;
 ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256;
 location / {
  proxy_pass https://127.0.0.1:4444;
  proxy_ssl_verify on;
  proxy_ssl_trusted_certificate /etc/nginx/tls/modern/server.crt;
  proxy_ssl_name proxy.topic4.lab;
  proxy_ssl_server_name on;
 }
}
server {
 listen 127.0.0.1:4444 ssl;
 server_name proxy.topic4.lab;
 access_log off; error_log /dev/null crit;
 ssl_certificate /etc/nginx/tls/modern/server.crt;
 ssl_certificate_key /etc/nginx/tls/modern/server.key;
 ssl_protocols TLSv1.2 TLSv1.3;
 location / { proxy_pass http://172.30.30.10:8080; }
}
EOF
    nginx -t >/dev/null 2>&1
    nginx -s reload
fi
