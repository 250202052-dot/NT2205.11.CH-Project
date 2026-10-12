#!/bin/sh
set -eu
profile="$1"
case "$profile" in modern|weak|weak-cert|expired-cert|wrong-host|replaced-cert) ;; *) exit 1 ;; esac
destination="/etc/nginx/tls/$profile"
mkdir -p "$destination"
refresh=${2:-reuse}
case "$refresh" in reuse|refresh-fixture) ;; *) exit 2 ;; esac
# Keep the pinned modern identity stable. Only disposable test fixtures rotate.
[ "$profile:$refresh" != modern:refresh-fixture ] || exit 2
if [ "$refresh" = reuse ] && [ -s "$destination/server.key" ] && [ -s "$destination/server.crt" ]; then exit 0; fi
umask 077
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT
bits=2048
case "$profile" in weak|weak-cert) bits=1024 ;; esac
hostname=proxy.topic4.lab
[ "$profile" != wrong-host ] || hostname=other.topic4.lab
openssl req -new -newkey "rsa:$bits" -nodes \
    -keyout "$temporary/server.key" -out "$temporary/server.csr" \
    -subj "/CN=$hostname" -addext "subjectAltName=DNS:$hostname"
openssl x509 -req -in "$temporary/server.csr" -signkey "$temporary/server.key" \
    -days 30 -sha256 -copy_extensions copy -out "$temporary/server.crt"
if [ "$profile" = expired-cert ]; then
    # Fixed historical validity, without changing the host/container clock.
    touch "$temporary/index.txt"
    printf '01\n' > "$temporary/serial"
    cat > "$temporary/ca.cnf" <<EOF
[ca]
default_ca = fixture
[fixture]
database = $temporary/index.txt
serial = $temporary/serial
new_certs_dir = $temporary
default_md = sha256
policy = fixture_policy
x509_extensions = server_extensions
[fixture_policy]
commonName = supplied
[server_extensions]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:proxy.topic4.lab
EOF
    openssl ca -batch -selfsign -notext -config "$temporary/ca.cnf" \
        -cert "$temporary/server.crt" -keyfile "$temporary/server.key" \
        -in "$temporary/server.csr" -out "$temporary/expired.crt" \
        -startdate 20000101000000Z -enddate 20010101000000Z
    mv "$temporary/expired.crt" "$temporary/server.crt"
fi
mv "$temporary/server.key" "$destination/server.key"
mv "$temporary/server.crt" "$destination/server.crt"
