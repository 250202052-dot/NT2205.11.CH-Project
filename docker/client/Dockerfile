FROM alpine:3.20
RUN apk add --no-cache curl iproute2 openssh-client openssl nmap
COPY entrypoint.sh /usr/local/bin/client-entrypoint
COPY init-keys.sh /usr/local/bin/init-keys
RUN chmod +x /usr/local/bin/client-entrypoint /usr/local/bin/init-keys
ENTRYPOINT ["/usr/local/bin/client-entrypoint"]
