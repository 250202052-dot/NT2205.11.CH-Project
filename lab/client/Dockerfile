FROM alpine:3.20

RUN apk add --no-cache curl iproute2 openssh-client openssl

COPY entrypoint.sh /usr/local/bin/client-entrypoint
RUN chmod +x /usr/local/bin/client-entrypoint

ENTRYPOINT ["/usr/local/bin/client-entrypoint"]
