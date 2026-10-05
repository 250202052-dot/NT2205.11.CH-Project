FROM alpine:3.20

RUN apk add --no-cache iproute2 iptables

COPY entrypoint.sh /usr/local/bin/router-entrypoint
COPY mirror.sh /usr/local/bin/configure-mirror
RUN chmod +x /usr/local/bin/router-entrypoint /usr/local/bin/configure-mirror

ENTRYPOINT ["/usr/local/bin/router-entrypoint"]
