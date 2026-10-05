FROM nginx:1.27-alpine

ARG TLS_PROFILE=modern

RUN apk add --no-cache iproute2 openssl \
    && mkdir -p /etc/nginx/tls /etc/nginx/profiles \
    && if [ "$TLS_PROFILE" = "modern" ]; then \
         openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
           -keyout /etc/nginx/tls/server.key \
           -out /etc/nginx/tls/server.crt \
           -subj "/CN=tls-modern.topic4.lab"; \
       elif [ "$TLS_PROFILE" = "alternate" ]; then \
         openssl req -x509 -newkey rsa:1024 -nodes -days 30 \
           -keyout /etc/nginx/tls/server.key \
           -out /etc/nginx/tls/server.crt \
           -subj "/CN=tls-weak.topic4.lab"; \
       else \
         echo "Unsupported TLS_PROFILE=$TLS_PROFILE" >&2; exit 1; \
       fi \
    && printf '%s\n' "$TLS_PROFILE" > /etc/nginx/tls/profile \
    && chmod 600 /etc/nginx/tls/server.key

COPY modern.conf alternate.conf /etc/nginx/profiles/
RUN cp "/etc/nginx/profiles/${TLS_PROFILE}.conf" /etc/nginx/conf.d/default.conf \
    && nginx -t
COPY entrypoint.sh /usr/local/bin/tls-entrypoint
RUN chmod +x /usr/local/bin/tls-entrypoint

ENTRYPOINT ["/usr/local/bin/tls-entrypoint"]
