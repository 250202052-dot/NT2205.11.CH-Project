FROM nginx:1.27-alpine
RUN apk add --no-cache iproute2 openssl curl
COPY modern.conf weak.conf /etc/nginx/profiles/
COPY entrypoint.sh /usr/local/bin/proxy-entrypoint
COPY create-certificate.sh /usr/local/bin/create-certificate
RUN chmod +x /usr/local/bin/proxy-entrypoint /usr/local/bin/create-certificate
ENTRYPOINT ["/usr/local/bin/proxy-entrypoint"]
