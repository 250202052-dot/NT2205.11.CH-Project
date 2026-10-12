FROM alpine:3.20 AS base
RUN apk add --no-cache iproute2 iptables openssh python3 curl \
    && adduser -D -s /bin/sh labadmin && passwd -d labadmin \
    && mkdir -p /run/sshd /etc/ssh/hostkeys /home/labadmin/.ssh
COPY common/entrypoint.sh common/network.sh common/supervise.py /usr/local/bin/
COPY common/sshd_config /etc/ssh/sshd_config
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/network.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

FROM base AS frontend
ENV NODE_ROLE=frontend
RUN apk add --no-cache nginx && mkdir -p /var/www/html
COPY frontend/nginx.conf /etc/nginx/http.d/default.conf
COPY frontend/index.html frontend/styles.css frontend/app.js /var/www/html/

FROM base AS backend
ENV NODE_ROLE=backend
RUN apk add --no-cache py3-psycopg2
COPY backend/app.py /opt/lab/app.py

FROM base AS db
ENV NODE_ROLE=db
RUN apk add --no-cache postgresql16 postgresql16-client \
    && mkdir -p /run/postgresql && chown postgres:postgres /run/postgresql
COPY db/pg_hba.conf db/postgresql.conf /opt/lab/
