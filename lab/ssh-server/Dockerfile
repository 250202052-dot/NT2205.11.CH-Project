FROM alpine:3.20

ARG SSH_PROFILE=baseline

RUN apk add --no-cache iproute2 openssh \
    && adduser -D -s /bin/sh labuser \
    && echo 'labuser:topic4-lab-only' | chpasswd \
    && printf '%s\n' "$SSH_PROFILE" > /etc/ssh/profile \
    && ssh-keygen -A \
    && mkdir -p /run/sshd

COPY sshd_config.baseline sshd_config.alternate /etc/ssh/profiles/
RUN cp "/etc/ssh/profiles/sshd_config.${SSH_PROFILE}" /etc/ssh/sshd_config \
    && /usr/sbin/sshd -t
COPY entrypoint.sh /usr/local/bin/ssh-entrypoint
RUN chmod +x /usr/local/bin/ssh-entrypoint

ENTRYPOINT ["/usr/local/bin/ssh-entrypoint"]
