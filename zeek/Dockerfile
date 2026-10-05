FROM zeek/zeek:lts@sha256:70733f4e540ba1608e37e00c6a93d009f79734262c9ec2ba09d90aa9abc16de5

# iproute2 tao interface VXLAN nhan traffic mirror trong namespace cua Zeek.
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /usr/local/bin/sensor-entrypoint
RUN chmod +x /usr/local/bin/sensor-entrypoint
ENTRYPOINT ["/usr/local/bin/sensor-entrypoint"]
