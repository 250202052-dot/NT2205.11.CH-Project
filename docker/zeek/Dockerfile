FROM zeek/zeek:lts@sha256:70733f4e540ba1608e37e00c6a93d009f79734262c9ec2ba09d90aa9abc16de5

# iproute2 tao interface VXLAN nhan traffic mirror trong namespace cua Zeek.
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Pin script packages; project acceptance tests cover Zeek 9 compatibility.
RUN zkg install --force --skiptests --nosuggestions --version v0.18.8 https://github.com/FoxIO-LLC/ja4 \
    && zkg install --force --skiptests --nosuggestions --version 502cc6395811c54743b0561419d61900a6df3ff7 https://github.com/salesforce/ja3 \
    && zkg install --force --skiptests --nosuggestions --version 8280c8d1c70b6b8a419e9733230740e395d744fb https://github.com/corelight/hassh

COPY entrypoint.sh /usr/local/bin/sensor-entrypoint
RUN chmod +x /usr/local/bin/sensor-entrypoint
ENTRYPOINT ["/usr/local/bin/sensor-entrypoint"]
