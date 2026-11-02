FROM debian:bookworm-slim
# nikto is not in Debian main, so it is installed from the upstream project (GPL, https://github.com/sullo/nikto).
RUN apt-get update && apt-get install -y --no-install-recommends nmap curl git perl libnet-ssleay-perl libxml-writer-perl libjson-perl openssl ca-certificates \
    && git clone --depth 1 https://github.com/sullo/nikto /opt/nikto \
    && printf '#!/bin/sh\nexec perl /opt/nikto/program/nikto.pl "$@"\n' > /usr/local/bin/nikto && chmod +x /usr/local/bin/nikto \
    && rm -rf /var/lib/apt/lists/*
