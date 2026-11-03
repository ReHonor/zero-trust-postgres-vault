# Attacker toolbox: psql (from the postgres image), nmap, tcpdump, openssl.
FROM postgres:16
RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap tcpdump openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
ENTRYPOINT []
CMD ["sleep", "infinity"]
