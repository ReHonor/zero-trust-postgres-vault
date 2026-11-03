#!/usr/bin/env bash
# The same kind of probes against the hardened lab, from the same attacker container.
set -uo pipefail
cd "$(dirname "$0")/.."
ATT=zt-baseline-attacker
A()  { docker exec "$ATT" "$@" </dev/null; }
h()  { printf '\n==== %s\n' "$1"; }
docker network connect zero-trust_zt "$ATT" 2>/dev/null || true   # the attacker is now also on the hardened network

h "H1. Port scan (nmap)"
A nmap -Pn -sV -p 5432 postgres | grep -E '^PORT|^5432'

h "H2. TLS probe: certificate chain checked against the CA, then against a wrong hostname"
A timeout 8 openssl s_client -starttls postgres -connect postgres:5432 -CAfile /tmp/ca.crt -verify_hostname postgres 2>&1 | grep -E 'Verify return code|Protocol|Cipher is| s:| i:'
echo "--- same server, hostname 'zt-postgres' (not in the certificate):"
A timeout 8 openssl s_client -starttls postgres -connect postgres:5432 -CAfile /tmp/ca.crt -verify_hostname zt-postgres 2>&1 | grep -E 'Verify return code'

h "H3. Stolen secrets from .env used over the network"
SUPER=$(grep -m1 '^POSTGRES_SUPERUSER_PASSWORD=' .env | cut -d= -f2-)
echo "--- the real superuser password:"
A env PGPASSWORD="$SUPER" PGSSLMODE=require psql -h postgres -U postgres -d appdb -X -c "SELECT 1" 2>&1 | head -2
VA=$(grep -m1 '^VAULT_ADMIN_BOOTSTRAP_PASSWORD=' .env | cut -d= -f2-)
echo "--- the bootstrap vault_admin password (rotated by Vault):"
A env PGPASSWORD="$VA" PGSSLMODE=verify-full PGSSLROOTCERT=/tmp/ca.crt psql -h postgres -U vault_admin -d appdb -X -c "SELECT 1" 2>&1 | head -2
unset SUPER VA

h "H4. A network observer next to the database, while an analyst reads customer names"
docker rm -f zt-sniff-hardened >/dev/null 2>&1
docker run -d --name zt-sniff-hardened --network container:zt-postgres \
  --cap-add NET_RAW --cap-add NET_ADMIN zt-baseline-attacker:local \
  timeout 20 tcpdump -n -i any -l -A -s0 'tcp port 5432' >/dev/null
sleep 3
bash scripts/run-client.sh analyst sql analyst "SELECT id, full_name, city FROM customers LIMIT 2" >/dev/null 2>&1
sleep 14
cap=$(docker logs zt-sniff-hardened 2>&1)
echo "captured packets mentioning the SQL text:   $(grep -ac 'full_name' <<<"$cap")"
echo "captured packets showing customer data:     $(grep -ac 'Amina' <<<"$cap")"
echo "captured packets in total (the capture works): $(docker logs zt-sniff-hardened 2>&1 | wc -l) lines"
docker rm -f zt-sniff-hardened >/dev/null 2>&1
