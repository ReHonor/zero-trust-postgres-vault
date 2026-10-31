#!/usr/bin/env bash
# Configures Vault from the host. Safe to re-run: every write is an overwrite.
set -euo pipefail
cd "$(dirname "$0")/.."
V="bash scripts/vexec.sh"

echo "[1/3] Enabling the database secrets engine"
mounts=$($V secrets list -format=json)
if grep -q '"database/"' <<<"$mounts"; then
  echo "  already enabled"
else
  $V secrets enable database
fi

echo "[2/3] Connecting Vault to PostgreSQL (verify-full TLS, SCRAM)"
DBPASS=$(grep -m1 '^VAULT_ADMIN_BOOTSTRAP_PASSWORD=' .env | cut -d= -f2-)
$V write database/config/appdb \
  plugin_name=postgresql-database-plugin \
  allowed_roles="analyst,app,admin" \
  connection_url='postgresql://{{username}}:{{password}}@postgres:5432/appdb?sslmode=verify-full&sslrootcert=/vault/certs/ca.crt' \
  username=vault_admin \
  password="$DBPASS" \
  password_authentication=scram-sha-256
unset DBPASS

echo "[3/3] Defining the dynamic credential roles"
for pair in analyst:analyst_ro app:app_rw admin:dba_admin; do
  role=${pair%%:*}; group=${pair##*:}
  $V write database/roles/$role \
    db_name=appdb default_ttl=30s max_ttl=5m \
    creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}' INHERIT; GRANT $group TO \"{{name}}\";" \
    revocation_statements="SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = '{{name}}'; DROP ROLE IF EXISTS \"{{name}}\";"
done

echo "Vault configured."
