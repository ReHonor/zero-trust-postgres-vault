#!/usr/bin/env bash
# Configures Vault from the host. Re-runnable.
set -euo pipefail
cd "$(dirname "$0")/.."
V="bash scripts/vexec.sh"

echo "[1/6] Audit device (every request is logged; secrets are HMAC-hashed)"
audits=$($V audit list -format=json 2>/dev/null || true)
if grep -q '"file/"' <<<"$audits"; then
  echo "  already enabled"
else
  $V audit enable file file_path=/vault/logs/audit.log
fi

echo "[2/6] Policies (deny by default)"
for p in analyst app admin monitor; do
  $V policy write "$p" - < "vault/policies/$p.hcl"
done

echo "[3/6] AppRole auth method, one AppRole per identity"
auths=$($V auth list -format=json)
if grep -q '"approle/"' <<<"$auths"; then
  echo "  already enabled"
else
  $V auth enable approle
fi
for r in analyst app admin monitor; do
  $V write "auth/approle/role/$r" \
    token_policies="$r" token_ttl=5m token_max_ttl=10m \
    secret_id_ttl=10m secret_id_num_uses=1
done

echo "[4/6] Database secrets engine"
mounts=$($V secrets list -format=json)
if grep -q '"database/"' <<<"$mounts"; then
  echo "  already enabled"
else
  $V secrets enable database
fi

echo "[5/6] Connect to PostgreSQL (verify-full TLS, SCRAM), then rotate the root password"
if $V read database/config/appdb >/dev/null 2>&1; then
  echo "  already configured: skipping (a rotated password must never be overwritten)"
else
  DBPASS=$(grep -m1 '^VAULT_ADMIN_BOOTSTRAP_PASSWORD=' .env | cut -d= -f2-)
  if ! $V write database/config/appdb \
      plugin_name=postgresql-database-plugin \
      allowed_roles="analyst,app,admin,monitor" \
      connection_url='postgresql://{{username}}:{{password}}@postgres:5432/appdb?sslmode=verify-full&sslrootcert=/vault/certs/ca.crt' \
      username=vault_admin \
      password="$DBPASS" \
      password_authentication=scram-sha-256; then
    echo "ERROR: Vault could not log in to PostgreSQL with the password from .env."
    echo "  If Vault was restarted after rotate-root, that password is dead. Run: bash scripts/reset-vault-admin.sh"
    exit 1
  fi
  unset DBPASS
  $V write -f database/rotate-root/appdb
  echo "  vault_admin password rotated: the value in .env no longer works"
fi

echo "[6/6] Dynamic credential roles"
for pair in analyst:analyst_ro app:app_rw admin:dba_admin monitor:monitor_ro; do
  role=${pair%%:*}; group=${pair##*:}
  ttl=30s; maxttl=5m
  if [ "$role" = monitor ]; then ttl=10m; maxttl=1h; fi
  $V write database/roles/$role \
    db_name=appdb default_ttl=$ttl max_ttl=$maxttl \
    creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}' INHERIT; GRANT $group TO \"{{name}}\";" \
    revocation_statements="SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = '{{name}}'; DROP ROLE IF EXISTS \"{{name}}\";"
done

echo "Vault configured."
