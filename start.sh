#!/usr/bin/env bash
# Brings the whole lab up. Safe to re-run: it never deletes data.
set -euo pipefail
cd "$(dirname "$0")"

# Docker Compose gives exported shell variables priority over .env. Make sure none leak in.
unset POSTGRES_SUPERUSER_PASSWORD VAULT_ADMIN_BOOTSTRAP_PASSWORD VAULT_ROOT_TOKEN

echo "[1/6] Certificates"
if [ -f certs/ca.crt ] && [ -f certs/server.crt ] && [ -f certs/server.key ]; then
  echo "  already present"
else
  bash scripts/gen-certs.sh
fi

echo "[2/6] Secrets (.env)"
if [ ! -f .env ] && docker volume inspect zero-trust_pgdata >/dev/null 2>&1; then
  echo "ERROR: a database volume exists but .env is missing."
  echo "  New random passwords would not match the existing data. Either restore .env,"
  echo "  or destroy everything with:  bash scripts/reset-lab.sh"
  exit 1
fi
bash scripts/gen-env.sh

echo "[3/6] Containers"
docker compose up -d --build
docker compose build client

echo "[4/6] Waiting until PostgreSQL and Vault are healthy"
for name in zt-postgres zt-vault; do
  for _ in $(seq 1 90); do
    [ "$(docker inspect -f '{{.State.Health.Status}}' "$name" 2>/dev/null || echo none)" = "healthy" ] && break
    sleep 2
  done
  [ "$(docker inspect -f '{{.State.Health.Status}}' "$name")" = "healthy" ] || { echo "ERROR: $name is not healthy"; exit 1; }
  echo "  $name healthy"
done

echo "[5/6] Configuring Vault"
if ! bash vault/vault-setup.sh; then
  echo
  echo "Setup failed. Most likely Vault restarted and the rotated vault_admin password was lost."
  echo "Running the recovery procedure."
  bash scripts/reset-vault-admin.sh
fi

echo "[6/6] Dashboard"
bash scripts/run-dashboard.sh

echo
echo "Lab is ready. Try:  bash demo.sh"
