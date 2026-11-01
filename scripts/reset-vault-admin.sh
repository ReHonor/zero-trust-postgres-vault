#!/usr/bin/env bash
# Recovery after a Vault restart. Dev-mode Vault keeps everything in memory, including the
# rotated vault_admin password, so after a restart nobody knows it any more.
# 1) set a NEW random password on vault_admin through the local superuser socket
# 2) store it in .env  3) re-run the Vault setup (which rotates it again)
set -euo pipefail
cd "$(dirname "$0")/.."
NEWPW=$(openssl rand -hex 24)
docker compose exec -T -u postgres postgres psql -d appdb -v ON_ERROR_STOP=1 -v newpw="$NEWPW" >/dev/null <<'SQL'
SET log_min_error_statement = 'panic';
ALTER ROLE vault_admin PASSWORD :'newpw';
SQL
sed -i "s|^VAULT_ADMIN_BOOTSTRAP_PASSWORD=.*|VAULT_ADMIN_BOOTSTRAP_PASSWORD=$NEWPW|" .env
unset NEWPW
echo "vault_admin password reset and stored in .env"
bash scripts/cleanup-expired-roles.sh
bash vault/vault-setup.sh
