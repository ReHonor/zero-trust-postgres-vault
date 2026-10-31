#!/usr/bin/env bash
# Creates .env with random secrets. Never overwrites an existing .env.
set -euo pipefail
cd "$(dirname "$0")/.."
if [ -f .env ]; then
  echo ".env already exists, not touching it"
  exit 0
fi
umask 077
{
  echo "POSTGRES_SUPERUSER_PASSWORD=$(openssl rand -hex 24)"
  echo "VAULT_ADMIN_BOOTSTRAP_PASSWORD=$(openssl rand -hex 24)"
  echo "VAULT_ROOT_TOKEN=$(openssl rand -hex 20)"
} > .env
echo ".env created (mode 600)"
