#!/usr/bin/env bash
# Runs once, on first start of an empty data directory.
set -euo pipefail
psql -v ON_ERROR_STOP=1 \
     --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
     -v vault_admin_password="$VAULT_ADMIN_BOOTSTRAP_PASSWORD" \
     -f /sql/init.sql
