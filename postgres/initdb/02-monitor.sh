#!/usr/bin/env bash
# Runs once, after 01-init.sh, on first start of an empty data directory.
set -euo pipefail
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -f /sql/monitor.sql
