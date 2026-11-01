#!/usr/bin/env bash
# Prints PostgreSQL's human-readable server log (the files in the pglogs volume).
cd "$(dirname "$0")/.."
docker compose exec -T postgres sh -c 'cat /var/log/pg/postgresql-*.log' </dev/null
