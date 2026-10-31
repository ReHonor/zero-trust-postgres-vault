#!/usr/bin/env bash
# Usage: scripts/db-as.sh <vault-role> "<SQL>" ["<SQL>" ...]
# Gets a fresh dynamic credential for the Vault role, then runs each SQL statement
# over a verify-full TLS connection as that temporary user.
set -euo pipefail
cd "$(dirname "$0")/.."
role="${1:?usage: db-as.sh <analyst|app|admin> \"SQL\" ...}"
shift
: "${1:?at least one SQL statement is required}"

creds=$(bash scripts/vexec.sh read -format=json "database/creds/$role")
user=$(printf '%s' "$creds" | python3 -c 'import sys,json; print(json.load(sys.stdin)["data"]["username"])')
pass=$(printf '%s' "$creds" | python3 -c 'import sys,json; print(json.load(sys.stdin)["data"]["password"])')

args=()
for q in "$@"; do args+=(-c "$q"); done

docker compose exec -T -e PGPASSWORD="$pass" postgres \
  psql "host=postgres dbname=appdb user=$user sslmode=verify-full sslrootcert=/etc/postgresql-certs/ca.crt" \
  "${args[@]}" </dev/null
