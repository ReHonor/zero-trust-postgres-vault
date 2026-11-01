#!/usr/bin/env bash
# DESTRUCTIVE: deletes containers, volumes (database data, audit log), .env and certificates.
set -euo pipefail
cd "$(dirname "$0")/.."
echo "This deletes ALL lab data, the secrets in .env and the certificates."
read -r -p "Type 'reset' to continue: " ans </dev/tty
[ "$ans" = "reset" ] || { echo "aborted"; exit 1; }
docker compose --profile client down -v --remove-orphans
rm -rf certs .env
echo "Clean. Now run:  bash start.sh"
