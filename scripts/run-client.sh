#!/usr/bin/env bash
# Usage: scripts/run-client.sh <approle> <command> <vault-role> [args...]
# Plays the trusted orchestrator: fetches role_id and a fresh single-use secret_id for <approle>
# (using the root token) and starts the client container with them.
set -euo pipefail
cd "$(dirname "$0")/.."
approle="${1:?usage: run-client.sh <approle> <command> <vault-role> [args...]}"
shift
role_id=$(bash scripts/vexec.sh read -field=role_id "auth/approle/role/$approle/role-id")
secret_id=$(bash scripts/vexec.sh write -f -field=secret_id "auth/approle/role/$approle/secret-id")
docker compose run --rm --no-deps -T -e ROLE_ID="$role_id" -e SECRET_ID="$secret_id" client "$@" </dev/null
