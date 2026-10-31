#!/usr/bin/env bash
# Runs a Vault CLI command inside the vault container, authenticated with the dev root token.
# The token is read inside the container, so it never appears in your shell, history or ps output.
# If stdin is a terminal it is NOT forwarded (otherwise pasted input gets swallowed);
# if data is piped in (e.g. policy files) it is forwarded.
set -euo pipefail
cd "$(dirname "$0")/.."
if [ -t 0 ]; then
  exec docker compose exec -T vault sh -c 'VAULT_TOKEN="$VAULT_DEV_ROOT_TOKEN_ID" exec vault "$@"' vault "$@" </dev/null
fi
exec docker compose exec -T vault sh -c 'VAULT_TOKEN="$VAULT_DEV_ROOT_TOKEN_ID" exec vault "$@"' vault "$@"
