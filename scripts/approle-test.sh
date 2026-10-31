#!/usr/bin/env bash
# Logs in to Vault with AppRole as <role> (no root token involved), then tries each credential path.
set -euo pipefail
cd "$(dirname "$0")/.."
role="${1:?usage: approle-test.sh <analyst|app|admin>}"
VADDR=http://127.0.0.1:8200

jget() { python3 -c '
import sys, json
d = json.load(sys.stdin)
for k in sys.argv[1].split("."):
    d = d[k]
print(d)' "$1"; }

# In production a trusted orchestrator delivers these two values. Here the root token plays that role.
role_id=$(bash scripts/vexec.sh read -field=role_id "auth/approle/role/$role/role-id")
secret_id=$(bash scripts/vexec.sh write -f -field=secret_id "auth/approle/role/$role/secret-id")

body="{\"role_id\":\"$role_id\",\"secret_id\":\"$secret_id\"}"
login=$(curl -sS -X POST "$VADDR/v1/auth/approle/login" -d "$body")
token=$(printf '%s' "$login" | jget auth.client_token)
echo "Logged in as AppRole '$role', token policies: $(printf '%s' "$login" | jget auth.policies)"

for p in analyst app admin; do
  code=$(curl -sS -o /dev/null -w '%{http_code}' -H "X-Vault-Token: $token" "$VADDR/v1/database/creds/$p")
  echo "  read database/creds/$p -> HTTP $code"
done

code=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$VADDR/v1/auth/approle/login" -d "$body")
echo "  replaying the same secret_id -> HTTP $code (expected 400: single use)"
