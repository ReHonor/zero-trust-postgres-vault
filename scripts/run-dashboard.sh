#!/usr/bin/env bash
# (Re)starts the dashboard with a fresh single-use secret_id for the 'monitor' AppRole.
# Run it again after every `start.sh` or Vault restart: the old secret_id is spent and the old token is gone.
set -euo pipefail
cd "$(dirname "$0")/.."
docker compose --profile dashboard build dashboard </dev/null
export DASH_ROLE_ID DASH_SECRET_ID
DASH_ROLE_ID=$(bash scripts/vexec.sh read -field=role_id auth/approle/role/monitor/role-id)
DASH_SECRET_ID=$(bash scripts/vexec.sh write -f -field=secret_id auth/approle/role/monitor/secret-id)
docker compose --profile dashboard up -d --force-recreate dashboard </dev/null
unset DASH_ROLE_ID DASH_SECRET_ID
echo
echo "Dashboard: http://127.0.0.1:8080  (user: viewer, password: DASHBOARD_PASSWORD in .env)"
echo "From your PC: ssh -i <your-key> -L 8080:127.0.0.1:8080 ubuntu@<VM_PUBLIC_IP>  then open http://localhost:8080"
