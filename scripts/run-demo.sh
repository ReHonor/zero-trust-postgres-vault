#!/usr/bin/env bash
# Trusted operator setup. Root Vault access stays in vexec.sh, outside the web services.
set -euo pipefail
cd "$(dirname "$0")/.."
umask 077
python3 -m py_compile demo/engine.py demo/server.py dashboard/demo_ui.py
test -f .env || { echo 'Run bash start.sh first to create the lab.'; exit 1; }

DEMO_API_KEY=$(sed -n 's/^DEMO_API_KEY=//p' .env | head -1)
if [[ ! "$DEMO_API_KEY" =~ ^[a-f0-9]{64}$ ]]; then
  DEMO_API_KEY=$(openssl rand -hex 32)
  if grep -q '^DEMO_API_KEY=' .env; then
    sed -i "s|^DEMO_API_KEY=.*|DEMO_API_KEY=$DEMO_API_KEY|" .env
  else
    printf '\nDEMO_API_KEY=%s\n' "$DEMO_API_KEY" >> .env
  fi
fi
chmod 600 .env
export DEMO_API_KEY

echo 'Configuring the limited demo broker policy'
bash scripts/vexec.sh policy write demo-runner - < vault/policies/demo-runner.hcl
DEMO_BROKER_TOKEN=$(bash scripts/vexec.sh token create -policy=demo-runner -period=1h -orphan -field=token)
DEMO_BASELINE_PASSWORD=$(sed -n 's/^DB_PASSWORD=//p' baseline/.env.baseline | head -1)
test -n "$DEMO_BASELINE_PASSWORD" || { echo 'Fake baseline password is missing'; exit 1; }
export DEMO_BROKER_TOKEN DEMO_BASELINE_PASSWORD
trap 'unset DEMO_BROKER_TOKEN DEMO_BASELINE_PASSWORD DEMO_API_KEY' EXIT

docker compose --profile demo build demo-runner </dev/null
docker compose --profile demo up -d demo-baseline demo-runner </dev/null
for _ in $(seq 1 30); do
  if docker compose exec -T demo-runner python -c \
    "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8081/healthz',timeout=3)" \
    </dev/null >/dev/null 2>&1; then
    echo 'Demo runner ready: 38 scenarios, no published runner or baseline ports.'
    exit 0
  fi
  sleep 2
done
echo 'ERROR: demo runner did not become ready. Check docker compose --profile demo logs --tail=30 demo-runner'
exit 1
