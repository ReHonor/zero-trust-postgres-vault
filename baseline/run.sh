#!/usr/bin/env bash
# Usage: baseline/run.sh up | audit | audit-hardened | down
set -euo pipefail
cd "$(dirname "$0")/.."
DC="docker compose -f baseline/docker-compose.baseline.yml --env-file baseline/.env.baseline"
case "${1:-}" in
  up)
    $DC build attacker </dev/null
    $DC up -d </dev/null
    for _ in $(seq 1 60); do
      docker exec zt-baseline-db pg_isready -U app -d appdb -h 127.0.0.1 </dev/null >/dev/null 2>&1 && break
      sleep 2
    done
    docker cp certs/ca.crt zt-baseline-attacker:/tmp/ca.crt
    echo "baseline up: no host ports, reachable only from the attacker container" ;;
  audit)          bash baseline/audit.sh ;;
  audit-hardened) bash baseline/audit-hardened.sh ;;
  down)           $DC down -v --remove-orphans </dev/null ;;
  *) echo "usage: baseline/run.sh up|audit|audit-hardened|down"; exit 1 ;;
esac
