#!/usr/bin/env bash
# Exit: 0=no alerts, 1=alerts, 2=read/parser/configuration error.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
docker compose exec -T postgres sh -c \
  'cat /var/log/pg/postgresql-*.json' </dev/null |
  python3 scripts/monitor.py "$@"
codes=("${PIPESTATUS[@]}")
if (( codes[0] != 0 )); then
  echo "ERROR: could not read PostgreSQL logs; report may be incomplete" >&2
  exit 2
fi
exit "${codes[1]}"
