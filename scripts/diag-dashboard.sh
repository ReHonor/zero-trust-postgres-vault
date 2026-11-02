#!/usr/bin/env bash
# Read-only diagnosis of the dashboard setup. Prints no secrets.
cd "$(dirname "$0")/.."
ok()   { printf '  OK       %s\n' "$1"; }
miss() { printf '  MISSING  %s\n' "$1"; }
chk()  { if eval "$2" >/dev/null 2>&1; then ok "$1"; else miss "$1"; fi; }

echo "== base stack"
for c in zt-postgres zt-vault; do
  s=$(docker inspect -f '{{.State.Health.Status}}' "$c" 2>/dev/null || echo "not created")
  [ "$s" = healthy ] && ok "$c healthy" || miss "$c is: $s"
done

echo "== files from the dashboard step"
for f in dashboard/Dockerfile dashboard/app.py dashboard/requirements.txt scripts/run-dashboard.sh scripts/dashboard-check.sh vault/policies/monitor.hcl; do
  chk "$f" "[ -s $f ]"
done
[ -s dashboard/requirements.txt ] && { echo "  requirements.txt:"; sed 's/^/             /' dashboard/requirements.txt; grep -q '==$' dashboard/requirements.txt && miss "a requirements line has an empty version"; }
[ -s dashboard/app.py ] && { python3 -m py_compile dashboard/app.py 2>/dev/null && ok "app.py compiles" || miss "app.py has a syntax error or is truncated"; echo "  app.py lines: $(wc -l < dashboard/app.py) (expected about 250)"; }

echo "== configuration"
chk "dashboard service in docker-compose.yml" "grep -q 'container_name: zt-dashboard' docker-compose.yml"
chk "compose file valid with the dashboard profile" "docker compose --profile dashboard config -q"
chk "DASHBOARD_PASSWORD in .env" "grep -q '^DASHBOARD_PASSWORD=' .env"
chk "periodic token in vault-setup.sh" "grep -q token_period vault/vault-setup.sh"
chk "monitor in vault-setup.sh" "grep -q 'admin monitor' vault/vault-setup.sh"

echo "== live Vault state"
tp=$(bash scripts/vexec.sh read -field=token_period auth/approle/role/monitor 2>/dev/null </dev/null)
[ -n "$tp" ] && ok "AppRole monitor exists, token_period=$tp" || miss "AppRole monitor (Vault was restarted or setup not re-run)"
chk "Vault dynamic role monitor" "bash scripts/vexec.sh read database/roles/monitor </dev/null"
chk "monitor_ro in PostgreSQL" "docker compose exec -T -u postgres postgres psql -d appdb -tAc \"SELECT 1 FROM pg_roles WHERE rolname='monitor_ro'\" </dev/null | grep -q 1"

echo "== image and container"
chk "image zero-trust-dashboard built" "docker image inspect zero-trust-dashboard"
if docker inspect zt-dashboard >/dev/null 2>&1; then
  docker inspect -f '  container: status={{.State.Status}} exit={{.State.ExitCode}} health={{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' zt-dashboard
  echo "  last log lines (no secrets are logged):"
  docker logs --tail 15 zt-dashboard 2>&1 | sed 's/^/             /'
else
  miss "container zt-dashboard has never been created"
fi
echo "== done"
