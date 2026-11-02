#!/usr/bin/env bash
# Smoke test for the dashboard. Run on the VM. Prints PASS/FAIL per check.
set -uo pipefail
cd "$(dirname "$0")/.."
URL=http://127.0.0.1:8080
PW=$(grep -m1 '^DASHBOARD_PASSWORD=' .env | cut -d= -f2-)
fail=0
pass() { echo "PASS  $1"; }
bad()  { echo "FAIL  $1"; fail=1; }
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

[ "$(code "$URL/")" = 401 ] && pass "no login -> 401" || bad "no login -> 401"
[ "$(code -u viewer:wrong "$URL/")" = 401 ] && pass "wrong password -> 401" || bad "wrong password -> 401"
[ "$(code "$URL/healthz")" = 200 ] && pass "/healthz is public -> 200" || bad "/healthz is public -> 200"
[ "$(code -u "viewer:$PW" "$URL/")" = 200 ] && pass "right password -> 200" || bad "right password -> 200"

page=$(curl -s -u "viewer:$PW" "$URL/")
[ "$(grep -c 'class="err"' <<<"$page")" = 0 ] && pass "no error banner" || bad "error banner on the page (Vault or database problem)"
hdr=$(curl -sI -u "viewer:$PW" "$URL/")
[ "$(grep -ci '^content-security-policy' <<<"$hdr")" = 1 ] && pass "Content-Security-Policy header" || bad "Content-Security-Policy header"

# Logs are untrusted input: a session whose application_name is HTML must be shown escaped.
docker compose exec -T -u postgres postgres psql "dbname=appdb application_name='<b>xss</b>'" -c "SELECT pg_sleep(20)" </dev/null >/dev/null 2>&1 &
sleep 3
page=$(curl -s -u "viewer:$PW" "$URL/")
[ "$(grep -c '&lt;b&gt;xss&lt;/b&gt;' <<<"$page")" -ge 1 ] && pass "HTML in application_name is escaped" || bad "escaped text not found"
[ "$(grep -c '<b>xss</b>' <<<"$page")" = 0 ] && pass "HTML in application_name is not rendered" || bad "HTML was rendered (injection!)"
wait
echo "INFO  event lines on the page: $(grep -c -E 'permission denied|password authentication failed|pg_hba' <<<"$page") (run demo.sh first to generate some)"
exit $fail
