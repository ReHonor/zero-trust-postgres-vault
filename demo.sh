#!/usr/bin/env bash
# Seven scenarios. Each one: attacker goal -> what they try -> what stops it.
# Optional: PAUSE=1 bash demo.sh   waits for Enter between scenarios (for presenting).
set -euo pipefail
cd "$(dirname "$0")"
RC="bash scripts/run-client.sh"
START=$(date -u "+%Y-%m-%d %H:%M:%S")

banner() { printf '\n==============================================================\n %s\n==============================================================\n' "$1"; }
say()    { printf '   %-14s %s\n' "$1" "$2"; }
pause()  { if [ "${PAUSE:-0}" = "1" ]; then read -r -p "   [Enter for the next scenario] " _ </dev/tty; fi; }

if [ "$(docker inspect -f '{{.State.Health.Status}}' zt-vault 2>/dev/null || echo none)" != "healthy" ] \
   || ! bash scripts/vexec.sh read database/config/appdb >/dev/null 2>&1; then
  echo "Vault is not running or not configured. Run:  bash start.sh"
  exit 1
fi

banner "1. Every request gets its own temporary identity"
say "Attacker goal:" "find a reusable database password"
say "Attempt:" "the app asks twice; we compare the usernames"
say "Result:" "two different users, TLS is really used"
$RC analyst whoami analyst
$RC analyst whoami analyst
pause

banner "2. Least privilege: the read-only analyst"
say "Attacker goal:" "read national IDs and tamper with orders using the analyst credential"
say "Attempt:" "SELECT orders, SELECT national_id, UPDATE orders"
say "Stopped by:" "PostgreSQL column-level and table-level privileges"
$RC analyst sql analyst "SELECT id, product, amount_mad FROM orders LIMIT 3" "SELECT national_id FROM customers LIMIT 1" "UPDATE orders SET amount_mad = 0"
pause

banner "3. A compromised app (think SQL injection) can work but cannot destroy"
say "Attacker goal:" "wipe or alter the database through the application"
say "Attempt:" "INSERT, DELETE, DROP TABLE with the app credential"
say "Stopped by:" "the app role has no DELETE and does not own the tables"
$RC app sql app "INSERT INTO orders (customer_id, product, amount_mad) VALUES (1, 'Cable', 99.90)" "DELETE FROM orders" "DROP TABLE orders"
pause

banner "4. Identity isolation: the app cannot ask for admin rights"
say "Attacker goal:" "escalate from the app identity to the admin identity"
say "Attempt:" "log in as the app, then request database/creds/admin"
say "Stopped by:" "Vault policy (the request never reaches the database)"
$RC app ask app admin
pause

banner "5. Plaintext is refused"
say "Attacker goal:" "sniff credentials and data on the network"
say "Attempt:" "connect with sslmode=disable"
say "Stopped by:" "pg_hba.conf: only hostssl rules allow logins"
$RC analyst plaintext analyst
pause

banner "6. A stolen credential dies by itself"
say "Attacker goal:" "reuse a leaked database password later"
say "Attempt:" "steal it, wait past the 30 s lease, log in again (about 40 s)"
say "Stopped by:" "Vault revocation plus VALID UNTIL. In the old setup this password would work for months"
$RC analyst stolen analyst
pause

banner "7. Accountability: who did what, from the PostgreSQL audit log"
say "Attacker goal:" "act without leaving a trace"
say "Evidence:" "pgaudit lines of this demo, tied to the unique temporary usernames"
bash scripts/pglog.sh | awk -v s="$START" '$0 >= s' | grep "AUDIT" | grep "user=v-approle" | tail -14 | cut -c1-230 || true
echo
echo "Trace any line back: Vault audit log (request) -> v-approle-<identity>-... (username) -> exact SQL (pgaudit)."
