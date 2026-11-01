#!/usr/bin/env bash
# Drops Vault-created database users whose password has expired but which Vault no longer tracks
# (for example after a dev-mode Vault restart erased its lease table).
set -euo pipefail
cd "$(dirname "$0")/.."
docker compose exec -T -u postgres postgres psql -d appdb -v ON_ERROR_STOP=1 -At <<'SQL'
DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT rolname FROM pg_roles WHERE rolname LIKE 'v-%' AND rolvaliduntil < now()
  LOOP
    PERFORM pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = r.rolname;
    EXECUTE format('DROP ROLE %I', r.rolname);
    RAISE NOTICE 'dropped expired role %', r.rolname;
  END LOOP;
END $$;
SQL
