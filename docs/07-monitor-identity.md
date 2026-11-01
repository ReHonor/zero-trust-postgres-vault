# 07 - The monitor identity (least privilege for the dashboard)

## Goal
Give the future dashboard its own identity that can show who is connected, which temporary users exist and who holds which privileges, but never customer data or SQL text.

## Why not pg_monitor
The built-in `pg_monitor` includes `pg_read_all_stats`, which exposes the query text (with its literal values) of every session. That would break least privilege.

## Design
- `monitor_ro` (NOLOGIN group) with CONNECT on appdb and USAGE on the `monitor` schema only. No access to the public schema.
- `monitor.temp_users`, `monitor.group_members`, `monitor.privileges` are views over public catalog metadata.
- `monitor.sessions()` is a SECURITY DEFINER function returning usename, application_name, client_addr, state, backend_start of all client sessions, and no query text. A view cannot do this: views do not change current_user, and pg_stat_activity masks other users' state, backend_start and client_addr for unprivileged roles. Hardening of the definer function: pinned search_path, EXECUTE revoked from PUBLIC and granted to monitor_ro only.
- Vault: policy `monitor` (read database/creds/monitor, list/read database/roles), AppRole `monitor`, dynamic role `monitor` with TTL 10 m (max 1 h) because a dashboard should not create a database user per page load.
- vault_admin can add members to monitor_ro (ADMIN) but can neither inherit nor SET ROLE into it.

## Verification
- The monitor's temporary user reads the four monitoring objects.
- SELECT on public.customers: permission denied for schema public.
- Direct pg_stat_activity: state and backend_start are NULL for other users' sessions.
- CREATE TABLE in the monitor schema: permission denied.
- Full cycle reset -> start -> demo repeated with the new init script.
