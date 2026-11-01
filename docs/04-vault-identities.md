# 04 - Vault identities, policies, audit and root rotation (part B)

## Goal
Remove the root token from day-to-day use, give every identity only the rights it needs, make every request traceable, and make the bootstrap database password useless.

## Components
| Piece | Choice |
|---|---|
| Audit device | `file` at /vault/logs/audit.log on a named volume; secrets are HMAC-SHA256 hashed. Vault fails closed if it cannot write the log |
| Policies | vault/policies/{analyst,app,admin}.hcl: read on exactly one `database/creds/<role>` path each; everything else denied |
| AppRole | one role per identity; token_ttl 5 m (max 10 m); secret_id TTL 10 m, single use |
| rotate-root | run once after the connection is verified; the .env value for vault_admin stops working |
| Recovery | scripts/reset-vault-admin.sh resets vault_admin through the local superuser socket, stores the new value in .env and re-runs the setup |

## Verification
- After setup the .env password for vault_admin is rejected by PostgreSQL ("password authentication failed"), while dynamic credentials still work.
- AppRole analyst: HTTP 200 on database/creds/analyst, 403 on app and admin; replaying a secret_id returns 400. Same pattern for app and admin.
- Temporary database users created through AppRole are named `v-approle-<role>-...`, linking the Vault identity to the SQL audit trail.
- The Vault audit log contains hashed values (hmac-sha256) and requests for each credential path; the real bootstrap password does not appear in clear (count 0).
- Restart drill: after `docker compose restart vault` the setup fails at the connection step (dead password), `scripts/reset-vault-admin.sh` restores a working state.

## Limitations and notes
- Dev-mode Vault is in-memory: a restart loses policies, AppRoles, engines and the rotated password. The recovery script depends on host access to the PostgreSQL superuser socket (a host administrator with Docker access can reach the superuser anyway).
- In this lab the root token plays the role of the trusted orchestrator that delivers role_id and secret_id (secret zero). Production would use platform identity (Kubernetes, cloud IAM) and response wrapping.
- The old bootstrap value still sits in the postgres container environment and .env until recovery rewrites it, but it no longer authenticates.
- Passwords passed to docker compose exec via -e / -v are briefly visible in the host process list (lab only).

## Finding: orphaned users after a Vault restart
- Evidence: after the restart drill, pg_roles still listed `v-approle-admin-...-1793458131`, created about 18 hours earlier. Its lease existed only in Vault's in-memory lease table, which the restart erased, so nothing revoked it.
- The second safety net held: its VALID UNTIL was in the past, so the password could not be used to log in. The role and its group membership remained.
- VALID UNTIL does not end sessions that are already open; Vault's revocation does (pg_terminate_backend). An orphan with an open session would stay connected.
- Fix: scripts/cleanup-expired-roles.sh terminates sessions and drops expired v-* roles; reset-vault-admin.sh runs it. In production, persistent Vault storage keeps the lease table across restarts.
