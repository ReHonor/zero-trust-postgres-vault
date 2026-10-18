# 02 - Hardened PostgreSQL

## Goal
PostgreSQL 16 that only accepts TLS + SCRAM connections, audits every action and enforces least privilege.

## Components
| File | Role |
|---|---|
| postgres/Dockerfile | postgres:16 + pgaudit |
| postgres/pg-entrypoint.sh | copies TLS files, sets owner postgres and mode 0600 on the key, then starts PostgreSQL |
| postgres/pg_hba.conf | host-based authentication (first match wins) |
| postgres/init.sql | roles, sample data, grants |
| postgres/initdb/01-init.sh | runs init.sql once, password passed as a psql variable |
| docker-compose.yml | service, flags, healthcheck, localhost-only port |
| scripts/gen-env.sh | generates random secrets into .env (git-ignored) |

## Roles
| Role | Type | Rights |
|---|---|---|
| app_rw | group | SELECT/INSERT/UPDATE on customers, orders; no DELETE, no DDL |
| analyst_ro | group | SELECT on orders; SELECT on customers(id, full_name, city) only |
| dba_admin | group | all privileges on the schema |
| vault_admin | login, CREATEROLE | manages group membership only (INHERIT FALSE), not a superuser |
| postgres | superuser | local socket only; remote login rejected |

## Verification results
- ssl=on, password_encryption=scram-sha-256, pgaudit preloaded
- TLS connection with sslmode=verify-full succeeds
- Superuser over the network: rejected by pg_hba.conf
- Plaintext (sslmode=disable): rejected
- Hostname not in SAN: rejected by verify-full
- vault_admin cannot read customer data

## Lessons and gotchas
- The TLS private key must be owned by postgres with mode 0600, hence the entrypoint wrapper.
- Init scripts run only on an empty data volume (`docker compose down -v` to re-run).
- During first init a temporary server listens on the socket only, so the healthcheck uses TCP.
- Inserting into serial columns needs USAGE on the sequences.
- pgaudit may log statement text including passwords: protect log access (see limitations).

## Security finding: password in the audit log
- Symptom: `docker compose logs postgres | grep -ci "create role.*password"` returned 1.
- Cause: psql substitutes `:'vault_admin_password'` on the client side, so the server audits the full `CREATE ROLE ... PASSWORD '<value>'` statement, password included. The `<not logged>` suffix in a pgaudit line refers to bind parameters, not to literals in the statement text.
- Fix: `SET pgaudit.log = 'none'` just before that statement and `RESET pgaudit.log` right after. Secrets were regenerated and the volume recreated, and the leak count is now 0.
- Residual risk: the bootstrap password is replaced by Vault (`rotate-root`) in Phase 3. Dynamic passwords created by Vault will need the same care (see Phase 3).

## Operational notes
- The healthcheck logs a `connection received` line with `user=[unknown]` every few seconds when `log_connections=on`. Monitoring must filter these.
- Never regenerate `.env` without `docker compose down -v`: the password stored in the data volume would no longer match.

## Troubleshooting: "password authentication failed" after regenerating secrets
- Symptom: `vault_admin` login failed right after `.env` was regenerated and the volume recreated.
- Cause: Docker Compose gives variables exported in the shell priority over `.env`. The shell still held the old passwords from an earlier `. ./.env`, so the database was initialised with the old values.
- Diagnosis: compare a short sha256 prefix of the variable inside the container (`printenv`) with the one in `.env`. Never print the secret itself.
- Fix: `unset` the variables, `docker compose down -v`, `docker compose up -d --build`. Tests read the password from the container's own environment instead of exporting secrets into the interactive shell.
- Lesson: a negative test is only meaningful if the matching positive control passes.

## Layered denial: schema before table
- `vault_admin` running `SELECT * FROM customers` gets `permission denied for schema public`, not a table error. PostgreSQL checks database CONNECT, then schema USAGE, then table privileges, then column privileges. The REVOKE on the schema is a second wall in front of the table grants.

## Finding: INHERIT FALSE does not prevent SET ROLE
- In PostgreSQL 16 a role grant has three options: ADMIN, INHERIT, SET. With INHERIT FALSE alone, `vault_admin` could still run `SET ROLE analyst_ro` and read data.
- Fix: `GRANT ... TO vault_admin WITH ADMIN TRUE, INHERIT FALSE, SET FALSE` (also in init.sql). Verified: `SET ROLE` now fails with `permission denied to set role`.
- Remaining limit: ADMIN OPTION lets vault_admin grant these three groups to other roles. A compromised Vault DB account has no superuser powers and is confined to the three groups, but it is not unable to reach their data.
