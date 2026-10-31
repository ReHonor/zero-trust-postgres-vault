# 03 - Vault and the database secrets engine (part A)

## Goal
Replace the static database password with unique, short-lived users created on demand by Vault.

## Design decisions
- Vault 1.21 line, exact tag pinned in docker-compose.yml (official image, arm64 build used on the Oracle VM). Image digest: DIGEST_PLACEHOLDER
- Dev mode (in-memory, HTTP, fixed root token) is accepted for the lab and listed as a limitation. `restart: "no"` because a restart wipes all state.
- Vault gets only `ca.crt`. It verifies PostgreSQL with `sslmode=verify-full` against hostname `postgres`.
- Connection config uses the templated URL form (`{{username}}`/`{{password}}`), which `rotate-root` requires.
- `password_authentication=scram-sha-256`: Vault hashes the password before sending it, so the cleartext never reaches the server and cannot appear in any server-side log, including the `STATEMENT:` context line written after a failed statement (see docs/02, experiments A to C). HashiCorp documents that the default can leave passwords in PostgreSQL logs as-is.
- Vault roles `analyst`, `app`, `admin` map to PostgreSQL group roles; TTL 30 s default, 5 min max (demo values).
- Revocation terminates open sessions first, then drops the role. `VALID UNTIL` is a second safety net.
- `vault/vault-setup.sh` configures Vault from the host and is re-runnable.
- `scripts/vexec.sh` runs vault commands in the container with the root token read inside the container, so the token never enters the host shell.
- `scripts/db-as.sh <role> "SQL"...` fetches a fresh credential and runs SQL as that temporary user (used for the demo scenarios).

## Verification
- `vault status`: unsealed, storage inmem.
- Saving the connection config succeeds: proves TLS verification + SCRAM login from Vault to PostgreSQL.
- `read database/creds/analyst` creates a `v-...` role; about 40 s later it no longer exists.
- analyst: reads id/full_name/city, cannot read national_id, cannot UPDATE.
- app: INSERT works; DELETE denied; DROP TABLE denied (must be owner).
- admin: reads everything, including national_id.
- pgaudit records the creation of vault_admin with the password redacted; the real password does not appear in the container logs (count 0).
- The whole lab was rebuilt from zero (`docker compose down -v`, `up -d --build`, `bash vault/vault-setup.sh`) and behaved identically.

## Troubleshooting
- `manifest for hashicorp/vault:<tag> not found`: the tag was guessed from a release note and was never published as an image. Fix: list real tags from the Docker Hub API (`/v2/repositories/hashicorp/vault/tags`) before pinning.
- Pasted multi-line blocks lose lines or merge outputs: `docker compose exec` keeps the terminal's stdin attached (even with `-T`) and swallows the rest of the pasted text. Fix: `</dev/null` (done inside vexec.sh and db-as.sh) and put sequences in script files.

## Gotchas
- `docker compose up` in the foreground: Ctrl+C stops the containers. Use `up -d` and `logs -f`.
- Dev mode prints the root token in the container logs: never share them.
- Dev-mode Vault loses everything on restart. After `rotate-root` (part B) this also means the rotated vault_admin password is lost, so a recovery procedure is needed.
- Passing the password with `docker compose exec -e` exposes it briefly in the host process list (lab only; the Python client keeps it in-process).
