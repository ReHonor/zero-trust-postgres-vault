# 05 - Python client and the seven-scenario demo

## Goal
An application with no database password anywhere, and a repeatable demonstration that each defense layer stops a different attack.

## The client (app/app.py)
- Inputs: ROLE_ID and SECRET_ID (the two halves of the AppRole login) and public addresses only. No password constant.
- Flow: AppRole login (hvac) -> request database/creds/<role> -> connect with psycopg2 using `sslmode=verify-full` and the CA file.
- Runs in a hardened container: read-only filesystem, all capabilities dropped, no-new-privileges, only ca.crt mounted, on-demand via a compose profile.
- scripts/run-client.sh plays the trusted orchestrator: it fetches role_id and a fresh single-use secret_id with the root token and hands them to the container. This is the "secret zero" problem in miniature; production would use platform identity and response wrapping.

## Scenarios
| # | Scenario | Result | Layer that stops it |
|---|---|---|---|
| 1 | whoami twice | two different v-approle-analyst-... users, TLSv1.3 | dynamic credentials |
| 2 | analyst reads national_id, updates orders | permission denied | PostgreSQL privileges (column/table) |
| 3 | app DELETE and DROP TABLE | permission denied / must be owner | PostgreSQL privileges |
| 4 | app requests admin credentials | 403 from Vault | Vault policy |
| 5 | connection with sslmode=disable | rejected, no encryption | pg_hba.conf (hostssl) |
| 6 | stolen credential used after the lease | password authentication failed | lease revocation + VALID UNTIL |
| 7 | audit trail | pgaudit lines with the temporary usernames | accountability |

## One-command operation
- `bash start.sh`: certificates, .env, containers, health wait, Vault setup (with automatic recovery if the rotated password was lost). Safe to re-run.
- `bash demo.sh` (`PAUSE=1` to step through).
- `bash scripts/reset-lab.sh`: destructive, back to zero. The full cycle reset -> start -> demo was tested.

## Design notes
- start.sh unsets secret variables before calling Compose, because exported shell variables beat .env.
- start.sh refuses to generate a new .env when a database volume already exists (the passwords would not match the data).

## Limitations
- Client to Vault traffic is plain HTTP inside the Docker network (dev mode): the secret_id and token cross it in clear. Production: TLS on Vault.
- No credential renewal in the client: it requests a new credential per run.
- The root token acts as the orchestrator in run-client.sh.
