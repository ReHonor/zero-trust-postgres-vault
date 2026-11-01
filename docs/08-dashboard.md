# 08 - Web dashboard (read-only monitoring)

## Goal
A browser view of who did what, who tried and failed, which temporary users exist and who holds which privileges, without breaking the zero-trust rules of the rest of the project.

## Design
- Flask + gunicorn (one worker), in a hardened container: read-only filesystem, tmpfs /tmp, all capabilities dropped, no-new-privileges, only ca.crt and the PostgreSQL log volume (read-only) mounted, port bound to 127.0.0.1 and reached through an SSH tunnel.
- No password in the code. It logs in to Vault with the `monitor` AppRole and uses a temporary database user (TTL 10 m, reused until 60 s before expiry) that can only read the `monitor` schema (docs/07).
- The AppRole `monitor` issues a periodic token (1 h, renewed every 20 min by the app) because the single-use secret_id allows only one login and a dashboard must outlive the normal 10-minute token. Restarting the dashboard needs a fresh secret_id: scripts/run-dashboard.sh does that (restart policy is "no" for the same reason).
- Logs: reads postgresql-*.json from the shared volume, in group 999 (postgres) so the 0640 files stay private. Audit panel: pgaudit entries. Security panel: ERROR/FATAL entries classified as denied, failed login, rejected by pg_hba, revoked, error. Only the `message` field is used, never `statement` (docs/02, experiment B).
- Login: HTTP Basic, random password in .env, constant-time comparison; fail closed when no password is configured. Acceptable behind an SSH tunnel; production would use SSO/OIDC.
- Logs are untrusted input: Jinja autoescaping plus a strict Content-Security-Policy (default-src 'none'), nosniff, no-store, no-referrer.

## Verification
- 401 without or with a wrong password, 200 with the right one, /healthz public and data-free.
- After demo.sh the panels show denied attempts, the failed login, the pg_hba rejection, revocations and the monitor's own temporary user.
- Injection test: a session with application_name `<b>xss</b>` is shown as escaped text, never rendered.
- The dashboard container's logs contain no secrets.

## Limitations
- Plain HTTP between the dashboard and Vault inside the Docker network (dev mode); HTTP Basic over the SSH tunnel only.
- Log window of about 5000 lines, no retention, no search, no alerting (next: monitoring script).
- After `start.sh` or a Vault restart, run scripts/run-dashboard.sh again.
