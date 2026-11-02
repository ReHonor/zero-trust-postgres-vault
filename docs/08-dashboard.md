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

## Access
- The dashboard listens on 127.0.0.1:8080 of the VM only. From a PC: `ssh -N -L 8080:127.0.0.1:8080 -o ServerAliveInterval=30 -o ServerAliveCountMax=4 -o ExitOnForwardFailure=yes -i <key> ubuntu@<vm>` and open http://127.0.0.1:8080 (use 127.0.0.1, not localhost: on Windows localhost may resolve to IPv6 ::1, where the tunnel does not listen).
- The tunnel lives inside the SSH connection: when the connection drops (idle timeout), the tunnel dies with it. Keepalive options and a dedicated -N window prevent this.
- No Oracle security-list rule is needed: the dashboard is loopback-only and the tunnel reuses SSH. A TCP test of port 8080 from the internet fails to connect.

## Troubleshooting log
- Symptom: curl to /healthz returned 000 on the VM and nothing listened on 8080.
- Diagnosis: scripts/diag-dashboard.sh (read-only, prints no secrets) showed that the base stack, the Vault state and the compose configuration were fine, but dashboard/app.py was one line long and the container had exited with a SyntaxError. A 250-line heredoc paste had been mangled by the terminal and only a fragment of the next command remained in the file.
- Fix: app.py was rewritten in six small chunks and verified with wc -l, py_compile and a count of top-level definitions. run-dashboard.sh now runs py_compile before building, so a broken file can never be built into an image.
- Lesson: an image built from a broken file only fails at runtime. Verify the artifact before using it (syntax check, size, definition count) and keep pasted blocks small.

## Operational notes
- start.sh now starts the dashboard as its last step. After a Vault restart, scripts/run-dashboard.sh (or start.sh) issues a fresh single-use secret_id.
- Each refresh of the page runs four SELECTs as the monitor's temporary user. They appear in the audit log (hidden in the UI by default, filtered out of demo scenario 7).
- The dashboard password was rotated after being displayed during troubleshooting.
