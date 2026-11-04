# Interactive web demo

Open `/demo/` on the existing dashboard host and port. It uses the dashboard's
existing `viewer` login and current password. The page lists 38 scenarios with
normal/attack/monitoring filters, per-scenario run buttons, asynchronous progress,
results, evidence and bounded recent history. Refreshing a result does not rerun it.

## Architecture and identities

The dashboard retains its existing read-only monitor database identity. A separate
non-root demo-runner container performs the actions. It publishes no host ports,
has no Docker socket and has no Vault root token. Its API accepts only fixed
scenario IDs. The dashboard is an authenticated gateway to that internal API.

The trusted host-side `scripts/run-demo.sh` uses the existing vexec helper to
write a narrowly scoped broker policy and issue a periodic broker token. That
policy can read role IDs and generate SecretIDs for app, analyst, admin and
monitor. Each protected scenario logs in using a fresh AppRole identity and the
existing per-identity policies still authorize database credential requests.
The broker can mint these lab identities; it is a privileged lab controller,
even though it is not a root token. Only trusted lab operators should receive
the dashboard login. The shared internal API key stays on the servers.

The runner renews its broker token every 20 minutes. Stopping the runner stops
renewal; the token expires after its remaining one-hour period. Restarting
dev-mode Vault invalidates it; start.sh recreates the runner's broker token.

## Scenario behavior

- Identity: unique users, policy boundaries, single-use SecretID replay,
  invalid AppRole login and wrong database password.
- Access: analyst column restrictions, app read/insert/update permissions,
  denied DELETE/DROP/role escalation/file access/program execution, admin DDL
  and restricted monitor views.
- Transport: verified TLS and rejection of plaintext, wrong hostnames and an
  unrelated CA bundle. A verified connection is tested first.
- Lifetime: real lease expiry and token revocation affecting new and existing
  sessions. Waiting tests use background jobs; HTTP requests do not wait for them.
- Monitoring: allowed-query auditing, denied-query error logs, SELECT-count,
  failed-login and off-hours alerts from the existing monitor parser.
- Baseline: unencrypted fake data, static-password reuse after 40 seconds,
  superuser deletion with rollback and missing audit configuration.

The web baseline is a separate PostgreSQL service, separate data volume and
internal network, with no published ports. It uses the existing fake baseline
password file and seed SQL. The runner is intentionally connected to both lab
networks so it can compare the protected database with this isolated baseline.

## Outcomes and limits

Expected permission denials are distinguished from network errors and malformed
SQL. A service outage is an error, not a successful security test. Unexpected
permissions are reported as unexpected results. SQL writes and DDL use rollback;
audit records persist and sequence values can advance despite rollback. The
program-execution probe is the fixed harmless `id` command and the file probe
uses `/etc/hostname`. No arbitrary query or command entry is provided.

Each run attempts to revoke its own token afterwards; lease expiry is the
fallback if cleanup fails. Revocation affects only identities minted for that
run. The off-hours scenario uses clearly displayed test-only working hours;
it does not change the VM clock or saved monitoring policy.

POST actions require the existing login, a session-bound CSRF token and a
same-origin submission. HTML and evidence are escaped. Six runs can be queued,
two execute concurrently, and at most 100 recent run records are retained in
memory. There is no persistent job history. Leaving the page does not cancel a run.

## Operation

    bash scripts/run-demo.sh
    bash scripts/run-dashboard.sh

start.sh also starts the demo service before the dashboard. No public firewall
rule or extra SSH tunnel is required. Keep the current tunnel to port 8080.

For diagnosis:

    docker compose --profile demo ps
    docker compose --profile demo logs --tail=40 demo-runner

The runner's core regression tests run during its image build. The CI workflow
adds a runner image scan, keeping the same HIGH/CRITICAL policy and existing
image findings visible. Live validation on the VM is still required after
installing this update. This feature does not establish production readiness.
