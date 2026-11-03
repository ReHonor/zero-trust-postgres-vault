# Before/after security comparison

## Scope

Tests were run on 2026-11-03 using fake data.
The intentionally insecure baseline publishes no host ports.
Its database and attacker toolbox use an internal Docker network.
For hardened tests, the attacker toolbox was also connected to the
hardened network.

These tests model an attacker with internal network access.
Packet capture additionally requires privileged access to the database
container's network namespace; ordinary network membership alone does
not provide that visibility.

## Observed results

| Test | Insecure baseline | Hardened system |
|---|---|---|
| Internal discovery | TCP 5432 open | TCP 5432 open; network reachability alone does not grant database access |
| TLS | No server certificate; strict TLS connection refused; session reported ssl=false | TLS 1.3; trusted CA and correct hostname produced verification code 0 |
| Wrong hostname | No TLS identity verification available | Verification code 62: hostname mismatch |
| Static credentials | Repository password authenticated as app; sensitive national_id values readable | Network login as postgres rejected even with its real password; old vault_admin bootstrap password rejected |
| Credential lifetime | Same password worked after 40 seconds; role had no configured expiry | Analyst received a credential with a reported 30-second lease; expiry rejection must be evidenced separately by demo scenario 6 |
| Excessive privileges | app was a superuser; DELETE and DROP succeeded inside a rolled-back transaction | This audit did not repeat application privilege-denial tests; those belong to demo scenarios 2 and 3 |
| Server command and file access | COPY FROM PROGRAM ran id as postgres inside the container; server hostname file readable | Equivalent commands were not tested in this hardened audit |
| Accountability | One login role; log_statement=none; log_connections=off; no preload libraries; zero AUDIT matches | Temporary analyst username visible in client output; SQL audit attribution belongs to demo scenario 7 |
| Packet capture | 19 packets captured; SQL-text matches=2; customer-name matches=1; fake identifiers visible | Analyst query succeeded during capture; SQL-text matches=0; customer-name matches=0; capture output contained 397 lines |

## Interpretation and limits

- Both databases were discoverable from their respective internal networks.
  The hardened system relies on authentication, authorization and TLS,
  rather than treating an internal network as trusted.
- The baseline capture exposed SQL and customer data. It found zero literal
  password matches; this is not evidence that the password travelled in
  plaintext.
- The hardened capture result is consistent with encrypted traffic.
  Its 397 output lines are not a packet count and may include dashboard
  traffic. The intended analyst query also visibly succeeded.
- The OpenSSL wrong-hostname probe reported a verification error.
  This probe alone does not demonstrate that an application aborts on
  certificate errors.
- DELETE and DROP were rolled back, and all six orders were restored.
  Operating-system command execution occurred inside the database
  container as its postgres user; host compromise was not demonstrated.
- Baseline credential validity was observed for 40 seconds. No configured
  role expiry was found; this is not a claim that credentials work forever.
- Vault dev mode, HTTP access to Vault, bootstrap secrets and Docker host
  administrator access remain lab limitations.
- No universal "attacks blocked" percentage is claimed from these tests.

## Reproduction and troubleshooting

Run:
    bash baseline/run.sh up
    bash baseline/run.sh audit
    bash baseline/run.sh audit-hardened

The initial baseline/audit.sh was empty following a malformed terminal
paste. An empty file passed bash -n and produced no audit output.
It was rewritten in small blocks and checked: 70 lines, seven scenario
headings, successful syntax check and visible execution of all scenarios.

The hardened script now displays the analyst query output and stops
if that query fails, avoiding a misleading zero-match capture result.

The baseline is deliberately insecure. Keep its fake password confined
to this lab. Never reuse it for another service.
