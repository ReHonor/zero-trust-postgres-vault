# Project progress

- [x] Phase 0: VM, Docker, Git, repository skeleton
- [x] Phase 1: Private CA and server certificate
- [x] Phase 2: PostgreSQL container (TLS, SCRAM, pgaudit, roles)
- [x] Phase 3: Vault (dynamic credentials, policies, AppRole, audit device, rotate-root, recovery)
- [x] Phase 4: Python client and 7-scenario demo (start.sh, demo.sh)
- [ ] Phase 5: dashboard, baseline, monitoring and CI implemented; documentation added; image vulnerability remediation remains open

## Notes
- Environment: Ubuntu VM on Oracle Cloud, Docker Engine + Compose v2

## Phase 5B verification - 2026-11-03
- Baseline deployed without published host ports.
- Repaired empty baseline/audit.sh; all seven scenarios executed.
- Confirmed plaintext data exposure, static password reuse, superuser
  operations, container command execution and missing audit configuration.
- Hardened tests confirmed certificate checks, rejected login attempts,
  and no matching plaintext SQL/customer name during a successful query.
- Findings: docs/09-baseline-findings.md.
- Remaining: Phase 5C monitoring, CI security scans, README and final packaging.

## Phase 5C verification - 2026-11-03
- On-demand JSON log monitor implemented.
- Live tests confirmed authentication, off-hours and SELECT-count alerts.
- Nine synthetic detection/filtering/error-handling tests passed.
- Python 3.8 timezone compatibility fixed.
- Documentation: docs/10-monitoring.md.
- Remaining: CI security scans, README and final packaging.

## Current handoff
- Main lab upgraded to Vault 2.2.1; restart recovery and analyst query verified.
- Isolated Vault compatibility: seven demo scenarios and eight dashboard checks passed.
- CI script tests, Gitleaks and configuration checks passed in reviewed runs.
- Container image findings remain unresolved; no all-green CI claim.
- Detailed gosu analysis deferred by choice.
- README includes architecture, operation, limitations and documentation links.
- Presentation guide: docs/13-demo-guide.md.

## Interactive web demo update
- Added a 38-scenario web runner with asynchronous results and log evidence.
- Added session-bound CSRF checks and an internal authenticated runner API.
- Protected SQL mutations use rollback; the web baseline has its own volume/network.
- Added scoped broker policy, startup integration, regression tests and CI image scan.
- Representative web scenarios passed on the VM: permitted reads and inserts,
  restricted-column denial, Vault policy denial, SecretID replay prevention,
  plaintext/wrong-host TLS rejection, credential expiry, token revocation,
  session termination, audit evidence and all three monitoring alerts.
- Baseline plaintext access and deletion-with-rollback behaved as expected.
- Fixed the form Origin check interaction by using Referrer-Policy: same-origin.
- Some of the 38 individual scenarios remain untested; existing image findings remain open.
