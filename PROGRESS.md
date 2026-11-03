# Project progress

- [x] Phase 0: VM, Docker, Git, repository skeleton
- [x] Phase 1: Private CA and server certificate
- [x] Phase 2: PostgreSQL container (TLS, SCRAM, pgaudit, roles)
- [x] Phase 3: Vault (dynamic credentials, policies, AppRole, audit device, rotate-root, recovery)
- [x] Phase 4: Python client and 7-scenario demo (start.sh, demo.sh)
- [ ] Phase 5: log pipeline, monitor identity and dashboard done (5A); baseline, monitoring script, CI, README pending

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
