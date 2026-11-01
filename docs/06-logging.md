# 06 - Log pipeline for monitoring

## Goal
Make PostgreSQL's audit and security events available to a read-only consumer (the future dashboard) without giving it the Docker socket.

## Design
- logging_collector writes to /var/log/pg on the named volume `pglogs`: a human-readable .log (stderr format) and a .json file (jsonlog, PostgreSQL 15+) for parsing.
- Files are mode 0640, owner postgres: only the postgres group can read them. The dashboard container will join that group and mount the volume read-only.
- One file per day (`postgresql-%Y-%m-%d`); no size limit or retention policy in this lab.

## Consequences
- `docker compose logs postgres` is almost empty now; scripts/pglog.sh prints the human log, and demo.sh scenario 7 reads it from there.
- The jsonlog `statement` field of error entries is the same leak path found in docs/02 (experiment B). Consumers must use the `message` field of AUDIT entries and must not display `statement`.

## Verification
- The full cycle `scripts/reset-lab.sh` -> `start.sh` -> `demo.sh` ran from zero with the new logging.
- Log files exist with the expected owner and mode; the JSON audit line has the expected fields.
