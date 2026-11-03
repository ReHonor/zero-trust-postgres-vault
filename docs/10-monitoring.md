# PostgreSQL log monitoring

## Usage

Run from the project directory:

    bash scripts/monitor.sh --minutes 5
    bash scripts/monitor.sh --minutes 15 --select-threshold 20
    bash scripts/monitor.sh --timezone Africa/Casablanca --start-hour 8 --end-hour 18
    python3 scripts/monitor-test.py

Defaults: five-minute window, SELECT threshold 20, working hours
08:00 inclusive to 18:00 exclusive in UTC. Overnight hours are supported.
Choose hours and timezone appropriate to the deployment.

Exit codes:
- 0: no configured alerts, including a window with no recent records.
- 1: at least one alert.
- 2: log-read, parsing or configuration error.

## Detection rules

- AUTH_FAILURE: selected FATAL authentication failures, including rejected
  pg_hba connections and failed password authentication.
- OFF_HOURS: audited statements outside configured working hours.
- HIGH_SELECT_COUNT: distinct audited SELECT statement/substatement
  identifiers per username within the window meet the threshold.
  This counts statements, not returned rows or transferred bytes.

Repeated relation entries for one audit statement are deduplicated.
Dashboard SQL from usernames beginning v-approle-monitor- is excluded
by default. Use --include-monitor to include it.
Dashboard authentication failures remain included.

Output contains timestamps, usernames and counts, rather than SQL text
or passwords. Protect usernames and monitoring output as operational data.

## Verified behavior - 2026-11-03

A successful analyst SELECT and an intentional failed login were generated.
With a test threshold of one SELECT and working hours excluding the test
time, the monitor reported:
- AUTH_FAILURE for zt-monitor-test-invalid, count 1.
- OFF_HOURS for the temporary analyst, count 1.
- HIGH_SELECT_COUNT for the same analyst, count 1.
- Additional off-hours Vault administration activity.
- Zero malformed records and exit code 1.

Nine synthetic tests passed: relation-entry deduplication, SELECT threshold,
old-event exclusion, dashboard exclusion, optional dashboard inclusion,
dashboard authentication failure detection, off-hours detection, empty
input rejection and malformed input rejection.

## Operation and limitations

This is an on-demand report, not a background service or notification system.
It scans retained PostgreSQL JSON files through Docker, filters by timestamp
and holds recent statement identifiers in memory.
It needs Docker access but no database password or Vault token.
Docker access itself is privileged host access.

Repeated runs with overlapping windows can repeat alerts.
A zero-alert result is not proof of complete logging or absence of attacks.
The record counters help show whether the window contained audit activity.
A partially written JSON record can cause an incomplete-report error;
retry after the write finishes and investigate persistent failures.

Short-lived usernames can spread activity across identities.
SELECT frequency alone does not detect large result sets or all exfiltration.
Off-hours administration can be legitimate and needs human interpretation.
Logs remain local and are not tamper-proof.

Python 3.8 compatibility uses Ubuntu's installed timezone database through
TZ and time.tzset(), rather than Python 3.9's zoneinfo module.
