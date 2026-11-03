#!/usr/bin/env python3
"""Read PostgreSQL JSON logs from stdin and summarize a recent window."""
import argparse
from pathlib import Path
import csv
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
import os
import time

p = argparse.ArgumentParser(description=__doc__)
p.add_argument("--minutes", type=int, default=5)
p.add_argument("--select-threshold", type=int, default=20)
p.add_argument("--timezone", default="UTC")
p.add_argument("--start-hour", type=int, choices=range(24), default=8)
p.add_argument("--end-hour", type=int, choices=range(24), default=18)
p.add_argument("--include-monitor", action="store_true")
a = p.parse_args()
if a.minutes < 1 or a.select_threshold < 1:
    p.error("window and threshold must be positive")
if a.start_hour == a.end_hour:
    p.error("start and end hours must differ")
zone = Path("/usr/share/zoneinfo") / a.timezone
if (a.timezone.startswith("/") or ".." in a.timezone.split("/")
        or not zone.is_file()):
    p.error("unknown timezone")
os.environ["TZ"] = a.timezone
time.tzset()

now = datetime.now(timezone.utc)
cutoff = now - timedelta(minutes=a.minutes)
failed = Counter()
offhours = defaultdict(set)
selects = defaultdict(set)
valid = malformed = recent = audit_rows = 0

for raw in sys.stdin:
    if not raw.strip():
        continue
    try:
        r = json.loads(raw)
        stamp = r["timestamp"].replace(" UTC", "+00:00").replace("Z", "+00:00")
        t = datetime.fromisoformat(stamp)
        if t.tzinfo is None:
            raise ValueError("timestamp lacks timezone")
        msg = r.get("message", "")
        user = r.get("user") or "(unknown)"
        if not isinstance(msg, str) or not isinstance(user, str):
            raise ValueError("unexpected field type")
    except (ValueError, TypeError, KeyError, AttributeError):
        malformed += 1
        continue
    valid += 1
    if not cutoff <= t <= now:
        continue
    recent += 1
    if r.get("error_severity") == "FATAL" and (
        "password authentication failed" in msg
        or "pg_hba.conf rejects connection" in msg
        or "no pg_hba.conf entry" in msg
    ):
        failed[user] += 1
    if not msg.startswith("AUDIT: "):
        continue
    audit_rows += 1
    if user.startswith("v-approle-monitor-") and not a.include_monitor:
        continue
    try:
        row = next(csv.reader([msg[len("AUDIT: "):]]))
        if len(row) < 5:
            raise ValueError("short audit record")
        identity = r.get("session_id") or str(r.get("pid", ""))
        key = (identity, row[0], row[1], row[2])
        command = row[4].upper()
    except (ValueError, csv.Error, StopIteration):
        malformed += 1
        continue
    if command == "SELECT":
        selects[user].add(key)
    hour = t.astimezone().hour
    if a.start_hour < a.end_hour:
        working = a.start_hour <= hour < a.end_hour
    else:
        working = hour >= a.start_hour or hour < a.end_hour
    if not working:
        offhours[user].add(key)

print(f"Window UTC: {cutoff.isoformat()} to {now.isoformat()}")
print(f"Working hours: {a.start_hour:02}:00-{a.end_hour:02}:00 {a.timezone}")
print(f"Records: valid={valid}, recent={recent}, audit={audit_rows}, malformed={malformed}")
alerts = 0

def emit(kind, user, count):
    global alerts
    alerts += 1
    print(f"ALERT {kind} user={json.dumps(user)} count={count}")

for user, count in sorted(failed.items()):
    emit("AUTH_FAILURE", user, count)
for user, statements in sorted(offhours.items()):
    emit("OFF_HOURS", user, len(statements))
for user, statements in sorted(selects.items()):
    if len(statements) >= a.select_threshold:
        emit("HIGH_SELECT_COUNT", user, len(statements))

if not valid:
    print("ERROR: no valid timestamped JSON records received", file=sys.stderr)
    sys.exit(2)
if malformed:
    print("ERROR: malformed records; report may be incomplete", file=sys.stderr)
    sys.exit(2)
if not recent:
    print("INFO: no records in this window; detection was not exercised")
elif not alerts:
    print("No configured alert thresholds matched.")
sys.exit(1 if alerts else 0)
