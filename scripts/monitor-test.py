#!/usr/bin/env python3
"""Controlled tests for monitor.py; no database access."""
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

monitor = Path(__file__).resolve().with_name("monitor.py")
stamp = datetime.now(timezone.utc) - timedelta(seconds=10)
hour = stamp.hour
working = ["--start-hour", str(hour), "--end-hour", str((hour + 1) % 24)]

def record(user="analyst-test", statement=1, when=stamp, message=None):
    return {
        "timestamp": when.isoformat(),
        "user": user,
        "session_id": "test-session",
        "error_severity": "LOG",
        "message": message or (
            "AUDIT: SESSION,%s,1,READ,SELECT,TABLE,public.customers,"
            "SELECT 1,<not logged>" % statement
        ),
    }

def run(rows, *args):
    data = "".join(json.dumps(r) + "\n" for r in rows)
    return subprocess.run(
        [sys.executable, str(monitor)] + working + list(args),
        input=data, text=True, capture_output=True,
    )

def check(name, result, code, contains=(), absent=()):
    assert result.returncode == code, (name, result.stdout, result.stderr)
    for text in contains:
        assert text in result.stdout, (name, result.stdout)
    for text in absent:
        assert text not in result.stdout, (name, result.stdout)
    print("PASS:", name)

one = record()
duplicate = dict(one)
duplicate["message"] = one["message"].replace(
    "public.customers", "public.orders"
)
check("relation entries do not double-count one statement",
      run([one, duplicate], "--select-threshold", "2"),
      0, absent=("ALERT",))

check("two distinct SELECT statements reach threshold",
      run([one, record(statement=2)], "--select-threshold", "2"),
      1, contains=('HIGH_SELECT_COUNT user="analyst-test" count=2',))

old = record(when=stamp - timedelta(hours=1))
check("old events are outside the window",
      run([old], "--select-threshold", "1"),
      0, contains=("recent=0",), absent=("ALERT",))

dashboard = record(user="v-approle-monitor-test")
check("dashboard SQL excluded by default",
      run([dashboard], "--select-threshold", "1"),
      0, absent=("ALERT",))

check("dashboard SQL can be included",
      run([dashboard], "--include-monitor", "--select-threshold", "1"),
      1, contains=("HIGH_SELECT_COUNT",))

failure = record(user="v-approle-monitor-test",
                 message="password authentication failed for user")
failure["error_severity"] = "FATAL"
check("dashboard authentication failures remain visible",
      run([failure]), 1, contains=("AUTH_FAILURE",))

off = ["--start-hour", str((hour + 1) % 24),
       "--end-hour", str((hour + 2) % 24)]
check("off-hours activity detected",
      run([one], *off), 1, contains=("OFF_HOURS",))

check("empty input is an error", run([]), 2)

bad = subprocess.run(
    [sys.executable, str(monitor)],
    input="{broken json\n", text=True, capture_output=True,
)
check("malformed input is an error", bad, 2)

print("All 9 monitoring tests passed.")
