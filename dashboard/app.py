#!/usr/bin/env python3
"""Zero-trust database dashboard (read-only).

No database password anywhere: the app logs in to Vault with AppRole (identity "monitor") and uses a
temporary database user that can only read the `monitor` schema. PostgreSQL logs come from a volume
mounted read-only. Log content is untrusted input and is always HTML-escaped."""
import csv
import glob
import hmac
import json
import os
import threading
import time
from datetime import datetime

import hvac
import psycopg2
from flask import Flask, Response, render_template_string, request

VAULT_ADDR = os.environ.get("VAULT_ADDR", "http://vault:8200")
PGHOST = os.environ.get("PGHOST", "postgres")
PGDATABASE = os.environ.get("PGDATABASE", "appdb")
CA_FILE = os.environ.get("PGSSLROOTCERT", "/certs/ca.crt")
LOG_DIR = os.environ.get("LOG_DIR", "/var/log/pg")
UI_PASSWORD = os.environ.get("DASHBOARD_PASSWORD", "")
MAX_LINES = 5000       # log lines examined per refresh
SHOW_ROWS = 60         # rows displayed per table
STMT_MAX = 90          # characters of an audited statement shown
RENEW_EVERY = 20 * 60  # renew the periodic Vault token every 20 minutes (period is 1 h)

app = Flask(__name__)


def first_line(err):
    return str(err).strip().splitlines()[0] if str(err).strip() else err.__class__.__name__


def fmt(value):
    if value is None:
        return "-"
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    return str(value)


class VaultSession:
    """AppRole login once, periodic token renewal, credential cache for the temporary database user."""

    def __init__(self):
        self.lock = threading.Lock()
        self.client = None
        self.error = None
        self.cred = None
        try:
            self._login()
        except Exception as err:  # keep the app up and show the reason instead of crash-looping
            self.error = "Vault login failed: " + first_line(err)
        threading.Thread(target=self._renew_loop, daemon=True).start()

    def _login(self):
        client = hvac.Client(url=VAULT_ADDR)
        client.auth.approle.login(role_id=os.environ["ROLE_ID"], secret_id=os.environ["SECRET_ID"])
        self.client = client
        self.error = None

    def _renew_loop(self):
        while True:
            time.sleep(RENEW_EVERY)
            if self.client is None:
                continue
            try:
                self.client.auth.token.renew_self()
                self.error = None
            except Exception as err:
                self.error = "Vault token renewal failed: " + first_line(err)

    def _require_client(self):
        if self.client is None:
            raise RuntimeError(self.error or "not logged in to Vault")
        return self.client

    def db_credentials(self):
        """A temporary database user, reused until about 60 s before its lease ends."""
        with self.lock:
            now = time.time()
            if self.cred and self.cred["expires_at"] - now > 60:
                return self.cred
            resp = self._require_client().secrets.database.generate_credentials(
                name="monitor", mount_point="database")
            self.cred = {
                "user": resp["data"]["username"],
                "password": resp["data"]["password"],
                "expires_at": now + resp["lease_duration"],
            }
            return self.cred

    def vault_roles(self):
        db = self._require_client().secrets.database
        out = []
        for name in sorted(db.list_roles(mount_point="database")["data"]["keys"]):
            d = db.read_role(name, mount_point="database")["data"]
            out.append([name, d.get("db_name"), ttl(d.get("default_ttl")), ttl(d.get("max_ttl"))])
        return {"cols": ["vault role", "database", "default TTL", "max TTL"], "rows": out}


vault = VaultSession()


def ttl(value):
    try:
        value = int(value)
    except (TypeError, ValueError):
        return fmt(value)
    if value % 3600 == 0:
        return f"{value // 3600}h"
    if value % 60 == 0:
        return f"{value // 60}m"
    return f"{value}s"


PANELS = {
    "temp_users": "SELECT rolname, rolvaliduntil, expired FROM monitor.temp_users ORDER BY rolvaliduntil DESC LIMIT 30",
    "sessions": "SELECT usename, application_name, client_addr::text, state, backend_start FROM monitor.sessions() ORDER BY backend_start DESC LIMIT 30",
    "members": "SELECT grp, member, admin_option, inherit_option, set_option FROM monitor.group_members ORDER BY 1, 2",
    "privileges": "SELECT object, col, grantee, privilege_type FROM monitor.privileges ORDER BY 1, 2, 3, 4",
}


def db_panels():
    cred = vault.db_credentials()
    conn = psycopg2.connect(host=PGHOST, dbname=PGDATABASE, user=cred["user"], password=cred["password"],
                            sslmode="verify-full", sslrootcert=CA_FILE, connect_timeout=5)
    try:
        conn.autocommit = True
        panels = {}
        with conn.cursor() as cur:
            for name, sql in PANELS.items():
                cur.execute(sql)
                panels[name] = {"cols": [d[0] for d in cur.description],
                                "rows": [[fmt(v) for v in row] for row in cur.fetchall()]}
        return panels
    finally:
        conn.close()


def tail_lines(path, max_bytes=2_000_000):
    size = os.path.getsize(path)
    with open(path, "rb") as fh:
        fh.seek(max(0, size - max_bytes))
        data = fh.read()
    lines = data.decode("utf-8", "replace").splitlines()
    return lines[1:] if size > max_bytes else lines  # the first line may be cut in half


def read_log_records():
    files = sorted(glob.glob(os.path.join(LOG_DIR, "postgresql-*.json")), reverse=True)[:2]
    chunks = [tail_lines(p) for p in reversed(files)]  # oldest file first
    lines = [line for chunk in chunks for line in chunk][-MAX_LINES:]
    for line in lines:
        try:
            yield json.loads(line)
        except ValueError:
            continue


def summarize(show_own):
    audit, events, counts = [], [], {}
    for rec in read_log_records():
        msg = rec.get("message") or ""  # never rec["statement"]: it can carry passwords (docs/02)
        user = rec.get("user") or "-"
        when = (rec.get("timestamp") or "")[:23]
        if msg.startswith("AUDIT: SESSION,"):
            if user.startswith("v-approle-monitor-") and not show_own:
                continue
            try:
                row = next(csv.reader([msg[len("AUDIT: "):]]))
            except Exception:
                continue
            row += [""] * (9 - len(row))
            stmt = " ".join(row[7].split())
            if len(stmt) > STMT_MAX:
                stmt = stmt[:STMT_MAX] + "..."
            audit.append([when, user, row[3], row[4], row[6] or "-", stmt])
            counts["audit events"] = counts.get("audit events", 0) + 1
        elif rec.get("error_severity") in ("ERROR", "FATAL", "PANIC"):
            low = msg.lower()
            if "permission denied" in low or "must be owner" in low:
                kind = "denied"
            elif "password authentication failed" in low:
                kind = "failed login"
            elif "pg_hba.conf rejects" in low:
                kind = "rejected"
            elif "terminating connection due to administrator command" in low:
                kind = "revoked"
            else:
                kind = "error"
            events.append([when, user, kind, rec.get("error_severity"), msg[:200]])
            counts[kind] = counts.get(kind, 0) + 1
    return {"cols": ["time (UTC)", "user", "class", "command", "object", "statement (truncated)"],
            "rows": audit[-SHOW_ROWS:][::-1]}, \
           {"cols": ["time (UTC)", "user", "kind", "severity", "message"],
            "rows": events[-SHOW_ROWS:][::-1]}, counts


@app.before_request
def require_login():
    if request.path == "/healthz":
        return None
    if not UI_PASSWORD:
        return Response("dashboard password not configured", 503)
    auth = request.authorization
    if not (auth and auth.username == "viewer"
            and hmac.compare_digest((auth.password or "").encode(), UI_PASSWORD.encode())):
        return Response("Login required", 401, {"WWW-Authenticate": 'Basic realm="zero-trust dashboard"'})
    return None


@app.after_request
def security_headers(resp):
    resp.headers["Content-Security-Policy"] = (
        "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; "
        "form-action 'none'; frame-ancestors 'none'")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


@app.route("/healthz")
def healthz():
    return "ok"


TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="refresh" content="15">
<title>Zero-trust database dashboard</title>
<style>
 body{font:14px/1.4 system-ui,sans-serif;margin:0;background:#0f172a;color:#e2e8f0}
 header{padding:16px 24px;background:#111c34;border-bottom:1px solid #1e293b}
 h1{margin:0;font-size:18px} h2{font-size:15px;margin:0 0 8px}
 main{padding:16px 24px;display:grid;gap:16px}
 section{background:#111c34;border:1px solid #1e293b;border-radius:8px;padding:12px 16px;overflow-x:auto}
 table{border-collapse:collapse;width:100%} th,td{text-align:left;padding:4px 8px;border-bottom:1px solid #1e293b;white-space:nowrap}
 th{color:#94a3b8;font-weight:600}
 .cards{display:flex;gap:12px;flex-wrap:wrap}
 .card{background:#111c34;border:1px solid #1e293b;border-radius:8px;padding:8px 14px}
 .card b{display:block;font-size:20px}
 .err{background:#7f1d1d;padding:8px 12px;border-radius:6px}
 .muted{color:#94a3b8}
 a{color:#93c5fd}
</style></head><body>
<header><h1>Zero-trust database dashboard</h1>
<div class="muted">Read-only. Times are UTC. Refreshes every 15 s. Identity: Vault AppRole "monitor" (temporary database user, monitor schema only).</div></header>
<main>
{% for e in errors %}<div class="err">{{ e }}</div>{% endfor %}
<div class="cards">
{% for k, v in counts.items() %}<div class="card"><b>{{ v }}</b><span class="muted">{{ k }}</span></div>{% endfor %}
<div class="card muted">counted over the last ~{{ max_lines }} log lines</div>
</div>
{% macro table(p) %}
<table><tr>{% for c in p.cols %}<th>{{ c }}</th>{% endfor %}</tr>
{% for r in p.rows %}<tr>{% for v in r %}<td>{{ v }}</td>{% endfor %}</tr>
{% else %}<tr><td class="muted">no rows</td></tr>{% endfor %}</table>
{% endmacro %}
<section><h2>Security events: who tried and failed (PostgreSQL error log)</h2>{{ table(events) }}</section>
<section><h2>Audit trail: who did what (pgaudit)</h2>{{ table(audit) }}
<p class="muted">The dashboard's own queries are hidden. {% if show_own %}<a href="/">hide them</a>{% else %}<a href="/?own=1">show them</a>{% endif %}</p></section>
{% if panels %}
<section><h2>Temporary database users</h2>{{ table(panels.temp_users) }}</section>
<section><h2>Connected sessions (no query text)</h2>{{ table(panels.sessions) }}</section>
<section><h2>Group membership</h2>{{ table(panels.members) }}</section>
<section><h2>Table and column privileges</h2>{{ table(panels.privileges) }}</section>
{% endif %}
{% if vault_roles %}<section><h2>Vault dynamic credential roles</h2>{{ table(vault_roles) }}</section>{% endif %}
</main></body></html>"""


@app.route("/")
def index():
    show_own = request.args.get("own") == "1"
    errors, panels, vault_roles = [], None, None
    audit = events = {"cols": [], "rows": []}
    counts = {}
    try:
        panels = db_panels()
    except Exception as err:
        errors.append("Database panels unavailable: " + first_line(err))
    try:
        vault_roles = vault.vault_roles()
    except Exception as err:
        errors.append("Vault panel unavailable: " + first_line(err))
    try:
        audit, events, counts = summarize(show_own)
    except Exception as err:
        errors.append("Log panels unavailable: " + first_line(err))
    if vault.error:
        errors.append(vault.error)
    return render_template_string(TEMPLATE, errors=errors, panels=panels, vault_roles=vault_roles,
                                  audit=audit, events=events, counts=counts, show_own=show_own,
                                  max_lines=MAX_LINES)
