"""Fixed, bounded lab scenarios. Never accepts SQL or commands from an HTTP caller."""
import csv
import glob
import io
import json
import os
import secrets
import socket
import ssl
import subprocess
import sys
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from urllib.error import HTTPError
from urllib.request import Request, urlopen

VAULT_ADDR = os.getenv("VAULT_ADDR", "http://vault:8200").rstrip("/")
PGHOST = os.getenv("PGHOST", "postgres")
CA_FILE = os.getenv("PGSSLROOTCERT", "/certs/ca.crt")
LOG_DIR = os.getenv("LOG_DIR", "/var/log/pg")


class VaultError(Exception):
    def __init__(self, status, operation=None):
        self.status = status
        self.operation = operation
        super().__init__("Vault request failed (HTTP %s)" % status)


class Vault:
    def __init__(self, token=None):
        self.token = token

    def call(self, method, path, data=None):
        body = None if data is None else json.dumps(data).encode()
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["X-Vault-Token"] = self.token
        req = Request(VAULT_ADDR + "/v1/" + path, data=body,
                      headers=headers, method=method)
        try:
            with urlopen(req, timeout=8) as response:
                raw = response.read(1_000_000)
        except HTTPError as error:
            raise VaultError(error.code, method + " " + path) from None
        return json.loads(raw) if raw else {}

    def revoke(self):
        self.call("POST", "auth/token/revoke-self", {})


class Broker:
    """Can only read four role IDs and issue their single-use SecretIDs."""
    def __init__(self, token):
        self.vault = Vault(token)
        self.lock = threading.Lock()

    def pair(self, role):
        if role not in {"app", "analyst", "admin", "monitor"}:
            raise ValueError("Unsupported identity")
        with self.lock:
            prefix = "auth/approle/role/" + role
            role_id = self.vault.call("GET", prefix + "/role-id")["data"]["role_id"]
            secret_id = self.vault.call("POST", prefix + "/secret-id", {})["data"]["secret_id"]
        return role_id, secret_id

    def login(self, role):
        role_id, secret_id = self.pair(role)
        return login(role_id, secret_id)


def login(role_id, secret_id):
    response = Vault().call("POST", "auth/approle/login",
                            {"role_id": role_id, "secret_id": secret_id})
    return Vault(response["auth"]["client_token"])


def connect_db(**kwargs):
    # Reuse the existing client for the normal protected-database connection.
    # Exceptional host/CA probes and the baseline need explicit libpq parameters.
    if (kwargs.get("host") == PGHOST and kwargs.get("sslrootcert") == CA_FILE
            and "hostaddr" not in kwargs
            and kwargs.get("dbname") == os.getenv("PGDATABASE", "appdb")):
        import client_lib
        conn = client_lib.connect(kwargs["user"], kwargs["password"], kwargs.get("sslmode", "verify-full"))
        try:
            with conn.cursor() as cur:
                cur.execute("SET application_name TO %s", (kwargs.get("application_name", "web-demo"),))
            return conn
        except Exception:
            conn.close()
            raise
    import psycopg2
    return psycopg2.connect(**kwargs)


class Identity:
    def __init__(self, broker, role, run_id):
        self.vault = broker.login(role)
        self.role, self.run_id = role, run_id
        self.secret = None
        self.revoked = False

    def credentials(self):
        if self.secret is None:
            self.secret = self.vault.call("GET", "database/creds/" + self.role)
        return self.secret

    def connect(self, **overrides):
        data = self.credentials()["data"]
        params = dict(host=PGHOST, dbname=os.getenv("PGDATABASE", "appdb"),
                      user=data["username"], password=data["password"],
                      sslmode="verify-full", sslrootcert=CA_FILE,
                      connect_timeout=5, application_name="web-demo:" + self.run_id[:12])
        params.update(overrides)
        return connect_db(**params)

    def revoke(self):
        self.vault.revoke()
        self.revoked = True

    def close(self):
        if not self.revoked:
            try:
                self.revoke()
            except Exception:
                pass  # Lease expiry remains the cleanup fallback; no secrets are logged.


@contextmanager
def identity(broker, role, run_id):
    actor = Identity(broker, role, run_id)
    try:
        yield actor
    finally:
        actor.close()


def result(outcome, summary, evidence=None, user=None):
    return dict(outcome=outcome, summary=summary, evidence=evidence or [], user=user)


def denied(error):
    return getattr(error, "pgcode", None) == "42501"


def authentication_failure(error):
    return "password authentication failed" in str(error).lower()


def message(error):
    # Never return connection strings, request bodies, tokens or passwords.
    primary = getattr(getattr(error, "diag", None), "message_primary", None)
    if primary:
        return str(primary).splitlines()[0][:220]
    return type(error).__name__ + " (connection or service error)"


def sql_attempt(actor, statements, should_deny=False):
    conn = None
    evidence = []
    executing_target = False
    user = actor.credentials()["data"]["username"]
    try:
        conn = actor.connect()
        conn.autocommit = False
        with conn.cursor() as cur:
            cur.execute("SET LOCAL statement_timeout = '5s'")
            for statement in statements:
                executing_target = True
                cur.execute(statement)
                if cur.description:
                    rows = cur.fetchmany(10)
                    evidence.append({"sql": statement, "rows": [[str(v) for v in row] for row in rows]})
                    if not rows:
                        return result("error", "The test returned no rows; the control was not demonstrated.", evidence, user)
                else:
                    evidence.append({"sql": statement, "status": cur.statusmessage})
        if should_deny:
            return result("unexpected", "The restricted operation was allowed. Table changes were rolled back.", evidence, user)
        return result("allowed", "The permitted operation succeeded. Table changes were rolled back.", evidence, user)
    except Exception as error:
        evidence.append({"error": message(error), "SQLSTATE": getattr(error, "pgcode", None)})
        if should_deny and executing_target and denied(error):
            return result("blocked", "PostgreSQL blocked the operation with insufficient privileges.", evidence, user)
        return result("unexpected" if denied(error) and executing_target else "error",
                      "The permitted operation was denied." if denied(error) and executing_target
                      else "The test could not be completed.", evidence, user)
    finally:
        if conn is not None:
            try:
                conn.rollback()
            finally:
                conn.close()


SQL_CASES = {
    "analyst_orders": ("analyst", False, ["SELECT id, product, amount_mad FROM orders LIMIT 3"]),
    "analyst_customers": ("analyst", False, ["SELECT id, full_name, city FROM customers LIMIT 3"]),
    "app_orders": ("app", False, ["SELECT id, product, amount_mad FROM orders LIMIT 3"]),
    "app_insert": ("app", False, ["INSERT INTO orders(customer_id, product, amount_mad) VALUES (1, 'Web demo test', 1.00) RETURNING id, product"]),
    "app_update": ("app", False, ["UPDATE orders SET amount_mad=amount_mad+1 WHERE id=1 RETURNING id, amount_mad"]),
    "admin_ddl": ("admin", False, ["CREATE TABLE public.web_demo_probe(id integer)"]),
    "monitor_views": ("monitor", False, ["SELECT grp, member FROM monitor.group_members LIMIT 5"]),
    "analyst_national": ("analyst", True, ["SELECT national_id FROM customers LIMIT 1"]),
    "analyst_email": ("analyst", True, ["SELECT email FROM customers LIMIT 1"]),
    "analyst_star": ("analyst", True, ["SELECT * FROM customers LIMIT 1"]),
    "analyst_update": ("analyst", True, ["UPDATE orders SET amount_mad=0 WHERE id=1"]),
    "app_delete": ("app", True, ["DELETE FROM orders WHERE id=1"]),
    "app_drop": ("app", True, ["DROP TABLE orders"]),
    "app_file": ("app", True, ["SELECT pg_read_file('/etc/hostname')"]),
    "app_program": ("app", True, ["COPY (SELECT 1) TO PROGRAM 'id'"]),
    "app_escalate": ("app", True, ["SET ROLE dba_admin"]),
}


def log_records():
    records = []
    files = sorted(glob.glob(os.path.join(LOG_DIR, "postgresql-*.json")))[-2:]
    for path in files:
        with open(path, "rb") as fh:
            size = os.fstat(fh.fileno()).st_size
            fh.seek(max(0, size - 2_000_000))
            lines = fh.read().decode("utf-8", "replace").splitlines()
        if size > 2_000_000:
            lines = lines[1:]
        for line in lines:
            try:
                records.append(json.loads(line))
            except ValueError:
                continue
    return records[-10000:]


def wait_logs(user, predicate):
    for _ in range(16):
        rows = [r for r in log_records() if r.get("user") == user and predicate(r)]
        if rows:
            return rows
        time.sleep(0.25)
    return []


def log_evidence(rows):
    return [{"time": r.get("timestamp"), "severity": r.get("error_severity"),
             "message": str(r.get("message", ""))[:350]} for r in rows[-5:]]


def monitor_report(user, wanted, rows, extra=None):
    args = [sys.executable, os.path.join(os.path.dirname(__file__), "monitor.py"), "--minutes", "5"]
    args += extra or []
    proc = subprocess.run(args, input="".join(json.dumps(r) + "\n" for r in rows),
                          text=True, capture_output=True, timeout=10)
    if proc.returncode not in (0, 1):
        return result("error", "The monitoring parser could not evaluate the test records.", user=user)
    matches = [line for line in proc.stdout.splitlines()
               if line.startswith("ALERT " + wanted + " ") and ('user=' + json.dumps(user)) in line]
    if not matches:
        return result("unexpected", "The expected alert was not produced.", [{"monitor": proc.stdout[:4000]}], user)
    return result("observed", "The monitoring rule detected the generated activity.",
                  [{"alerts": matches}] + log_evidence(rows), user)


def connection_test(actor, scenario):
    conn = actor.connect()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT ssl, version, cipher FROM pg_stat_ssl WHERE pid=pg_backend_pid()")
            tls = cur.fetchone()
    finally:
        conn.close()
    user = actor.credentials()["data"]["username"]
    evidence = [{"verified_tls_control": list(tls)}]
    if not tls or not tls[0]:
        return result("unexpected", "The positive control was not encrypted.", evidence, user)
    if scenario == "tls_ok":
        return result("allowed", "The CA and hostname were verified and the session uses TLS.", evidence, user)
    params = {}
    if scenario == "tls_plain":
        params["sslmode"] = "disable"
    elif scenario == "tls_hostname":
        params.update(host="wrong-demo-host.invalid", hostaddr=socket.gethostbyname(PGHOST))
    elif scenario == "tls_ca":
        params["sslrootcert"] = ssl.get_default_verify_paths().cafile or "/etc/ssl/certs/ca-certificates.crt"
    elif scenario == "bad_password":
        params["password"] = secrets.token_urlsafe(32)
    try:
        unexpected = actor.connect(**params)
        unexpected.close()
        return result("unexpected", "The invalid connection was accepted.", evidence, user)
    except Exception as error:
        text = str(error).lower()
        expected = {
            "tls_plain": "pg_hba.conf" in text and "no encryption" in text,
            "tls_hostname": "does not match host name" in text or "hostname mismatch" in text,
            "tls_ca": "certificate verify failed" in text or "unable to get local issuer" in text,
            "bad_password": authentication_failure(error),
        }.get(scenario, False)
        if not expected:
            return result("error", "The connection failed for an unrelated reason.", evidence + [{"error": message(error)}], user)
        return result("blocked", "The invalid connection was rejected for the expected reason.", evidence, user)


def baseline_connect():
    host = os.getenv("DEMO_BASELINE_HOST", "demo-baseline")
    if socket.gethostbyname(host) == socket.gethostbyname(PGHOST):
        raise RuntimeError("Baseline host must be separate from the protected database")
    return connect_db(host=host, dbname="appdb", user="app",
                      password=os.environ["DEMO_BASELINE_PASSWORD"], sslmode="disable", connect_timeout=5)


def baseline(scenario, progress):
    if scenario == "baseline_reuse":
        first = baseline_connect()
        first.close()
        progress("First baseline login succeeded. Waiting 40 seconds before reuse.")
        time.sleep(40)
        again = baseline_connect()
        again.close()
        return result("insecure", "The same static baseline credential still worked after 40 seconds.")
    conn = baseline_connect()
    try:
        with conn.cursor() as cur:
            cur.execute("SET LOCAL statement_timeout='5s'")
            if scenario == "baseline_plain":
                cur.execute("SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()")
                encrypted = cur.fetchone()[0]
                cur.execute("SELECT full_name, national_id FROM customers LIMIT 2")
                data = cur.fetchall()
                return result("insecure" if not encrypted and data else "unexpected",
                              "The baseline exposed fake sensitive data over an unencrypted session.",
                              [{"TLS": encrypted, "fake_customer_data": data}])
            if scenario == "baseline_admin":
                cur.execute("SELECT count(*) FROM orders")
                before = cur.fetchone()[0]
                cur.execute("DELETE FROM orders")
                deleted = cur.rowcount
                cur.execute("SELECT count(*) FROM orders")
                remaining = cur.fetchone()[0]
                conn.rollback()
                cur.execute("SELECT count(*) FROM orders")
                restored = cur.fetchone()[0]
                ok = before > 0 and deleted == before and remaining == 0 and restored == before
                return result("insecure" if ok else "unexpected",
                              "The baseline application deleted the rows; rollback restored them.",
                              [{"before": before, "deleted": deleted, "after_rollback": restored}])
            settings = {}
            for name in ("log_statement", "log_connections", "shared_preload_libraries"):
                cur.execute("SHOW " + name)
                settings[name] = cur.fetchone()[0]
            missing = (settings["log_statement"] == "none" and settings["log_connections"] == "off"
                       and "pgaudit" not in settings["shared_preload_libraries"])
            return result("insecure" if missing else "unexpected",
                          "The baseline has no statement logging, connection logging or loaded pgaudit.", [settings])
    finally:
        conn.rollback()
        conn.close()


SPECIAL = {"unique_users", "app_admin", "analyst_app", "approle_replay", "approle_invalid", "bad_password",
           "tls_ok", "tls_plain", "tls_hostname", "tls_ca", "expiry", "revoke_login", "revoke_session",
           "audit_allowed", "audit_denied", "monitor_burst", "monitor_failed", "monitor_offhours",
           "baseline_plain", "baseline_reuse", "baseline_admin", "baseline_audit"}
CAPABILITIES = set(SQL_CASES) | SPECIAL


def run(broker, scenario, run_id, progress):
    if scenario not in CAPABILITIES:
        return result("error", "Unknown scenario.")
    if scenario.startswith("baseline_"):
        return baseline(scenario, progress)
    if scenario in SQL_CASES:
        role, should_deny, statements = SQL_CASES[scenario]
        if scenario == "admin_ddl":
            statements = [statements[0].replace("web_demo_probe", "web_demo_" + uuid.uuid4().hex[:12])]
        progress("Authenticating as " + role + " and running the fixed test transaction.")
        with identity(broker, role, run_id) as actor:
            return sql_attempt(actor, statements, should_deny)
    if scenario == "unique_users":
        with identity(broker, "analyst", run_id) as a, identity(broker, "analyst", run_id) as b:
            names = [a.credentials()["data"]["username"], b.credentials()["data"]["username"]]
            return result("allowed" if names[0] != names[1] else "unexpected",
                          "Two separate credential requests produced different identities.", [{"usernames": names}])
    if scenario in {"app_admin", "analyst_app"}:
        role, other = ("app", "admin") if scenario == "app_admin" else ("analyst", "app")
        with identity(broker, role, run_id) as actor:
            actor.credentials()  # Positive control: this identity can request its own role.
            try:
                actor.vault.call("GET", "database/creds/" + other)
                return result("unexpected", "Vault allowed the cross-identity credential request.")
            except VaultError as error:
                if error.status == 403:
                    return result("blocked", "Vault allowed the identity's own credentials and denied the other role.",
                                  [{"identity": role, "requested_role": other, "HTTP": 403}])
                raise
    if scenario in {"approle_replay", "approle_invalid"}:
        role_id, secret_id = broker.pair("analyst")
        first = login(role_id, secret_id)
        try:
            if scenario == "approle_invalid":
                _, secret_id = broker.pair("analyst")
                role_id = str(uuid.uuid4())
            try:
                other = login(role_id, secret_id)
                other.revoke()
                return result("unexpected", "Vault accepted the invalid or reused login.")
            except VaultError as error:
                if error.status in (400, 403):
                    return result("blocked", "A valid AppRole login succeeded; the invalid or replayed login was denied.",
                                  [{"HTTP": error.status}])
                raise
        finally:
            first.revoke()
    with identity(broker, "analyst", run_id) as actor:
        if scenario in {"tls_ok", "tls_plain", "tls_hostname", "tls_ca", "bad_password"}:
            return connection_test(actor, scenario)
        secret = actor.credentials()
        user = secret["data"]["username"]
        if scenario in {"expiry", "revoke_login", "revoke_session"}:
            conn = actor.connect()
            conn.autocommit = True
            try:
                with conn.cursor() as cur:
                    cur.execute("SELECT current_user")
                    initial = cur.fetchone()[0]
                if scenario == "expiry":
                    conn.close()
                    seconds = int(secret["lease_duration"]) + 5
                    if not 1 <= seconds <= 90:
                        return result("error", "The lease is too long for this bounded expiry test.", user=user)
                    progress("Initial login succeeded. Waiting %s seconds for the lease to expire." % seconds)
                    time.sleep(seconds)
                else:
                    progress("Initial login succeeded. Revoking this test identity's own Vault token.")
                    actor.revoke()
                    time.sleep(1)
                if scenario == "revoke_session":
                    try:
                        with conn.cursor() as cur:
                            cur.execute("SELECT 1")
                        return result("unexpected", "The existing session remained usable after revocation.", user=user)
                    except Exception as error:
                        text = str(error).lower()
                        closed = (getattr(error, "pgcode", None) == "57P01"
                                  or "closed" in text or "terminating connection" in text)
                        return result("blocked" if closed else "error",
                                      "The test session was terminated after its own token was revoked." if closed
                                      else "The session failed for an unrelated reason.", [{"initial_user": initial}], user)
                try:
                    again = actor.connect()
                    again.close()
                    return result("unexpected", "The credential still authenticated after expiry or revocation.", user=user)
                except Exception as error:
                    ok = authentication_failure(error)
                    return result("blocked" if ok else "error",
                                  "The initial login worked; the same credential was later rejected." if ok
                                  else "The reconnect failed for an unrelated reason.", [{"initial_user": initial}], user)
            finally:
                conn.close()
        if scenario == "monitor_failed":
            check = connection_test(actor, "bad_password")
            if check["outcome"] != "blocked":
                return check
            rows = wait_logs(user, lambda r: "password authentication failed" in r.get("message", ""))
            return monitor_report(user, "AUTH_FAILURE", rows)
        should_deny = scenario == "audit_denied"
        count = 25 if scenario == "monitor_burst" else 1
        sql = "SELECT national_id FROM customers LIMIT 1" if should_deny else "SELECT count(*) FROM orders"
        control = sql_attempt(actor, [sql] * count, should_deny)
        if control["outcome"] not in {"allowed", "blocked"}:
            return control
        if should_deny:
            rows = wait_logs(user, lambda r: "permission denied" in r.get("message", ""))
        else:
            rows = wait_logs(user, lambda r: r.get("message", "").startswith("AUDIT: SESSION,"))
        if not rows:
            return result("unexpected", "The test ran, but matching log evidence was not found.", user=user)
        if scenario == "monitor_burst":
            # Wait for all statements, not merely the first flushed audit record.
            for _ in range(16):
                rows = [r for r in log_records() if r.get("user") == user and r.get("message", "").startswith("AUDIT: SESSION,")]
                if len(rows) >= count:
                    break
                time.sleep(0.25)
            return monitor_report(user, "HIGH_SELECT_COUNT", rows)
        if scenario == "monitor_offhours":
            stamp = rows[-1]["timestamp"].replace(" UTC", "+00:00").replace("Z", "+00:00")
            hour = datetime.fromisoformat(stamp).astimezone(timezone.utc).hour
            args = ["--timezone", "UTC", "--start-hour", str((hour + 1) % 24), "--end-hour", str((hour + 2) % 24)]
            observed = monitor_report(user, "OFF_HOURS", rows, args)
            observed["evidence"].insert(0, {"test_working_hours_UTC": "%02d:00-%02d:00" % ((hour+1)%24, (hour+2)%24),
                                          "note": "Test-only hours exclude the event time; the real clock was not changed."})
            return observed
        return result("observed", "The operation produced matching audit or error-log evidence.", log_evidence(rows), user)
