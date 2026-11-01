#!/usr/bin/env python3
"""Zero-trust demo client. There is no database password anywhere in this file."""
import os
import sys
import time

import hvac
import psycopg2

USAGE = """usage:
  app.py whoami <vault-role>
  app.py sql <vault-role> "<SQL>" ["<SQL>" ...]
  app.py ask <vault-role> <other-vault-role>
  app.py plaintext <vault-role>
  app.py stolen <vault-role> [seconds]"""

VAULT_ADDR = os.environ.get("VAULT_ADDR", "http://vault:8200")
PGHOST = os.environ.get("PGHOST", "postgres")
PGDATABASE = os.environ.get("PGDATABASE", "appdb")
CA_FILE = os.environ.get("PGSSLROOTCERT", "/certs/ca.crt")


def first_line(err):
    return str(err).strip().splitlines()[0]


def vault_login():
    """Step 1: prove our identity to Vault with AppRole (role_id + single-use secret_id)."""
    client = hvac.Client(url=VAULT_ADDR)
    client.auth.approle.login(role_id=os.environ["ROLE_ID"], secret_id=os.environ["SECRET_ID"])
    return client


def get_credentials(client, role):
    """Step 2: ask Vault for a brand-new temporary database user."""
    resp = client.secrets.database.generate_credentials(name=role, mount_point="database")
    data = resp["data"]
    print(f"[vault] received temporary DB user {data['username']} (lease {resp['lease_duration']}s)")
    return data["username"], data["password"], resp["lease_duration"]


def connect(user, password, sslmode="verify-full"):
    """Step 5: connect over TLS, checking the CA chain and the hostname."""
    conn = psycopg2.connect(
        host=PGHOST, dbname=PGDATABASE, user=user, password=password,
        sslmode=sslmode, sslrootcert=CA_FILE, connect_timeout=5,
    )
    conn.autocommit = True
    return conn


def run_sql(conn, sql):
    print(f"[pg] > {sql}")
    try:
        with conn.cursor() as cur:
            cur.execute(sql)
            if cur.description:
                for row in cur.fetchall():
                    print("      ", row)
            else:
                print(f"       OK ({cur.statusmessage})")
    except psycopg2.Error as err:
        print(f"       DENIED by PostgreSQL: {first_line(err)}")


def cmd_whoami(role):
    user, password, _ = get_credentials(vault_login(), role)
    conn = connect(user, password)
    run_sql(conn, "SELECT current_user")
    run_sql(conn, "SELECT ssl, version, cipher FROM pg_stat_ssl WHERE pid = pg_backend_pid()")


def cmd_sql(role, statements):
    user, password, _ = get_credentials(vault_login(), role)
    conn = connect(user, password)
    for sql in statements:
        run_sql(conn, sql)


def cmd_ask(role, other):
    client = vault_login()
    print(f"[vault] logged in; now asking for database/creds/{other}")
    try:
        get_credentials(client, other)
        print("       !!! unexpectedly allowed")
    except hvac.exceptions.Forbidden:
        print(f"       DENIED by Vault policy: this identity may not read database/creds/{other}")


def cmd_plaintext(role):
    user, password, _ = get_credentials(vault_login(), role)
    print("[pg] trying a connection WITHOUT TLS (sslmode=disable)")
    try:
        connect(user, password, sslmode="disable")
        print("       !!! plaintext connection accepted: misconfiguration")
    except psycopg2.OperationalError as err:
        print(f"       REFUSED (no TLS): {first_line(err)}")


def cmd_stolen(role, wait=None):
    user, password, lease = get_credentials(vault_login(), role)
    wait = wait if wait is not None else lease + 10
    conn = connect(user, password)
    run_sql(conn, "SELECT current_user")
    conn.close()
    print(f"[attacker] stole the credential; waiting {wait}s (lease is {lease}s)")
    time.sleep(wait)
    try:
        connect(user, password)
        print("       !!! credential still valid")
    except psycopg2.OperationalError as err:
        print(f"       REJECTED after expiry: {first_line(err)}")


def main(argv):
    if len(argv) < 3:
        sys.exit(USAGE)
    cmd, role, rest = argv[1], argv[2], argv[3:]
    if cmd == "whoami":
        cmd_whoami(role)
    elif cmd == "sql" and rest:
        cmd_sql(role, rest)
    elif cmd == "ask" and rest:
        cmd_ask(role, rest[0])
    elif cmd == "plaintext":
        cmd_plaintext(role)
    elif cmd == "stolen":
        cmd_stolen(role, int(rest[0]) if rest else None)
    else:
        sys.exit(USAGE)


if __name__ == "__main__":
    main(sys.argv)
