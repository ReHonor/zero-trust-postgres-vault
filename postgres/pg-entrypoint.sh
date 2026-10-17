#!/usr/bin/env bash
# PostgreSQL refuses to start if the TLS private key is not owned by the
# postgres user with mode 0600. Bind-mounted files keep the host ownership,
# so we copy them to a private location and fix owner and mode first.
set -euo pipefail

DEST=/etc/postgresql-certs
mkdir -p "$DEST"
cp /certs-src/server.crt /certs-src/server.key /certs-src/ca.crt "$DEST"/
chown postgres:postgres "$DEST"/*
chmod 600 "$DEST/server.key"
chmod 644 "$DEST/server.crt" "$DEST/ca.crt"

exec docker-entrypoint.sh "$@"
