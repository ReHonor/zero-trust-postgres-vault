#!/usr/bin/env bash

set -euo pipefail
cd "$(dirname "$0")/.."
config="$PWD/.gitleaks.toml"
fixtures=$(mktemp -d)
trap 'rm -rf -- "$fixtures"' EXIT

mkdir -p "$fixtures"/{allowed,copied,changed,extra}/baseline
mkdir -p "$fixtures/copied/other"

printf 'DB_PASSWORD=welcome2024\n' \
  > "$fixtures/allowed/baseline/.env.baseline"
printf 'DB_PASSWORD=welcome2024\n' \
  > "$fixtures/copied/other/.env"
printf 'DB_PASSWORD=another-fake-test-password\n' \
  > "$fixtures/changed/baseline/.env.baseline"
printf 'DB_PASSWORD=welcome2024\nVAULT_ROOT_TOKEN=fake-test-token-only\n' \
  > "$fixtures/extra/baseline/.env.baseline"

check() {
  local name="$1" expected="$2" actual
  if docker run --rm \
    -v "$fixtures/$name:/scan:ro" \
    -v "$config:/config/gitleaks.toml:ro" \
    -w /scan ghcr.io/gitleaks/gitleaks:v8.30.1 \
    dir . --config /config/gitleaks.toml \
    --redact=100 --no-banner --exit-code 23; then
    actual=0
  else
    actual=$?
  fi
  if [[ "$actual" != "$expected" ]]; then
    echo "FAIL: $name expected=$expected actual=$actual"
    exit 1
  fi
  echo "PASS: $name (exit=$actual)"
}

check allowed 0
check copied 23
check changed 23
check extra 23
echo "All 4 Gitleaks tests passed."
